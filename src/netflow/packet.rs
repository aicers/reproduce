use std::{
    io::{BufRead, Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{anyhow, bail, Result};
use byteorder::{BigEndian, ReadBytesExt};
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use num_enum::FromPrimitive;
use pcap::Packet;
use serde::{Deserialize, Serialize};

use super::{
    fields::{DataTypes, FieldTypes, OptionsScopeFieldTypes, FORWARDING_STATUS, TCP_FLAGS},
    templates::Template,
    ProcessStats,
};

// TODO: other ports can be used
const CFLOW_UDP_PORTS: [u16; 1] = [2055];
const MAC_ADDRESS_LEN: usize = 6;
const IEEE_802_1Q_TCI_LEN: usize = 2;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_DCE: u16 = 0x8903;
const PROTO_UDP: u8 = 0x11;
const IPV4_MORE_FRAG: u16 = 0b0010_0000_0000_0000;
const NETFLOW_V5_RECORD_LENGTH: u64 = 48;

type TypeLengthPairs = (u16, u64, Vec<(u16, u16)>);

pub struct PktBuf {
    data: Cursor<Vec<u8>>,
    len: u64,
    iph: IpHeader,
}

struct AddrPair {
    src: IpAddr,
    dst: IpAddr,
}

struct IpHeader {
    addr_pair: AddrPair,
    proto: u8,
    id: u32,
}

impl IpHeader {
    fn new() -> Self {
        Self {
            addr_pair: AddrPair {
                src: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                dst: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            },
            proto: 0,
            id: 0,
        }
    }
}

impl std::fmt::Display for IpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "IP({}) {} > {}",
            self.id, self.addr_pair.src, self.addr_pair.dst,
        )
    }
}

struct UdpHeader {
    dst_port: u16,
}

pub enum NetflowHeader {
    V5(Netflow5Header),
    V9(Netflow9Header),
}

impl NetflowHeader {
    pub fn timestamp(&self) -> (u32, u32) {
        match self {
            NetflowHeader::V5(x) => (x.unix_secs, x.unix_nanos),
            NetflowHeader::V9(x) => (x.unix_secs, 0),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Netflow5Header {
    pub version: u16,
    pub count: u16,
    pub sys_uptime: u32, // milliseconds
    pub unix_secs: u32,  // seconds
    pub unix_nanos: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_interval: u16,
}

impl std::fmt::Display for Netflow5Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Version: {}", self.version)?;
        writeln!(f, "Count: {}", self.count)?;
        writeln!(
            f,
            "System Uptime: {}.{}",
            self.sys_uptime / 1000,
            self.sys_uptime - (self.sys_uptime / 1000) * 1000
        )?;
        writeln!(f, "Timestamp: {}.{:09}", self.unix_secs, self.unix_nanos)?;
        writeln!(f, "Flow Sequence: {}", self.flow_sequence)?;
        writeln!(f, "Engine Type: {}", self.engine_type)?;
        writeln!(f, "Engine Id: {}", self.engine_id)?;
        writeln!(f, "Sampling Mode: {}", self.sampling_interval & 0xC000)?;
        writeln!(f, "Sampling Rate: {}", self.sampling_interval & 0x3FFF)
    }
}

/*
Netflow V9 Header:
20 = 2(version) + 2(count) + 4(SysUptime) + 4(Timestamp) + 4(FlowSequence) + 4(SourceId)

Flowset Header:
4 = 2(FlowSet Id) + 2(FlowSet Length)

Flowset:
 = Flowset ID (2B) + Flowset Length (2B) + Field(Type + Length) Count * 4
*/

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Netflow9Header {
    pub version: u16,
    pub count: u16,
    pub sys_uptime: u32,
    pub unix_secs: u32,
    pub flow_sequence: u32,
    pub source_id: u32,
}

impl std::fmt::Display for Netflow9Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Version: {}", self.version)?;
        writeln!(f, "Count: {}", self.count)?;
        writeln!(f, "Source id: {}", self.source_id)?;
        writeln!(f, "System Uptime: {}", self.sys_uptime)?;
        writeln!(f, "Timestamp: {}", self.unix_secs)?;
        writeln!(f, "Sequence: {}", self.flow_sequence)
    }
}

impl PktBuf {
    pub fn new(pkt: &Packet<'_>) -> Self {
        Self {
            data: Cursor::new(pkt.data.to_vec()),
            len: u64::try_from(pkt.len()).unwrap_or_default(),
            iph: IpHeader::new(),
        }
    }

    pub fn src_addr(&self) -> IpAddr {
        self.iph.addr_pair.src
    }

    fn remained(&self) -> Option<u64> {
        let remained = self.len - self.data.position();
        if remained > 0 {
            Some(remained)
        } else {
            None
        }
    }

    fn parse_ethernet(&mut self) -> Result<u16> {
        self.data.consume(MAC_ADDRESS_LEN * 2);
        let ethertype = self.data.read_u16::<BigEndian>()?;
        match ethertype {
            ETHERTYPE_VLAN => {
                self.data.consume(IEEE_802_1Q_TCI_LEN);
                Ok(self.data.read_u16::<BigEndian>()?)
            }
            ETHERTYPE_DCE => {
                self.data.consume(MAC_ADDRESS_LEN * 2);
                Ok(self.data.read_u16::<BigEndian>()?)
            }
            _ => Ok(ethertype),
        }
    }

    fn parse_ipv4(&mut self) -> Result<IpHeader> {
        let ihl = self.data.read_u8()?; // Version + Length, 1 Byte
        self.data.consume(1); // ToS, 1 Byte
        let len = self.data.read_u16::<BigEndian>()?; // Total Length, 2 Byte
        let _payload_len = len - (u16::from(ihl & 0xf) << 2);
        let id = self.data.read_u16::<BigEndian>()?; // Identifier, 2 Byte
        let flag_offset = self.data.read_u16::<BigEndian>()?; // Flags, Fragmented Offset, 2 Byte
        let _: bool = flag_offset & IPV4_MORE_FRAG == IPV4_MORE_FRAG; // mf
        let _ = flag_offset << 3; // fragmentation offset
        self.data.consume(1); // TTL, 1 Byte
        let proto = self.data.read_u8()?; // Protocol, 1 Byte
        self.data.consume(2); // Checksum, 2 Byte
        let src = self.data.read_u32::<BigEndian>()?;
        let dst = self.data.read_u32::<BigEndian>()?;
        let addr_pair = AddrPair {
            src: Ipv4Addr::from(src).into(),
            dst: Ipv4Addr::from(dst).into(),
        };

        if (ihl & 0x0F) * 4 > 20 {
            self.data.consume(usize::from(ihl & 0x0F) - 20);
        }
        Ok(IpHeader {
            addr_pair,
            proto,
            id: id.into(),
        })
    }

    fn parse_udp(&mut self) -> Result<UdpHeader> {
        let _src_port = self.data.read_u16::<BigEndian>()?;
        let dst_port = self.data.read_u16::<BigEndian>()?;
        let _len = self.data.read_u16::<BigEndian>()?;
        let _csum = self.data.read_u16::<BigEndian>()?;
        Ok(UdpHeader { dst_port })
    }

    pub fn is_netflow(&mut self) -> ProcessStats {
        // L2
        let Ok(ethertype) = self.parse_ethernet() else {
            return ProcessStats::InvalidPackets;
        };

        // IPv4
        if ethertype != ETHERTYPE_IPV4 {
            return ProcessStats::NoNetflowPackets;
        }
        let Ok(ipv4) = self.parse_ipv4() else {
            return ProcessStats::InvalidPackets;
        };

        self.iph = ipv4;

        // UDP
        if self.iph.proto != PROTO_UDP {
            return ProcessStats::NoNetflowPackets;
        }
        let Ok(udp_hdr) = self.parse_udp() else {
            return ProcessStats::InvalidPackets;
        };

        // CFLOW (Netflow)
        if CFLOW_UDP_PORTS.contains(&udp_hdr.dst_port) {
            ProcessStats::YesNetflowPackets
        } else {
            ProcessStats::NoNetflowPackets
        }
    }

    pub fn parse_netflow_header(&mut self) -> Result<NetflowHeader> {
        let version = self.data.read_u16::<BigEndian>()?;
        let count = self.data.read_u16::<BigEndian>()?;
        let sys_uptime = self.data.read_u32::<BigEndian>()?;
        let unix_secs = self.data.read_u32::<BigEndian>()?;
        match version {
            5 => {
                let unix_nanos = self.data.read_u32::<BigEndian>()?;
                let flow_sequence = self.data.read_u32::<BigEndian>()?;
                let engine_type = self.data.read_u8()?;
                let engine_id = self.data.read_u8()?;
                let sampling_interval = self.data.read_u16::<BigEndian>()?;
                Ok(NetflowHeader::V5(Netflow5Header {
                    version,
                    count,
                    sys_uptime,
                    unix_secs,
                    unix_nanos,
                    flow_sequence,
                    engine_type,
                    engine_id,
                    sampling_interval,
                }))
            }
            9 => {
                let flow_sequence = self.data.read_u32::<BigEndian>()?;
                let source_id = self.data.read_u32::<BigEndian>()?;
                Ok(NetflowHeader::V9(Netflow9Header {
                    version,
                    count,
                    sys_uptime,
                    unix_secs,
                    flow_sequence,
                    source_id,
                }))
            }
            _ => bail!("unimplemented netflow version {}", version),
        }
    }

    pub fn parse_netflow_v9_flowset_header(&mut self) -> Result<(u16, u16)> {
        let flowset_id = self.data.read_u16::<BigEndian>()?;
        let flowset_length = self.data.read_u16::<BigEndian>()?;
        Ok((flowset_id, flowset_length))
    }

    fn read_type_value_pairs(&mut self, len: u16) -> Result<TypeLengthPairs> {
        let mut fields = vec![];
        let mut read = 0;
        let mut count = 0;
        let mut length = 0;
        loop {
            let field_type = self.data.read_u16::<BigEndian>()?;
            let field_length = self.data.read_u16::<BigEndian>()?;
            fields.push((field_type, field_length));
            count += 1;
            length += field_length;
            read += 4;
            if read >= len || self.remained().is_none() {
                break;
            }
        }
        Ok((count, u64::from(length), fields))
    }

    pub fn parse_netflow_template(
        &mut self,
        flowset_length: u16,
        header: &Netflow9Header,
    ) -> Result<Vec<Template>> {
        let mut fds = vec![];
        while let Some(remained) = self.remained() {
            // 4: flowset_id(2B) + flowset_length(2B)
            if remained + 4 < u64::from(flowset_length) {
                break;
            }
            let template_id = self.data.read_u16::<BigEndian>()?;
            let field_count = self.data.read_u16::<BigEndian>()?;
            let (_, flow_length, fields) = self.read_type_value_pairs(field_count * 4)?;
            fds.push(Template {
                header: header.clone(),
                template_id,
                field_count,
                flow_length,
                fields,
                options_template: false,
                scope_field_count: 0,
            });
        }
        Ok(fds)
    }

    pub fn parse_netflow_options_template(
        &mut self,
        flowset_length: u16,
        header: &Netflow9Header,
    ) -> Result<Vec<Template>> {
        let mut fds = vec![];
        while let Some(remained) = self.remained() {
            // 4: flowset_id(2B) + flowset_length(2B)
            if remained + 4 < u64::from(flowset_length) {
                break;
            }
            let template_id = self.data.read_u16::<BigEndian>()?;
            let option_scope_length = self.data.read_u16::<BigEndian>()?;
            let option_length = self.data.read_u16::<BigEndian>()?;
            let (scope_count, scope_field_len, scope_fields) = if option_scope_length > 0 {
                self.read_type_value_pairs(option_scope_length)?
            } else {
                (0, 0, vec![])
            };
            let (option_count, option_field_len, option_fields) = if option_length > 0 {
                self.read_type_value_pairs(option_length)?
            } else {
                (0, 0, vec![])
            };
            let field_count = scope_count + option_count;
            let fields_length = scope_field_len + option_field_len;
            let mut fields = scope_fields;
            fields.extend_from_slice(&option_fields);
            fds.push(Template {
                header: header.clone(),
                template_id,
                field_count,
                flow_length: fields_length,
                fields,
                options_template: true,
                scope_field_count: usize::from(scope_count),
            });
            let padding = flowset_length - (10 + field_count * 4);
            if padding > 0 {
                self.data.consume(usize::from(padding));
            }
        }
        Ok(fds)
    }

    pub fn parse_netflow_v5_datasets(&mut self, header: &Netflow5Header) -> Result<Vec<Netflow5>> {
        let mut flows = vec![];
        let mut dataset_count = 0;
        while let Some(remained) = self.remained() {
            if remained < NETFLOW_V5_RECORD_LENGTH || header.count <= dataset_count {
                break;
            }
            let src_addr: IpAddr = Ipv4Addr::from(self.data.read_u32::<BigEndian>()?).into();
            let dst_addr: IpAddr = Ipv4Addr::from(self.data.read_u32::<BigEndian>()?).into();
            let next_hop: IpAddr = Ipv4Addr::from(self.data.read_u32::<BigEndian>()?).into();
            let input = self.data.read_u16::<BigEndian>()?;
            let output = self.data.read_u16::<BigEndian>()?;
            let d_pkts = self.data.read_u32::<BigEndian>()?;
            let d_octets = self.data.read_u32::<BigEndian>()?;
            let first = self.data.read_u32::<BigEndian>()?;
            let last = self.data.read_u32::<BigEndian>()?;
            let src_port = self.data.read_u16::<BigEndian>()?;
            let dst_port = self.data.read_u16::<BigEndian>()?;
            self.data.consume(1);
            let tcp_flags = self.data.read_u8()?;
            let prot = self.data.read_u8()?;
            let tos = self.data.read_u8()?;
            let src_as = self.data.read_u16::<BigEndian>()?;
            let dst_as = self.data.read_u16::<BigEndian>()?;
            let src_mask = self.data.read_u8()?;
            let dst_mask = self.data.read_u8()?;
            self.data.consume(2);
            flows.push(Netflow5 {
                src_addr,
                dst_addr,
                next_hop,
                input,
                output,
                d_pkts,
                d_octets,
                first,
                last,
                src_port,
                dst_port,
                tcp_flags,
                prot,
                tos,
                src_as,
                dst_as,
                src_mask,
                dst_mask,
                sequence: header.flow_sequence,
                engine_type: header.engine_type,
                engine_id: header.engine_id,
                sampling_mode: ((header.sampling_interval & 0xC000) >> 8)
                    .try_into()
                    .unwrap_or_default(),
                sampling_rate: header.sampling_interval & 0x3FFF,
            });
            dataset_count += 1;
        }
        Ok(flows)
    }

    // TODO: Parse multiple(template set + data set) in a packet
    pub fn parse_netflow_v9_datasets(
        &mut self,
        template: &Template,
        header: &Netflow9Header,
        template_id: u16,
    ) -> Vec<Netflow9> {
        let mut flows = vec![];
        let mut dataset_count = 0;
        while let Some(remained) = self.remained() {
            if remained < template.flow_length || header.count <= dataset_count {
                break;
            }

            let mut flow = vec![];
            let mut orig_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            let mut orig_port = 0;
            let mut resp_port = 0;
            let mut resp_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            let mut proto = 0;
            if template.options_template {
                if template.scope_field_count > 0 {
                    if let Some(fields) = template.fields.get(..template.scope_field_count) {
                        for (k, len) in fields {
                            let ft = OptionsScopeFieldTypes::from_primitive(*k);
                            let value = self
                                .parse_data(&DataTypes::Ascii, *len)
                                .unwrap_or("-".to_string());
                            flow.push(format!("{ft:?}:{value}"));
                        }
                    }
                }
                if usize::from(template.field_count) > template.scope_field_count {
                    if let Some(fields) = template.fields.get(template.scope_field_count..) {
                        for (k, len) in fields {
                            let ft = FieldTypes::from_primitive(*k);
                            let kind = ft.get_types();
                            let value = self.parse_data(&kind, *len).unwrap_or("-".to_string());
                            flow.push(format!("{ft:?}:{value}"));
                        }
                    }
                }
            } else {
                for (k, len) in &template.fields {
                    let ft = FieldTypes::from_primitive(*k);
                    let kind = ft.get_types();
                    let value = match ft {
                        FieldTypes::IPv4SrcAddr | FieldTypes::IPv6SrcAddr => {
                            let Ok(ipaddr) = self.parse_ipaddr(&kind) else {
                                continue;
                            };
                            orig_addr = ipaddr;
                            ipaddr.to_string()
                        }
                        FieldTypes::IPv4DstAddr | FieldTypes::IPv6DstAddr => {
                            let Ok(ipaddr) = self.parse_ipaddr(&kind) else {
                                continue;
                            };
                            resp_addr = ipaddr;
                            ipaddr.to_string()
                        }
                        FieldTypes::L4SrcPort => {
                            let Ok(port) = self.parse_port() else {
                                continue;
                            };
                            orig_port = port;
                            port.to_string()
                        }
                        FieldTypes::L4DstPort => {
                            let Ok(port) = self.parse_port() else {
                                continue;
                            };
                            resp_port = port;
                            port.to_string()
                        }
                        FieldTypes::Protocol => {
                            let Ok(flag) = self.parse_flag() else {
                                continue;
                            };
                            proto = flag;
                            proto.to_string()
                        }
                        _ => self.parse_data(&kind, *len).unwrap_or("-".to_string()),
                    };
                    flow.push(format!("{ft:?}:{value}"));
                }
            }
            flows.push(Netflow9 {
                sequence: header.flow_sequence,
                source_id: header.source_id,
                template_id,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                contents: flow.join(", "),
            });
            dataset_count += 1;
        }
        flows
    }

    fn parse_data(&mut self, kind: &DataTypes, len: u16) -> Result<String> {
        match *kind {
            DataTypes::Ascii => {
                let b = match len {
                    1 => u64::from(self.data.read_u8()?),
                    2 => u64::from(self.data.read_u16::<BigEndian>()?),
                    4 => u64::from(self.data.read_u32::<BigEndian>()?),
                    8 => self.data.read_u64::<BigEndian>()?,
                    _ => 0,
                };
                Ok(format!("{b:x}"))
            }
            DataTypes::ForwardingStatus => {
                let b = self.data.read_u8()?;
                if let Some((_, fs)) = FORWARDING_STATUS.iter().find(|(f, _)| *f == b) {
                    Ok((*fs).to_string())
                } else {
                    Ok(b.to_string())
                }
            }
            DataTypes::Integer => match len {
                1 => Ok(self.data.read_u8()?.to_string()),
                2 => Ok(self.data.read_u16::<BigEndian>()?.to_string()),
                4 => Ok(self.data.read_u32::<BigEndian>()?.to_string()),
                8 => Ok(self.data.read_u64::<BigEndian>()?.to_string()),
                _ => Ok(0_u64.to_string()),
            },
            DataTypes::Ipv4 | DataTypes::Ipv6 => Ok(self.parse_ipaddr(kind)?.to_string()),
            DataTypes::TcpFlags => {
                let b = self.data.read_u8()?;
                let mut res = String::new();
                for e in &TCP_FLAGS {
                    if b & e.0 == e.0 {
                        res.push_str(e.1);
                        res.push('-');
                    }
                }
                if res.is_empty() {
                    res.push_str("None");
                }

                if res.ends_with('-') {
                    res.pop();
                }
                Ok(res)
            }
            DataTypes::Text => {
                let mut buf = vec![0; len.into()];
                self.data.read_exact(&mut buf)?;
                if let Some(pos) = buf.iter().position(|b| *b < 0x20 || *b > 0x7e) {
                    Ok(buf
                        .get(..pos)
                        .map_or("-".to_string(), |v| String::from_utf8_lossy(v).to_string()))
                } else {
                    Ok("-".to_string())
                }
            }
        }
    }

    fn parse_ipaddr(&mut self, kind: &DataTypes) -> Result<IpAddr> {
        match *kind {
            DataTypes::Ipv4 => {
                let ipaddr = self.data.read_u32::<BigEndian>()?;
                Ok(IpAddr::V4(Ipv4Addr::from(ipaddr)))
            }
            DataTypes::Ipv6 => {
                let ipaddr = self.data.read_u128::<BigEndian>()?;
                Ok(IpAddr::V6(Ipv6Addr::from(ipaddr)))
            }
            _ => bail!("invalid ip address"),
        }
    }

    fn parse_port(&mut self) -> Result<u16> {
        Ok(self.data.read_u16::<BigEndian>()?)
    }

    fn parse_flag(&mut self) -> Result<u8> {
        self.data
            .read_u8()
            .map_err(|e| anyhow!("fail to parse flag. {}", e))
    }
}
