use std::{
    io::{BufRead, Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Result, anyhow, bail};
use byteorder::{BigEndian, ReadBytesExt};
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use num_enum::FromPrimitive;
use pcap::Packet;
use serde::{Deserialize, Serialize};

use super::{
    ProcessStats,
    fields::{DataTypes, FORWARDING_STATUS, FieldTypes, OptionsScopeFieldTypes, TCP_FLAGS},
    templates::Template,
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

pub(crate) struct PktBuf {
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

pub(crate) enum NetflowHeader {
    V5(Netflow5Header),
    V9(Netflow9Header),
}

impl NetflowHeader {
    pub(crate) fn timestamp(&self) -> (u32, u32) {
        match self {
            NetflowHeader::V5(x) => (x.unix_secs, x.unix_nanos),
            NetflowHeader::V9(x) => (x.unix_secs, 0),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Netflow5Header {
    version: u16,
    pub(super) count: u16,
    sys_uptime: u32,           // milliseconds
    pub(super) unix_secs: u32, // seconds
    unix_nanos: u32,
    flow_sequence: u32,
    engine_type: u8,
    engine_id: u8,
    sampling_interval: u16,
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
pub(crate) struct Netflow9Header {
    version: u16,
    pub(super) count: u16,
    sys_uptime: u32,
    pub(super) unix_secs: u32,
    flow_sequence: u32,
    pub(super) source_id: u32,
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
    pub(crate) fn new(pkt: &Packet<'_>) -> Self {
        Self {
            data: Cursor::new(pkt.data.to_vec()),
            len: u64::try_from(pkt.len()).unwrap_or_default(),
            iph: IpHeader::new(),
        }
    }

    pub(crate) fn src_addr(&self) -> IpAddr {
        self.iph.addr_pair.src
    }

    fn remained(&self) -> Option<u64> {
        let remained = self.len - self.data.position();
        if remained > 0 { Some(remained) } else { None }
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

    pub(crate) fn is_netflow(&mut self) -> ProcessStats {
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

    pub(crate) fn parse_netflow_header(&mut self) -> Result<NetflowHeader> {
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
            _ => bail!("unimplemented netflow version {version}"),
        }
    }

    pub(super) fn parse_netflow_v9_flowset_header(&mut self) -> Result<(u16, u16)> {
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

    pub(super) fn parse_netflow_template(
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

    pub(super) fn parse_netflow_options_template(
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

    pub(super) fn parse_netflow_v5_datasets(
        &mut self,
        header: &Netflow5Header,
    ) -> Result<Vec<Netflow5>> {
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
    pub(super) fn parse_netflow_v9_datasets(
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
                if template.scope_field_count > 0
                    && let Some(fields) = template.fields.get(..template.scope_field_count)
                {
                    for (k, len) in fields {
                        let ft = OptionsScopeFieldTypes::from_primitive(*k);
                        let value = self
                            .parse_data(&DataTypes::Ascii, *len)
                            .unwrap_or("-".to_string());
                        flow.push(format!("{ft:?}:{value}"));
                    }
                }

                if usize::from(template.field_count) > template.scope_field_count
                    && let Some(fields) = template.fields.get(template.scope_field_count..)
                {
                    for (k, len) in fields {
                        let ft = FieldTypes::from_primitive(*k);
                        let kind = ft.get_types();
                        let value = self.parse_data(&kind, *len).unwrap_or("-".to_string());
                        flow.push(format!("{ft:?}:{value}"));
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
            .map_err(|e| anyhow!("fail to parse flag. {e}"))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::Netflow9Header;

    pub(crate) fn netflow9_header_fixture(source_id: u32) -> Netflow9Header {
        Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use anyhow::Result;
    use tempfile::tempdir;

    use super::ProcessStats;
    use super::*;
    use crate::netflow::ParseNetflowDatasets;
    use crate::netflow::Stats;
    use crate::netflow::fields::DataTypes;
    use crate::netflow::templates::{Template, TemplatesBox};

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let mut iter = filtered.as_bytes().chunks_exact(2);
        for pair in &mut iter {
            let v = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
            bytes.push(v);
        }
        bytes
    }

    fn pktbuf_from_bytes(bytes: Vec<u8>) -> PktBuf {
        let len = bytes.len() as u64;
        PktBuf {
            data: Cursor::new(bytes),
            len,
            iph: IpHeader::new(),
        }
    }

    fn build_ipv4_udp_packet(payload: &[u8], dst_port: u16, proto: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 6]);
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        bytes.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        let total_len = 20u16 + 8u16 + u16::try_from(payload.len()).unwrap_or(0);
        bytes.push(0x45);
        bytes.push(0);
        bytes.extend_from_slice(&total_len.to_be_bytes());
        bytes.extend_from_slice(&0x1234u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.push(64);
        bytes.push(proto);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&[10, 0, 0, 1]);
        bytes.extend_from_slice(&[10, 0, 0, 2]);

        if proto == PROTO_UDP {
            let udp_len = 8u16 + u16::try_from(payload.len()).unwrap_or(0);
            bytes.extend_from_slice(&1000u16.to_be_bytes());
            bytes.extend_from_slice(&dst_port.to_be_bytes());
            bytes.extend_from_slice(&udp_len.to_be_bytes());
            bytes.extend_from_slice(&0u16.to_be_bytes());
            bytes.extend_from_slice(payload);
        }

        bytes
    }

    fn v5_header_bytes(count: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u16.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.push(5);
        bytes.push(6);
        bytes.extend_from_slice(&0x4001u16.to_be_bytes());
        bytes
    }

    fn v9_header_bytes(count: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&9u16.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes
    }

    #[test]
    fn is_netflow_rejects_invalid_packets() {
        let mut buf = pktbuf_from_bytes(Vec::new());
        assert_eq!(buf.is_netflow(), ProcessStats::InvalidPackets);
    }

    #[test]
    fn is_netflow_returns_no_for_non_ipv4() {
        let mut bytes = vec![0u8; 12];
        // EtherType 0x86DD indicates IPv6.
        bytes.extend_from_slice(&0x86DDu16.to_be_bytes());
        let mut buf = pktbuf_from_bytes(bytes);
        assert_eq!(buf.is_netflow(), ProcessStats::NoNetflowPackets);
    }

    #[test]
    fn is_netflow_returns_no_for_non_udp() {
        // 0x06 is TCP (not UDP), so this should not be treated as NetFlow.
        let bytes = build_ipv4_udp_packet(&[], 2055, 0x06);
        let mut buf = pktbuf_from_bytes(bytes);
        assert_eq!(buf.is_netflow(), ProcessStats::NoNetflowPackets);
    }

    #[test]
    fn is_netflow_returns_yes_for_cflow_port() {
        let bytes = build_ipv4_udp_packet(&[], 2055, PROTO_UDP);
        let mut buf = pktbuf_from_bytes(bytes);
        assert_eq!(buf.is_netflow(), ProcessStats::YesNetflowPackets);
    }

    #[test]
    fn parse_netflow_header_v5() -> Result<()> {
        let payload = v5_header_bytes(1);
        let bytes = build_ipv4_udp_packet(&payload, 2055, PROTO_UDP);
        let mut buf = pktbuf_from_bytes(bytes);
        assert_eq!(buf.is_netflow(), ProcessStats::YesNetflowPackets);
        let header = buf.parse_netflow_header()?;
        let NetflowHeader::V5(v5) = header else {
            panic!("expected v5 header");
        };
        assert_eq!(v5.count, 1);
        assert_eq!(v5.unix_secs, 2);
        Ok(())
    }

    #[test]
    fn parse_netflow_header_v9() -> Result<()> {
        let payload = v9_header_bytes(2);
        let bytes = build_ipv4_udp_packet(&payload, 2055, PROTO_UDP);
        let mut buf = pktbuf_from_bytes(bytes);
        assert_eq!(buf.is_netflow(), ProcessStats::YesNetflowPackets);
        let header = buf.parse_netflow_header()?;
        let NetflowHeader::V9(v9) = header else {
            panic!("expected v9 header");
        };
        assert_eq!(v9.count, 2);
        assert_eq!(v9.unix_secs, 2);
        Ok(())
    }

    #[test]
    fn parse_netflow_header_unimplemented_version() {
        let mut payload = Vec::new();
        // Netflow version 10 (unimplemented).
        payload.extend_from_slice(&10u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&2u32.to_be_bytes());
        let bytes = build_ipv4_udp_packet(&payload, 2055, PROTO_UDP);
        let mut buf = pktbuf_from_bytes(bytes);
        assert_eq!(buf.is_netflow(), ProcessStats::YesNetflowPackets);
        let err = buf.parse_netflow_header().err().unwrap();
        assert!(err.to_string().contains("unimplemented netflow version"));
    }

    #[test]
    fn parse_netflow_v9_flowset_header_reads_values() -> Result<()> {
        let mut buf = pktbuf_from_bytes(vec![0x01, 0x00, 0x00, 0x10]);
        let (id, len) = buf.parse_netflow_v9_flowset_header()?;
        assert_eq!(id, 256);
        assert_eq!(len, 16);
        Ok(())
    }

    #[test]
    fn parse_netflow_template_reads_fields() -> Result<()> {
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id: 1,
        };
        let mut buf = pktbuf_from_bytes(vec![
            0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04,
        ]);
        let templates = buf.parse_netflow_template(16, &header)?;
        assert_eq!(templates.len(), 1);
        let t = &templates[0];
        assert_eq!(t.template_id, 256);
        assert_eq!(t.field_count, 2);
        assert_eq!(t.flow_length, 8);
        Ok(())
    }

    #[test]
    fn parse_netflow_options_template_reads_scope_and_option_fields() -> Result<()> {
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id: 1,
        };
        let mut buf = pktbuf_from_bytes(vec![
            0x01, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04,
        ]);
        let templates = buf.parse_netflow_options_template(18, &header)?;
        assert_eq!(templates.len(), 1);
        let t = &templates[0];
        assert!(t.options_template);
        assert_eq!(t.scope_field_count, 1);
        assert_eq!(t.field_count, 2);
        Ok(())
    }

    #[test]
    fn parse_netflow_v5_datasets_reads_record() -> Result<()> {
        let header = Netflow5Header {
            version: 5,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            unix_nanos: 0,
            flow_sequence: 1,
            engine_type: 2,
            engine_id: 3,
            sampling_interval: 0x4001,
        };
        let record = hex_to_bytes(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/netflow/v5_record.hex"
        )));
        let mut buf = pktbuf_from_bytes(record);
        let flows = buf.parse_netflow_v5_datasets(&header)?;
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].src_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(flows[0].dst_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(flows[0].src_port, 1234);
        assert_eq!(flows[0].dst_port, 80);
        Ok(())
    }

    #[test]
    fn parse_netflow_v9_datasets_reads_flow() {
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 7,
            source_id: 9,
        };
        let template = Template {
            header: header.clone(),
            template_id: 256,
            field_count: 5,
            flow_length: 13,
            fields: vec![(8, 4), (12, 4), (7, 2), (11, 2), (4, 1)],
            options_template: false,
            scope_field_count: 0,
        };
        let bytes = hex_to_bytes(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/netflow/v9_dataset.hex"
        )));
        let mut buf = pktbuf_from_bytes(bytes);
        let flows = buf.parse_netflow_v9_datasets(&template, &header, 256);
        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(flow.orig_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(flow.resp_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(flow.orig_port, 1234);
        assert_eq!(flow.resp_port, 80);
        assert_eq!(flow.proto, 6);
        assert!(flow.contents.contains("IPv4SrcAddr:10.0.0.1"));
        assert!(flow.contents.contains("IPv4DstAddr:10.0.0.2"));
    }

    #[test]
    fn parse_data_handles_text_and_flags() -> Result<()> {
        let mut buf = pktbuf_from_bytes(vec![0x12, b'a', b'b', b'c', 0x00]);
        let flags = buf.parse_data(&DataTypes::TcpFlags, 1)?;
        assert_eq!(flags, "SYN-ACK");
        let text = buf.parse_data(&DataTypes::Text, 4)?;
        assert_eq!(text, "abc");
        Ok(())
    }

    #[test]
    fn parse_data_handles_forwarding_status_and_ipaddr() -> Result<()> {
        let mut buf = pktbuf_from_bytes(vec![
            0x40, 0x0a, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        let status = buf.parse_data(&DataTypes::ForwardingStatus, 1)?;
        assert_eq!(status, "Forwarded (Unknown)");
        let v4 = buf.parse_data(&DataTypes::Ipv4, 4)?;
        assert_eq!(v4, "10.0.0.1");
        let v6 = buf.parse_data(&DataTypes::Ipv6, 16)?;
        assert_eq!(v6, IpAddr::V6(Ipv6Addr::LOCALHOST).to_string());
        Ok(())
    }

    #[test]
    fn parse_ipaddr_rejects_invalid_kind() {
        let mut buf = pktbuf_from_bytes(vec![0x01, 0x02, 0x03, 0x04]);
        let err = buf.parse_ipaddr(&DataTypes::Integer).unwrap_err();
        assert!(err.to_string().contains("invalid ip address"));
    }

    #[test]
    fn templates_box_add_and_get_template() {
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id: 10,
        };
        let template = Template {
            header,
            template_id: 256,
            field_count: 1,
            flow_length: 4,
            fields: vec![(1, 4)],
            options_template: false,
            scope_field_count: 0,
        };
        let mut box_ = TemplatesBox::new();
        assert!(box_.is_empty());
        box_.add(
            1,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            std::slice::from_ref(&template),
        );
        assert!(!box_.is_empty());
        let key = (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 10, 256);
        let stored = box_.get(&key).expect("template should exist");
        assert_eq!(stored.template_id, 256);
        assert_eq!(stored.flow_length, 4);
    }

    #[test]
    fn templates_box_save_and_load_roundtrip() -> Result<()> {
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id: 10,
        };
        let template = Template {
            header,
            template_id: 300,
            field_count: 1,
            flow_length: 4,
            fields: vec![(1, 4)],
            options_template: false,
            scope_field_count: 0,
        };
        let mut box_ = TemplatesBox::new();
        box_.add(1, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), &[template]);

        let dir = tempdir()?;
        let path = dir.path().join("templates.bin");
        box_.save(path.to_str().unwrap())?;

        let loaded = TemplatesBox::from_path(path.to_str().unwrap())?;
        let key = (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 10, 300);
        let stored = loaded.get(&key).expect("template should be loaded");
        assert_eq!(stored.template_id, 300);
        Ok(())
    }

    #[test]
    fn parse_netflow_datasets_v5_updates_stats() -> Result<()> {
        let header = Netflow5Header {
            version: 5,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            unix_nanos: 0,
            flow_sequence: 1,
            engine_type: 2,
            engine_id: 3,
            sampling_interval: 0x4001,
        };
        let record = hex_to_bytes(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/netflow/v5_record.hex"
        )));
        let mut buf = pktbuf_from_bytes(record);
        let mut stats = Stats::new();
        let mut templates = TemplatesBox::new();
        let mut nanos = 0u32;

        let events = Netflow5::parse_netflow_datasets(
            1,
            &mut templates,
            &NetflowHeader::V5(header),
            &mut nanos,
            &mut buf,
            &mut stats,
        )?;

        assert_eq!(events.len(), 1);
        assert_eq!(nanos, 1);
        assert!(format!("{stats}").contains("Events = 1"));
        Ok(())
    }

    #[test]
    fn parse_netflow_datasets_v5_rejects_wrong_header() {
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id: 1,
        };
        let mut buf = pktbuf_from_bytes(Vec::new());
        let mut stats = Stats::new();
        let mut templates = TemplatesBox::new();
        let mut nanos = 0u32;

        let err = Netflow5::parse_netflow_datasets(
            1,
            &mut templates,
            &NetflowHeader::V9(header),
            &mut nanos,
            &mut buf,
            &mut stats,
        )
        .err()
        .unwrap();

        assert!(err.to_string().contains("invalid netflow v5 header"));
    }

    #[test]
    fn parse_netflow_datasets_v9_template_not_found() -> Result<()> {
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id: 1,
        };
        let mut data = Vec::new();
        data.extend_from_slice(&256u16.to_be_bytes());
        data.extend_from_slice(&17u16.to_be_bytes());
        data.extend_from_slice(&hex_to_bytes(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/netflow/v9_dataset.hex"
        ))));

        let mut buf = pktbuf_from_bytes(data);
        let mut stats = Stats::new();
        let mut templates = TemplatesBox::new();
        let mut nanos = 0u32;

        let events = Netflow9::parse_netflow_datasets(
            1,
            &mut templates,
            &NetflowHeader::V9(header),
            &mut nanos,
            &mut buf,
            &mut stats,
        )?;

        assert!(events.is_empty());
        assert!(format!("{stats}").contains("TemplateNotFound = 1"));
        Ok(())
    }

    #[test]
    fn parse_netflow_datasets_v9_with_template() -> Result<()> {
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id: 1,
        };
        let template = Template {
            header: header.clone(),
            template_id: 256,
            field_count: 5,
            flow_length: 13,
            fields: vec![(8, 4), (12, 4), (7, 2), (11, 2), (4, 1)],
            options_template: false,
            scope_field_count: 0,
        };
        let mut templates = TemplatesBox::new();
        templates.add(1, IpAddr::V4(Ipv4Addr::UNSPECIFIED), &[template]);

        let mut data = Vec::new();
        data.extend_from_slice(&256u16.to_be_bytes());
        data.extend_from_slice(&17u16.to_be_bytes());
        data.extend_from_slice(&hex_to_bytes(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/netflow/v9_dataset.hex"
        ))));
        let mut buf = pktbuf_from_bytes(data);
        let mut stats = Stats::new();
        let mut nanos = 0u32;

        let events = Netflow9::parse_netflow_datasets(
            1,
            &mut templates,
            &NetflowHeader::V9(header),
            &mut nanos,
            &mut buf,
            &mut stats,
        )?;

        assert_eq!(events.len(), 1);
        assert_eq!(nanos, 1);
        assert!(format!("{stats}").contains("Events = 1"));
        Ok(())
    }

    #[test]
    fn parse_netflow_datasets_v9_template_flowset_id_0() -> Result<()> {
        // Test the Template FlowSet (ID=0) path in parse_netflow_datasets
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id: 1,
        };

        // Build a FlowSet with ID=0 (Template FlowSet) containing one template
        // FlowSet header: flowset_id=0 (2B), flowset_length=16 (2B)
        // Template: template_id=256 (2B), field_count=2 (2B), fields=(8,4), (12,4)
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_be_bytes()); // FlowSet ID = 0 (Template)
        data.extend_from_slice(&16u16.to_be_bytes()); // FlowSet length
        data.extend_from_slice(&256u16.to_be_bytes()); // template_id
        data.extend_from_slice(&2u16.to_be_bytes()); // field_count
        data.extend_from_slice(&8u16.to_be_bytes()); // field type: IPv4SrcAddr
        data.extend_from_slice(&4u16.to_be_bytes()); // field length
        data.extend_from_slice(&12u16.to_be_bytes()); // field type: IPv4DstAddr
        data.extend_from_slice(&4u16.to_be_bytes()); // field length

        let mut buf = pktbuf_from_bytes(data);
        let mut stats = Stats::new();
        let mut templates = TemplatesBox::new();
        let mut nanos = 0u32;

        let events = Netflow9::parse_netflow_datasets(
            1,
            &mut templates,
            &NetflowHeader::V9(header),
            &mut nanos,
            &mut buf,
            &mut stats,
        )?;

        // Template FlowSets don't produce events
        assert!(events.is_empty());
        // Template should be added to templates box
        let key = (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, 256);
        let stored = templates.get(&key).expect("template should be stored");
        assert_eq!(stored.template_id, 256);
        assert_eq!(stored.field_count, 2);
        assert!(!stored.options_template);
        // Stats should show template was processed
        assert!(format!("{stats}").contains("V9Templates = 1"));
        Ok(())
    }

    #[test]
    fn parse_netflow_datasets_v9_options_template_flowset_id_1() -> Result<()> {
        // Test the Options Template FlowSet (ID=1) path in parse_netflow_datasets
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 1,
            source_id: 1,
        };

        // Build a FlowSet with ID=1 (Options Template FlowSet)
        // FlowSet header: flowset_id=1 (2B), flowset_length=18 (2B)
        // Options Template: template_id=257 (2B), scope_length=4 (2B), option_length=4 (2B)
        // Scope field: (1, 4) - System scope
        // Option field: (1, 4) - InBytes
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_be_bytes()); // FlowSet ID = 1 (Options Template)
        data.extend_from_slice(&18u16.to_be_bytes()); // FlowSet length
        data.extend_from_slice(&257u16.to_be_bytes()); // template_id
        data.extend_from_slice(&4u16.to_be_bytes()); // scope_length (one scope field: 4 bytes)
        data.extend_from_slice(&4u16.to_be_bytes()); // option_length (one option field: 4 bytes)
        data.extend_from_slice(&1u16.to_be_bytes()); // scope field type: System
        data.extend_from_slice(&4u16.to_be_bytes()); // scope field length
        data.extend_from_slice(&1u16.to_be_bytes()); // option field type: InBytes
        data.extend_from_slice(&4u16.to_be_bytes()); // option field length

        let mut buf = pktbuf_from_bytes(data);
        let mut stats = Stats::new();
        let mut templates = TemplatesBox::new();
        let mut nanos = 0u32;

        let events = Netflow9::parse_netflow_datasets(
            1,
            &mut templates,
            &NetflowHeader::V9(header),
            &mut nanos,
            &mut buf,
            &mut stats,
        )?;

        // Options Template FlowSets don't produce events
        assert!(events.is_empty());
        // Template should be added to templates box with options_template=true
        let key = (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, 257);
        let stored = templates
            .get(&key)
            .expect("options template should be stored");
        assert_eq!(stored.template_id, 257);
        assert!(stored.options_template);
        assert_eq!(stored.scope_field_count, 1);
        assert_eq!(stored.field_count, 2); // 1 scope + 1 option
        // Stats should show options template was processed
        assert!(format!("{stats}").contains("V9OptionsTemplate = 1"));
        Ok(())
    }

    #[test]
    fn parse_netflow_v9_datasets_with_options_template() {
        // Test the options_template branch in parse_netflow_v9_datasets (lines 476-498)
        let header = Netflow9Header {
            version: 9,
            count: 1,
            sys_uptime: 0,
            unix_secs: 0,
            flow_sequence: 7,
            source_id: 9,
        };

        // Create an options template with 1 scope field and 2 option fields
        // Scope field: System (type=1), length=4
        // Option fields: InBytes (type=1), length=4 and InPackets (type=2), length=4
        let template = Template {
            header: header.clone(),
            template_id: 257,
            field_count: 3,                       // 1 scope + 2 option
            flow_length: 12,                      // 4 + 4 + 4
            fields: vec![(1, 4), (1, 4), (2, 4)], // scope field + option fields
            options_template: true,
            scope_field_count: 1,
        };

        // Build data record: 4 bytes for scope + 4 bytes for option1 + 4 bytes for option2
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234_5678_u32.to_be_bytes()); // Scope field value
        data.extend_from_slice(&1000u32.to_be_bytes()); // InBytes value
        data.extend_from_slice(&50u32.to_be_bytes()); // InPackets value

        let mut buf = pktbuf_from_bytes(data);
        let flows = buf.parse_netflow_v9_datasets(&template, &header, 257);

        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(flow.template_id, 257);
        // For options template, IP addresses and ports remain unspecified
        assert_eq!(flow.orig_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(flow.resp_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(flow.orig_port, 0);
        assert_eq!(flow.resp_port, 0);
        // Contents should include scope field with OptionsScopeFieldTypes format
        assert!(flow.contents.contains("System:"));
        // Contents should include option fields with FieldTypes format
        assert!(flow.contents.contains("InBytes:"));
        assert!(flow.contents.contains("InPackets:"));
    }
}
