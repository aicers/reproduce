use std::net::{IpAddr, Ipv4Addr};

use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::sysmon::NetworkConnection;
use serde::Serialize;

use super::{parse_sysmon_time, EventToCsv, TryFromSysmonRecord};

impl TryFromSysmonRecord for NetworkConnection {
    #[allow(clippy::too_many_lines)]
    fn try_from_sysmon_record(rec: &csv::StringRecord, serial: i64) -> Result<(Self, i64)> {
        let agent_name = if let Some(agent_name) = rec.get(0) {
            agent_name.to_string()
        } else {
            return Err(anyhow!("missing agent_name"));
        };
        let agent_id = if let Some(agent_id) = rec.get(1) {
            agent_id.to_string()
        } else {
            return Err(anyhow!("missing agent_id"));
        };
        let time = if let Some(utc_time) = rec.get(3) {
            parse_sysmon_time(utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
                + serial
        } else {
            return Err(anyhow!("missing time"));
        };
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let user = if let Some(user) = rec.get(7) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let protocol = if let Some(protocol) = rec.get(8) {
            protocol.to_string()
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let initiated = if let Some(initiated) = rec.get(9) {
            if initiated.eq("true") {
                true
            } else if initiated.eq("false") || initiated.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid initiated"));
            }
        } else {
            return Err(anyhow!("missing initiated"));
        };
        let source_is_ipv6 = if let Some(source_is_ipv6) = rec.get(10) {
            if source_is_ipv6.eq("true") {
                true
            } else if source_is_ipv6.eq("false") || source_is_ipv6.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid source_is_ipv6"));
            }
        } else {
            return Err(anyhow!("missing source_is_ipv6"));
        };
        let source_ip = if let Some(source_ip) = rec.get(11) {
            if source_ip.eq("-") {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                source_ip.parse::<IpAddr>().context("invalid source_ip")?
            }
        } else {
            return Err(anyhow!("missing source_ip"));
        };
        let source_hostname = if let Some(source_hostname) = rec.get(12) {
            source_hostname.to_string()
        } else {
            return Err(anyhow!("missing source_hostname"));
        };
        let source_port = if let Some(source_port) = rec.get(13) {
            if source_port.eq("-") {
                0
            } else {
                source_port.parse::<u16>().context("invalid source_port")?
            }
        } else {
            return Err(anyhow!("missing source_port"));
        };
        let source_port_name = if let Some(source_port_name) = rec.get(14) {
            source_port_name.to_string()
        } else {
            return Err(anyhow!("missing source_port_name"));
        };
        let destination_is_ipv6 = if let Some(destination_is_ipv6) = rec.get(15) {
            if destination_is_ipv6.eq("true") {
                true
            } else if destination_is_ipv6.eq("false") || destination_is_ipv6.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid destination_is_ipv6"));
            }
        } else {
            return Err(anyhow!("missing destination_is_ipv6"));
        };
        let destination_ip = if let Some(destination_ip) = rec.get(16) {
            if destination_ip.eq("-") {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                destination_ip
                    .parse::<IpAddr>()
                    .context("invalid destination_ip")?
            }
        } else {
            return Err(anyhow!("missing destination_ip"));
        };
        let destination_hostname = if let Some(destination_hostname) = rec.get(17) {
            destination_hostname.to_string()
        } else {
            return Err(anyhow!("missing destination_hostname"));
        };
        let destination_port = if let Some(destination_port) = rec.get(18) {
            if destination_port.eq("-") {
                0
            } else {
                destination_port
                    .parse::<u16>()
                    .context("invalid destination_port")?
            }
        } else {
            return Err(anyhow!("missing destination_port"));
        };
        let destination_port_name = if let Some(destination_port_name) = rec.get(19) {
            destination_port_name.to_string()
        } else {
            return Err(anyhow!("missing destination_port_name"));
        };

        Ok((
            Self {
                agent_name,
                agent_id,
                process_guid,
                process_id,
                image,
                user,
                protocol,
                initiated,
                source_is_ipv6,
                source_ip,
                source_hostname,
                source_port,
                source_port_name,
                destination_is_ipv6,
                destination_ip,
                destination_hostname,
                destination_port,
                destination_port_name,
            },
            time,
        ))
    }
}

#[derive(Serialize)]
pub(super) struct ElasticNetworkConnection {
    agent_name: Option<String>,
    agent_id: Option<String>,
    event_action: Option<String>,
    utc_time: Option<String>,
    process_guid: Option<String>,
    process_id: Option<String>,
    image: Option<String>,
    user: Option<String>,
    protocol: Option<String>,
    initiated: Option<String>,
    source_is_ipv6: Option<String>,
    source_ip: Option<String>,
    source_hostname: Option<String>,
    source_port: Option<String>,
    source_port_name: Option<String>,
    destination_is_ipv6: Option<String>,
    destination_ip: Option<String>,
    destination_hostname: Option<String>,
    destination_port: Option<String>,
    destination_port_name: Option<String>,
}

impl EventToCsv for ElasticNetworkConnection {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticNetworkConnection {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("Network connection detected".to_string()),
                        utc_time: None,
                        process_guid: None,
                        process_id: None,
                        image: None,
                        user: None,
                        protocol: None,
                        initiated: None,
                        source_is_ipv6: None,
                        source_ip: None,
                        source_hostname: None,
                        source_port: None,
                        source_port_name: None,
                        destination_is_ipv6: None,
                        destination_ip: None,
                        destination_hostname: None,
                        destination_port: None,
                        destination_port_name: None,
                    };

                    if let Some(agent_name) = hit["_source"]["agent"]["name"].as_str() {
                        entry.agent_name = Some(agent_name.to_string());
                    }

                    if let Some(agent_id) = hit["_source"]["agent"]["id"].as_str() {
                        entry.agent_id = Some(agent_id.to_string());
                    }

                    for part in message.split('\n') {
                        let segments: Vec<_> = part.splitn(2, ':').collect();
                        if segments.len() == 2 {
                            let key = segments[0].trim();
                            let value = segments[1].trim();
                            match key {
                                "UtcTime" => entry.utc_time = Some(value.to_string()),
                                "ProcessGuid" => entry.process_guid = Some(value.to_string()),
                                "ProcessId" => entry.process_id = Some(value.to_string()),
                                "Image" => entry.image = Some(value.to_string()),
                                "User" => entry.user = Some(value.to_string()),
                                "Protocol" => entry.protocol = Some(value.to_string()),
                                "Initiated" => entry.initiated = Some(value.to_string()),
                                "SourceIsIpv6" => entry.source_is_ipv6 = Some(value.to_string()),
                                "SourceIp" => entry.source_ip = Some(value.to_string()),
                                "SourceHostname" => entry.source_hostname = Some(value.to_string()),
                                "SourcePort" => entry.source_port = Some(value.to_string()),
                                "SourcePortName" => {
                                    entry.source_port_name = Some(value.to_string());
                                }
                                "DestinationIsIpv6" => {
                                    entry.destination_is_ipv6 = Some(value.to_string());
                                }
                                "DestinationIp" => entry.destination_ip = Some(value.to_string()),
                                "DestinationHostname" => {
                                    entry.destination_hostname = Some(value.to_string());
                                }
                                "DestinationPort" => {
                                    entry.destination_port = Some(value.to_string());
                                }
                                "DestinationPortName" => {
                                    entry.destination_port_name = Some(value.to_string());
                                }
                                _ => {}
                            }
                        }
                    }

                    entries.push(entry);
                }
            }
        }

        entries
    }
}
