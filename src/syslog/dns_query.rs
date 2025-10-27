use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::sysmon::DnsEvent;
use serde::Serialize;

use super::{parse_sysmon_time, EventToCsv, TryFromSysmonRecord};

impl TryFromSysmonRecord for DnsEvent {
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
        let time: i64 = if let Some(utc_time) = rec.get(3) {
            parse_sysmon_time(utc_time)?
                .as_nanosecond()
                .try_into()
                .context("timestamp out of range")?
        } else {
            return Err(anyhow!("missing time"));
        };
        let time = time + serial;
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
        let query_name = if let Some(query_name) = rec.get(6) {
            query_name.to_string()
        } else {
            return Err(anyhow!("missing query_name"));
        };
        let query_status = if let Some(query_status) = rec.get(7) {
            if query_status.eq("-") {
                0
            } else {
                query_status
                    .parse::<u32>()
                    .context("invalid query_status")?
            }
        } else {
            return Err(anyhow!("missing query_status"));
        };
        let query_results = if let Some(query_results) = rec.get(8) {
            query_results
                .split(';')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing query_results"));
        };
        let image = if let Some(image) = rec.get(9) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let user = if let Some(user) = rec.get(10) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };

        Ok((
            Self {
                agent_name,
                agent_id,
                process_guid,
                process_id,
                query_name,
                query_status,
                query_results,
                image,
                user,
            },
            time,
        ))
    }
}

#[derive(Serialize)]
pub(crate) struct ElasticDnsEvent {
    agent_name: Option<String>,
    agent_id: Option<String>,
    event_action: Option<String>,
    utc_time: Option<String>,
    process_guid: Option<String>,
    process_id: Option<String>,
    query_name: Option<String>,
    query_status: Option<String>,
    query_results: Option<String>,
    image: Option<String>,
    user: Option<String>,
}

impl EventToCsv for ElasticDnsEvent {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticDnsEvent {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("Dns query".to_string()),
                        utc_time: None,
                        process_guid: None,
                        process_id: None,
                        query_name: None,
                        query_status: None,
                        query_results: None,
                        image: None,
                        user: None,
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
                                "QueryName" => entry.query_name = Some(value.to_string()),
                                "QueryStatus" => entry.query_status = Some(value.to_string()),
                                "QueryResults" => entry.query_results = Some(value.to_string()),
                                "Image" => entry.image = Some(value.to_string()),
                                "User" => entry.user = Some(value.to_string()),
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
