use anyhow::{Context, Result, anyhow};
use giganto_client::ingest::sysmon::PipeEvent;
use serde::Serialize;

use super::{EventToCsv, TryFromSysmonRecord, parse_sysmon_timestamp_ns};

impl TryFromSysmonRecord for PipeEvent {
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
            parse_sysmon_timestamp_ns(utc_time)? + serial
        } else {
            return Err(anyhow!("missing time"));
        };
        let event_type = if let Some(event_type) = rec.get(4) {
            event_type.to_string()
        } else {
            return Err(anyhow!("missing event_type"));
        };
        let process_guid = if let Some(process_guid) = rec.get(5) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(6) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let pipe_name = if let Some(pipe_name) = rec.get(7) {
            pipe_name.to_string()
        } else {
            return Err(anyhow!("missing pipe_name"));
        };
        let image = if let Some(image) = rec.get(8) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let user = if let Some(user) = rec.get(9) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };

        Ok((
            Self {
                agent_name,
                agent_id,
                event_type,
                process_guid,
                process_id,
                pipe_name,
                image,
                user,
            },
            time,
        ))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize)]
pub(crate) struct ElasticPipeEvent {
    agent_name: Option<String>,
    agent_id: Option<String>,
    event_action: Option<String>,
    utc_time: Option<String>,
    event_type: Option<String>,
    process_guid: Option<String>,
    process_id: Option<String>,
    pipe_name: Option<String>,
    image: Option<String>,
    user: Option<String>,
}

impl EventToCsv for ElasticPipeEvent {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticPipeEvent {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("Pipe Created".to_string()),
                        utc_time: None,
                        event_type: None,
                        process_guid: None,
                        process_id: None,
                        pipe_name: None,
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
                                "EventType" => entry.event_type = Some(value.to_string()),
                                "ProcessGuid" => entry.process_guid = Some(value.to_string()),
                                "ProcessId" => entry.process_id = Some(value.to_string()),
                                "PipeName" => entry.pipe_name = Some(value.to_string()),
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
