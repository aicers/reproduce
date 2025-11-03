use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::sysmon::FileCreate;
use serde::Serialize;

use super::{parse_sysmon_time, EventToCsv, TryFromSysmonRecord};

impl TryFromSysmonRecord for FileCreate {
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
        let target_filename = if let Some(target_filename) = rec.get(7) {
            target_filename.to_string()
        } else {
            return Err(anyhow!("missing target_filename"));
        };
        let creation_utc_time = if let Some(creation_utc_time) = rec.get(8) {
            if creation_utc_time.eq("-") {
                0
            } else {
                parse_sysmon_time(creation_utc_time)?
                    .timestamp_nanos_opt()
                    .context("to_timestamp_nanos")?
            }
        } else {
            return Err(anyhow!("missing creation_utc_time"));
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
                process_guid,
                process_id,
                image,
                target_filename,
                creation_utc_time,
                user,
            },
            time,
        ))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize)]
pub(crate) struct ElasticFileCreate {
    agent_name: Option<String>,
    agent_id: Option<String>,
    event_action: Option<String>,
    utc_time: Option<String>,
    process_guid: Option<String>,
    process_id: Option<String>,
    image: Option<String>,
    target_filename: Option<String>,
    creation_utc_time: Option<String>,
    user: Option<String>,
}

impl EventToCsv for ElasticFileCreate {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticFileCreate {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("File created".to_string()),
                        utc_time: None,
                        process_guid: None,
                        process_id: None,
                        image: None,
                        target_filename: None,
                        creation_utc_time: None,
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
                                "Image" => entry.image = Some(value.to_string()),
                                "TargetFilename" => entry.target_filename = Some(value.to_string()),
                                "CreationUtcTime" => {
                                    entry.creation_utc_time = Some(value.to_string());
                                }
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
