use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::sysmon::FileDeleteDetected;
use serde::Serialize;

use super::{
    is_datastore_format, parse_datastore_time, parse_sysmon_time, EventToCsv, TryFromSysmonRecord,
};

impl TryFromSysmonRecord for FileDeleteDetected {
    fn try_from_sysmon_record(rec: &csv::StringRecord, serial: i64) -> Result<(Self, i64)> {
        let is_datastore = is_datastore_format(rec);
        let field_offset = if is_datastore { 2 } else { 0 };

        let time = if is_datastore {
            if let Some(timestamp) = rec.get(0) {
                parse_datastore_time(timestamp)?
                    .timestamp_nanos_opt()
                    .context("to_timestamp_nanos")?
                    + serial
            } else {
                return Err(anyhow!("missing timestamp"));
            }
        } else if let Some(utc_time) = rec.get(3) {
            parse_sysmon_time(utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
                + serial
        } else {
            return Err(anyhow!("missing time"));
        };

        let agent_name = if let Some(agent_name) = rec.get(field_offset) {
            agent_name.to_string()
        } else {
            return Err(anyhow!("missing agent_name"));
        };
        let agent_id = if let Some(agent_id) = rec.get(field_offset + 1) {
            agent_id.to_string()
        } else {
            return Err(anyhow!("missing agent_id"));
        };
        let process_guid = if let Some(process_guid) = rec.get(field_offset + 2) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(field_offset + 3) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let user = if let Some(user) = rec.get(field_offset + 4) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let image = if let Some(image) = rec.get(field_offset + 5) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let target_filename = if let Some(target_filename) = rec.get(field_offset + 6) {
            target_filename.to_string()
        } else {
            return Err(anyhow!("missing target_filename"));
        };
        let hashes = if let Some(hashes) = rec.get(field_offset + 7) {
            hashes
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing hashes"));
        };
        let is_executable = if let Some(is_executable) = rec.get(field_offset + 8) {
            if is_executable.eq("true") {
                true
            } else if is_executable.eq("false") || is_executable.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid is_executable"));
            }
        } else {
            return Err(anyhow!("missing is_executable"));
        };

        Ok((
            Self {
                agent_name,
                agent_id,
                process_guid,
                process_id,
                user,
                image,
                target_filename,
                hashes,
                is_executable,
            },
            time,
        ))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize)]
pub(crate) struct ElasticFileDeleteDetected {
    agent_name: Option<String>,
    agent_id: Option<String>,
    event_action: Option<String>,
    utc_time: Option<String>,
    process_guid: Option<String>,
    process_id: Option<String>,
    user: Option<String>,
    image: Option<String>,
    target_filename: Option<String>,
    hashes: Option<String>,
    is_executable: Option<String>,
}

impl EventToCsv for ElasticFileDeleteDetected {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticFileDeleteDetected {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("File Delete logged,".to_string()),
                        utc_time: None,
                        process_guid: None,
                        process_id: None,
                        user: None,
                        image: None,
                        target_filename: None,
                        hashes: None,
                        is_executable: None,
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
                                "User" => entry.user = Some(value.to_string()),
                                "Image" => entry.image = Some(value.to_string()),
                                "TargetFilename" => entry.target_filename = Some(value.to_string()),
                                "Hashes" => entry.hashes = Some(value.to_string()),
                                "IsExecutable" => entry.is_executable = Some(value.to_string()),
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
