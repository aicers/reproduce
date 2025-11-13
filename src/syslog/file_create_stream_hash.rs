use anyhow::{Context, Result, anyhow};
use giganto_client::ingest::sysmon::FileCreateStreamHash;
use serde::Serialize;

use super::{
    EventToCsv, TryFromSysmonRecord, is_datastore_format, parse_datastore_time, parse_sysmon_time,
};

impl TryFromSysmonRecord for FileCreateStreamHash {
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
        let image = if let Some(image) = rec.get(field_offset + 4) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let target_filename = if let Some(target_filename) = rec.get(field_offset + 5) {
            target_filename.to_string()
        } else {
            return Err(anyhow!("missing target_filename"));
        };
        let creation_utc_time = if let Some(creation_utc_time) = rec.get(field_offset + 6) {
            parse_sysmon_time(creation_utc_time)?
        } else {
            return Err(anyhow!("missing creation_utc_time"));
        };
        let hash = if let Some(hash) = rec.get(field_offset + 7) {
            hash.split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing hash"));
        };
        let contents = if let Some(contents) = rec.get(field_offset + 8) {
            contents.to_string()
        } else {
            return Err(anyhow!("missing contents"));
        };
        let user = if let Some(user) = rec.get(field_offset + 9) {
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
                hash,
                contents,
                user,
            },
            time,
        ))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize)]
pub(crate) struct ElasticFileCreateStreamHash {
    agent_name: Option<String>,
    agent_id: Option<String>,
    event_action: Option<String>,
    utc_time: Option<String>,
    process_guid: Option<String>,
    process_id: Option<String>,
    image: Option<String>,
    target_filename: Option<String>,
    creation_utc_time: Option<String>,
    hash: Option<String>,
    contents: Option<String>,
    user: Option<String>,
}

impl EventToCsv for ElasticFileCreateStreamHash {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticFileCreateStreamHash {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("File stream created".to_string()),
                        utc_time: None,
                        process_guid: None,
                        process_id: None,
                        image: None,
                        target_filename: None,
                        creation_utc_time: None,
                        hash: None,
                        contents: None,
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
                                "Hash" => entry.hash = Some(value.to_string()),
                                "Contents" => entry.contents = Some(value.to_string()),
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
