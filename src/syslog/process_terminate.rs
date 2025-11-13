use anyhow::{Context, Result, anyhow};
use giganto_client::ingest::sysmon::ProcessTerminated;
use serde::Serialize;

use super::{
    EventToCsv, TryFromSysmonRecord, is_datastore_format, parse_datastore_time, parse_sysmon_time,
};

fn parse_fields(
    rec: &csv::StringRecord,
    offset: usize,
) -> Result<(String, String, String, u32, String, String)> {
    let process_guid = rec
        .get(offset)
        .ok_or_else(|| anyhow!("missing process_guid"))?
        .to_string();
    let process_id = rec
        .get(offset + 1)
        .ok_or_else(|| anyhow!("missing process_id"))?
        .parse::<u32>()
        .context("invalid process_id")?;
    let image = rec
        .get(offset + 2)
        .ok_or_else(|| anyhow!("missing image"))?
        .to_string();
    let user = rec
        .get(offset + 3)
        .ok_or_else(|| anyhow!("missing user"))?
        .to_string();
    let agent_name = rec
        .get(offset - 2)
        .ok_or_else(|| anyhow!("missing agent_name"))?
        .to_string();
    let agent_id = rec
        .get(offset - 1)
        .ok_or_else(|| anyhow!("missing agent_id"))?
        .to_string();

    Ok((agent_name, agent_id, process_guid, process_id, image, user))
}

impl TryFromSysmonRecord for ProcessTerminated {
    fn try_from_sysmon_record(rec: &csv::StringRecord, serial: i64) -> Result<(Self, i64)> {
        let is_datastore = is_datastore_format(rec);

        let time = if is_datastore {
            let timestamp = rec.get(0).ok_or_else(|| anyhow!("missing timestamp"))?;
            parse_datastore_time(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
                + serial
        } else {
            let utc_time = rec.get(3).ok_or_else(|| anyhow!("missing time"))?;
            parse_sysmon_time(utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
                + serial
        };

        // Data-store format: timestamp(0), "sensor"(1), agent_name(2), agent_id(3), process_guid(4), process_id(5), image(6), user(7)
        // Elasticsearch format: agent_name(0), agent_id(1), event_action(2), utc_time(3), process_guid(4), process_id(5), image(6), user(7)
        let field_offset = if is_datastore { 6 } else { 4 };
        let (agent_name, agent_id, process_guid, process_id, image, user) =
            parse_fields(rec, field_offset)?;

        Ok((
            Self {
                agent_name,
                agent_id,
                process_guid,
                process_id,
                image,
                user,
            },
            time,
        ))
    }
}

#[derive(Serialize)]
pub(crate) struct ElasticProcessTerminated {
    agent_name: Option<String>,
    agent_id: Option<String>,
    event_action: Option<String>,
    utc_time: Option<String>,
    process_guid: Option<String>,
    process_id: Option<String>,
    image: Option<String>,
    user: Option<String>,
}

impl EventToCsv for ElasticProcessTerminated {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticProcessTerminated {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("Process terminated".to_string()),
                        utc_time: None,
                        process_guid: None,
                        process_id: None,
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
