use super::{parse_sysmon_time, EventToCsv, TryFromSysmonRecord};
use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::sysmon::RegistryValueSet;
use serde::Serialize;

impl TryFromSysmonRecord for RegistryValueSet {
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
        let image = if let Some(image) = rec.get(7) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let target_object = if let Some(target_object) = rec.get(8) {
            target_object.to_string()
        } else {
            return Err(anyhow!("missing target_object"));
        };
        let details = if let Some(details) = rec.get(9) {
            details.to_string()
        } else {
            return Err(anyhow!("missing details"));
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
                event_type,
                process_guid,
                process_id,
                image,
                target_object,
                details,
                user,
            },
            time,
        ))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize)]
pub struct ElasticRegistryValueSet {
    pub agent_name: Option<String>,
    pub agent_id: Option<String>,
    pub event_action: Option<String>,
    pub utc_time: Option<String>,
    pub event_type: Option<String>,
    pub process_guid: Option<String>,
    pub process_id: Option<String>,
    pub image: Option<String>,
    pub target_object: Option<String>,
    pub details: Option<String>,
    pub user: Option<String>,
}

impl EventToCsv for ElasticRegistryValueSet {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticRegistryValueSet {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("Registry value set".to_string()),
                        utc_time: None,
                        event_type: None,
                        process_guid: None,
                        process_id: None,
                        image: None,
                        target_object: None,
                        details: None,
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
                                "EventType" => entry.event_type = Some(value.to_string()),
                                "UtcTime" => entry.utc_time = Some(value.to_string()),
                                "ProcessGuid" => entry.process_guid = Some(value.to_string()),
                                "ProcessId" => entry.process_id = Some(value.to_string()),
                                "Image" => entry.image = Some(value.to_string()),
                                "TargetObject" => entry.target_object = Some(value.to_string()),
                                "Details" => entry.details = Some(value.to_string()),
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
