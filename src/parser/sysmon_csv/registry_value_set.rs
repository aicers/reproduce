use anyhow::{Context, anyhow};
use giganto_client::ingest::sysmon::RegistryValueSet;

use super::{SysmonCsvResult, TryFromSysmonRecord, parse_sysmon_timestamp_ns};

impl TryFromSysmonRecord for RegistryValueSet {
    fn try_from_sysmon_record(rec: &csv::StringRecord) -> SysmonCsvResult<(Self, i64)> {
        let agent_name = if let Some(agent_name) = rec.get(0) {
            agent_name.to_string()
        } else {
            return Err(anyhow!("missing agent_name").into());
        };
        let agent_id = if let Some(agent_id) = rec.get(1) {
            agent_id.to_string()
        } else {
            return Err(anyhow!("missing agent_id").into());
        };
        let time = if let Some(utc_time) = rec.get(3) {
            parse_sysmon_timestamp_ns(utc_time)?
        } else {
            return Err(anyhow!("missing time").into());
        };
        let event_type = if let Some(event_type) = rec.get(4) {
            event_type.to_string()
        } else {
            return Err(anyhow!("missing event_type").into());
        };
        let process_guid = if let Some(process_guid) = rec.get(5) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid").into());
        };
        let process_id = if let Some(process_id) = rec.get(6) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id").into());
        };
        let image = if let Some(image) = rec.get(7) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image").into());
        };
        let target_object = if let Some(target_object) = rec.get(8) {
            target_object.to_string()
        } else {
            return Err(anyhow!("missing target_object").into());
        };
        let details = if let Some(details) = rec.get(9) {
            details.to_string()
        } else {
            return Err(anyhow!("missing details").into());
        };
        let user = if let Some(user) = rec.get(10) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user").into());
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
