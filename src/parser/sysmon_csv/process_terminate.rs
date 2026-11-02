use anyhow::{Context, anyhow};
use giganto_client::ingest::sysmon::ProcessTerminated;

use super::{SysmonCsvResult, TryFromSysmonRecord, parse_sysmon_timestamp_ns};

impl TryFromSysmonRecord for ProcessTerminated {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid").into());
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id").into());
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image").into());
        };
        let user = if let Some(user) = rec.get(7) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user").into());
        };

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
