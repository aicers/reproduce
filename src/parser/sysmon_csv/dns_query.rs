use anyhow::{Context, anyhow};
use giganto_client::ingest::sysmon::DnsEvent;

use super::{SysmonCsvResult, TryFromSysmonRecord, parse_sysmon_timestamp_ns};

impl TryFromSysmonRecord for DnsEvent {
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
        let query_name = if let Some(query_name) = rec.get(6) {
            query_name.to_string()
        } else {
            return Err(anyhow!("missing query_name").into());
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
            return Err(anyhow!("missing query_status").into());
        };
        let query_results = if let Some(query_results) = rec.get(8) {
            query_results
                .split(';')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing query_results").into());
        };
        let image = if let Some(image) = rec.get(9) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image").into());
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
