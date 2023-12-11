use super::{parse_sysmon_time, TryFromSysmonRecord};
use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::sysmon::PEFile;

impl TryFromSysmonRecord for PEFile {
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
        let time = if let Some(utc_time) = rec.get(2) {
            parse_sysmon_time(utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
                + serial
        } else {
            return Err(anyhow!("missing time"));
        };
        let file_name = if let Some(file_name) = rec.get(3) {
            file_name.to_string()
        } else {
            return Err(anyhow!("missing file_hash"));
        };
        let file_hash = if let Some(file_hash) = rec.get(4) {
            file_hash.to_string()
        } else {
            return Err(anyhow!("missing file_hash"));
        };
        let encord_data = if let Some(data) = rec.get(5) {
            data.to_string()
        } else {
            return Err(anyhow!("missing data"));
        };
        let data = data_encoding::BASE64.decode(encord_data.as_bytes())?;
        Ok((
            Self {
                agent_name,
                agent_id,
                file_name,
                file_hash,
                data,
            },
            time,
        ))
    }
}
