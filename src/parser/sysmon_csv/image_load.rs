use anyhow::{Context, anyhow};
use giganto_client::ingest::sysmon::ImageLoaded;

use super::{SysmonCsvResult, TryFromSysmonRecord, parse_sysmon_timestamp_ns};

impl TryFromSysmonRecord for ImageLoaded {
    #[allow(clippy::too_many_lines)]
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
        let image_loaded = if let Some(image_loaded) = rec.get(7) {
            image_loaded.to_string()
        } else {
            return Err(anyhow!("missing image_loaded").into());
        };
        let file_version = if let Some(file_version) = rec.get(8) {
            file_version.to_string()
        } else {
            return Err(anyhow!("missing file_version").into());
        };
        let description = if let Some(description) = rec.get(9) {
            description.to_string()
        } else {
            return Err(anyhow!("missing description").into());
        };
        let product = if let Some(product) = rec.get(10) {
            product.to_string()
        } else {
            return Err(anyhow!("missing product").into());
        };
        let company = if let Some(company) = rec.get(11) {
            company.to_string()
        } else {
            return Err(anyhow!("missing company").into());
        };
        let original_file_name = if let Some(original_file_name) = rec.get(12) {
            original_file_name.to_string()
        } else {
            return Err(anyhow!("missing original_file_name").into());
        };
        let hashes = if let Some(hashes) = rec.get(13) {
            hashes
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing hashes").into());
        };
        let signed = if let Some(signed) = rec.get(14) {
            if signed.eq("true") {
                true
            } else if signed.eq("false") || signed.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid signed").into());
            }
        } else {
            return Err(anyhow!("missing destination_is_ipv6").into());
        };
        let signature = if let Some(signature) = rec.get(15) {
            signature.to_string()
        } else {
            return Err(anyhow!("missing signature").into());
        };
        let signature_status = if let Some(signature_status) = rec.get(16) {
            signature_status.to_string()
        } else {
            return Err(anyhow!("missing signature_status").into());
        };
        let user = if let Some(user) = rec.get(17) {
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
                image_loaded,
                file_version,
                description,
                product,
                company,
                original_file_name,
                hashes,
                signed,
                signature,
                signature_status,
                user,
            },
            time,
        ))
    }
}
