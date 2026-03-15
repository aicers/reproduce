use anyhow::{Context, anyhow};
use giganto_client::ingest::sysmon::ImageLoaded;
use serde::Serialize;

use super::{
    EventToCsv, SysmonCsvResult, TryFromSysmonRecord, parse_sysmon_timestamp_ns, split_message_part,
};

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

#[derive(Serialize)]
pub struct ElasticImageLoaded {
    agent_name: Option<String>,
    agent_id: Option<String>,
    event_action: Option<String>,
    utc_time: Option<String>,
    process_guid: Option<String>,
    process_id: Option<String>,
    image: Option<String>,
    image_loaded: Option<String>,
    file_version: Option<String>,
    description: Option<String>,
    product: Option<String>,
    company: Option<String>,
    original_file_name: Option<String>,
    hashes: Option<String>,
    signed: Option<String>,
    signature: Option<String>,
    signature_status: Option<String>,
    user: Option<String>,
}

impl EventToCsv for ElasticImageLoaded {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticImageLoaded {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("Image loaded".to_string()),
                        utc_time: None,
                        process_guid: None,
                        process_id: None,
                        image: None,
                        image_loaded: None,
                        file_version: None,
                        description: None,
                        product: None,
                        company: None,
                        original_file_name: None,
                        hashes: None,
                        signed: None,
                        signature: None,
                        signature_status: None,
                        user: None,
                    };

                    if let Some(agent_name) = hit["_source"]["agent"]["name"].as_str() {
                        entry.agent_name = Some(agent_name.to_string());
                    }

                    if let Some(agent_id) = hit["_source"]["agent"]["id"].as_str() {
                        entry.agent_id = Some(agent_id.to_string());
                    }

                    for part in message.split('\n') {
                        if let Some((key, value)) = split_message_part(part) {
                            match key {
                                "UtcTime" => entry.utc_time = Some(value.to_string()),
                                "ProcessGuid" => entry.process_guid = Some(value.to_string()),
                                "ProcessId" => entry.process_id = Some(value.to_string()),
                                "Image" => entry.image = Some(value.to_string()),
                                "ImageLoaded" => entry.image_loaded = Some(value.to_string()),
                                "FileVersion" => entry.file_version = Some(value.to_string()),
                                "Description" => entry.description = Some(value.to_string()),
                                "Product" => entry.product = Some(value.to_string()),
                                "Company" => entry.company = Some(value.to_string()),
                                "OriginalFileName" => {
                                    entry.original_file_name = Some(value.to_string());
                                }
                                "Hashes" => entry.hashes = Some(value.to_string()),
                                "Signed" => entry.signed = Some(value.to_string()),
                                "Signature" => entry.signature = Some(value.to_string()),
                                "SignatureStatus" => {
                                    entry.signature_status = Some(value.to_string());
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
