use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::sysmon::ProcessCreate;
use serde::Serialize;

use super::{
    is_datastore_format, parse_datastore_time, parse_sysmon_time, EventToCsv, TryFromSysmonRecord,
};

impl TryFromSysmonRecord for ProcessCreate {
    #[allow(clippy::too_many_lines)]
    fn try_from_sysmon_record(rec: &csv::StringRecord, serial: i64) -> Result<(Self, i64)> {
        let is_datastore = is_datastore_format(rec);

        // Field offset: for data-store format, fields start at index 2 (after timestamp and "sensor")
        // For elasticsearch format, fields start at index 0
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
        // For elasticsearch: fields start at index 4 (after agent_name, agent_id, event_action, utc_time)
        // For datastore: fields start at index 2 (after timestamp, "sensor") + 2 (agent_name, agent_id) = 4
        // So the data fields start at the same index (4) for both formats!
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
        let file_version = if let Some(file_version) = rec.get(field_offset + 5) {
            file_version.to_string()
        } else {
            return Err(anyhow!("missing file_version"));
        };
        let description = if let Some(description) = rec.get(field_offset + 6) {
            description.to_string()
        } else {
            return Err(anyhow!("missing description"));
        };
        let product = if let Some(product) = rec.get(field_offset + 7) {
            product.to_string()
        } else {
            return Err(anyhow!("missing product"));
        };
        let company = if let Some(company) = rec.get(field_offset + 8) {
            company.to_string()
        } else {
            return Err(anyhow!("missing company"));
        };
        let original_file_name = if let Some(original_file_name) = rec.get(field_offset + 9) {
            original_file_name.to_string()
        } else {
            return Err(anyhow!("missing original_file_name"));
        };
        let command_line = if let Some(command_line) = rec.get(field_offset + 10) {
            command_line.to_string()
        } else {
            return Err(anyhow!("missing command_line"));
        };
        let current_directory = if let Some(current_directory) = rec.get(field_offset + 11) {
            current_directory.to_string()
        } else {
            return Err(anyhow!("missing current_directory"));
        };
        let user = if let Some(user) = rec.get(field_offset + 12) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let logon_guid = if let Some(logon_guid) = rec.get(field_offset + 13) {
            logon_guid.to_string()
        } else {
            return Err(anyhow!("missing logon_guid"));
        };
        let logon_id = if let Some(logon_id) = rec.get(field_offset + 14) {
            if logon_id.eq("-") {
                0
            } else {
                u32::from_str_radix(logon_id.trim_start_matches("0x"), 16)?
            }
        } else {
            return Err(anyhow!("missing logon_id"));
        };
        let terminal_session_id = if let Some(terminal_session_id) = rec.get(field_offset + 15) {
            if terminal_session_id.eq("-") {
                0
            } else {
                terminal_session_id
                    .parse::<u32>()
                    .context("invalid terminal_session_id")?
            }
        } else {
            return Err(anyhow!("missing terminal_session_id"));
        };
        let integrity_level = if let Some(integrity_level) = rec.get(field_offset + 16) {
            integrity_level.to_string()
        } else {
            return Err(anyhow!("missing integrity_level"));
        };
        let hashes = if let Some(hashes) = rec.get(field_offset + 17) {
            hashes
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing hashes"));
        };
        let parent_process_guid = if let Some(parent_process_guid) = rec.get(field_offset + 18) {
            parent_process_guid.to_string()
        } else {
            return Err(anyhow!("missing parent_process_guid"));
        };
        let parent_process_id = if let Some(parent_process_id) = rec.get(field_offset + 19) {
            if parent_process_id.eq("-") {
                0
            } else {
                parent_process_id
                    .parse::<u32>()
                    .context("invalid parent_process_id")?
            }
        } else {
            return Err(anyhow!("missing parent_process_id"));
        };
        let parent_image = if let Some(parent_image) = rec.get(field_offset + 20) {
            parent_image.to_string()
        } else {
            return Err(anyhow!("missing parent_image"));
        };
        let parent_command_line = if let Some(parent_command_line) = rec.get(field_offset + 21) {
            parent_command_line.to_string()
        } else {
            return Err(anyhow!("missing parent_command_line"));
        };
        let parent_user = if let Some(parent_user) = rec.get(field_offset + 22) {
            parent_user.to_string()
        } else {
            return Err(anyhow!("missing parent_user"));
        };

        Ok((
            Self {
                agent_name,
                agent_id,
                process_guid,
                process_id,
                image,
                file_version,
                description,
                product,
                company,
                original_file_name,
                command_line,
                current_directory,
                user,
                logon_guid,
                logon_id,
                terminal_session_id,
                integrity_level,
                hashes,
                parent_process_guid,
                parent_process_id,
                parent_image,
                parent_command_line,
                parent_user,
            },
            time,
        ))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize)]
pub(crate) struct ElasticProcessCreate {
    agent_name: Option<String>,
    agent_id: Option<String>,
    event_action: Option<String>,
    utc_time: Option<String>,
    process_guid: Option<String>,
    process_id: Option<String>,
    image: Option<String>,
    file_version: Option<String>,
    description: Option<String>,
    product: Option<String>,
    company: Option<String>,
    original_file_name: Option<String>,
    command_line: Option<String>,
    current_directory: Option<String>,
    user: Option<String>,
    logon_guid: Option<String>,
    logon_id: Option<String>,
    terminal_session_id: Option<String>,
    integrity_level: Option<String>,
    hashes: Option<String>,
    parent_process_id: Option<String>,
    parent_process_guid: Option<String>,
    parent_image: Option<String>,
    parent_command_line: Option<String>,
    parent_user: Option<String>,
}

impl EventToCsv for ElasticProcessCreate {
    fn parse(data: &serde_json::Value) -> Vec<Self> {
        let mut entries = Vec::new();

        if let Some(hits) = data["hits"]["hits"].as_array() {
            for hit in hits {
                if let Some(message) = hit["_source"]["message"].as_str() {
                    let mut entry = ElasticProcessCreate {
                        agent_name: None,
                        agent_id: None,
                        event_action: Some("Process Create".to_string()),
                        utc_time: None,
                        process_guid: None,
                        process_id: None,
                        image: None,
                        file_version: None,
                        description: None,
                        product: None,
                        company: None,
                        original_file_name: None,
                        command_line: None,
                        current_directory: None,
                        user: None,
                        logon_guid: None,
                        logon_id: None,
                        terminal_session_id: None,
                        integrity_level: None,
                        hashes: None,
                        parent_process_guid: None,
                        parent_process_id: None,
                        parent_image: None,
                        parent_command_line: None,
                        parent_user: None,
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
                                "FileVersion" => entry.file_version = Some(value.to_string()),
                                "Description" => entry.description = Some(value.to_string()),
                                "Product" => entry.product = Some(value.to_string()),
                                "Company" => entry.company = Some(value.to_string()),
                                "OriginalFileName" => {
                                    entry.original_file_name = Some(value.to_string());
                                }
                                "CommandLine" => entry.command_line = Some(value.to_string()),
                                "CurrentDirectory" => {
                                    entry.current_directory = Some(value.to_string());
                                }
                                "User" => entry.user = Some(value.to_string()),
                                "LogonGuid" => entry.logon_guid = Some(value.to_string()),
                                "LogonId" => entry.logon_id = Some(value.to_string()),
                                "TerminalSessionId" => {
                                    entry.terminal_session_id = Some(value.to_string());
                                }
                                "IntegrityLevel" => entry.integrity_level = Some(value.to_string()),
                                "Hashes" => entry.hashes = Some(value.to_string()),
                                "ParentProcessGuid" => {
                                    entry.parent_process_guid = Some(value.to_string());
                                }
                                "ParentProcessId" => {
                                    entry.parent_process_id = Some(value.to_string());
                                }
                                "ParentImage" => entry.parent_image = Some(value.to_string()),
                                "ParentCommandLine" => {
                                    entry.parent_command_line = Some(value.to_string());
                                }
                                "ParentUser" => entry.parent_user = Some(value.to_string()),
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
