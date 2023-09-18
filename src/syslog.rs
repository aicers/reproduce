#![allow(clippy::too_many_lines)]
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use csv::{Reader, ReaderBuilder, StringRecord};
use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};
use std::{
    fs::File,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

impl TryFromSysmonRecord for ProcessCreate {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let file_version = if let Some(file_version) = rec.get(7) {
            file_version.to_string()
        } else {
            return Err(anyhow!("missing file_version"));
        };
        let description = if let Some(description) = rec.get(8) {
            description.to_string()
        } else {
            return Err(anyhow!("missing description"));
        };
        let product = if let Some(product) = rec.get(9) {
            product.to_string()
        } else {
            return Err(anyhow!("missing product"));
        };
        let company = if let Some(company) = rec.get(10) {
            company.to_string()
        } else {
            return Err(anyhow!("missing company"));
        };
        let original_file_name = if let Some(original_file_name) = rec.get(11) {
            original_file_name.to_string()
        } else {
            return Err(anyhow!("missing original_file_name"));
        };
        let command_line = if let Some(command_line) = rec.get(12) {
            command_line.to_string()
        } else {
            return Err(anyhow!("missing command_line"));
        };
        let current_directory = if let Some(current_directory) = rec.get(13) {
            current_directory.to_string()
        } else {
            return Err(anyhow!("missing current_directory"));
        };
        let user = if let Some(user) = rec.get(14) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let logon_guid = if let Some(logon_guid) = rec.get(15) {
            logon_guid.to_string()
        } else {
            return Err(anyhow!("missing logon_guid"));
        };
        let logon_id = if let Some(logon_id) = rec.get(16) {
            if logon_id.eq("-") {
                0
            } else {
                u32::from_str_radix(logon_id.trim_start_matches("0x"), 16)?
            }
        } else {
            return Err(anyhow!("missing logon_id"));
        };
        let terminal_session_id = if let Some(terminal_session_id) = rec.get(17) {
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
        let integrity_level = if let Some(integrity_level) = rec.get(18) {
            integrity_level.to_string()
        } else {
            return Err(anyhow!("missing integrity_level"));
        };
        let hashes = if let Some(hashes) = rec.get(19) {
            hashes
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing hashes"));
        };
        let parent_process_guid = if let Some(parent_process_guid) = rec.get(20) {
            parent_process_guid.to_string()
        } else {
            return Err(anyhow!("missing parent_process_guid"));
        };
        let parent_process_id = if let Some(parent_process_id) = rec.get(21) {
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
        let parent_image = if let Some(parent_image) = rec.get(22) {
            parent_image.to_string()
        } else {
            return Err(anyhow!("missing parent_image"));
        };
        let parent_command_line = if let Some(parent_command_line) = rec.get(23) {
            parent_command_line.to_string()
        } else {
            return Err(anyhow!("missing parent_command_line"));
        };
        let parent_user = if let Some(parent_user) = rec.get(24) {
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

impl TryFromSysmonRecord for FileCreationTimeChanged {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let target_filename = if let Some(target_filename) = rec.get(7) {
            target_filename.to_string()
        } else {
            return Err(anyhow!("missing target_filename"));
        };
        let creation_utc_time = if let Some(creation_utc_time) = rec.get(8) {
            parse_sysmon_time(creation_utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing creation_utc_time"));
        };
        let previous_creation_utc_time = if let Some(previous_creation_utc_time) = rec.get(9) {
            parse_sysmon_time(previous_creation_utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing previous_creation_utc_time"));
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
                process_guid,
                process_id,
                image,
                target_filename,
                creation_utc_time,
                previous_creation_utc_time,
                user,
            },
            time,
        ))
    }
}

impl TryFromSysmonRecord for NetworkConnection {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let user = if let Some(user) = rec.get(7) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let protocol = if let Some(protocol) = rec.get(8) {
            protocol.to_string()
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let initiated = if let Some(initiated) = rec.get(9) {
            if initiated.eq("true") {
                true
            } else if initiated.eq("false") || initiated.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid initiated"));
            }
        } else {
            return Err(anyhow!("missing initiated"));
        };
        let source_is_ipv6 = if let Some(source_is_ipv6) = rec.get(10) {
            if source_is_ipv6.eq("true") {
                true
            } else if source_is_ipv6.eq("false") || source_is_ipv6.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid source_is_ipv6"));
            }
        } else {
            return Err(anyhow!("missing source_is_ipv6"));
        };
        let source_ip = if let Some(source_ip) = rec.get(11) {
            if source_ip.eq("-") {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                source_ip.parse::<IpAddr>().context("invalid source_ip")?
            }
        } else {
            return Err(anyhow!("missing source_ip"));
        };
        let source_hostname = if let Some(source_hostname) = rec.get(12) {
            source_hostname.to_string()
        } else {
            return Err(anyhow!("missing source_hostname"));
        };
        let source_port = if let Some(source_port) = rec.get(13) {
            if source_port.eq("-") {
                0
            } else {
                source_port.parse::<u16>().context("invalid source_port")?
            }
        } else {
            return Err(anyhow!("missing source_port"));
        };
        let source_port_name = if let Some(source_port_name) = rec.get(14) {
            source_port_name.to_string()
        } else {
            return Err(anyhow!("missing source_port_name"));
        };
        let destination_is_ipv6 = if let Some(destination_is_ipv6) = rec.get(15) {
            if destination_is_ipv6.eq("true") {
                true
            } else if destination_is_ipv6.eq("false") || destination_is_ipv6.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid destination_is_ipv6"));
            }
        } else {
            return Err(anyhow!("missing destination_is_ipv6"));
        };
        let destination_ip = if let Some(destination_ip) = rec.get(16) {
            if destination_ip.eq("-") {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                destination_ip
                    .parse::<IpAddr>()
                    .context("invalid destination_ip")?
            }
        } else {
            return Err(anyhow!("missing destination_ip"));
        };
        let destination_hostname = if let Some(destination_hostname) = rec.get(17) {
            destination_hostname.to_string()
        } else {
            return Err(anyhow!("missing destination_hostname"));
        };
        let destination_port = if let Some(destination_port) = rec.get(18) {
            if destination_port.eq("-") {
                0
            } else {
                destination_port
                    .parse::<u16>()
                    .context("invalid destination_port")?
            }
        } else {
            return Err(anyhow!("missing destination_port"));
        };
        let destination_port_name = if let Some(destination_port_name) = rec.get(19) {
            destination_port_name.to_string()
        } else {
            return Err(anyhow!("missing destination_port_name"));
        };

        Ok((
            Self {
                agent_name,
                agent_id,
                process_guid,
                process_id,
                image,
                user,
                protocol,
                initiated,
                source_is_ipv6,
                source_ip,
                source_hostname,
                source_port,
                source_port_name,
                destination_is_ipv6,
                destination_ip,
                destination_hostname,
                destination_port,
                destination_port_name,
            },
            time,
        ))
    }
}

impl TryFromSysmonRecord for ProcessTerminated {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let user = if let Some(user) = rec.get(7) {
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
                user,
            },
            time,
        ))
    }
}

impl TryFromSysmonRecord for ImageLoaded {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let image_loaded = if let Some(image_loaded) = rec.get(7) {
            image_loaded.to_string()
        } else {
            return Err(anyhow!("missing image_loaded"));
        };
        let file_version = if let Some(file_version) = rec.get(8) {
            file_version.to_string()
        } else {
            return Err(anyhow!("missing file_version"));
        };
        let description = if let Some(description) = rec.get(9) {
            description.to_string()
        } else {
            return Err(anyhow!("missing description"));
        };
        let product = if let Some(product) = rec.get(10) {
            product.to_string()
        } else {
            return Err(anyhow!("missing product"));
        };
        let company = if let Some(company) = rec.get(11) {
            company.to_string()
        } else {
            return Err(anyhow!("missing company"));
        };
        let original_file_name = if let Some(original_file_name) = rec.get(12) {
            original_file_name.to_string()
        } else {
            return Err(anyhow!("missing original_file_name"));
        };
        let hashes = if let Some(hashes) = rec.get(13) {
            hashes
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing hashes"));
        };
        let signed = if let Some(signed) = rec.get(14) {
            if signed.eq("true") {
                true
            } else if signed.eq("false") || signed.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid signed"));
            }
        } else {
            return Err(anyhow!("missing destination_is_ipv6"));
        };
        let signature = if let Some(signature) = rec.get(15) {
            signature.to_string()
        } else {
            return Err(anyhow!("missing signature"));
        };
        let signature_status = if let Some(signature_status) = rec.get(16) {
            signature_status.to_string()
        } else {
            return Err(anyhow!("missing signature_status"));
        };
        let user = if let Some(user) = rec.get(17) {
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

impl TryFromSysmonRecord for FileCreate {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let target_filename = if let Some(target_filename) = rec.get(7) {
            target_filename.to_string()
        } else {
            return Err(anyhow!("missing target_filename"));
        };
        let creation_utc_time = if let Some(creation_utc_time) = rec.get(8) {
            if creation_utc_time.eq("-") {
                0
            } else {
                parse_sysmon_time(creation_utc_time)?
                    .timestamp_nanos_opt()
                    .context("to_timestamp_nanos")?
            }
        } else {
            return Err(anyhow!("missing creation_utc_time"));
        };
        let user = if let Some(user) = rec.get(9) {
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
                user,
            },
            time,
        ))
    }
}

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
        let event_type = if let Some(event_type) = rec.get(3) {
            event_type.to_string()
        } else {
            return Err(anyhow!("missing event_type"));
        };
        let time = if let Some(utc_time) = rec.get(4) {
            parse_sysmon_time(utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
                + serial
        } else {
            return Err(anyhow!("missing time"));
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

impl TryFromSysmonRecord for RegistryKeyValueRename {
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
        let event_type = if let Some(event_type) = rec.get(3) {
            event_type.to_string()
        } else {
            return Err(anyhow!("missing event_type"));
        };
        let time = if let Some(utc_time) = rec.get(4) {
            parse_sysmon_time(utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
                + serial
        } else {
            return Err(anyhow!("missing time"));
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
        let new_name = if let Some(new_name) = rec.get(9) {
            new_name.to_string()
        } else {
            return Err(anyhow!("missing new_name"));
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
                new_name,
                user,
            },
            time,
        ))
    }
}

impl TryFromSysmonRecord for FileCreateStreamHash {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let target_filename = if let Some(target_filename) = rec.get(7) {
            target_filename.to_string()
        } else {
            return Err(anyhow!("missing target_filename"));
        };
        let creation_utc_time = if let Some(creation_utc_time) = rec.get(8) {
            parse_sysmon_time(creation_utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing creation_utc_time"));
        };
        let hash = if let Some(hash) = rec.get(9) {
            hash.split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing hash"));
        };
        let contents = if let Some(contents) = rec.get(10) {
            contents.to_string()
        } else {
            return Err(anyhow!("missing contents"));
        };
        let user = if let Some(user) = rec.get(11) {
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

impl TryFromSysmonRecord for PipeEvent {
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
        let event_type = if let Some(event_type) = rec.get(3) {
            event_type.to_string()
        } else {
            return Err(anyhow!("missing event_type"));
        };
        let time = if let Some(utc_time) = rec.get(4) {
            parse_sysmon_time(utc_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
                + serial
        } else {
            return Err(anyhow!("missing time"));
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
        let pipe_name = if let Some(pipe_name) = rec.get(7) {
            pipe_name.to_string()
        } else {
            return Err(anyhow!("missing pipe_name"));
        };
        let image = if let Some(image) = rec.get(8) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let user = if let Some(user) = rec.get(9) {
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
                pipe_name,
                image,
                user,
            },
            time,
        ))
    }
}

impl TryFromSysmonRecord for DnsEvent {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let query_name = if let Some(query_name) = rec.get(6) {
            query_name.to_string()
        } else {
            return Err(anyhow!("missing query_name"));
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
            return Err(anyhow!("missing query_status"));
        };
        let query_results = if let Some(query_results) = rec.get(8) {
            query_results
                .split(';')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing query_results"));
        };
        let image = if let Some(image) = rec.get(9) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
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

impl TryFromSysmonRecord for FileDelete {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let user = if let Some(user) = rec.get(6) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let image = if let Some(image) = rec.get(7) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let target_filename = if let Some(target_filename) = rec.get(8) {
            target_filename.to_string()
        } else {
            return Err(anyhow!("missing target_filename"));
        };
        let hashes = if let Some(hashes) = rec.get(9) {
            hashes
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing hashes"));
        };
        let is_executable = if let Some(is_executable) = rec.get(10) {
            if is_executable.eq("true") {
                true
            } else if is_executable.eq("false") || is_executable.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid is_executable"));
            }
        } else {
            return Err(anyhow!("missing is_executable"));
        };
        let archived = if let Some(archived) = rec.get(11) {
            if archived.eq("true") {
                true
            } else if archived.eq("false") || archived.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid archived"));
            }
        } else {
            return Err(anyhow!("missing archived"));
        };

        Ok((
            Self {
                agent_name,
                agent_id,
                process_guid,
                process_id,
                user,
                image,
                target_filename,
                hashes,
                is_executable,
                archived,
            },
            time,
        ))
    }
}

impl TryFromSysmonRecord for ProcessTampering {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let image = if let Some(image) = rec.get(6) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let tamper_type = if let Some(types) = rec.get(7) {
            types.to_string()
        } else {
            return Err(anyhow!("missing tamper_type"));
        };
        let user = if let Some(user) = rec.get(8) {
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
                tamper_type,
                user,
            },
            time,
        ))
    }
}

impl TryFromSysmonRecord for FileDeleteDetected {
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
        let process_guid = if let Some(process_guid) = rec.get(4) {
            process_guid.to_string()
        } else {
            return Err(anyhow!("missing process_guid"));
        };
        let process_id = if let Some(process_id) = rec.get(5) {
            process_id.parse::<u32>().context("invalid process_id")?
        } else {
            return Err(anyhow!("missing process_id"));
        };
        let user = if let Some(user) = rec.get(6) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let image = if let Some(image) = rec.get(7) {
            image.to_string()
        } else {
            return Err(anyhow!("missing image"));
        };
        let target_filename = if let Some(target_filename) = rec.get(8) {
            target_filename.to_string()
        } else {
            return Err(anyhow!("missing target_filename"));
        };
        let hashes = if let Some(hashes) = rec.get(9) {
            hashes
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing hashes"));
        };
        let is_executable = if let Some(is_executable) = rec.get(10) {
            if is_executable.eq("true") {
                true
            } else if is_executable.eq("false") || is_executable.eq("-") {
                false
            } else {
                return Err(anyhow!("invalid is_executable"));
            }
        } else {
            return Err(anyhow!("missing is_executable"));
        };

        Ok((
            Self {
                agent_name,
                agent_id,
                process_guid,
                process_id,
                user,
                image,
                target_filename,
                hashes,
                is_executable,
            },
            time,
        ))
    }
}

fn parse_sysmon_time(time: &str) -> Result<DateTime<Utc>> {
    if let Ok(ndt) = NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S%.f") {
        Ok(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc))
    } else {
        Err(anyhow!("invalid time: {}", time))
    }
}

pub fn open_sysmon_csv_file(path: &Path) -> Result<Reader<File>> {
    Ok(ReaderBuilder::new()
        .comment(Some(b'#'))
        .delimiter(b'\t')
        .flexible(true)
        .from_path(path)?)
}

pub trait TryFromSysmonRecord: Sized {
    fn try_from_sysmon_record(rec: &StringRecord, serial: i64) -> Result<(Self, i64)>;
}
