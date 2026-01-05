use std::net::IpAddr;

use anyhow::{Context, Result, anyhow};
use csv::StringRecord;
use giganto_client::ingest::sysmon::{
    DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
    FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate, ProcessTampering,
    ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
};

use super::{TryFromGigantoRecord, parse_giganto_timestamp_ns};

fn record_timestamp(rec: &StringRecord, idx: usize) -> Result<i64> {
    let timestamp = rec.get(idx).ok_or_else(|| anyhow!("missing timestamp"))?;
    parse_giganto_timestamp_ns(timestamp)
}

fn field<'a>(rec: &'a StringRecord, idx: usize, name: &str) -> Result<&'a str> {
    rec.get(idx).ok_or_else(|| anyhow!("missing {name}"))
}

fn parse_string(rec: &StringRecord, idx: usize, name: &str) -> Result<String> {
    Ok(field(rec, idx, name)?.to_string())
}

fn parse_timestamp_ns(rec: &StringRecord, idx: usize, name: &str) -> Result<i64> {
    let value = field(rec, idx, name)?;
    parse_giganto_timestamp_ns(value).with_context(|| format!("invalid {name}"))
}

fn parse_u32(rec: &StringRecord, idx: usize, name: &str) -> Result<u32> {
    let value = field(rec, idx, name)?;
    value.parse::<u32>().context(format!("invalid {name}"))
}

fn parse_u16(rec: &StringRecord, idx: usize, name: &str) -> Result<u16> {
    let value = field(rec, idx, name)?;
    value.parse::<u16>().context(format!("invalid {name}"))
}

fn parse_bool(rec: &StringRecord, idx: usize, name: &str) -> Result<bool> {
    let value = field(rec, idx, name)?;
    value.parse::<bool>().context(format!("invalid {name}"))
}

fn parse_vec_field(rec: &StringRecord, idx: usize, name: &str, split: char) -> Result<Vec<String>> {
    let value = field(rec, idx, name)?;
    if value.is_empty() || value == "-" {
        Ok(Vec::new())
    } else {
        Ok(value
            .split(split)
            .map(std::string::ToString::to_string)
            .collect())
    }
}

impl TryFromGigantoRecord for ProcessCreate {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let image = parse_string(rec, 6, "image")?;
        let file_version = parse_string(rec, 7, "file_version")?;
        let description = parse_string(rec, 8, "description")?;
        let product = parse_string(rec, 9, "product")?;
        let company = parse_string(rec, 10, "company")?;
        let original_file_name = parse_string(rec, 11, "original_file_name")?;
        let command_line = parse_string(rec, 12, "command_line")?;
        let current_directory = parse_string(rec, 13, "current_directory")?;
        let user = parse_string(rec, 14, "user")?;
        let logon_guid = parse_string(rec, 15, "logon_guid")?;
        let logon_id = parse_u32(rec, 16, "logon_id")?;
        let terminal_session_id = parse_u32(rec, 17, "terminal_session_id")?;
        let integrity_level = parse_string(rec, 18, "integrity_level")?;
        let hashes = parse_vec_field(rec, 19, "hashes", ',')?;
        let parent_process_guid = parse_string(rec, 20, "parent_process_guid")?;
        let parent_process_id = parse_u32(rec, 21, "parent_process_id")?;
        let parent_image = parse_string(rec, 22, "parent_image")?;
        let parent_command_line = parse_string(rec, 23, "parent_command_line")?;
        let parent_user = parse_string(rec, 24, "parent_user")?;

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

impl TryFromGigantoRecord for FileCreationTimeChanged {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let image = parse_string(rec, 6, "image")?;
        let target_filename = parse_string(rec, 7, "target_filename")?;
        let creation_utc_time = parse_timestamp_ns(rec, 8, "creation_utc_time")?;
        let previous_creation_utc_time = parse_timestamp_ns(rec, 9, "previous_creation_utc_time")?;
        let user = parse_string(rec, 10, "user")?;

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

impl TryFromGigantoRecord for NetworkConnection {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let image = parse_string(rec, 6, "image")?;
        let user = parse_string(rec, 7, "user")?;
        let protocol = parse_string(rec, 8, "protocol")?;
        let initiated = parse_bool(rec, 9, "initiated")?;
        let source_is_ipv6 = parse_bool(rec, 10, "source_is_ipv6")?;
        let source_ip = field(rec, 11, "source_ip")?
            .parse::<IpAddr>()
            .context("invalid source_ip")?;
        let source_hostname = parse_string(rec, 12, "source_hostname")?;
        let source_port = parse_u16(rec, 13, "source_port")?;
        let source_port_name = parse_string(rec, 14, "source_port_name")?;
        let destination_is_ipv6 = parse_bool(rec, 15, "destination_is_ipv6")?;
        let destination_ip = field(rec, 16, "destination_ip")?
            .parse::<IpAddr>()
            .context("invalid destination_ip")?;
        let destination_hostname = parse_string(rec, 17, "destination_hostname")?;
        let destination_port = parse_u16(rec, 18, "destination_port")?;
        let destination_port_name = parse_string(rec, 19, "destination_port_name")?;

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

impl TryFromGigantoRecord for ProcessTerminated {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let image = parse_string(rec, 6, "image")?;
        let user = parse_string(rec, 7, "user")?;

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

impl TryFromGigantoRecord for ImageLoaded {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let image = parse_string(rec, 6, "image")?;
        let image_loaded = parse_string(rec, 7, "image_loaded")?;
        let file_version = parse_string(rec, 8, "file_version")?;
        let description = parse_string(rec, 9, "description")?;
        let product = parse_string(rec, 10, "product")?;
        let company = parse_string(rec, 11, "company")?;
        let original_file_name = parse_string(rec, 12, "original_file_name")?;
        let hashes = parse_vec_field(rec, 13, "hashes", ',')?;
        let signed = parse_bool(rec, 14, "signed")?;
        let signature = parse_string(rec, 15, "signature")?;
        let signature_status = parse_string(rec, 16, "signature_status")?;
        let user = parse_string(rec, 17, "user")?;

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

impl TryFromGigantoRecord for FileCreate {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let image = parse_string(rec, 6, "image")?;
        let target_filename = parse_string(rec, 7, "target_filename")?;
        let creation_utc_time = parse_timestamp_ns(rec, 8, "creation_utc_time")?;
        let user = parse_string(rec, 9, "user")?;

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

impl TryFromGigantoRecord for RegistryValueSet {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let event_type = parse_string(rec, 4, "event_type")?;
        let process_guid = parse_string(rec, 5, "process_guid")?;
        let process_id = parse_u32(rec, 6, "process_id")?;
        let image = parse_string(rec, 7, "image")?;
        let target_object = parse_string(rec, 8, "target_object")?;
        let details = parse_string(rec, 9, "details")?;
        let user = parse_string(rec, 10, "user")?;

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

impl TryFromGigantoRecord for RegistryKeyValueRename {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let event_type = parse_string(rec, 4, "event_type")?;
        let process_guid = parse_string(rec, 5, "process_guid")?;
        let process_id = parse_u32(rec, 6, "process_id")?;
        let image = parse_string(rec, 7, "image")?;
        let target_object = parse_string(rec, 8, "target_object")?;
        let new_name = parse_string(rec, 9, "new_name")?;
        let user = parse_string(rec, 10, "user")?;

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

impl TryFromGigantoRecord for FileCreateStreamHash {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let image = parse_string(rec, 6, "image")?;
        let target_filename = parse_string(rec, 7, "target_filename")?;
        let creation_utc_time = parse_timestamp_ns(rec, 8, "creation_utc_time")?;
        let hash = parse_vec_field(rec, 9, "hash", ',')?;
        let contents = parse_string(rec, 10, "contents")?;
        let user = parse_string(rec, 11, "user")?;

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

impl TryFromGigantoRecord for PipeEvent {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let event_type = parse_string(rec, 4, "event_type")?;
        let process_guid = parse_string(rec, 5, "process_guid")?;
        let process_id = parse_u32(rec, 6, "process_id")?;
        let pipe_name = parse_string(rec, 7, "pipe_name")?;
        let image = parse_string(rec, 8, "image")?;
        let user = parse_string(rec, 9, "user")?;

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

impl TryFromGigantoRecord for DnsEvent {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let query_name = parse_string(rec, 6, "query_name")?;
        let query_status = parse_u32(rec, 7, "query_status")?;
        let query_results = parse_vec_field(rec, 8, "query_results", ';')?;
        let image = parse_string(rec, 9, "image")?;
        let user = parse_string(rec, 10, "user")?;

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

impl TryFromGigantoRecord for FileDelete {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let user = parse_string(rec, 6, "user")?;
        let image = parse_string(rec, 7, "image")?;
        let target_filename = parse_string(rec, 8, "target_filename")?;
        let hashes = parse_vec_field(rec, 9, "hashes", ',')?;
        let is_executable = parse_bool(rec, 10, "is_executable")?;
        let archived = parse_bool(rec, 11, "archived")?;

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

impl TryFromGigantoRecord for ProcessTampering {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let image = parse_string(rec, 6, "image")?;
        let tamper_type = parse_string(rec, 7, "tamper_type")?;
        let user = parse_string(rec, 8, "user")?;

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

impl TryFromGigantoRecord for FileDeleteDetected {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)> {
        let time = record_timestamp(rec, 0)?;
        let agent_name = parse_string(rec, 2, "agent_name")?;
        let agent_id = parse_string(rec, 3, "agent_id")?;
        let process_guid = parse_string(rec, 4, "process_guid")?;
        let process_id = parse_u32(rec, 5, "process_id")?;
        let user = parse_string(rec, 6, "user")?;
        let image = parse_string(rec, 7, "image")?;
        let target_filename = parse_string(rec, 8, "target_filename")?;
        let hashes = parse_vec_field(rec, 9, "hashes", ',')?;
        let is_executable = parse_bool(rec, 10, "is_executable")?;

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
