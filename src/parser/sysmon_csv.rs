mod dns_query;
mod file_create;
mod file_create_stream_hash;
mod file_create_time;
mod file_delete;
mod file_delete_detected;
mod image_load;
mod network_connect;
mod pipe_event;
mod process_create;
mod process_tamper;
mod process_terminate;
mod registry_key_rename;
mod registry_value_set;

use std::{
    fs::{self, File},
    io::{self},
    path::Path,
};

use anyhow::{Context, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use csv::{Reader, ReaderBuilder, StringRecord};
use jiff::{Timestamp, tz::TimeZone};
use reqwest::{
    Client,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::task;
use tracing::{error, info};

use self::{
    dns_query::ElasticDnsEvent, file_create::ElasticFileCreate,
    file_create_stream_hash::ElasticFileCreateStreamHash,
    file_create_time::ElasticFileCreationTimeChanged, file_delete::ElasticFileDelete,
    file_delete_detected::ElasticFileDeleteDetected, image_load::ElasticImageLoaded,
    network_connect::ElasticNetworkConnection, pipe_event::ElasticPipeEvent,
    process_create::ElasticProcessCreate, process_tamper::ElasticProcessTampering,
    process_terminate::ElasticProcessTerminated,
    registry_key_rename::ElasticRegistryKeyValueRename,
    registry_value_set::ElasticRegistryValueSet,
};
/// Describes a binary-driven Elasticsearch export request.
#[derive(Clone, Copy)]
pub struct ElasticDumpOptions<'a> {
    pub url: &'a str,
    pub event_codes: &'a [String],
    pub indices: &'a [String],
    pub start_time: &'a str,
    pub end_time: &'a str,
    pub size: usize,
    pub dump_dir: &'a str,
    pub elastic_auth: &'a str,
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct SysmonCsvError(anyhow::Error);

impl From<anyhow::Error> for SysmonCsvError {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}

pub type SysmonCsvResult<T> = std::result::Result<T, SysmonCsvError>;

/// Fetches sysmon event data from Elasticsearch and writes CSV files to a dump directory.
///
/// # Errors
///
/// Returns an error if the Elasticsearch query or file I/O fails.
pub async fn fetch_elastic_search(
    elasticsearch: ElasticDumpOptions<'_>,
) -> SysmonCsvResult<String> {
    let now = Timestamp::now().to_zoned(TimeZone::UTC);
    let exec_time = now.strftime("%F %T").to_string();

    let size = elasticsearch.size;
    let dump_dir = format!("{}/{exec_time}", elasticsearch.dump_dir);
    let dump_dir_for_creation = dump_dir.clone();
    task::spawn_blocking(move || fs::create_dir_all(&dump_dir_for_creation))
        .await
        .map_err(|source| anyhow!("failed to join dump-dir creation task: {source}"))?
        .map_err(anyhow::Error::from)?;

    for event_code in elasticsearch.event_codes {
        match fetch_data_from_es(event_code, elasticsearch).await {
            Ok(data_vec) => {
                let file_name = format!("{dump_dir}/event{event_code}_log.csv");
                info!("Event {event_code}");
                for data in &data_vec {
                    match event_code.as_str() {
                        "1" => {
                            process_event_data::<ElasticProcessCreate>(data, &file_name, size)
                                .await;
                        }
                        "2" => {
                            process_event_data::<ElasticFileCreationTimeChanged>(
                                data, &file_name, size,
                            )
                            .await;
                        }
                        "3" => {
                            process_event_data::<ElasticNetworkConnection>(data, &file_name, size)
                                .await;
                        }
                        "5" => {
                            process_event_data::<ElasticProcessTerminated>(data, &file_name, size)
                                .await;
                        }
                        "7" => {
                            process_event_data::<ElasticImageLoaded>(data, &file_name, size).await;
                        }
                        "11" => {
                            process_event_data::<ElasticFileCreate>(data, &file_name, size).await;
                        }
                        "13" => {
                            process_event_data::<ElasticRegistryValueSet>(data, &file_name, size)
                                .await;
                        }
                        "14" => {
                            process_event_data::<ElasticRegistryKeyValueRename>(
                                data, &file_name, size,
                            )
                            .await;
                        }
                        "15" => {
                            process_event_data::<ElasticFileCreateStreamHash>(
                                data, &file_name, size,
                            )
                            .await;
                        }
                        "17" => {
                            process_event_data::<ElasticPipeEvent>(data, &file_name, size).await;
                        }
                        "22" => process_event_data::<ElasticDnsEvent>(data, &file_name, size).await,
                        "23" => {
                            process_event_data::<ElasticFileDelete>(data, &file_name, size).await;
                        }
                        "25" => {
                            process_event_data::<ElasticProcessTampering>(data, &file_name, size)
                                .await;
                        }
                        "26" => {
                            process_event_data::<ElasticFileDeleteDetected>(data, &file_name, size)
                                .await;
                        }
                        _ => {}
                    }
                }
            }
            Err(error) => error!("Error {error:?}"),
        }
    }
    Ok(dump_dir)
}

/// Queries multiple indices for the requested `event_code`.
async fn fetch_data_from_es(
    event_code: &str,
    config: ElasticDumpOptions<'_>,
) -> SysmonCsvResult<Vec<Value>> {
    let mut last_ts = 0_u64;
    let client = build_elastic_client(config.elastic_auth)?;
    let mut all_results = Vec::new();
    for index in config.indices {
        info!("Index: {index}");
        loop {
            let query = build_query(
                event_code,
                config.start_time,
                config.end_time,
                config.size,
                last_ts,
            );

            let result = send_request(&client, &query, config.url, index).await?;
            if let Some(data) = result["hits"]["hits"].as_array() {
                if let Some(last) = data.last() {
                    if let Some(lts) = last
                        .get("sort")
                        .and_then(Value::as_array)
                        .and_then(|sort| sort.first())
                        .and_then(Value::as_u64)
                    {
                        if data.len() == config.size {
                            last_ts = lts;
                        } else {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            all_results.push(result);
        }
    }

    Ok(all_results)
}

fn build_elastic_client(auth: &str) -> SysmonCsvResult<Client> {
    let encoded = base64_engine.encode(auth.as_bytes());
    let basic_auth = format!("Basic {encoded}");

    Ok(Client::builder()
        // bypass ssl cert
        .danger_accept_invalid_certs(true)
        .default_headers({
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&basic_auth).map_err(anyhow::Error::from)?,
            );

            headers
        })
        .build()
        .map_err(|e| anyhow!("Failed to build elastic client: {e}"))?)
}

fn build_query(event_code: &str, start: &str, end: &str, size: usize, last: u64) -> Value {
    json!({
        "query": {
            "bool": {
                "must": [
                    { "term": {"event.code": event_code} },
                    { "term": {"event.module": "sysmon"} },
                    { "range": {"@timestamp": {"gt": start, "lt": end}} },
                ],
            }
        },
        "size": size,
        "sort": [
            {"@timestamp": "asc"}
        ],
        "search_after": [last]
    })
}

/// Sends a query using the Elasticsearch `_search` endpoint.
async fn send_request(
    client: &Client,
    query: &Value,
    url: &str,
    index: &str,
) -> SysmonCsvResult<Value> {
    Ok(client
        .post(format!("{url}/{index}/_search"))
        .json(query)
        .send()
        .await
        .map_err(anyhow::Error::from)?
        .json()
        .await
        .map_err(|e| anyhow!({ e }))?)
}

async fn process_event_data<T>(data: &Value, file_name: &str, size: usize)
where
    T: EventToCsv + Serialize + Send + 'static,
{
    let entries = T::parse(data);
    info!("Data counts(Max: {size}): {}", entries.len());
    let file_name = file_name.to_string();
    match task::spawn_blocking(move || write_to_csv(&entries, &file_name)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => error!("Failed to write csv: {error:?}"),
        Err(error) => error!("Failed to join csv writer task: {error}"),
    }
}

fn write_to_csv<T: EventToCsv + Serialize>(entries: &[T], file_name: &str) -> io::Result<()> {
    info!("CSV file name: {file_name}");
    if entries.is_empty() {
        return Ok(());
    }

    let file_exists = fs::metadata(file_name).is_ok();

    let mut wtr = if file_exists {
        csv::WriterBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_writer(fs::OpenOptions::new().append(true).open(file_name)?)
    } else {
        csv::WriterBuilder::new()
            .delimiter(b'\t')
            .from_path(file_name)?
    };

    for entry in entries {
        wtr.serialize(entry)?;
    }
    wtr.flush()?;
    Ok(())
}

/// Parses a Sysmon time string (`YYYY-MM-DD HH:MM:SS.fff`) into a UTC `Timestamp`.
///
/// # Errors
///
/// Returns an error if the time string is malformed.
pub fn parse_sysmon_time(time: &str) -> SysmonCsvResult<Timestamp> {
    let dt = jiff::civil::DateTime::strptime("%Y-%m-%d %H:%M:%S%.f", time)
        .map_err(|_| anyhow!("invalid time: {time}"))?;
    Ok(dt
        .to_zoned(TimeZone::UTC)
        .map_err(|e| anyhow!("failed to create zoned datetime: {e}"))
        .map(|z| z.timestamp())?)
}

/// Parses a Sysmon time string into nanoseconds since the Unix epoch.
///
/// # Errors
///
/// Returns an error if the time string is malformed or overflows.
pub fn parse_sysmon_timestamp_ns(time: &str) -> SysmonCsvResult<i64> {
    let ts = parse_sysmon_time(time)?;
    Ok(i64::try_from(ts.as_nanosecond()).context("timestamp nanoseconds overflow")?)
}

/// Opens a Sysmon CSV file and returns a configured CSV reader.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
pub fn open_sysmon_csv_file(path: &Path) -> SysmonCsvResult<Reader<File>> {
    Ok(ReaderBuilder::new()
        .comment(Some(b'#'))
        .delimiter(b'\t')
        .flexible(true)
        .from_path(path)
        .map_err(anyhow::Error::from)?)
}

/// Converts a Sysmon CSV record into a typed event.
pub trait TryFromSysmonRecord: Sized {
    /// Parses the record and returns the typed event with its raw timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be parsed.
    fn try_from_sysmon_record(rec: &StringRecord) -> SysmonCsvResult<(Self, i64)>;
}

trait EventToCsv: Sized {
    fn parse(data: &Value) -> Vec<Self>;
}

pub(super) fn split_message_part(part: &str) -> Option<(&str, &str)> {
    let (key, value) = part.split_once(':')?;
    Some((key.trim(), value.trim()))
}

#[cfg(test)]
mod sysmon_timestamp_tests {
    use super::*;

    #[test]
    fn test_parse_sysmon_time_valid() {
        // Valid timestamp with microseconds
        let result = parse_sysmon_time("2023-01-15 14:30:45.123456");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let zoned = ts.to_zoned(TimeZone::UTC);
        assert_eq!(zoned.year(), 2023);
        assert_eq!(zoned.month(), 1);
        assert_eq!(zoned.day(), 15);
        assert_eq!(zoned.hour(), 14);
        assert_eq!(zoned.minute(), 30);
        assert_eq!(zoned.second(), 45);
    }

    #[test]
    fn test_parse_sysmon_time_no_subseconds() {
        // Timestamp without fractional seconds
        let result = parse_sysmon_time("2023-01-15 14:30:45");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.subsec_nanosecond(), 0);
    }

    #[test]
    fn test_parse_sysmon_time_milliseconds() {
        // Timestamp with milliseconds only
        let result = parse_sysmon_time("2023-01-15 14:30:45.123");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.subsec_millisecond(), 123);
    }

    #[test]
    fn test_parse_sysmon_time_nanoseconds() {
        // Timestamp with full nanosecond precision
        let result = parse_sysmon_time("2023-01-15 14:30:45.123456789");
        assert!(result.is_ok());
        let ts = result.unwrap();
        assert_eq!(ts.subsec_nanosecond(), 123_456_789);
    }

    #[test]
    fn test_parse_sysmon_time_midnight() {
        // Midnight timestamp
        let result = parse_sysmon_time("2023-01-15 00:00:00.000000");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let zoned = ts.to_zoned(TimeZone::UTC);
        assert_eq!(zoned.hour(), 0);
        assert_eq!(zoned.minute(), 0);
        assert_eq!(zoned.second(), 0);
    }

    #[test]
    fn test_parse_sysmon_time_end_of_day() {
        // End of day timestamp
        let result = parse_sysmon_time("2023-01-15 23:59:59.999999");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let zoned = ts.to_zoned(TimeZone::UTC);
        assert_eq!(zoned.hour(), 23);
        assert_eq!(zoned.minute(), 59);
        assert_eq!(zoned.second(), 59);
    }

    #[test]
    fn test_parse_sysmon_time_leap_day() {
        // Leap day: February 29, 2024
        let result = parse_sysmon_time("2024-02-29 12:00:00.000000");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let zoned = ts.to_zoned(TimeZone::UTC);
        assert_eq!(zoned.year(), 2024);
        assert_eq!(zoned.month(), 2);
        assert_eq!(zoned.day(), 29);
    }

    #[test]
    fn test_parse_sysmon_time_invalid_date() {
        // Invalid date: February 30
        let result = parse_sysmon_time("2023-02-30 12:00:00.000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_invalid_month() {
        // Invalid month: 13
        let result = parse_sysmon_time("2023-13-15 12:00:00.000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_invalid_hour() {
        // Invalid hour: 24
        let result = parse_sysmon_time("2023-01-15 24:00:00.000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_invalid_format() {
        // Wrong format
        let result = parse_sysmon_time("2023/01/15 14:30:45");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_empty_string() {
        // Empty string
        let result = parse_sysmon_time("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sysmon_time_conversion_to_nanos() {
        // Verify nanosecond conversion
        let result = parse_sysmon_time("2023-01-15 14:30:45.123456");
        assert!(result.is_ok());
        let ts = result.unwrap();
        let nanos = i64::try_from(ts.as_nanosecond());
        assert!(nanos.is_ok());
    }

    #[test]
    fn test_parse_sysmon_timestamp_ns_returns_nanoseconds() {
        let ns = parse_sysmon_timestamp_ns("2023-08-08 07:51:14.875").unwrap();
        assert_eq!(ns, 1_691_481_074_875_000_000);
    }

    #[test]
    fn test_parse_sysmon_timestamp_ns_rejects_invalid_input() {
        assert!(parse_sysmon_timestamp_ns("invalid").is_err());
    }
}
