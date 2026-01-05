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

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as base64_engine};
use csv::{Reader, ReaderBuilder, StringRecord};
use jiff::{Timestamp, tz::TimeZone};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use reqwest::{
    Client,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::Serialize;
use serde_json::{Value, json};
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
use crate::config::ElasticSearch;

#[allow(clippy::unused_async)]
pub(crate) async fn fetch_elastic_search(elasticsearch: &ElasticSearch) -> Result<String> {
    let now = Timestamp::now().to_zoned(TimeZone::UTC);
    let exec_time = now.strftime("%F %T").to_string();

    let size = elasticsearch.size;
    let event_codes = elasticsearch
        .event_codes
        .iter()
        .map(std::string::String::as_str)
        .collect::<Vec<&str>>();
    let dump_dir = format!("{}/{exec_time}", elasticsearch.dump_dir);
    fs::create_dir_all(&dump_dir)?;

    event_codes.par_iter().for_each(|&event_code| {
        let Ok(runtime) = tokio::runtime::Runtime::new() else {
            error!("Failed to init tokio runtime for event_code {event_code}");
            return;
        };
        runtime.block_on(async {
            match fetch_data_from_es(event_code, elasticsearch).await {
                Ok(data_vec) => {
                    let file_name = format!("{dump_dir}/event{event_code}_log.csv",);
                    info!("Event {event_code}");
                    for data in &data_vec {
                        match event_code {
                            "1" => {
                                process_event_data::<ElasticProcessCreate>(data, &file_name, size);
                            }
                            "2" => process_event_data::<ElasticFileCreationTimeChanged>(
                                data, &file_name, size,
                            ),
                            "3" => process_event_data::<ElasticNetworkConnection>(
                                data, &file_name, size,
                            ),
                            "5" => process_event_data::<ElasticProcessTerminated>(
                                data, &file_name, size,
                            ),
                            "7" => process_event_data::<ElasticImageLoaded>(data, &file_name, size),
                            "11" => process_event_data::<ElasticFileCreate>(data, &file_name, size),
                            "13" => process_event_data::<ElasticRegistryValueSet>(
                                data, &file_name, size,
                            ),
                            "14" => process_event_data::<ElasticRegistryKeyValueRename>(
                                data, &file_name, size,
                            ),
                            "15" => process_event_data::<ElasticFileCreateStreamHash>(
                                data, &file_name, size,
                            ),
                            "17" => process_event_data::<ElasticPipeEvent>(data, &file_name, size),
                            "22" => process_event_data::<ElasticDnsEvent>(data, &file_name, size),
                            "23" => process_event_data::<ElasticFileDelete>(data, &file_name, size),
                            "25" => process_event_data::<ElasticProcessTampering>(
                                data, &file_name, size,
                            ),
                            "26" => process_event_data::<ElasticFileDeleteDetected>(
                                data, &file_name, size,
                            ),
                            _ => {}
                        }
                    }
                }
                Err(e) => error!("Error {e:?}"),
            }
        });
    });
    Ok(dump_dir)
}

/// Query multiple index with `event_code`
async fn fetch_data_from_es(event_code: &str, config: &ElasticSearch) -> Result<Vec<Value>> {
    let mut last_ts = 0_u64;
    let client = build_elastic_client(&config.elastic_auth)?;
    let mut all_results = Vec::new();
    for index in &config.indices {
        info!("Index: {index}");
        loop {
            let query = build_query(
                event_code,
                &config.start_time,
                &config.end_time,
                config.size,
                last_ts,
            );

            let result = send_request(&client, &query, &config.url, index).await?;
            all_results.push(result.clone());
            if let Some(data) = result["hits"]["hits"].as_array() {
                if let Some(last) = data.last() {
                    if let Some(lts) = last["sort"][0].as_u64() {
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
        }
    }

    Ok(all_results)
}

fn build_elastic_client(auth: &str) -> Result<Client> {
    let encoded = base64_engine.encode(auth.as_bytes());
    let basic_auth = format!("Basic {encoded}");

    Client::builder()
        // bypass ssl cert
        .danger_accept_invalid_certs(true)
        .default_headers({
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&basic_auth)?);

            headers
        })
        .build()
        .map_err(|e| anyhow!("Failed to build elastic client: {e}"))
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

/// Send a query with `_search` option.
async fn send_request(client: &Client, query: &Value, url: &str, index: &str) -> Result<Value> {
    client
        .post(format!("{url}/{index}/_search"))
        .json(query)
        .send()
        .await?
        .json()
        .await
        .map_err(|e| anyhow!({ e }))
}

fn process_event_data<T: EventToCsv + Serialize>(data: &Value, file_name: &str, size: usize) {
    let entries = T::parse(data);
    info!("Data counts(Max: {size}): {}", entries.len());
    if let Err(e) = write_to_csv(&entries, file_name) {
        error!("Failed to write csv: {e:?}");
    }
}

fn write_to_csv<T: EventToCsv + Serialize>(entries: &Vec<T>, file_name: &str) -> io::Result<()> {
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

pub(crate) fn parse_sysmon_time(time: &str) -> Result<Timestamp> {
    let dt = jiff::civil::DateTime::strptime("%Y-%m-%d %H:%M:%S%.f", time)
        .map_err(|_| anyhow!("invalid time: {time}"))?;
    dt.to_zoned(TimeZone::UTC)
        .map_err(|e| anyhow!("failed to create zoned datetime: {e}"))
        .map(|z| z.timestamp())
}

pub(crate) fn parse_sysmon_timestamp_ns(time: &str) -> Result<i64> {
    let ts = parse_sysmon_time(time)?;
    i64::try_from(ts.as_nanosecond()).context("timestamp nanoseconds overflow")
}

pub(crate) fn open_sysmon_csv_file(path: &Path) -> Result<Reader<File>> {
    Ok(ReaderBuilder::new()
        .comment(Some(b'#'))
        .delimiter(b'\t')
        .flexible(true)
        .from_path(path)?)
}

pub(crate) trait TryFromSysmonRecord: Sized {
    fn try_from_sysmon_record(rec: &StringRecord, serial: i64) -> Result<(Self, i64)>;
}

trait EventToCsv: Sized {
    fn parse(data: &Value) -> Vec<Self>;
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
