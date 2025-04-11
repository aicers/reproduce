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

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use chrono::{DateTime, NaiveDateTime, Utc};
use csv::{Reader, ReaderBuilder, StringRecord};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION},
    Client,
};
use serde::Serialize;
use serde_json::{json, Value};
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
pub async fn fetch_elastic_search(elasticsearch: &ElasticSearch) -> Result<String> {
    let now = Utc::now();
    let exec_time = format!("{}", now.format("%F %T"));

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
            error!("failed to init tokio runtime for event_code {event_code}");
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
    info!("{file_name}");
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

pub trait EventToCsv: Sized {
    fn parse(data: &Value) -> Vec<Self>;
}
