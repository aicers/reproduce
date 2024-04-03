use anyhow::{Context, Result};
use serde::{de::Error, Deserialize, Deserializer};
use std::{net::SocketAddr, path::Path};

const DEFAULT_REPORT_MODE: bool = false;
const DEFAULT_POLLING_MODE: bool = false;
const DEFAULT_EXPORT_FROM_GIGANTO: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputType {
    Log,
    Dir,
    Elastic,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(unused)]
pub struct Common {
    pub cert: String,
    pub key: String,
    pub root: String,
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub giganto_ingest_srv_addr: SocketAddr,
    pub giganto_name: String,
    pub kind: String,
    pub input: String,
    pub report: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct File {
    pub export_from_giganto: Option<bool>,
    pub polling_mode: bool,
    pub transfer_count: Option<u64>,
    pub transfer_skip_count: Option<u64>,
    pub last_transfer_line_suffix: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Directory {
    pub file_prefix: Option<String>,
    pub polling_mode: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ElasticSearch {
    pub url: String,
    pub event_codes: Vec<String>,
    pub indices: Vec<String>,
    pub start_time: String,
    pub end_time: String,
    pub size: usize,
    pub dump_dir: String,
    pub elastic_auth: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub common: Common,
    pub file: Option<File>,
    pub directory: Option<Directory>,
    pub elastic: Option<ElasticSearch>,
}

impl Config {
    /// Creates a new `Config` instance from a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if it fails to parse the configuration file correctly or it runs out of parameters.
    pub fn new(path: &Path) -> Result<Self> {
        let config = config::Config::builder()
            .set_default("common.kind", String::new())
            .context("cannot set the default kind value")?
            .set_default("common.report", DEFAULT_REPORT_MODE)
            .context("cannot set the default report value")?
            .set_default("file.polling_mode", DEFAULT_POLLING_MODE)
            .context("cannot set the default file polling mode value")?
            .set_default("directory.polling_mode", DEFAULT_POLLING_MODE)
            .context("cannot set the default directory polling mode value")?
            .set_default("file.export_from_giganto", DEFAULT_EXPORT_FROM_GIGANTO)
            .context("cannot set the default export_from_giganto value")?
            .add_source(config::File::from(path))
            .build()
            .context("cannot build the config")?;
        Ok(config.try_deserialize()?)
    }
}

/// Deserializes a socket address.
///
/// # Errors
///
/// Returns an error if the address is not in the form of 'IP:PORT'.
fn deserialize_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: Deserializer<'de>,
{
    let addr = String::deserialize(deserializer)?;
    addr.parse()
        .map_err(|e| D::Error::custom(format!("invalid address \"{addr}\": {e}")))
}
