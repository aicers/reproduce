use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{de::Error, Deserialize, Deserializer};

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
pub(super) struct File {
    pub(super) export_from_giganto: Option<bool>,
    pub(super) polling_mode: bool,
    pub(super) transfer_count: Option<u64>,
    pub(super) transfer_skip_count: Option<u64>,
    pub(super) last_transfer_line_suffix: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub(super) struct Directory {
    pub(super) file_prefix: Option<String>,
    pub(super) polling_mode: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub(super) struct ElasticSearch {
    pub(super) url: String,
    pub(super) event_codes: Vec<String>,
    pub(super) indices: Vec<String>,
    pub(super) start_time: String,
    pub(super) end_time: String,
    pub(super) size: usize,
    pub(super) dump_dir: String,
    pub(super) elastic_auth: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub(super) cert: String,
    pub(super) key: String,
    pub(super) ca_certs: Vec<String>,
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub(super) giganto_ingest_srv_addr: SocketAddr,
    pub(super) giganto_name: String,
    pub(super) kind: String,
    pub(super) input: String,
    pub(super) report: bool,
    pub log_path: Option<PathBuf>,

    pub(super) file: Option<File>,
    pub(super) directory: Option<Directory>,
    pub(super) elastic: Option<ElasticSearch>,
}

impl Config {
    /// Creates a new `Config` instance from a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if it fails to parse the configuration file correctly or it runs out of parameters.
    pub fn new(path: &Path) -> Result<Self> {
        let config = config::Config::builder()
            .set_default("kind", String::new())
            .context("cannot set the default kind value")?
            .set_default("report", DEFAULT_REPORT_MODE)
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
