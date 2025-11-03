use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, de::Error};

const DEFAULT_REPORT_MODE: bool = false;
const DEFAULT_POLLING_MODE: bool = false;
const DEFAULT_EXPORT_FROM_GIGANTO: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputType {
    Log,
    Dir,
    Elastic,
}
#[derive(Deserialize, Debug, Clone)]
pub(crate) struct File {
    pub(crate) export_from_giganto: Option<bool>,
    pub(crate) polling_mode: bool,
    pub(crate) transfer_count: Option<u64>,
    pub(crate) transfer_skip_count: Option<u64>,
    pub(crate) last_transfer_line_suffix: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct Directory {
    pub(crate) file_prefix: Option<String>,
    pub(crate) polling_mode: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct ElasticSearch {
    pub(crate) url: String,
    pub(crate) event_codes: Vec<String>,
    pub(crate) indices: Vec<String>,
    pub(crate) start_time: String,
    pub(crate) end_time: String,
    pub(crate) size: usize,
    pub(crate) dump_dir: String,
    pub(crate) elastic_auth: String,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct Config {
    pub(crate) cert: String,
    pub(crate) key: String,
    pub(crate) ca_certs: Vec<String>,
    #[serde(deserialize_with = "deserialize_socket_addr")]
    pub(crate) giganto_ingest_srv_addr: SocketAddr,
    pub(crate) giganto_name: String,
    pub(crate) kind: String,
    pub(crate) input: String,
    pub(crate) report: bool,
    pub(crate) log_path: Option<PathBuf>,

    pub(crate) file: Option<File>,
    pub(crate) directory: Option<Directory>,
    pub(crate) elastic: Option<ElasticSearch>,
}

impl Config {
    /// Creates a new `Config` instance from a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if it fails to parse the configuration file correctly or it runs out of parameters.
    pub(crate) fn new(path: &Path) -> Result<Self> {
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
