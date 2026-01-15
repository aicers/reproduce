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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{Config, DEFAULT_EXPORT_FROM_GIGANTO, DEFAULT_POLLING_MODE, DEFAULT_REPORT_MODE};

    // Minimal required TOML for a valid config (required fields only)
    const MINIMAL_TOML: &str = r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
input = "/path/to/input"
"#;

    /// Creates a temporary TOML config file with the given content.
    fn create_temp_config(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("should create temp file");
        file.write_all(content.as_bytes())
            .expect("should write to temp file");
        file
    }

    #[test]
    fn default_values_applied() {
        let file = create_temp_config(MINIMAL_TOML);

        let config = Config::new(file.path()).expect("should parse minimal TOML");

        // Assert default values are correctly applied
        assert_eq!(config.kind, "");
        assert_eq!(config.report, DEFAULT_REPORT_MODE);
    }

    #[test]
    fn default_file_polling_mode() {
        let toml = r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
input = "/path/to/input"

[file]
"#;
        let file = create_temp_config(toml);

        let config = Config::new(file.path()).expect("should parse TOML with file section");

        let file_section = config.file.expect("file section should exist");
        assert_eq!(file_section.polling_mode, DEFAULT_POLLING_MODE);
        assert_eq!(
            file_section.export_from_giganto,
            Some(DEFAULT_EXPORT_FROM_GIGANTO)
        );
    }

    #[test]
    fn default_directory_polling_mode() {
        let toml = r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
input = "/path/to/input"

[directory]
"#;
        let file = create_temp_config(toml);

        let config = Config::new(file.path()).expect("should parse TOML with directory section");

        let directory = config.directory.expect("directory section should exist");
        assert_eq!(directory.polling_mode, DEFAULT_POLLING_MODE);
    }

    #[test]
    fn socket_addr_ipv4_parses() {
        let toml = r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
input = "/path/to/input"
"#;
        let file = create_temp_config(toml);

        let config = Config::new(file.path()).expect("should parse IPv4 socket address");

        assert_eq!(
            config.giganto_ingest_srv_addr,
            "127.0.0.1:8080".parse().expect("valid socket addr")
        );
    }

    #[test]
    fn socket_addr_ipv6_parses() {
        let toml = r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "[::1]:8080"
giganto_name = "test"
input = "/path/to/input"
"#;
        let file = create_temp_config(toml);

        let config = Config::new(file.path()).expect("should parse IPv6 socket address");

        assert_eq!(
            config.giganto_ingest_srv_addr,
            "[::1]:8080".parse().expect("valid socket addr")
        );
    }

    #[test]
    fn socket_addr_missing_port_fails() {
        let toml = r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1"
giganto_name = "test"
input = "/path/to/input"
"#;
        let file = create_temp_config(toml);

        let result = Config::new(file.path());
        assert!(result.is_err(), "missing port should fail to parse");
    }

    #[test]
    fn socket_addr_hostname_fails() {
        let toml = r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "localhost:8080"
giganto_name = "test"
input = "/path/to/input"
"#;
        let file = create_temp_config(toml);

        let result = Config::new(file.path());
        assert!(
            result.is_err(),
            "hostname should fail to parse as socket address"
        );
    }
}
