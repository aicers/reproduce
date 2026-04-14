use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use reproduce::config::GigantoConfig;
use serde::Deserialize;
use tracing::warn;

const DEFAULT_REPORT_MODE: bool = false;
const DEFAULT_POLLING_MODE: bool = false;
const DEFAULT_IMPORT_FROM_GIGANTO: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputType {
    Log,
    Dir,
    Elastic,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct File {
    pub(crate) import_from_giganto: Option<bool>,
    /// Deprecated: use `import_from_giganto` instead.
    export_from_giganto: Option<bool>,
    pub(crate) polling_mode: bool,
    pub(crate) transfer_count: Option<u64>,
    pub(crate) transfer_skip_count: Option<u64>,
    pub(crate) last_transfer_line_suffix: Option<String>,
}

impl File {
    #[cfg(test)]
    pub(crate) fn new(
        import_from_giganto: Option<bool>,
        polling_mode: bool,
        transfer_count: Option<u64>,
        transfer_skip_count: Option<u64>,
        last_transfer_line_suffix: Option<String>,
    ) -> Self {
        Self {
            import_from_giganto,
            export_from_giganto: None,
            polling_mode,
            transfer_count,
            transfer_skip_count,
            last_transfer_line_suffix,
        }
    }
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
    #[serde(flatten)]
    pub(crate) giganto: GigantoConfig,
    pub(crate) kind: String,
    pub(crate) input: String,
    pub(crate) report: bool,
    pub(crate) report_dir: Option<PathBuf>,
    /// Path to the log file. `None` means stdout.
    pub(crate) log_path: Option<PathBuf>,
    pub(crate) file: Option<File>,
    pub(crate) directory: Option<Directory>,
    pub(crate) elastic: Option<ElasticSearch>,
}

impl Config {
    /// Creates a new `Config` from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, parsed, or validated.
    pub(crate) fn new(path: &Path) -> Result<Self> {
        let config = config::Config::builder()
            .set_default("report", DEFAULT_REPORT_MODE)
            .context("cannot set the default report value")?
            .set_default("file.polling_mode", DEFAULT_POLLING_MODE)
            .context("cannot set the default file polling mode value")?
            .set_default("directory.polling_mode", DEFAULT_POLLING_MODE)
            .context("cannot set the default directory polling mode value")?
            .set_default("file.import_from_giganto", DEFAULT_IMPORT_FROM_GIGANTO)
            .context("cannot set the default import_from_giganto value")?
            .add_source(config::File::from(path))
            .build()
            .context("cannot build the config")?;
        let mut config: Self = config.try_deserialize()?;

        if let Some(ref mut file) = config.file
            && let Some(value) = file.export_from_giganto.take()
        {
            warn!(
                "`export_from_giganto` is deprecated and will be removed in a future release; \
                 use `import_from_giganto` instead"
            );
            if file.import_from_giganto.is_none() {
                file.import_from_giganto = Some(value);
            }
        }

        if config.kind.trim().is_empty() {
            bail!("kind cannot be empty");
        }

        if config.report && config.report_dir.is_none() {
            bail!(
                "Configuration error: 'report' is set to true but \
                 'report_dir' is not configured. Add 'report_dir' \
                 pointing to the directory where report files should \
                 be written (absolute or relative path). Example: \
                 report_dir = \"/var/lib/reproduce/reports\""
            );
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{Config, DEFAULT_IMPORT_FROM_GIGANTO, DEFAULT_POLLING_MODE, DEFAULT_REPORT_MODE};

    fn create_temp_config(content: &str) -> (tempfile::TempDir, PathBuf) {
        let temp_dir = tempfile::tempdir().expect("temporary directory should be created");
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, content).expect("test config should be written");
        (temp_dir, config_path)
    }

    #[test]
    fn config_new_missing_kind_returns_error() {
        let config_content = r#"
cert = "tests/cert.pem"
key = "tests/key.pem"
ca_certs = ["tests/root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "aicers"
input = "/path/to/file"
"#;
        let (_temp_dir, config_path) = create_temp_config(config_content);
        let result = Config::new(config_path.as_ref());

        assert!(result.is_err());
        let err_msg = result.expect_err("missing kind must fail").to_string();
        assert!(
            err_msg.contains("kind"),
            "error message should mention 'kind': {err_msg}"
        );
    }

    #[test]
    fn config_new_empty_kind_returns_error() {
        let config_content = r#"
cert = "tests/cert.pem"
key = "tests/key.pem"
ca_certs = ["tests/root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "aicers"
kind = ""
input = "/path/to/file"
"#;
        let (_temp_dir, config_path) = create_temp_config(config_content);
        let result = Config::new(config_path.as_ref());

        assert!(result.is_err());
        let err_msg = result.expect_err("empty kind must fail").to_string();
        assert!(
            err_msg.contains("kind cannot be empty"),
            "error message should indicate empty kind: {err_msg}"
        );
    }

    #[test]
    fn config_new_whitespace_only_kind_returns_error() {
        let config_content = r#"
cert = "tests/cert.pem"
key = "tests/key.pem"
ca_certs = ["tests/root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "aicers"
kind = "   "
input = "/path/to/file"
"#;
        let (_temp_dir, config_path) = create_temp_config(config_content);
        let result = Config::new(config_path.as_ref());

        assert!(result.is_err());
        let err_msg = result
            .expect_err("whitespace-only kind must fail")
            .to_string();
        assert!(
            err_msg.contains("kind cannot be empty"),
            "error message should indicate empty kind: {err_msg}"
        );
    }

    #[test]
    fn config_new_valid_log_kind_succeeds() {
        let config_content = r#"
cert = "tests/cert.pem"
key = "tests/key.pem"
ca_certs = ["tests/root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "aicers"
kind = "valid log"
input = "/path/to/file"
"#;
        let (_temp_dir, config_path) = create_temp_config(config_content);
        let result = Config::new(config_path.as_ref());

        assert!(
            result.is_ok(),
            "config with 'log' kind should load successfully: {result:?}"
        );
        let config = result.expect("valid config should deserialize");
        assert_eq!(config.kind, "valid log");
    }

    #[test]
    fn default_values_applied() {
        let (_temp_dir, config_path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
kind = "log"
input = "/path/to/input"
"#,
        );

        let config = Config::new(config_path.as_ref()).expect("minimal TOML should parse");

        assert_eq!(config.report, DEFAULT_REPORT_MODE);
    }

    #[test]
    fn default_file_polling_mode() {
        let (_temp_dir, config_path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
kind = "log"
input = "/path/to/input"

[file]
"#,
        );

        let config = Config::new(config_path.as_ref())
            .expect("config with a file section should deserialize");

        let file_section = config.file.expect("file section should exist");
        assert_eq!(file_section.polling_mode, DEFAULT_POLLING_MODE);
        assert_eq!(
            file_section.import_from_giganto,
            Some(DEFAULT_IMPORT_FROM_GIGANTO)
        );
    }

    #[test]
    fn default_directory_polling_mode() {
        let (_temp_dir, config_path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
kind = "log"
input = "/path/to/input"

[directory]
"#,
        );

        let config = Config::new(config_path.as_ref())
            .expect("config with a directory section should deserialize");

        let directory = config.directory.expect("directory section should exist");
        assert_eq!(directory.polling_mode, DEFAULT_POLLING_MODE);
    }

    #[test]
    fn report_true_without_report_dir_fails() {
        let (_temp_dir, config_path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
kind = "log"
input = "/path/to/input"
report = true
"#,
        );

        let result = Config::new(config_path.as_ref());
        assert!(result.is_err());
        let err_msg = result
            .expect_err("missing report_dir must fail")
            .to_string();
        assert!(
            err_msg.contains("report_dir"),
            "error should mention 'report_dir': {err_msg}"
        );
    }

    #[test]
    fn report_true_with_report_dir_succeeds() {
        let (_temp_dir, config_path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
kind = "log"
input = "/path/to/input"
report = true
report_dir = "reports"
"#,
        );

        let config =
            Config::new(config_path.as_ref()).expect("report=true with report_dir should succeed");
        assert!(config.report);
        assert_eq!(config.report_dir, Some(PathBuf::from("reports")));
    }

    #[test]
    fn report_false_without_report_dir_succeeds() {
        let (_temp_dir, config_path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
kind = "log"
input = "/path/to/input"
report = false
"#,
        );

        let config =
            Config::new(config_path.as_ref()).expect("report=false without report_dir must work");
        assert!(!config.report);
        assert!(config.report_dir.is_none());
    }

    #[test]
    fn report_false_with_report_dir_succeeds() {
        let (_temp_dir, config_path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
kind = "log"
input = "/path/to/input"
report = false
report_dir = "reports"
"#,
        );

        let config =
            Config::new(config_path.as_ref()).expect("report=false with report_dir must work");
        assert!(!config.report);
        assert_eq!(config.report_dir, Some(PathBuf::from("reports")));
    }
}
