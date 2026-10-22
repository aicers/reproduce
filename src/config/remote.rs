//! The configuration the Central Manager provides in remote mode.
//!
//! The manager returns the configuration as a TOML string. It is parsed with
//! `toml::from_str` rather than the `config` crate, which reads top-level keys
//! as path expressions and turns numbers and booleans into strings.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use giganto_client::RawEventKind;
use serde::Deserialize;
use thiserror::Error;

use super::parse_socket_addr;

/// The largest number of collectors a configuration may hold.
pub const MAX_COLLECTORS: usize = 64;

/// The longest collector kind, in bytes.
const MAX_KIND_LEN: usize = 64;

/// The longest collector path, in bytes.
const MAX_PATH_LEN: usize = 4096;

/// Directories a collector path must not be equal to or lie under.
pub(crate) const RESERVED_DIRS: [&str; 4] = [
    "/etc/clumit-security",
    "/var/lib/clumit-security",
    "/opt/clumit-security",
    "/proc",
];

/// A validated remote configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteConfig {
    pub giganto_ingest_srv_addr: SocketAddr,
    pub giganto_name: String,
    pub collectors: Vec<CollectorConfig>,
}

/// A validated collector entry of a remote configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectorConfig {
    pub collector_type: CollectorType,
    pub kind: String,
    pub path: PathBuf,
    pub start: StartPosition,
}

/// The type of a collector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorType {
    /// Follows a log file and sends each line as a Giganto `Log`.
    Log,
}

/// Where a collector starts reading a file it has no checkpoint for.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StartPosition {
    /// The current end of the file.
    #[default]
    End,
    /// The start of the file.
    Beginning,
}

/// An error refusing a remote configuration.
#[derive(Debug, Error)]
pub enum RemoteConfigError {
    /// The configuration is an empty string.
    #[error("the remote configuration is empty")]
    Empty,
    /// The configuration is not valid TOML, has a missing or unknown key, or
    /// a value of the wrong type.
    #[error("{0}")]
    Parse(#[from] toml::de::Error),
    /// A value breaks a rule of the schema.
    #[error("{key}: {reason}")]
    Invalid { key: String, reason: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    giganto_ingest_srv_addr: String,
    giganto_name: String,
    collectors: Vec<RawCollector>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCollector {
    #[serde(rename = "type")]
    collector_type: String,
    kind: String,
    path: String,
    start: Option<String>,
}

impl FromStr for RemoteConfig {
    type Err = RemoteConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

/// Parses and validates a remote configuration.
///
/// # Errors
///
/// Returns an error if the string is empty, is not valid TOML, has a missing
/// or unknown key or a value of the wrong type, or breaks a rule of the
/// schema. A rule error names the key and, for a collector, its 0-based
/// index, as `collectors[2].path`.
pub fn parse(s: &str) -> Result<RemoteConfig, RemoteConfigError> {
    if s.is_empty() {
        return Err(RemoteConfigError::Empty);
    }
    let raw: RawConfig = toml::from_str(s)?;

    let giganto_ingest_srv_addr = parse_socket_addr(&raw.giganto_ingest_srv_addr)
        .map_err(|reason| invalid("giganto_ingest_srv_addr", reason))?;
    if raw.giganto_name.is_empty() {
        return Err(invalid("giganto_name", "must not be empty"));
    }
    if raw.collectors.is_empty() || raw.collectors.len() > MAX_COLLECTORS {
        return Err(invalid(
            "collectors",
            format!(
                "must hold 1 to {MAX_COLLECTORS} entries, found {}",
                raw.collectors.len()
            ),
        ));
    }

    let mut kinds: HashMap<&str, usize> = HashMap::new();
    let mut paths: HashMap<&str, usize> = HashMap::new();
    let mut collectors = Vec::with_capacity(raw.collectors.len());
    for (index, collector) in raw.collectors.iter().enumerate() {
        let key = |field: &str| format!("collectors[{index}].{field}");

        let collector_type = match collector.collector_type.as_str() {
            "log" => CollectorType::Log,
            other => {
                return Err(invalid(
                    key("type"),
                    format!("unsupported type \"{other}\"; the only type is \"log\""),
                ));
            }
        };

        validate_kind(&collector.kind).map_err(|reason| invalid(key("kind"), reason))?;
        if let Some(first) = kinds.insert(&collector.kind, index) {
            return Err(invalid(
                key("kind"),
                format!(
                    "\"{}\" is already used by collectors[{first}]",
                    collector.kind
                ),
            ));
        }

        validate_path(&collector.path).map_err(|reason| invalid(key("path"), reason))?;
        if let Some(first) = paths.insert(&collector.path, index) {
            return Err(invalid(
                key("path"),
                format!(
                    "\"{}\" is already used by collectors[{first}]",
                    collector.path
                ),
            ));
        }

        let start = match collector.start.as_deref() {
            None | Some("end") => StartPosition::End,
            Some("beginning") => StartPosition::Beginning,
            Some(other) => {
                return Err(invalid(
                    key("start"),
                    format!("unsupported value \"{other}\"; expected \"end\" or \"beginning\""),
                ));
            }
        };

        collectors.push(CollectorConfig {
            collector_type,
            kind: collector.kind.clone(),
            path: PathBuf::from(&collector.path),
            start,
        });
    }

    Ok(RemoteConfig {
        giganto_ingest_srv_addr,
        giganto_name: raw.giganto_name,
        collectors,
    })
}

fn invalid(key: impl Into<String>, reason: impl Into<String>) -> RemoteConfigError {
    RemoteConfigError::Invalid {
        key: key.into(),
        reason: reason.into(),
    }
}

/// Checks that a kind matches `^[a-z0-9][a-z0-9_.-]{0,63}$` and is not a
/// named Giganto kind.
fn validate_kind(kind: &str) -> Result<(), String> {
    let mut bytes = kind.bytes();
    let well_formed = bytes
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
        && kind.len() <= MAX_KIND_LEN;
    if !well_formed {
        return Err(format!(
            "\"{kind}\" does not match ^[a-z0-9][a-z0-9_.-]{{0,63}}$"
        ));
    }

    // Giganto resolves a requested kind with `RawEventKind::from_str` before
    // reading, so a log stored under a name that parses as another kind could
    // never be read back as a log.
    match RawEventKind::from_str(kind) {
        Ok(RawEventKind::Log) | Err(_) => Ok(()),
        Ok(named) => Err(format!(
            "\"{kind}\" is a named Giganto kind ({named:?}) and cannot be used for a log"
        )),
    }
}

/// Checks the path rules: absolute, at most 4096 bytes, no NUL, no empty, `.`
/// or `..` segment, no trailing `/`, and not equal to or under a reserved
/// directory.
fn validate_path(path: &str) -> Result<(), String> {
    if path.len() > MAX_PATH_LEN {
        return Err(format!("must be at most {MAX_PATH_LEN} bytes long"));
    }
    if path.contains('\0') {
        return Err("must not contain NUL".to_string());
    }
    let Some(relative) = path.strip_prefix('/') else {
        return Err(format!("\"{path}\" is not an absolute path"));
    };
    if path.ends_with('/') {
        return Err(format!("\"{path}\" must not end with /"));
    }
    for segment in relative.split('/') {
        match segment {
            "" => return Err(format!("\"{path}\" has an empty segment")),
            "." | ".." => return Err(format!("\"{path}\" has a \"{segment}\" segment")),
            _ => {}
        }
    }
    if let Some(dir) = RESERVED_DIRS
        .iter()
        .find(|dir| Path::new(path).starts_with(dir))
    {
        return Err(format!(
            "\"{path}\" lies under the reserved directory {dir}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    const VALID: &str = r#"
giganto_ingest_srv_addr = "10.0.0.5:38370"
giganto_name = "001.giganto.ds1.customer.example"

[[collectors]]
type = "log"
kind = "nginx_access"
path = "/var/log/nginx/access.log"
start = "end"
"#;

    fn header() -> String {
        "giganto_ingest_srv_addr = \"10.0.0.5:38370\"\ngiganto_name = \"giganto\"\n".to_string()
    }

    fn collector(kind: &str, path: &str) -> String {
        format!("\n[[collectors]]\ntype = \"log\"\nkind = \"{kind}\"\npath = \"{path}\"\n")
    }

    fn with_collector(kind: &str, path: &str) -> String {
        header() + &collector(kind, path)
    }

    fn invalid_key(s: &str) -> (String, String) {
        match parse(s) {
            Err(RemoteConfigError::Invalid { key, reason }) => (key, reason),
            other => panic!("expected a rule error, got {other:?}"),
        }
    }

    fn parse_error(s: &str) -> String {
        match parse(s) {
            Err(RemoteConfigError::Parse(error)) => error.to_string(),
            other => panic!("expected a TOML parser error, got {other:?}"),
        }
    }

    #[test]
    fn valid_configuration_parses() {
        let config: RemoteConfig = VALID.parse().expect("valid configuration");
        assert_eq!(
            config,
            RemoteConfig {
                giganto_ingest_srv_addr: "10.0.0.5:38370".parse().expect("address"),
                giganto_name: "001.giganto.ds1.customer.example".to_string(),
                collectors: vec![CollectorConfig {
                    collector_type: CollectorType::Log,
                    kind: "nginx_access".to_string(),
                    path: PathBuf::from("/var/log/nginx/access.log"),
                    start: StartPosition::End,
                }],
            }
        );
    }

    #[test]
    fn start_defaults_to_end_and_accepts_beginning() {
        let config = parse(&with_collector("app", "/var/log/app.log")).expect("valid");
        assert_eq!(config.collectors[0].start, StartPosition::End);

        let config =
            parse(&(with_collector("app", "/var/log/app.log") + "start = \"beginning\"\n"))
                .expect("valid");
        assert_eq!(config.collectors[0].start, StartPosition::Beginning);
    }

    #[test]
    fn invalid_start_is_refused() {
        let (key, _) =
            invalid_key(&(with_collector("app", "/var/log/app.log") + "start = \"middle\"\n"));
        assert_eq!(key, "collectors[0].start");
    }

    #[test]
    fn empty_string_is_refused() {
        assert!(matches!(parse(""), Err(RemoteConfigError::Empty)));
    }

    #[test]
    fn ipv6_address_parses() {
        let s =
            with_collector("app", "/var/log/app.log").replace("10.0.0.5:38370", "[fd00::5]:38370");
        let config = parse(&s).expect("valid");
        assert_eq!(
            config.giganto_ingest_srv_addr,
            "[fd00::5]:38370".parse().expect("address")
        );
    }

    #[test]
    fn invalid_address_is_refused() {
        for addr in ["10.0.0.5", "localhost:38370", ""] {
            let s = with_collector("app", "/var/log/app.log").replace("10.0.0.5:38370", addr);
            let (key, _) = invalid_key(&s);
            assert_eq!(key, "giganto_ingest_srv_addr", "address {addr:?}");
        }
    }

    #[test]
    fn empty_giganto_name_is_refused() {
        let s = with_collector("app", "/var/log/app.log").replace("\"giganto\"", "\"\"");
        let (key, _) = invalid_key(&s);
        assert_eq!(key, "giganto_name");
    }

    #[test]
    fn collector_count_is_bounded() {
        let (key, _) = invalid_key(&(header() + "collectors = []\n"));
        assert_eq!(key, "collectors");

        let mut s = header();
        for i in 0..MAX_COLLECTORS {
            s += &collector(&format!("app{i}"), &format!("/var/log/app{i}.log"));
        }
        let config = parse(&s).expect("64 collectors are accepted");
        assert_eq!(config.collectors.len(), MAX_COLLECTORS);

        s += &collector("one-too-many", "/var/log/one-too-many.log");
        let (key, reason) = invalid_key(&s);
        assert_eq!(key, "collectors");
        assert!(reason.contains("65"), "{reason}");
    }

    #[test]
    fn missing_keys_are_refused_by_the_parser() {
        for missing in ["giganto_ingest_srv_addr", "giganto_name"] {
            let s: String = with_collector("app", "/var/log/app.log")
                .lines()
                .filter(|line| !line.starts_with(missing))
                .fold(String::new(), |mut s, line| {
                    let _ = writeln!(s, "{line}");
                    s
                });
            let error = parse_error(&s);
            assert!(error.contains(missing), "{error}");
        }
        let error = parse_error(&header());
        assert!(error.contains("collectors"), "{error}");

        for missing in ["type", "kind", "path"] {
            let s: String = with_collector("app", "/var/log/app.log")
                .lines()
                .filter(|line| !line.starts_with(missing))
                .fold(String::new(), |mut s, line| {
                    let _ = writeln!(s, "{line}");
                    s
                });
            let error = parse_error(&s);
            assert!(error.contains(missing), "{error}");
        }
    }

    #[test]
    fn unknown_keys_are_refused_by_the_parser() {
        let error = parse_error(&(header() + "cert = \"cert.pem\"\n" + &collector("app", "/a")));
        assert!(error.contains("cert"), "{error}");
        assert!(error.contains("line 3"), "{error}");

        let error =
            parse_error(&(with_collector("app", "/var/log/app.log") + "polling_mode = true\n"));
        assert!(error.contains("polling_mode"), "{error}");

        let error = parse_error(&(header() + "\"collectors[0]\" = 1\n"));
        assert!(error.contains("collectors[0]"), "{error}");

        let error =
            parse_error(&(header() + "\"collectors[2000000000]\" = 1\n" + &collector("app", "/a")));
        assert!(error.contains("collectors[2000000000]"), "{error}");
    }

    #[test]
    fn duplicate_keys_are_refused_by_the_parser() {
        let s = header() + "giganto_name = \"other\"\n" + &collector("app", "/var/log/app.log");
        let error = parse_error(&s);
        assert!(error.contains("giganto_name"), "{error}");
    }

    #[test]
    fn wrong_types_are_refused_by_the_parser() {
        let s = with_collector("app", "/var/log/app.log").replace("\"giganto\"", "5");
        let error = parse_error(&s);
        assert!(error.contains("giganto_name"), "{error}");
        assert!(error.contains("line 2"), "{error}");

        let s = header() + "collectors = 1\n";
        let error = parse_error(&s);
        assert!(error.contains("collectors"), "{error}");

        let s = with_collector("app", "/var/log/app.log") + "start = true\n";
        let error = parse_error(&s);
        assert!(error.contains("start"), "{error}");
    }

    #[test]
    fn non_log_type_is_refused() {
        let s = with_collector("app", "/var/log/app.log").replace("\"log\"", "\"file\"");
        let (key, _) = invalid_key(&s);
        assert_eq!(key, "collectors[0].type");
    }

    #[test]
    fn kind_pattern_is_enforced() {
        let longest = format!("a{}", "b".repeat(63));
        for kind in ["log", "nginx_access", "0app", "a.b-c_d", longest.as_str()] {
            parse(&with_collector(kind, "/var/log/app.log"))
                .unwrap_or_else(|error| panic!("kind {kind:?} should be accepted: {error}"));
        }

        let too_long = format!("a{}", "b".repeat(64));
        for kind in [
            "",
            "Nginx",
            "_app",
            ".app",
            "-app",
            "app log",
            "app/log",
            "앱",
            too_long.as_str(),
        ] {
            let (key, _) = invalid_key(&with_collector(kind, "/var/log/app.log"));
            assert_eq!(key, "collectors[0].kind", "kind {kind:?}");
        }
    }

    #[test]
    fn named_giganto_kinds_are_refused() {
        for kind in [
            "dns",
            "dns_event",
            "dns_query",
            "timeseries",
            "periodic_time_series",
            "conn",
            "http",
            "op_log",
            "netflow5",
            "secu_log",
            "malformed_dns",
        ] {
            let (key, reason) = invalid_key(&with_collector(kind, "/var/log/app.log"));
            assert_eq!(key, "collectors[0].kind", "kind {kind:?}");
            assert!(reason.contains("named Giganto kind"), "{reason}");
        }
    }

    #[test]
    fn kinds_and_paths_are_unique() {
        let s =
            header() + &collector("app", "/var/log/a.log") + &collector("app", "/var/log/b.log");
        let (key, reason) = invalid_key(&s);
        assert_eq!(key, "collectors[1].kind");
        assert!(reason.contains("collectors[0]"), "{reason}");

        let s = header()
            + &collector("a", "/var/log/a.log")
            + &collector("b", "/var/log/b.log")
            + &collector("c", "/var/log/a.log");
        let (key, reason) = invalid_key(&s);
        assert_eq!(key, "collectors[2].path");
        assert!(reason.contains("collectors[0]"), "{reason}");
    }

    #[test]
    fn path_rules_are_enforced() {
        for path in [
            "/var/log/app.log",
            "/etc/clumit-security-x/a.log",
            "/var/lib/clumit-securityd/a.log",
            "/procfs/a.log",
            "/a",
        ] {
            parse(&with_collector("app", path))
                .unwrap_or_else(|error| panic!("path {path:?} should be accepted: {error}"));
        }

        let too_long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        for path in [
            "",
            "/",
            "var/log/app.log",
            "./app.log",
            "/var/log/",
            "/var//log/app.log",
            "/var/log/./app.log",
            "/var/log/../app.log",
            "/var/log/..",
            "/var/log/app.log\\u0000",
            "/etc/clumit-security",
            "/etc/clumit-security/a.log",
            "/var/lib/clumit-security/state/a.log",
            "/opt/clumit-security/bin/a.log",
            "/proc",
            "/proc/self/fd/0",
            too_long.as_str(),
        ] {
            let (key, _) = invalid_key(&with_collector("app", path));
            assert_eq!(key, "collectors[0].path", "path {path:?}");
        }

        let longest = format!("/{}", "a".repeat(MAX_PATH_LEN - 1));
        parse(&with_collector("app", &longest)).expect("a 4096-byte path is accepted");
    }

    #[test]
    fn rule_errors_name_the_collector_index() {
        let s = header()
            + &collector("a", "/var/log/a.log")
            + &collector("b", "/var/log/b.log")
            + &collector("c", "/var/log/../c.log");
        let error = parse(&s).expect_err("invalid path");
        assert!(
            error.to_string().starts_with("collectors[2].path: "),
            "{error}"
        );
    }
}
