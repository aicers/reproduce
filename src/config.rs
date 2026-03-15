use std::net::SocketAddr;

use serde::{Deserialize, Deserializer, de::Error};

/// Stores the shared Giganto connection settings used by binary entrypoints.
#[derive(Deserialize, Debug, Clone)]
pub struct GigantoConfig {
    pub cert: String,
    pub key: String,
    pub ca_certs: Vec<String>,
    #[serde(
        rename = "giganto_ingest_srv_addr",
        deserialize_with = "deserialize_socket_addr"
    )]
    pub ingest_srv_addr: SocketAddr,
    #[serde(rename = "giganto_name")]
    pub name: String,
}

/// Deserializes a socket address written as `IP:PORT`.
///
/// # Errors
///
/// Returns an error if the address is not in the expected format.
fn deserialize_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: Deserializer<'de>,
{
    let addr = String::deserialize(deserializer)?;
    addr.parse()
        .map_err(|error| D::Error::custom(format!("invalid address \"{addr}\": {error}")))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use serde::Deserialize;

    use super::GigantoConfig;

    #[derive(Deserialize)]
    struct TestConfig {
        #[serde(flatten)]
        giganto: GigantoConfig,
    }

    fn create_temp_config(content: &str) -> (tempfile::TempDir, PathBuf) {
        let temp_dir = tempfile::tempdir().expect("temporary directory should be created");
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, content).expect("test config should be written");
        (temp_dir, config_path)
    }

    fn load_test_config(path: &Path) -> TestConfig {
        config::Config::builder()
            .add_source(config::File::from(path))
            .build()
            .expect("test config should load")
            .try_deserialize()
            .expect("test config should deserialize")
    }

    #[test]
    fn socket_addr_ipv4_parses() {
        let (_temp_dir, path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:8080"
giganto_name = "test"
"#,
        );

        let config = load_test_config(&path);

        assert_eq!(
            config.giganto.ingest_srv_addr,
            "127.0.0.1:8080"
                .parse()
                .expect("IPv4 socket address literal should parse")
        );
    }

    #[test]
    fn socket_addr_ipv6_parses() {
        let (_temp_dir, path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "[::1]:8080"
giganto_name = "test"
"#,
        );

        let config = load_test_config(&path);

        assert_eq!(
            config.giganto.ingest_srv_addr,
            "[::1]:8080"
                .parse()
                .expect("IPv6 socket address literal should parse")
        );
    }

    #[test]
    fn socket_addr_missing_port_fails() {
        let (_temp_dir, path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "127.0.0.1"
giganto_name = "test"
"#,
        );

        let result = config::Config::builder()
            .add_source(config::File::from(path.as_path()))
            .build()
            .and_then(config::Config::try_deserialize::<TestConfig>);
        assert!(result.is_err(), "socket addresses without a port must fail");
    }

    #[test]
    fn socket_addr_hostname_fails() {
        let (_temp_dir, path) = create_temp_config(
            r#"
cert = "test.pem"
key = "test.key"
ca_certs = ["root.pem"]
giganto_ingest_srv_addr = "localhost:8080"
giganto_name = "test"
"#,
        );

        let result = config::Config::builder()
            .add_source(config::File::from(path.as_path()))
            .build()
            .and_then(config::Config::try_deserialize::<TestConfig>);
        assert!(
            result.is_err(),
            "hostnames must not deserialize as SocketAddr values"
        );
    }
}
