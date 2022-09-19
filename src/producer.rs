use anyhow::{bail, Result};
use chrono::{DateTime, Duration, Utc};
use kafka::error::Error as KafkaError;
use kafka::producer::Record;
use quinn::{Connection, Endpoint};
use serde::Deserialize;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

#[allow(clippy::large_enum_variant)]
pub enum Producer {
    File(File),
    Giganto(Giganto),
    Kafka(Kafka),
    Null,
}

impl Producer {
    /// # Errors
    ///
    /// Returns an error if file creation fails.
    pub fn new_file(filename: &str) -> Result<Self> {
        let output = File::create(filename)?;
        Ok(Producer::File(output))
    }

    /// # Errors
    ///
    /// Returns an error if it fails to set up Giganto.
    pub async fn new_giganto(addr: &str, name: &str, certs_toml: &str) -> Result<Self> {
        let endpoint = match init_giganto(certs_toml) {
            Ok(ret) => ret,
            Err(e) => {
                bail!("Failed to create giganto producer: {:?}", e);
            }
        };
        let remote = match addr.parse::<SocketAddr>() {
            Ok(ret) => ret,
            Err(e) => {
                bail!("Failed to parse giganto server: {:?}", e);
            }
        };

        let new_connection = endpoint
            .connect(remote, name)
            .expect("Failed to connect giganto, please check setting is correct")
            .await
            .expect("Failed to connect giganto, Please make sure giganto alive");
        let quinn::NewConnection {
            connection: conn, ..
        } = new_connection;

        Ok(Self::Giganto(Giganto { conn, endpoint }))
    }

    /// Constructs a new Kafka producer.
    ///
    /// # Errors
    ///
    /// Returns an error if it fails to create the underlying Kafka producer.
    pub fn new_kafka(
        broker: &str,
        topic: &str,
        queue_size: usize,
        queue_period: i64,
        periodic: bool,
    ) -> Result<Self, KafkaError> {
        const IDLE_TIMEOUT: u64 = 540;
        const ACK_TIMEOUT: u64 = 5;
        let producer = kafka::producer::Producer::from_hosts(vec![broker.to_string()])
            .with_connection_idle_timeout(std::time::Duration::new(IDLE_TIMEOUT, 0))
            .with_ack_timeout(std::time::Duration::new(ACK_TIMEOUT, 0))
            .create()?;
        let last_time = Utc::now();
        Ok(Self::Kafka(Kafka {
            inner: producer,
            topic: topic.to_string(),
            queue_data: Vec::new(),
            queue_data_cnt: 0,
            queue_size,
            queue_period: Duration::seconds(queue_period),
            period_check: periodic,
            last_time,
        }))
    }

    #[must_use]
    pub fn new_null() -> Self {
        Self::Null
    }

    #[must_use]
    pub fn max_bytes() -> usize {
        const DEFAULT_MAX_BYTES: usize = 100_000;
        DEFAULT_MAX_BYTES
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    pub fn produce(&mut self, message: &[u8], flush: bool) -> Result<()> {
        match self {
            Producer::File(f) => {
                f.write_all(message)?;
                f.write_all(b"\n")?;
                if flush {
                    f.flush()?;
                }
                Ok(())
            }
            Producer::Kafka(inner) => {
                if !message.is_empty() {
                    inner.queue_data.extend(message);
                    if !flush {
                        inner.queue_data_cnt += 1;
                    }
                }

                if flush || inner.periodic_flush() || inner.queue_data.len() >= inner.queue_size {
                    if let Err(e) = inner.send(message) {
                        inner.queue_data.clear();
                        inner.queue_data_cnt = 0;
                        // TODO: error handling
                        return Err(anyhow::Error::msg(e.to_string()));
                    }
                    inner.queue_data.clear();
                    inner.queue_data_cnt = 0;

                    inner.last_time = Utc::now();
                } else {
                    inner.queue_data.push(b'\n');
                }
                Ok(())
            }
            Producer::Giganto(_) | Producer::Null => Ok(()),
        }
    }
}

pub struct Kafka {
    inner: kafka::producer::Producer,
    topic: String,
    queue_data: Vec<u8>,
    queue_data_cnt: usize,
    queue_size: usize,
    queue_period: Duration,
    period_check: bool,
    last_time: DateTime<Utc>,
}

impl Kafka {
    fn periodic_flush(&mut self) -> bool {
        if !self.period_check {
            return false;
        }

        let current = Utc::now();
        current - self.last_time > self.queue_period
    }

    /// Sends a message to the Kafka server.
    ///
    /// # Errors
    ///
    /// Returns an error if transmission fails.
    pub fn send(&mut self, msg: &[u8]) -> Result<(), KafkaError> {
        self.inner.send(&Record::from_value(&self.topic, msg))
    }
}

#[derive(Deserialize, Debug)]
struct Config {
    certification: Certification,
}

#[derive(Deserialize, Debug)]
struct Certification {
    cert: String,
    key: String,
    roots: Vec<String>,
}

#[allow(unused)]
pub struct Giganto {
    conn: Connection,
    endpoint: Endpoint,
}

fn init_giganto(certs_toml: &str) -> Result<Endpoint> {
    let mut cfg_str = String::new();
    if let Err(e) =
        File::open(Path::new(certs_toml)).and_then(|mut f| f.read_to_string(&mut cfg_str))
    {
        bail!(
            "Failed to open file, Please check certs_toml file name: {:?}",
            e
        );
    }
    let config = match toml::from_str::<Config>(&cfg_str) {
        Ok(r) => r,
        Err(e) => {
            bail!("Failed to parse toml file, please check file: {:?}", e);
        }
    };

    let (cert, key) = match fs::read(&config.certification.cert)
        .and_then(|x| Ok((x, fs::read(&config.certification.key)?)))
    {
        Ok(r) => r,
        Err(_) => {
            bail!(
                "Failed to read (cert, key) file, cert_path:{}, key_path:{}",
                &config.certification.cert,
                &config.certification.key
            );
        }
    };

    let pv_key = if Path::new(&config.certification.key)
        .extension()
        .map_or(false, |x| x == "der")
    {
        rustls::PrivateKey(key)
    } else {
        let pkcs8 =
            rustls_pemfile::pkcs8_private_keys(&mut &*key).expect("malformed PKCS #8 private key");
        match pkcs8.into_iter().next() {
            Some(x) => rustls::PrivateKey(x),
            None => {
                let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                    .expect("malformed PKCS #1 private key");
                match rsa.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        bail!("No private key found");
                    }
                }
            }
        }
    };

    let cert_chain = if Path::new(&config.certification.cert)
        .extension()
        .map_or(false, |x| x == "der")
    {
        vec![rustls::Certificate(cert)]
    } else {
        rustls_pemfile::certs(&mut &*cert)
            .expect("invalid PEM-encoded certificate")
            .into_iter()
            .map(rustls::Certificate)
            .collect()
    };

    let mut server_root = rustls::RootCertStore::empty();
    for root in config.certification.roots {
        let file = fs::read(&root).expect("Failed to read file");
        let root_cert: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*file)
            .expect("invalid PEM-encoded certificate")
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        if let Some(cert) = root_cert.get(0) {
            server_root.add(cert).expect("Failed to add cert");
        }
    }

    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(server_root)
        .with_single_cert(cert_chain, pv_key)
        .expect("the server root, cert chain or private key are not valid");

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::Producer;

    #[test]
    fn null() {
        let mut producer = Producer::new_null();
        assert!(producer.produce(b"A message", true).is_ok());
    }
}
