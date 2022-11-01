use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration as CrnDuration, Utc};
use kafka::error::Error as KafkaError;
use kafka::producer::Record;
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig, WriteError};
use serde::Deserialize;
use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

type GigantoLog = (String, Vec<u8>);

const GIGANTO_TYPE: u32 = 0x02;
const GIGANTO_VERSION: &str = "0.4.0";
const INTERVAL: u64 = 5;

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
    ///
    ///  # Panics
    ///
    /// Connection error, not `TimedOut`
    pub async fn new_giganto(addr: &str, name: &str, certs_toml: &str, kind: &str) -> Result<Self> {
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
        loop {
            let conn = match endpoint.connect(remote, name)?.await {
                Ok(r) => r,
                Err(quinn::ConnectionError::TimedOut) => {
                    println!("Server TimedOut, reconnecting...");
                    tokio::time::sleep(Duration::from_secs(INTERVAL)).await;
                    continue;
                }
                Err(e) => panic!("{}", e),
            };

            let (check_send, check_recv) = conn
                .open_bi()
                .await
                .context("Failed to open giganto handshake stream")?;
            if check_stream(check_send, check_recv).await.is_err() {
                bail!("Protocol Check fail, please check protocol version");
            }

            let (giganto_send, giganto_recv) =
                conn.open_bi().await.expect("Failed to open giganto stream");

            tokio::spawn(async move { recv_ack(giganto_recv).await });

            return Ok(Self::Giganto(Giganto {
                giganto_endpoint: endpoint.clone(),
                giganto_server: remote,
                giganto_info: GigantoInfo {
                    name: name.to_string(),
                    kind: kind.to_string(),
                },
                giganto_conn: conn,
                giganto_sender: giganto_send,
                init_msg: true,
            }));
        }
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
            .with_connection_idle_timeout(Duration::new(IDLE_TIMEOUT, 0))
            .with_ack_timeout(std::time::Duration::new(ACK_TIMEOUT, 0))
            .create()?;
        let last_time = Utc::now();
        Ok(Self::Kafka(Kafka {
            inner: producer,
            topic: topic.to_string(),
            queue_data: Vec::new(),
            queue_data_cnt: 0,
            queue_size,
            queue_period: CrnDuration::seconds(queue_period),
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
    pub async fn produce(&mut self, message: &[u8], flush: bool) -> Result<()> {
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
            Producer::Giganto(giganto) => {
                giganto.send(message).await.context("Send fail")?;

                Ok(())
            }
            Producer::Null => Ok(()),
        }
    }
}

pub struct Kafka {
    inner: kafka::producer::Producer,
    topic: String,
    queue_data: Vec<u8>,
    queue_data_cnt: usize,
    queue_size: usize,
    queue_period: CrnDuration,
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

#[derive(Debug)]
pub struct Giganto {
    giganto_endpoint: Endpoint,
    giganto_server: SocketAddr,
    giganto_info: GigantoInfo,
    giganto_conn: Connection,
    giganto_sender: SendStream,
    init_msg: bool,
}

#[derive(Debug)]
struct GigantoInfo {
    name: String,
    kind: String,
}

impl Giganto {
    async fn send(&mut self, msg: &[u8]) -> Result<(), WriteError> {
        let mut giganto_data: Vec<u8> = Vec::new();
        let body: GigantoLog = (self.giganto_info.kind.to_string(), msg.to_vec());
        let mut serial_body = bincode::serialize(&body).expect("failed to serialize log");
        if self.init_msg {
            giganto_data.append(&mut GIGANTO_TYPE.to_le_bytes().to_vec());
            self.init_msg = false;
        }
        let body_len: u32 = serial_body.len().try_into().expect("conversion as `u32`");
        giganto_data.append(&mut Utc::now().timestamp_nanos().to_le_bytes().to_vec());
        giganto_data.append(&mut body_len.to_le_bytes().to_vec());
        giganto_data.append(&mut serial_body);

        // println!("Send"); // print console `Send` to test
        if self.giganto_sender.write_all(&giganto_data).await.is_err() {
            self.reconnect().await.expect("reconnect giganto");
        }
        giganto_data.clear();

        Ok(())
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.giganto_sender
            .finish()
            .await
            .context("Failed to finish stream")?;
        self.giganto_conn.close(0u32.into(), b"log_done");
        self.giganto_endpoint.wait_idle().await;
        println!("giganto end");

        Ok(())
    }

    async fn reconnect(&mut self) -> Result<()> {
        loop {
            let conn = match self
                .giganto_endpoint
                .connect(self.giganto_server, &self.giganto_info.name)
                .context("Failed to connect giganto, please check setting is correct")?
                .await
            {
                Ok(r) => r,
                Err(quinn::ConnectionError::TimedOut) => {
                    println!("Server TimedOut, reconnecting...");
                    tokio::time::sleep(Duration::from_secs(INTERVAL)).await;
                    continue;
                }
                Err(e) => panic!("{}", e),
            };
            let (check_send, check_recv) = conn
                .open_bi()
                .await
                .context("Failed to open giganto handshake stream")?;
            if check_stream(check_send, check_recv).await.is_err() {
                bail!("Protocol Check fail, please check protocol version");
            }

            let (giganto_send, giganto_recv) = conn
                .open_bi()
                .await
                .context("Failed to open giganto stream")?;
            tokio::spawn(async move { recv_ack(giganto_recv).await });

            self.giganto_conn = conn;
            self.giganto_sender = giganto_send;
            self.init_msg = true;

            return Ok(());
        }
    }
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
        if let Some(key) = pkcs8.into_iter().next() {
            rustls::PrivateKey(key)
        } else {
            let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                .expect("malformed PKCS #1 private key");
            match rsa.into_iter().next() {
                Some(x) => rustls::PrivateKey(x),
                None => {
                    bail!("No private key found");
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

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(INTERVAL)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

async fn recv_ack(mut recv: RecvStream) -> Result<()> {
    let mut ack_buf = [0; std::mem::size_of::<u64>()];
    loop {
        match recv.read_exact(&mut ack_buf).await {
            Ok(()) => {
                let recv_ts = i64::from_be_bytes(ack_buf);
                println!("ACK: {}", recv_ts);
            }
            Err(quinn::ReadExactError::FinishedEarly) => {
                eprintln!("Finished Early");
                break;
            }
            Err(e) => bail!("Receive ACK Err: {}", e),
        }
    }
    Ok(())
}

async fn check_stream(mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let mut handshake_vec = Vec::new();
    let version = GIGANTO_VERSION.as_bytes();
    let len = version.len() as u64;
    handshake_vec.extend(len.to_le_bytes());
    handshake_vec.extend(version);
    send.write_all(&handshake_vec).await?;
    send.finish().await?;

    let mut len_buf = [0; std::mem::size_of::<u64>()];
    let mut recv_buf: Vec<u8> = Vec::new();
    recv.read_exact(&mut len_buf).await?;
    let len = u64::from_le_bytes(len_buf);
    recv_buf.resize(len.try_into()?, 0);
    recv.read_exact(&mut recv_buf).await?;

    if bincode::deserialize::<Option<&str>>(&recv_buf)?.is_none() {
        bail!("connection reject");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Producer;

    #[tokio::test]
    async fn null() {
        let mut producer = Producer::new_null();
        assert!(producer.produce(b"A message", true).await.is_ok());
    }
}
