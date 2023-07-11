use anyhow::{bail, Context, Result};
use chrono::Utc;
use csv::{Position, StringRecord, StringRecordsIntoIter};
use giganto_client::{
    connection::client_handshake,
    frame::{RecvError, SendError},
    ingest::{
        log::Log,
        network::{
            Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
        },
        receive_ack_timestamp, send_event, send_record_header, RecordType,
    },
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    net::SocketAddr,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Duration,
};
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::{migration::TryFromGigantoRecord, operation_log, zeek::TryFromZeekRecord};

const CHANNEL_CLOSE_COUNT: u8 = 150;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const GIGANTO_VERSION: &str = "0.12.3";
const INTERVAL: u64 = 5;

#[allow(clippy::large_enum_variant)]
pub enum Producer {
    File(File),
    Giganto(Giganto),
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
                bail!("failed to create Giganto producer: {:?}", e);
            }
        };
        let remote = match addr.parse::<SocketAddr>() {
            Ok(ret) => ret,
            Err(e) => {
                bail!("failed to parse Giganto server: {:?}", e);
            }
        };
        loop {
            let conn = match endpoint.connect(remote, name)?.await {
                Ok(r) => r,
                Err(quinn::ConnectionError::TimedOut) => {
                    info!("server timeout, reconnecting...");
                    tokio::time::sleep(Duration::from_secs(INTERVAL)).await;
                    continue;
                }
                Err(e) => panic!("{}", e),
            };

            client_handshake(&conn, GIGANTO_VERSION).await?;

            let (giganto_send, giganto_recv) = conn
                .open_bi()
                .await
                .expect("failed to open stream to Giganto");

            let finish_checker_send = Arc::new(AtomicBool::new(false));
            let finish_checker_recv = finish_checker_send.clone();

            tokio::spawn(async move { recv_ack(giganto_recv, finish_checker_recv).await });

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
                finish_checker: finish_checker_send,
            }));
        }
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
            Producer::Giganto(giganto) => {
                giganto
                    .send(message)
                    .await
                    .context("failed to send message")?;

                Ok(())
            }
            Producer::Null => Ok(()),
        }
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    #[allow(clippy::too_many_lines)]
    pub async fn send_raw_to_giganto(
        &mut self,
        iter: StringRecordsIntoIter<File>,
        from: u64,
        grow: bool,
        migration: bool,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        if let Producer::Giganto(giganto) = self {
            match giganto.giganto_info.kind.as_str() {
                "conn" => {
                    if migration {
                        giganto
                            .migration::<Conn>(iter, RecordType::Conn, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Conn>(iter, RecordType::Conn, from, grow, running)
                            .await?;
                    }
                }
                "http" => {
                    if migration {
                        giganto
                            .migration::<Http>(iter, RecordType::Http, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Http>(iter, RecordType::Http, from, grow, running)
                            .await?;
                    }
                }
                "rdp" => {
                    if migration {
                        giganto
                            .migration::<Rdp>(iter, RecordType::Rdp, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Rdp>(iter, RecordType::Rdp, from, grow, running)
                            .await?;
                    }
                }
                "smtp" => {
                    if migration {
                        giganto
                            .migration::<Smtp>(iter, RecordType::Smtp, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Smtp>(iter, RecordType::Smtp, from, grow, running)
                            .await?;
                    }
                }
                "dns" => {
                    if migration {
                        giganto
                            .migration::<Dns>(iter, RecordType::Dns, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Dns>(iter, RecordType::Dns, from, grow, running)
                            .await?;
                    }
                }
                "ntlm" => {
                    if migration {
                        giganto
                            .migration::<Ntlm>(iter, RecordType::Ntlm, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Ntlm>(iter, RecordType::Ntlm, from, grow, running)
                            .await?;
                    }
                }
                "kerberos" => {
                    if migration {
                        giganto
                            .migration::<Kerberos>(iter, RecordType::Kerberos, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Kerberos>(iter, RecordType::Kerberos, from, grow, running)
                            .await?;
                    }
                }
                "ssh" => {
                    if migration {
                        giganto
                            .migration::<Ssh>(iter, RecordType::Ssh, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Ssh>(iter, RecordType::Ssh, from, grow, running)
                            .await?;
                    }
                }
                "dce_rpc" => {
                    if migration {
                        giganto
                            .migration::<DceRpc>(iter, RecordType::DceRpc, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<DceRpc>(iter, RecordType::DceRpc, from, grow, running)
                            .await?;
                    }
                }
                "ftp" => {
                    if migration {
                        giganto
                            .migration::<Ftp>(iter, RecordType::Ftp, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Ftp>(iter, RecordType::Ftp, from, grow, running)
                            .await?;
                    }
                }
                "mqtt" => {
                    if migration {
                        giganto
                            .migration::<Mqtt>(iter, RecordType::Mqtt, from, grow, running)
                            .await?;
                    } else {
                        bail!("mqtt's zeek is not supported".to_string());
                    }
                }
                "ldap" => {
                    if migration {
                        giganto
                            .migration::<Ldap>(iter, RecordType::Ldap, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Ldap>(iter, RecordType::Ldap, from, grow, running)
                            .await?;
                    }
                }
                "tls" => {
                    if migration {
                        giganto
                            .migration::<Tls>(iter, RecordType::Tls, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Tls>(iter, RecordType::Tls, from, grow, running)
                            .await?;
                    }
                }
                "smb" => {
                    if migration {
                        giganto
                            .migration::<Smb>(iter, RecordType::Smb, from, grow, running)
                            .await?;
                    } else {
                        bail!("smb's zeek is not supported".to_string());
                    }
                }
                "nfs" => {
                    if migration {
                        giganto
                            .migration::<Nfs>(iter, RecordType::Nfs, from, grow, running)
                            .await?;
                    } else {
                        bail!("nfs's zeek is not supported".to_string());
                    }
                }
                _ => error!("unknown zeek/migration kind"),
            }
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    pub async fn send_oplog_to_giganto(
        &mut self,
        reader: BufReader<File>,
        agent: &str,
        grow: bool,
        from: u64,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        if let Producer::Giganto(giganto) = self {
            if giganto.giganto_info.kind.as_str() == "oplog" {
                giganto
                    .send_oplog(reader, agent, grow, from, running)
                    .await?;
            }
        }
        Ok(())
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
    finish_checker: Arc<AtomicBool>,
}

#[derive(Debug)]
struct GigantoInfo {
    name: String,
    kind: String,
}

impl Giganto {
    async fn send_zeek<T>(
        &mut self,
        mut zeek_iter: StringRecordsIntoIter<File>,
        protocol: RecordType,
        from: u64,
        grow: bool,
        running: Arc<AtomicBool>,
    ) -> Result<()>
    where
        T: Serialize + TryFromZeekRecord + Unpin + Debug,
    {
        info!("send zeek");
        let mut success_cnt = 0u32;
        let mut failed_cnt = 0u32;
        let mut pos = Position::new();
        let mut last_record = StringRecord::new();
        while running.load(Ordering::SeqCst) {
            let next_pos = zeek_iter.reader().position().clone();
            if let Some(result) = zeek_iter.next() {
                if next_pos.line() < from {
                    continue;
                }
                match result {
                    Ok(record) if record != last_record => {
                        last_record = record.clone();
                        match T::try_from_zeek_record(&record) {
                            Ok((event, timestamp)) => {
                                if self.init_msg {
                                    send_record_header(&mut self.giganto_sender, protocol).await?;
                                    self.init_msg = false;
                                }
                                match send_event(&mut self.giganto_sender, timestamp, event).await {
                                    Err(SendError::WriteError(_)) => {
                                        self.reconnect().await?;
                                        continue;
                                    }
                                    Err(e) => {
                                        bail!("{e:?}");
                                    }
                                    Ok(_) => {}
                                }
                                success_cnt += 1;
                            }
                            Err(e) => {
                                failed_cnt += 1;
                                error!("failed to convert data #{}: {e}", next_pos.line());
                            }
                        }
                    }
                    Ok(_) => {
                        continue;
                    }
                    Err(e) => {
                        failed_cnt += 1;
                        error!("invalid record: {e}");
                    }
                }
            } else {
                if grow {
                    tokio::time::sleep(Duration::from_millis(3_000)).await;
                    zeek_iter.reader_mut().seek(pos.clone())?;
                    zeek_iter = zeek_iter.into_reader().into_records();
                    continue;
                }
                break;
            }
            pos = next_pos;
        }

        info!(
            "last line: {}, success line: {}, failed line: {} ",
            pos.line(),
            success_cnt,
            failed_cnt
        );

        Ok(())
    }

    async fn migration<T>(
        &mut self,
        mut giganto_iter: StringRecordsIntoIter<File>,
        protocol: RecordType,
        from: u64,
        grow: bool,
        running: Arc<AtomicBool>,
    ) -> Result<()>
    where
        T: Serialize + TryFromGigantoRecord + Unpin + Debug,
    {
        info!("migration");
        let mut success_cnt = 0u32;
        let mut failed_cnt = 0u32;
        let mut pos = Position::new();
        let mut last_record = StringRecord::new();
        while running.load(Ordering::SeqCst) {
            let next_pos = giganto_iter.reader().position().clone();
            if let Some(result) = giganto_iter.next() {
                if next_pos.line() < from {
                    continue;
                }
                match result {
                    Ok(record) if record != last_record => {
                        last_record = record.clone();
                        match T::try_from_giganto_record(&record) {
                            Ok((event, timestamp)) => {
                                if self.init_msg {
                                    send_record_header(&mut self.giganto_sender, protocol).await?;
                                    self.init_msg = false;
                                }
                                match send_event(&mut self.giganto_sender, timestamp, event).await {
                                    Err(SendError::WriteError(_)) => {
                                        self.reconnect().await?;
                                        continue;
                                    }
                                    Err(e) => {
                                        bail!("{e:?}");
                                    }
                                    Ok(_) => {}
                                }
                                success_cnt += 1;
                            }
                            Err(e) => {
                                failed_cnt += 1;
                                error!("failed to convert data #{}: {e}", next_pos.line());
                            }
                        }
                    }
                    Ok(_) => {
                        continue;
                    }
                    Err(e) => {
                        failed_cnt += 1;
                        error!("invalid record: {e}");
                    }
                }
            } else {
                if grow {
                    tokio::time::sleep(Duration::from_millis(3_000)).await;
                    giganto_iter.reader_mut().seek(pos.clone())?;
                    giganto_iter = giganto_iter.into_reader().into_records();
                    continue;
                }
                break;
            }
            pos = next_pos;
        }

        info!(
            "last line: {}, success line: {}, failed line: {} ",
            pos.line(),
            success_cnt,
            failed_cnt
        );

        Ok(())
    }

    async fn send_oplog(
        &mut self,
        reader: BufReader<File>,
        agent: &str,
        grow: bool,
        from: u64,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        let mut lines = reader.lines();
        let mut cnt = 0;
        let mut success_cnt = 0u32;
        let mut failed_cnt = 0u32;
        while running.load(Ordering::SeqCst) {
            if let Some(Ok(line)) = lines.next() {
                cnt += 1;
                if cnt < from {
                    continue;
                }
                let (oplog_data, timestamp) = if let Ok(r) = operation_log::log_regex(&line, agent)
                {
                    success_cnt += 1;
                    r
                } else {
                    failed_cnt += 1;
                    continue;
                };

                if self.init_msg {
                    send_record_header(&mut self.giganto_sender, RecordType::Oplog).await?;
                    self.init_msg = false;
                }

                match send_event(&mut self.giganto_sender, timestamp, oplog_data).await {
                    Err(SendError::WriteError(_)) => {
                        self.reconnect().await?;
                    }
                    Err(e) => {
                        bail!("{e:?}");
                    }
                    Ok(_) => {}
                }
            } else {
                if grow {
                    tokio::time::sleep(Duration::from_millis(3_000)).await;
                    continue;
                }
                break;
            }
        }
        info!(
            "last line: {}, success: {}, failed: {}",
            cnt, success_cnt, failed_cnt
        );

        Ok(())
    }

    async fn send(&mut self, msg: &[u8]) -> Result<()> {
        let send_log: Log = Log {
            kind: self.giganto_info.kind.to_string(),
            log: msg.to_vec(),
        };

        if self.init_msg {
            send_record_header(&mut self.giganto_sender, RecordType::Log).await?;
            self.init_msg = false;
        }

        match send_event(
            &mut self.giganto_sender,
            Utc::now().timestamp_nanos(),
            send_log,
        )
        .await
        {
            Err(SendError::WriteError(_)) => {
                self.reconnect().await?;
            }
            Err(e) => {
                bail!("{e:?}");
            }
            Ok(_) => {}
        }
        Ok(())
    }

    async fn send_finish(&mut self) -> Result<()> {
        match send_event(
            &mut self.giganto_sender,
            CHANNEL_CLOSE_TIMESTAMP,
            CHANNEL_CLOSE_MESSAGE,
        )
        .await
        {
            Err(SendError::WriteError(_)) => {
                bail!("failed to send channel done message");
            }
            Err(e) => {
                bail!("{e:?}");
            }
            Ok(_) => {}
        }
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.send_finish().await?;
        let mut force_finish_count = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if self.finish_checker.load(Ordering::SeqCst) {
                self.giganto_sender
                    .finish()
                    .await
                    .context("failed to finish stream")?;
                self.giganto_conn.close(0u32.into(), b"log_done");
                self.giganto_endpoint.wait_idle().await;
                break;
            }

            //Wait for a response for 15 seconds
            //If there is no response, the program ends.
            force_finish_count += 1;
            if force_finish_count == CHANNEL_CLOSE_COUNT {
                break;
            }
        }
        info!("Giganto end");
        Ok(())
    }

    async fn reconnect(&mut self) -> Result<()> {
        loop {
            sleep(Duration::from_secs(2)).await;
            let conn = match self
                .giganto_endpoint
                .connect(self.giganto_server, &self.giganto_info.name)
                .context("failed to connect Giganto")?
                .await
            {
                Ok(r) => r,
                Err(quinn::ConnectionError::TimedOut) => {
                    info!("server timeout, reconnecting...");
                    tokio::time::sleep(Duration::from_secs(INTERVAL)).await;
                    continue;
                }
                Err(e) => panic!("{}", e),
            };

            client_handshake(&conn, GIGANTO_VERSION).await?;

            let (giganto_send, giganto_recv) = conn
                .open_bi()
                .await
                .context("failed to open stream to Giganto")?;
            let finish_checker_send = Arc::new(AtomicBool::new(false));
            let finish_checker_recv = finish_checker_send.clone();

            tokio::spawn(async move { recv_ack(giganto_recv, finish_checker_recv).await });

            self.giganto_conn = conn;
            self.giganto_sender = giganto_send;
            self.init_msg = true;
            self.finish_checker = finish_checker_send;

            return Ok(());
        }
    }
}

fn init_giganto(certs_toml: &str) -> Result<Endpoint> {
    let mut cfg_str = String::new();
    if let Err(e) =
        File::open(Path::new(certs_toml)).and_then(|mut f| f.read_to_string(&mut cfg_str))
    {
        bail!("failed to open cert file{:?}", e);
    }
    let config = match toml::from_str::<Config>(&cfg_str) {
        Ok(r) => r,
        Err(e) => {
            bail!("failed to parse config file. {:?}", e);
        }
    };

    let Ok((cert,key)) = fs::read(&config.certification.cert)
        .and_then(|x| Ok((x, fs::read(&config.certification.key)?))) else {
             bail!(
                 "failed to read (cert, key) file. cert_path:{}, key_path:{}",
                 &config.certification.cert,
                 &config.certification.key
             );
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
                    bail!("no private key found");
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
        let file = fs::read(root).expect("failed to read file");
        let root_cert: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &*file)
            .expect("invalid PEM-encoded certificate")
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        if let Some(cert) = root_cert.get(0) {
            server_root.add(cert).expect("failed to add cert");
        }
    }

    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(server_root)
        .with_client_auth_cert(cert_chain, pv_key)
        .expect("the server root, cert chain or private key are not valid");

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(INTERVAL)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("failed to parse Endpoint addr"))
            .expect("failed to create endpoint");
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

async fn recv_ack(mut recv: RecvStream, finish_checker: Arc<AtomicBool>) -> Result<()> {
    loop {
        match receive_ack_timestamp(&mut recv).await {
            Ok(timestamp) => {
                if timestamp == CHANNEL_CLOSE_TIMESTAMP {
                    finish_checker.store(true, Ordering::SeqCst);
                    info!("finish ACK: {timestamp}");
                } else {
                    info!("ACK: {timestamp}");
                }
            }
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly)) => {
                warn!("finished early");
                break;
            }
            Err(e) => bail!("receive ACK err: {}", e),
        }
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
