#![allow(clippy::struct_field_names)]
use crate::{
    migration::TryFromGigantoRecord,
    netflow::{NetflowHeader, ParseNetflowDatasets, PktBuf, ProcessStats, Stats, TemplatesBox},
    operation_log,
    security_log::{
        Aiwaf, Axgate, Fgt, Mf2, Nginx, ParseSecurityLog, SecurityLogInfo, ShadowWall, SniperIps,
        SonicWall, Srx, Tg, Ubuntu, Vforce, Wapples,
    },
    syslog::TryFromSysmonRecord,
    zeek::TryFromZeekRecord,
};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use csv::{Position, StringRecord, StringRecordsIntoIter};
use giganto_client::{
    connection::client_handshake,
    frame::{send_raw, RecvError, SendError},
    ingest::{
        log::Log,
        netflow::{Netflow5, Netflow9},
        network::{
            Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
        },
        receive_ack_timestamp, send_record_header,
        sysmon::{
            DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
            FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
            ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
        },
    },
    RawEventKind,
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use serde::{Deserialize, Serialize};
use std::{
    env,
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

const CHANNEL_CLOSE_COUNT: u8 = 150;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const GIGANTO_VERSION: &str = "0.15.1";
const INTERVAL: u64 = 5;
const BATCH_SIZE: usize = 100;

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
                            .migration::<Conn>(iter, RawEventKind::Conn, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Conn>(iter, RawEventKind::Conn, from, grow, running)
                            .await?;
                    }
                }
                "http" => {
                    if migration {
                        giganto
                            .migration::<Http>(iter, RawEventKind::Http, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Http>(iter, RawEventKind::Http, from, grow, running)
                            .await?;
                    }
                }
                "rdp" => {
                    if migration {
                        giganto
                            .migration::<Rdp>(iter, RawEventKind::Rdp, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Rdp>(iter, RawEventKind::Rdp, from, grow, running)
                            .await?;
                    }
                }
                "smtp" => {
                    if migration {
                        giganto
                            .migration::<Smtp>(iter, RawEventKind::Smtp, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Smtp>(iter, RawEventKind::Smtp, from, grow, running)
                            .await?;
                    }
                }
                "dns" => {
                    if migration {
                        giganto
                            .migration::<Dns>(iter, RawEventKind::Dns, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Dns>(iter, RawEventKind::Dns, from, grow, running)
                            .await?;
                    }
                }
                "ntlm" => {
                    if migration {
                        giganto
                            .migration::<Ntlm>(iter, RawEventKind::Ntlm, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Ntlm>(iter, RawEventKind::Ntlm, from, grow, running)
                            .await?;
                    }
                }
                "kerberos" => {
                    if migration {
                        giganto
                            .migration::<Kerberos>(
                                iter,
                                RawEventKind::Kerberos,
                                from,
                                grow,
                                running,
                            )
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Kerberos>(
                                iter,
                                RawEventKind::Kerberos,
                                from,
                                grow,
                                running,
                            )
                            .await?;
                    }
                }
                "ssh" => {
                    if migration {
                        giganto
                            .migration::<Ssh>(iter, RawEventKind::Ssh, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Ssh>(iter, RawEventKind::Ssh, from, grow, running)
                            .await?;
                    }
                }
                "dce_rpc" => {
                    if migration {
                        giganto
                            .migration::<DceRpc>(iter, RawEventKind::DceRpc, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<DceRpc>(iter, RawEventKind::DceRpc, from, grow, running)
                            .await?;
                    }
                }
                "ftp" => {
                    if migration {
                        giganto
                            .migration::<Ftp>(iter, RawEventKind::Ftp, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Ftp>(iter, RawEventKind::Ftp, from, grow, running)
                            .await?;
                    }
                }
                "mqtt" => {
                    if migration {
                        giganto
                            .migration::<Mqtt>(iter, RawEventKind::Mqtt, from, grow, running)
                            .await?;
                    } else {
                        bail!("mqtt's zeek is not supported".to_string());
                    }
                }
                "ldap" => {
                    if migration {
                        giganto
                            .migration::<Ldap>(iter, RawEventKind::Ldap, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Ldap>(iter, RawEventKind::Ldap, from, grow, running)
                            .await?;
                    }
                }
                "tls" => {
                    if migration {
                        giganto
                            .migration::<Tls>(iter, RawEventKind::Tls, from, grow, running)
                            .await?;
                    } else {
                        giganto
                            .send_zeek::<Tls>(iter, RawEventKind::Tls, from, grow, running)
                            .await?;
                    }
                }
                "smb" => {
                    if migration {
                        giganto
                            .migration::<Smb>(iter, RawEventKind::Smb, from, grow, running)
                            .await?;
                    } else {
                        bail!("smb's zeek is not supported".to_string());
                    }
                }
                "nfs" => {
                    if migration {
                        giganto
                            .migration::<Nfs>(iter, RawEventKind::Nfs, from, grow, running)
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

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    #[allow(clippy::too_many_lines)]
    pub async fn send_sysmon_to_giganto(
        &mut self,
        iter: StringRecordsIntoIter<File>,
        from: u64,
        grow: bool,
        kind: &str,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        if let Producer::Giganto(giganto) = self {
            match kind {
                "process_create" => {
                    giganto
                        .send_sysmon::<ProcessCreate>(
                            iter,
                            RawEventKind::ProcessCreate,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "file_create_time" => {
                    giganto
                        .send_sysmon::<FileCreationTimeChanged>(
                            iter,
                            RawEventKind::FileCreateTime,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "network_connect" => {
                    giganto
                        .send_sysmon::<NetworkConnection>(
                            iter,
                            RawEventKind::NetworkConnect,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "process_terminate" => {
                    giganto
                        .send_sysmon::<ProcessTerminated>(
                            iter,
                            RawEventKind::ProcessTerminate,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "image_load" => {
                    giganto
                        .send_sysmon::<ImageLoaded>(
                            iter,
                            RawEventKind::ImageLoad,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "file_create" => {
                    giganto
                        .send_sysmon::<FileCreate>(
                            iter,
                            RawEventKind::FileCreate,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "registry_value_set" => {
                    giganto
                        .send_sysmon::<RegistryValueSet>(
                            iter,
                            RawEventKind::RegistryValueSet,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "registry_key_rename" => {
                    giganto
                        .send_sysmon::<RegistryKeyValueRename>(
                            iter,
                            RawEventKind::RegistryKeyRename,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "file_create_stream_hash" => {
                    giganto
                        .send_sysmon::<FileCreateStreamHash>(
                            iter,
                            RawEventKind::FileCreateStreamHash,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "pipe_event" => {
                    giganto
                        .send_sysmon::<PipeEvent>(
                            iter,
                            RawEventKind::PipeEvent,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "dns_query" => {
                    giganto
                        .send_sysmon::<DnsEvent>(iter, RawEventKind::DnsQuery, from, grow, running)
                        .await?;
                }
                "file_delete" => {
                    giganto
                        .send_sysmon::<FileDelete>(
                            iter,
                            RawEventKind::FileDelete,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "process_tamper" => {
                    giganto
                        .send_sysmon::<ProcessTampering>(
                            iter,
                            RawEventKind::ProcessTamper,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                "file_delete_detected" => {
                    giganto
                        .send_sysmon::<FileDeleteDetected>(
                            iter,
                            RawEventKind::FileDeleteDetected,
                            from,
                            grow,
                            running,
                        )
                        .await?;
                }
                _ => error!("unknown sysmon kind"),
            }
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if it failed to parse netflow pcap.
    pub async fn send_netflow_to_giganto(
        &mut self,
        filename: &Path,
        from: u64,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        if let Producer::Giganto(giganto) = self {
            match giganto.giganto_info.kind.as_str() {
                "netflow5" => {
                    giganto
                        .send_netflow::<Netflow5>(RawEventKind::Netflow5, filename, from, running)
                        .await?;
                }
                "netflow9" => {
                    giganto
                        .send_netflow::<Netflow9>(RawEventKind::Netflow9, filename, from, running)
                        .await?;
                }
                _ => error!("unknown netflow version"),
            }
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    #[allow(clippy::too_many_lines)]
    pub async fn send_seculog_to_giganto(
        &mut self,
        reader: BufReader<File>,
        grow: bool,
        from: u64,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        if let Producer::Giganto(giganto) = self {
            match giganto.giganto_info.kind.as_str() {
                "wapples_fw_6.0" => {
                    giganto
                        .send_seculog::<Wapples>(reader, grow, from, running)
                        .await?;
                }
                "mf2_ips_4.0" => {
                    giganto
                        .send_seculog::<Mf2>(reader, grow, from, running)
                        .await?;
                }
                "sniper_ips_8.0" => {
                    giganto
                        .send_seculog::<SniperIps>(reader, grow, from, running)
                        .await?;
                }
                "aiwaf_waf_4.1" => {
                    giganto
                        .send_seculog::<Aiwaf>(reader, grow, from, running)
                        .await?;
                }
                "tg_ips_2.7" => {
                    giganto
                        .send_seculog::<Tg>(reader, grow, from, running)
                        .await?;
                }
                "vforce_ips_4.6" => {
                    giganto
                        .send_seculog::<Vforce>(reader, grow, from, running)
                        .await?;
                }
                "srx_ips_15.1" => {
                    giganto
                        .send_seculog::<Srx>(reader, grow, from, running)
                        .await?;
                }
                "sonicwall_fw_6.5" => {
                    giganto
                        .send_seculog::<SonicWall>(reader, grow, from, running)
                        .await?;
                }
                "fgt_ips_6.2" => {
                    giganto
                        .send_seculog::<Fgt>(reader, grow, from, running)
                        .await?;
                }
                "shadowwall_ips_5.0" => {
                    giganto
                        .send_seculog::<ShadowWall>(reader, grow, from, running)
                        .await?;
                }
                "axgate_fw_2.1" => {
                    giganto
                        .send_seculog::<Axgate>(reader, grow, from, running)
                        .await?;
                }
                "ubuntu_syslog_20.04" => {
                    giganto
                        .send_seculog::<Ubuntu>(reader, grow, from, running)
                        .await?;
                }
                "nginx_accesslog_1.25.2" => {
                    giganto
                        .send_seculog::<Nginx>(reader, grow, from, running)
                        .await?;
                }
                _ => error!("invalid security log kind"),
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
        protocol: RawEventKind,
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
        let mut buf = Vec::new();

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

                                let record_data = bincode::serialize(&event)?;
                                buf.push((timestamp, record_data));
                                if buf.len() >= BATCH_SIZE {
                                    match self.send_event_in_batch(&buf).await {
                                        Err(SendError::WriteError(_)) => {
                                            self.reconnect().await?;
                                            continue;
                                        }
                                        Err(e) => {
                                            bail!("{e:?}");
                                        }
                                        Ok(()) => {}
                                    }
                                    buf.clear();
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

        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
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
        protocol: RawEventKind,
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
        let mut buf = Vec::new();

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

                                let record_data = bincode::serialize(&event)?;
                                buf.push((timestamp, record_data));
                                if buf.len() >= BATCH_SIZE {
                                    match self.send_event_in_batch(&buf).await {
                                        Err(SendError::WriteError(_)) => {
                                            self.reconnect().await?;
                                            continue;
                                        }
                                        Err(e) => {
                                            bail!("{e:?}");
                                        }
                                        Ok(()) => {}
                                    }
                                    buf.clear();
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

        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
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
        info!("send oplog");
        let mut lines = reader.lines();
        let mut cnt = 0;
        let mut success_cnt = 0u32;
        let mut failed_cnt = 0u32;
        let mut buf = Vec::new();

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
                    send_record_header(&mut self.giganto_sender, RawEventKind::OpLog).await?;
                    self.init_msg = false;
                }

                let record_data = bincode::serialize(&oplog_data)?;
                buf.push((timestamp, record_data));
                if buf.len() >= BATCH_SIZE {
                    match self.send_event_in_batch(&buf).await {
                        Err(SendError::WriteError(_)) => {
                            self.reconnect().await?;
                        }
                        Err(e) => {
                            bail!("{e:?}");
                        }
                        Ok(()) => {}
                    }
                    buf.clear();
                }
            } else {
                if grow {
                    tokio::time::sleep(Duration::from_millis(3_000)).await;
                    continue;
                }
                break;
            }
        }

        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
        }

        info!(
            "last line: {}, success: {}, failed: {}",
            cnt, success_cnt, failed_cnt
        );

        Ok(())
    }

    async fn send_sysmon<T>(
        &mut self,
        mut sysmon_iter: StringRecordsIntoIter<File>,
        protocol: RawEventKind,
        from: u64,
        grow: bool,
        running: Arc<AtomicBool>,
    ) -> Result<()>
    where
        T: Serialize + TryFromSysmonRecord + Unpin + Debug,
    {
        info!("send sysmon, {protocol:?}");
        let mut success_cnt = 0u32;
        let mut failed_cnt = 0u32;
        let mut pos = Position::new();
        let mut last_record = StringRecord::new();
        let mut time_serial = 0_i64;
        let mut buf = Vec::new();

        while running.load(Ordering::SeqCst) {
            let next_pos = sysmon_iter.reader().position().clone();
            if let Some(result) = sysmon_iter.next() {
                if next_pos.line() < from {
                    continue;
                }
                match result {
                    Ok(record) if record != last_record => {
                        last_record = record.clone();
                        time_serial += 1;
                        if time_serial > 999 {
                            time_serial = 1;
                        }
                        match T::try_from_sysmon_record(&record, time_serial) {
                            Ok((event, timestamp)) => {
                                if self.init_msg {
                                    send_record_header(&mut self.giganto_sender, protocol).await?;
                                    self.init_msg = false;
                                }

                                let record_data = bincode::serialize(&event)?;
                                buf.push((timestamp, record_data));
                                if buf.len() >= BATCH_SIZE {
                                    match self.send_event_in_batch(&buf).await {
                                        Err(SendError::WriteError(_)) => {
                                            self.reconnect().await?;
                                            continue;
                                        }
                                        Err(e) => {
                                            bail!("{e:?}");
                                        }
                                        Ok(()) => {}
                                    }
                                    buf.clear();
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
                    sysmon_iter.reader_mut().seek(pos.clone())?;
                    sysmon_iter = sysmon_iter.into_reader().into_records();
                    continue;
                }
                break;
            }
            pos = next_pos;
        }

        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
        }

        self.init_msg = true;
        info!(
            "last line: {}, success line: {}, failed line: {} ",
            pos.line(),
            success_cnt,
            failed_cnt
        );

        Ok(())
    }

    async fn send_netflow<T>(
        &mut self,
        protocol: RawEventKind,
        filename: &Path,
        from: u64,
        running: Arc<AtomicBool>,
    ) -> Result<()>
    where
        T: Serialize + ParseNetflowDatasets + Unpin + Debug,
    {
        info!("send netflow");
        let tmpl_path = env::var("NETFLOW_TEMPLATES_PATH");
        let mut templates = if let Ok(tmpl_path) = tmpl_path.as_ref() {
            TemplatesBox::from_path(tmpl_path).unwrap_or_default()
        } else {
            TemplatesBox::new()
        };
        let mut handle = pcap::Capture::from_file(filename)?;
        if handle.get_datalink() != pcap::Linktype::ETHERNET {
            bail!(
                "Error: unknown datalink {:?} in {:?}",
                handle.get_datalink().get_name(),
                filename
            );
        }

        let mut stats = Stats::new();
        let mut pkt_cnt = 0_u64;
        let mut timestamp_old = 0_u32;
        let mut nanos = 1_u32;
        let mut buf = Vec::new();

        while let Ok(pkt) = handle.next_packet() {
            pkt_cnt += 1;
            if from > pkt_cnt {
                continue;
            }

            let mut input = PktBuf::new(&pkt);
            let rst = input.is_netflow();
            stats.add(rst, 1);
            if rst != ProcessStats::YesNetflowPackets {
                continue;
            }

            let Ok(header) = input.parse_netflow_header() else {
                stats.add(ProcessStats::InvalidNetflowPackets, 1);
                continue;
            };

            let (unix_secs, unix_nanos) = header.timestamp();
            if timestamp_old != unix_secs {
                nanos = unix_nanos;
            }
            timestamp_old = unix_secs;

            match header {
                NetflowHeader::V5(_) => stats.add(ProcessStats::NetflowV5DataPackets, 1),
                NetflowHeader::V9(_) => stats.add(ProcessStats::NetflowV9DataPackets, 1),
            }
            let events = T::parse_netflow_datasets(
                pkt_cnt,
                &mut templates,
                &header,
                &mut nanos,
                &mut input,
                &mut stats,
            )?;
            if self.init_msg {
                send_record_header(&mut self.giganto_sender, protocol).await?;
                self.init_msg = false;
            }
            for (timestamp, event) in events {
                let record_data = bincode::serialize(&event)?;
                buf.push((timestamp, record_data));
                if buf.len() >= BATCH_SIZE {
                    match self.send_event_in_batch(&buf).await {
                        Err(SendError::WriteError(_)) => {
                            self.reconnect().await?;
                            continue;
                        }
                        Err(e) => {
                            bail!("{e:?}");
                        }
                        Ok(()) => {}
                    }
                    buf.clear();
                }
            }

            if !buf.is_empty() {
                self.send_event_in_batch(&buf).await?;
                buf.clear();
            }

            if !running.load(Ordering::SeqCst) {
                break;
            }
        }
        stats.add(
            ProcessStats::Packets,
            pkt_cnt.try_into().unwrap_or_default(),
        );
        info!("netflow pcap processing statistics: {:?}", stats);
        if !templates.is_empty() {
            if let Ok(tmpl_path) = tmpl_path.as_ref() {
                if let Err(e) = templates.save(tmpl_path) {
                    error!("{}. {}", e, tmpl_path);
                }
            }
        }
        Ok(())
    }

    async fn send_seculog<T>(
        &mut self,
        reader: BufReader<File>,
        grow: bool,
        from: u64,
        running: Arc<AtomicBool>,
    ) -> Result<()>
    where
        T: Serialize + ParseSecurityLog + Unpin + Debug,
    {
        info!("send seculog");
        let mut lines = reader.lines();
        let mut cnt = 0;
        let mut success_cnt = 0u32;
        let mut failed_cnt = 0u32;
        let mut time_serial = 0_i64;
        let mut buf = Vec::new();
        while running.load(Ordering::SeqCst) {
            if let Some(Ok(line)) = lines.next() {
                cnt += 1;
                time_serial += 1;
                if time_serial > 999 {
                    time_serial = 1;
                }
                if cnt < from {
                    continue;
                }
                let (seculog_data, timestamp) = if let Ok(r) = T::parse_security_log(
                    &line,
                    time_serial,
                    SecurityLogInfo::new(&self.giganto_info.kind),
                ) {
                    success_cnt += 1;
                    r
                } else {
                    failed_cnt += 1;
                    continue;
                };

                if self.init_msg {
                    send_record_header(&mut self.giganto_sender, RawEventKind::SecuLog).await?;
                    self.init_msg = false;
                }

                let record_data = bincode::serialize(&seculog_data)?;
                buf.push((timestamp, record_data));
                if buf.len() >= BATCH_SIZE {
                    match self.send_event_in_batch(&buf).await {
                        Err(SendError::WriteError(_)) => {
                            self.reconnect().await?;
                        }
                        Err(e) => {
                            bail!("{e:?}");
                        }
                        Ok(()) => {}
                    }
                    buf.clear();
                }
            } else {
                if grow {
                    tokio::time::sleep(Duration::from_millis(3_000)).await;
                    continue;
                }
                break;
            }
        }
        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
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
            send_record_header(&mut self.giganto_sender, RawEventKind::Log).await?;
            self.init_msg = false;
        }

        let timestamp = Utc::now()
            .timestamp_nanos_opt()
            .context("to_timestamp_nanos")?;
        let record_data = bincode::serialize(&send_log)?;
        let buf = vec![(timestamp, record_data)];

        match self.send_event_in_batch(&buf).await {
            Err(SendError::WriteError(_)) => {
                self.reconnect().await?;
            }
            Err(e) => {
                bail!("{e:?}");
            }
            Ok(()) => {}
        }
        Ok(())
    }

    async fn send_event_in_batch(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
        let buf = bincode::serialize(&events)?;
        send_raw(&mut self.giganto_sender, &buf).await
    }

    async fn send_finish(&mut self) -> Result<()> {
        let record_data = bincode::serialize(CHANNEL_CLOSE_MESSAGE)?;
        let buf = vec![(CHANNEL_CLOSE_TIMESTAMP, record_data)];
        match self.send_event_in_batch(&buf).await {
            Err(SendError::WriteError(_)) => {
                bail!("failed to send channel done message");
            }
            Err(e) => {
                bail!("{e:?}");
            }
            Ok(()) => {}
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

    let Ok((cert, key)) = fs::read(&config.certification.cert)
        .and_then(|x| Ok((x, fs::read(&config.certification.key)?)))
    else {
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
        if let Some(cert) = root_cert.first() {
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
