#![allow(clippy::struct_field_names, clippy::too_many_arguments)]
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
    Config, Report,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use csv::{Position, StringRecord, StringRecordsIntoIter};
use giganto_client::{
    connection::client_handshake,
    frame::{RecvError, SendError},
    ingest::{
        log::Log,
        netflow::{Netflow5, Netflow9},
        network::{
            Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
        },
        receive_ack_timestamp, send_event, send_record_header,
        sysmon::{
            DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
            FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
            ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
        },
    },
    RawEventKind,
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use std::{
    env,
    fmt::Debug,
    fs::{self, File},
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::sleep;
use tracing::{error, info, warn};

const CHANNEL_CLOSE_COUNT: u8 = 150;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const GIGANTO_VERSION: &str = "0.21.0-alpha.1";
const INTERVAL: u64 = 5;

#[allow(clippy::large_enum_variant)]
pub struct Producer {
    pub giganto: Giganto,
}

impl Producer {
    /// # Errors
    ///
    /// Returns an error if it fails to set up Giganto.
    ///
    ///  # Panics
    ///
    /// Connection error, not `TimedOut`
    pub async fn new_giganto(config: &Config) -> Result<Self> {
        let endpoint =
            match init_giganto(&config.common.cert, &config.common.key, &config.common.root) {
                Ok(ret) => ret,
                Err(e) => {
                    bail!("failed to create Giganto producer: {:?}", e);
                }
            };
        loop {
            let conn = match endpoint
                .connect(
                    config.common.giganto_ingest_srv_addr,
                    &config.common.giganto_name,
                )?
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
                .expect("failed to open stream to Giganto");

            let finish_checker_send = Arc::new(AtomicBool::new(false));
            let finish_checker_recv = finish_checker_send.clone();

            tokio::spawn(async move { recv_ack(giganto_recv, finish_checker_recv).await });

            return Ok(Self {
                giganto: Giganto {
                    giganto_endpoint: endpoint.clone(),
                    giganto_server: config.common.giganto_ingest_srv_addr,
                    giganto_info: GigantoInfo {
                        name: config.common.giganto_name.clone(),
                        kind: config.common.kind.clone(),
                    },
                    giganto_conn: conn,
                    giganto_sender: giganto_send,
                    init_msg: true,
                    finish_checker: finish_checker_send,
                },
            });
        }
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    #[allow(clippy::too_many_lines)]
    pub async fn send_raw_to_giganto(
        &mut self,
        iter: StringRecordsIntoIter<File>,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        migration: Option<bool>,
        running: Arc<AtomicBool>,
    ) -> Result<u64> {
        let Some(migration) = migration else {
            bail!("export_from_giganto parameter is required");
        };
        match self.giganto.giganto_info.kind.as_str() {
            "conn" => {
                if migration {
                    self.giganto
                        .migration::<Conn>(
                            iter,
                            RawEventKind::Conn,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Conn>(
                            iter,
                            RawEventKind::Conn,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "http" => {
                if migration {
                    self.giganto
                        .migration::<Http>(
                            iter,
                            RawEventKind::Http,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Http>(
                            iter,
                            RawEventKind::Http,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "rdp" => {
                if migration {
                    self.giganto
                        .migration::<Rdp>(
                            iter,
                            RawEventKind::Rdp,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Rdp>(
                            iter,
                            RawEventKind::Rdp,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "smtp" => {
                if migration {
                    self.giganto
                        .migration::<Smtp>(
                            iter,
                            RawEventKind::Smtp,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Smtp>(
                            iter,
                            RawEventKind::Smtp,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "dns" => {
                if migration {
                    self.giganto
                        .migration::<Dns>(
                            iter,
                            RawEventKind::Dns,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Dns>(
                            iter,
                            RawEventKind::Dns,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "ntlm" => {
                if migration {
                    self.giganto
                        .migration::<Ntlm>(
                            iter,
                            RawEventKind::Ntlm,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Ntlm>(
                            iter,
                            RawEventKind::Ntlm,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "kerberos" => {
                if migration {
                    self.giganto
                        .migration::<Kerberos>(
                            iter,
                            RawEventKind::Kerberos,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Kerberos>(
                            iter,
                            RawEventKind::Kerberos,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "ssh" => {
                if migration {
                    self.giganto
                        .migration::<Ssh>(
                            iter,
                            RawEventKind::Ssh,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Ssh>(
                            iter,
                            RawEventKind::Ssh,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "dce_rpc" => {
                if migration {
                    self.giganto
                        .migration::<DceRpc>(
                            iter,
                            RawEventKind::DceRpc,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<DceRpc>(
                            iter,
                            RawEventKind::DceRpc,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "ftp" => {
                if migration {
                    self.giganto
                        .migration::<Ftp>(
                            iter,
                            RawEventKind::Ftp,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Ftp>(
                            iter,
                            RawEventKind::Ftp,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "mqtt" => {
                if migration {
                    self.giganto
                        .migration::<Mqtt>(
                            iter,
                            RawEventKind::Mqtt,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    bail!("mqtt's zeek is not supported".to_string());
                }
            }
            "ldap" => {
                if migration {
                    self.giganto
                        .migration::<Ldap>(
                            iter,
                            RawEventKind::Ldap,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Ldap>(
                            iter,
                            RawEventKind::Ldap,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "tls" => {
                if migration {
                    self.giganto
                        .migration::<Tls>(
                            iter,
                            RawEventKind::Tls,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    self.giganto
                        .send_zeek::<Tls>(
                            iter,
                            RawEventKind::Tls,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                }
            }
            "smb" => {
                if migration {
                    self.giganto
                        .migration::<Smb>(
                            iter,
                            RawEventKind::Smb,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    bail!("smb's zeek is not supported".to_string());
                }
            }
            "nfs" => {
                if migration {
                    self.giganto
                        .migration::<Nfs>(
                            iter,
                            RawEventKind::Nfs,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                        )
                        .await
                } else {
                    bail!("nfs's zeek is not supported".to_string());
                }
            }
            _ => bail!("unknown zeek/migration kind"),
        }
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    pub async fn send_oplog_to_giganto(
        &mut self,
        reader: BufReader<File>,
        agent: &str,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> Result<u64> {
        self.giganto
            .send_oplog(
                reader,
                agent,
                file_polling_mode,
                dir_polling_mode,
                skip,
                count_sent,
                running,
            )
            .await
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    #[allow(clippy::too_many_lines)]
    pub async fn send_sysmon_to_giganto(
        &mut self,
        iter: StringRecordsIntoIter<File>,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        kind: &str,
        running: Arc<AtomicBool>,
    ) -> Result<u64> {
        match kind {
            "process_create" => {
                self.giganto
                    .send_sysmon::<ProcessCreate>(
                        iter,
                        RawEventKind::ProcessCreate,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "file_create_time" => {
                self.giganto
                    .send_sysmon::<FileCreationTimeChanged>(
                        iter,
                        RawEventKind::FileCreateTime,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "network_connect" => {
                self.giganto
                    .send_sysmon::<NetworkConnection>(
                        iter,
                        RawEventKind::NetworkConnect,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "process_terminate" => {
                self.giganto
                    .send_sysmon::<ProcessTerminated>(
                        iter,
                        RawEventKind::ProcessTerminate,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "image_load" => {
                self.giganto
                    .send_sysmon::<ImageLoaded>(
                        iter,
                        RawEventKind::ImageLoad,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "file_create" => {
                self.giganto
                    .send_sysmon::<FileCreate>(
                        iter,
                        RawEventKind::FileCreate,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "registry_value_set" => {
                self.giganto
                    .send_sysmon::<RegistryValueSet>(
                        iter,
                        RawEventKind::RegistryValueSet,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "registry_key_rename" => {
                self.giganto
                    .send_sysmon::<RegistryKeyValueRename>(
                        iter,
                        RawEventKind::RegistryKeyRename,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "file_create_stream_hash" => {
                self.giganto
                    .send_sysmon::<FileCreateStreamHash>(
                        iter,
                        RawEventKind::FileCreateStreamHash,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "pipe_event" => {
                self.giganto
                    .send_sysmon::<PipeEvent>(
                        iter,
                        RawEventKind::PipeEvent,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "dns_query" => {
                self.giganto
                    .send_sysmon::<DnsEvent>(
                        iter,
                        RawEventKind::DnsQuery,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "file_delete" => {
                self.giganto
                    .send_sysmon::<FileDelete>(
                        iter,
                        RawEventKind::FileDelete,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "process_tamper" => {
                self.giganto
                    .send_sysmon::<ProcessTampering>(
                        iter,
                        RawEventKind::ProcessTamper,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            "file_delete_detected" => {
                self.giganto
                    .send_sysmon::<FileDeleteDetected>(
                        iter,
                        RawEventKind::FileDeleteDetected,
                        skip,
                        count_sent,
                        file_polling_mode,
                        dir_polling_mode,
                        running,
                    )
                    .await
            }
            _ => bail!("unknown sysmon kind"),
        }
    }

    /// # Errors
    ///
    /// Returns an error if it failed to parse netflow pcap.
    pub async fn send_netflow_to_giganto(
        &mut self,
        filename: &Path,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> Result<u64> {
        match self.giganto.giganto_info.kind.as_str() {
            "netflow5" => {
                self.giganto
                    .send_netflow::<Netflow5>(
                        RawEventKind::Netflow5,
                        filename,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "netflow9" => {
                self.giganto
                    .send_netflow::<Netflow9>(
                        RawEventKind::Netflow9,
                        filename,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            _ => bail!("unknown netflow version"),
        }
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    #[allow(clippy::too_many_lines)]
    pub async fn send_seculog_to_giganto(
        &mut self,
        reader: BufReader<File>,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> Result<u64> {
        match self.giganto.giganto_info.kind.as_str() {
            "wapples_fw_6.0" => {
                self.giganto
                    .send_seculog::<Wapples>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "mf2_ips_4.0" => {
                self.giganto
                    .send_seculog::<Mf2>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "sniper_ips_8.0" => {
                self.giganto
                    .send_seculog::<SniperIps>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "aiwaf_waf_4.1" => {
                self.giganto
                    .send_seculog::<Aiwaf>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "tg_ips_2.7" => {
                self.giganto
                    .send_seculog::<Tg>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "vforce_ips_4.6" => {
                self.giganto
                    .send_seculog::<Vforce>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "srx_ips_15.1" => {
                self.giganto
                    .send_seculog::<Srx>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "sonicwall_fw_6.5" => {
                self.giganto
                    .send_seculog::<SonicWall>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "fgt_ips_6.2" => {
                self.giganto
                    .send_seculog::<Fgt>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "shadowwall_ips_5.0" => {
                self.giganto
                    .send_seculog::<ShadowWall>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "axgate_fw_2.1" => {
                self.giganto
                    .send_seculog::<Axgate>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "ubuntu_syslog_20.04" => {
                self.giganto
                    .send_seculog::<Ubuntu>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            "nginx_accesslog_1.25.2" => {
                self.giganto
                    .send_seculog::<Nginx>(
                        reader,
                        file_polling_mode,
                        dir_polling_mode,
                        skip,
                        count_sent,
                        running,
                    )
                    .await
            }
            _ => bail!("invalid security log kind"),
        }
    }

    /// # Errors
    ///
    /// Returns an error if any writing log fails.
    pub async fn send_log_to_giganto(
        &mut self,
        file_name: &Path,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        skip: u64,
        count_sent: u64,
        report: &mut Report,
        running: Arc<AtomicBool>,
    ) -> Result<u64> {
        self.giganto
            .send_log(
                file_name,
                file_polling_mode,
                dir_polling_mode,
                skip,
                count_sent,
                report,
                running,
            )
            .await
    }
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
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        running: Arc<AtomicBool>,
    ) -> Result<u64>
    where
        T: Serialize + TryFromZeekRecord + Unpin + Debug,
    {
        info!("send zeek");
        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        let mut pos = Position::new();
        let mut last_record = StringRecord::new();
        while running.load(Ordering::SeqCst) {
            let next_pos = zeek_iter.reader().position().clone();
            if let Some(result) = zeek_iter.next() {
                if next_pos.line() <= skip {
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
                                    Ok(()) => {}
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
                pos = next_pos;
                if count_sent != 0 && success_cnt >= count_sent {
                    break;
                }
            } else {
                if file_polling_mode && !dir_polling_mode {
                    tokio::time::sleep(Duration::from_millis(3_000)).await;
                    zeek_iter.reader_mut().seek(pos.clone())?;
                    zeek_iter = zeek_iter.into_reader().into_records();
                    continue;
                }
                break;
            }
        }

        info!(
            "last line: {}, success line: {}, failed line: {} ",
            pos.line(),
            success_cnt,
            failed_cnt
        );

        Ok(pos.line())
    }

    async fn migration<T>(
        &mut self,
        mut giganto_iter: StringRecordsIntoIter<File>,
        protocol: RawEventKind,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        running: Arc<AtomicBool>,
    ) -> Result<u64>
    where
        T: Serialize + TryFromGigantoRecord + Unpin + Debug,
    {
        info!("migration");
        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        let mut pos = Position::new();
        let mut last_record = StringRecord::new();
        while running.load(Ordering::SeqCst) {
            let next_pos = giganto_iter.reader().position().clone();
            if let Some(result) = giganto_iter.next() {
                if next_pos.line() <= skip {
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
                                    Ok(()) => {}
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
                pos = next_pos;
                if count_sent != 0 && success_cnt >= count_sent {
                    break;
                }
            } else {
                if file_polling_mode && !dir_polling_mode {
                    tokio::time::sleep(Duration::from_millis(3_000)).await;
                    giganto_iter.reader_mut().seek(pos.clone())?;
                    giganto_iter = giganto_iter.into_reader().into_records();
                    continue;
                }
                break;
            }
        }

        info!(
            "last line: {}, success line: {}, failed line: {} ",
            pos.line(),
            success_cnt,
            failed_cnt
        );
        Ok(pos.line())
    }

    async fn send_oplog(
        &mut self,
        reader: BufReader<File>,
        agent: &str,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> Result<u64> {
        info!("send oplog");
        let mut lines = reader.lines();
        let mut cnt = 0;
        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        while running.load(Ordering::SeqCst) {
            if let Some(Ok(line)) = lines.next() {
                cnt += 1;
                if cnt <= skip {
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

                match send_event(&mut self.giganto_sender, timestamp, oplog_data).await {
                    Err(SendError::WriteError(_)) => {
                        self.reconnect().await?;
                    }
                    Err(e) => {
                        bail!("{e:?}");
                    }
                    Ok(()) => {}
                }
                if count_sent != 0 && success_cnt >= count_sent {
                    break;
                }
            } else {
                if file_polling_mode && !dir_polling_mode {
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

        Ok(cnt)
    }

    async fn send_sysmon<T>(
        &mut self,
        mut sysmon_iter: StringRecordsIntoIter<File>,
        protocol: RawEventKind,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        running: Arc<AtomicBool>,
    ) -> Result<u64>
    where
        T: Serialize + TryFromSysmonRecord + Unpin + Debug,
    {
        info!("send sysmon, {protocol:?}");
        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        let mut pos = Position::new();
        let mut last_record = StringRecord::new();
        let mut time_serial = 0_i64;
        while running.load(Ordering::SeqCst) {
            let next_pos = sysmon_iter.reader().position().clone();
            if let Some(result) = sysmon_iter.next() {
                if next_pos.line() <= skip {
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
                                match send_event(&mut self.giganto_sender, timestamp, event).await {
                                    Err(SendError::WriteError(_)) => {
                                        self.reconnect().await?;
                                        continue;
                                    }
                                    Err(e) => {
                                        bail!("{e:?}");
                                    }
                                    Ok(()) => {}
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
                pos = next_pos;
                if count_sent != 0 && success_cnt >= count_sent {
                    break;
                }
            } else {
                if file_polling_mode && !dir_polling_mode {
                    tokio::time::sleep(Duration::from_millis(3_000)).await;
                    sysmon_iter.reader_mut().seek(pos.clone())?;
                    sysmon_iter = sysmon_iter.into_reader().into_records();
                    continue;
                }
                break;
            }
        }

        self.init_msg = true;
        info!(
            "last line: {}, success line: {}, failed line: {} ",
            pos.line(),
            success_cnt,
            failed_cnt
        );

        Ok(pos.line())
    }

    async fn send_netflow<T>(
        &mut self,
        protocol: RawEventKind,
        filename: &Path,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> Result<u64>
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

        while let Ok(pkt) = handle.next_packet() {
            pkt_cnt += 1;
            if skip >= pkt_cnt {
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
                match send_event(&mut self.giganto_sender, timestamp, event).await {
                    Err(SendError::WriteError(_)) => {
                        self.reconnect().await?;
                        continue;
                    }
                    Err(e) => {
                        bail!("{e:?}");
                    }
                    Ok(()) => {}
                }
            }

            if count_sent != 0 && pkt_cnt >= count_sent {
                break;
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
        Ok(pkt_cnt)
    }

    async fn send_seculog<T>(
        &mut self,
        reader: BufReader<File>,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
    ) -> Result<u64>
    where
        T: Serialize + ParseSecurityLog + Unpin + Debug,
    {
        info!("send seculog");
        let mut lines = reader.lines();
        let mut cnt = 0;
        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        let mut time_serial = 0_i64;
        while running.load(Ordering::SeqCst) {
            if let Some(Ok(line)) = lines.next() {
                cnt += 1;
                time_serial += 1;
                if time_serial > 999 {
                    time_serial = 1;
                }
                if cnt <= skip {
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

                match send_event(&mut self.giganto_sender, timestamp, seculog_data).await {
                    Err(SendError::WriteError(_)) => {
                        self.reconnect().await?;
                    }
                    Err(e) => {
                        bail!("{e:?}");
                    }
                    Ok(()) => {}
                }

                if count_sent != 0 && success_cnt >= count_sent {
                    break;
                }
            } else {
                if file_polling_mode && !dir_polling_mode {
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

        Ok(cnt)
    }

    async fn send_log(
        &mut self,
        file_name: &Path,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        skip: u64,
        count_sent: u64,
        report: &mut Report,
        running: Arc<AtomicBool>,
    ) -> Result<u64> {
        let log_file = open_log(file_name).map_err(|e| anyhow!("failed to open: {}", e))?;
        let mut lines = BinaryLines::new(BufReader::new(log_file)).skip(usize::try_from(skip)?);
        let mut giganto_msg: Vec<u8> = Vec::new();
        let mut conv_cnt = 0;
        report.start();
        while running.load(Ordering::SeqCst) {
            let line = match lines.next() {
                Some(Ok(line)) => {
                    if line.is_empty() {
                        continue;
                    }
                    line
                }
                Some(Err(e)) => {
                    error!("failed to convert input data: {e}");
                    break;
                }
                None => {
                    if file_polling_mode && !dir_polling_mode {
                        tokio::time::sleep(Duration::from_millis(3_000)).await;
                        continue;
                    }
                    break;
                }
            };

            giganto_msg.extend(&line);
            self.send(giganto_msg.as_slice())
                .await
                .context("failed to to send message to Giganto")?;
            giganto_msg.clear();
            conv_cnt += 1;
            report.process(line.len());
            if count_sent != 0 && conv_cnt >= count_sent {
                break;
            }
        }
        if let Err(e) = report.end() {
            warn!("cannot write report: {e}");
        }
        Ok(conv_cnt + skip)
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

        match send_event(
            &mut self.giganto_sender,
            Utc::now()
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?,
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
            Ok(()) => {}
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

fn init_giganto(cert: &str, key: &str, root: &str) -> Result<Endpoint> {
    let Ok((cert_pem, key_pem)) = fs::read(cert).and_then(|x| Ok((x, fs::read(key)?))) else {
        bail!(
            "failed to read (cert, key) file. cert_path:{}, key_path:{}",
            cert,
            key
        );
    };

    let pv_key = if Path::new(key).extension().map_or(false, |x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pem))
    } else {
        rustls_pemfile::private_key(&mut &*key_pem)
            .expect("malformed PKCS #1 private key")
            .expect("no private keys found")
    };

    let cert_chain = if Path::new(cert).extension().map_or(false, |x| x == "der") {
        vec![CertificateDer::from(cert_pem)]
    } else {
        rustls_pemfile::certs(&mut &*cert_pem)
            .collect::<Result<_, _>>()
            .expect("invalid PEM-encoded certificate")
    };

    let mut server_root = rustls::RootCertStore::empty();
    let file = fs::read(root).expect("failed to read file");
    let root_cert: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*file)
        .collect::<Result<_, _>>()
        .context("invalid PEM-encoded certificate")?;
    if let Some(cert) = root_cert.first() {
        server_root
            .add(cert.to_owned())
            .context("failed to add root cert")?;
    }

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(server_root)
        .with_client_auth_cert(cert_chain, pv_key)
        .expect("the server root, cert chain or private key are not valid");

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(INTERVAL)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("Failed to generate QuicClientConfig"),
    ));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().expect("Failed to parse Endpoint addr"))
            .expect("Failed to create endpoint");
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
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_))) => {
                warn!("finished early");
                break;
            }
            Err(e) => bail!("receive ACK err: {}", e),
        }
    }
    Ok(())
}

fn open_log<P: AsRef<Path>>(input: P) -> Result<File> {
    let log_file = File::open(input.as_ref())?;
    info!("input={:?}, input type=LOG", input.as_ref());

    Ok(log_file)
}

struct BinaryLines<B> {
    buf: B,
}

impl<B> BinaryLines<B> {
    /// Returns an iterator for binary strings separated by '\n'.
    fn new(buf: B) -> Self {
        Self { buf }
    }
}

impl<B: BufRead> Iterator for BinaryLines<B> {
    type Item = Result<Vec<u8>, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = Vec::new();
        match self.buf.read_until(b'\n', &mut buf) {
            Ok(0) => None,
            Ok(_n) => {
                if matches!(buf.last(), Some(b'\n')) {
                    buf.pop();
                    if matches!(buf.last(), Some(b'\r')) {
                        buf.pop();
                    }
                }
                Some(Ok(buf))
            }
            Err(e) => Some(Err(e)),
        }
    }
}
