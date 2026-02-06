#![allow(
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::single_match_else
)]
use std::{
    any::type_name,
    env,
    fmt::Debug,
    fs::{self, File},
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use csv::{Position, StringRecord, StringRecordsIntoIter};
use giganto_client::{
    RawEventKind,
    connection::client_handshake,
    frame::{RecvError, SendError, send_raw},
    ingest::{
        log::Log,
        netflow::{Netflow5, Netflow9},
        network::{
            Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Kerberos, Ldap, MalformedDns, Mqtt, Nfs,
            Ntlm, Radius, Rdp, Smb, Smtp, Ssh, Tls,
        },
        receive_ack_timestamp, send_record_header,
        sysmon::{
            DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
            FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
            ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
        },
    },
};
use jiff::Timestamp;
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::{
    Config, Report,
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

const CHANNEL_CLOSE_COUNT: u8 = 150;
const CHANNEL_CLOSE_MESSAGE: &[u8; 12] = b"channel done";
const CHANNEL_CLOSE_TIMESTAMP: i64 = -1;
const REQUIRED_GIGANTO_VERSION: &str = "0.26.1";
const INTERVAL: u64 = 5;
const BATCH_SIZE: usize = 100;

#[allow(clippy::large_enum_variant)]
pub(crate) struct Producer {
    pub(crate) giganto: Giganto,
}

impl Producer {
    /// # Errors
    ///
    /// Returns an error if it fails to set up Giganto.
    ///
    ///  # Panics
    ///
    /// Connection error, not `TimedOut`
    pub(crate) async fn new_giganto(config: &Config) -> Result<Self> {
        let endpoint = match init_giganto(&config.cert, &config.key, &config.ca_certs) {
            Ok(ret) => ret,
            Err(e) => {
                bail!("failed to create Giganto producer: {e:?}");
            }
        };
        loop {
            let conn = match endpoint
                .connect(config.giganto_ingest_srv_addr, &config.giganto_name)?
                .await
            {
                Ok(r) => {
                    info!(
                        "Connected to data store ingest server at {}",
                        config.giganto_ingest_srv_addr
                    );
                    r
                }
                Err(quinn::ConnectionError::TimedOut) => {
                    info!("Server timeout, reconnecting...");
                    tokio::time::sleep(Duration::from_secs(INTERVAL)).await;
                    continue;
                }
                Err(e) => panic!("{}", e),
            };

            client_handshake(&conn, REQUIRED_GIGANTO_VERSION).await?;

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
                    giganto_server: config.giganto_ingest_srv_addr,
                    giganto_info: GigantoInfo {
                        name: config.giganto_name.clone(),
                        kind: config.kind.clone(),
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
    pub(crate) async fn send_raw_to_giganto(
        &mut self,
        iter: StringRecordsIntoIter<File>,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        migration: Option<bool>,
        running: Arc<AtomicBool>,
        report: &mut Report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
                        )
                        .await
                } else {
                    bail!("mqtt zeek log is not supported".to_string());
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
                            report,
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
                            report,
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
                            report,
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
                            report,
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
                            report,
                        )
                        .await
                } else {
                    bail!("smb zeek log is not supported".to_string());
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
                            report,
                        )
                        .await
                } else {
                    bail!("nfs zeek log is not supported".to_string());
                }
            }
            "bootp" => {
                if migration {
                    self.giganto
                        .migration::<Bootp>(
                            iter,
                            RawEventKind::Bootp,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    bail!("bootp zeek log is not supported".to_string());
                }
            }
            "dhcp" => {
                if migration {
                    self.giganto
                        .migration::<Dhcp>(
                            iter,
                            RawEventKind::Dhcp,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    bail!("dhcp zeek log is not supported".to_string());
                }
            }
            "radius" => {
                if migration {
                    self.giganto
                        .migration::<Radius>(
                            iter,
                            RawEventKind::Radius,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    bail!("radius zeek log is not supported");
                }
            }
            "malformed_dns" => {
                if migration {
                    self.giganto
                        .migration::<MalformedDns>(
                            iter,
                            RawEventKind::MalformedDns,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    bail!("malformed_dns zeek log is not supported");
                }
            }
            _ => bail!("unknown zeek/migration kind"),
        }
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    pub(crate) async fn send_oplog_to_giganto(
        &mut self,
        reader: BufReader<File>,
        agent: &str,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
        report: &mut Report,
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
                report,
            )
            .await
    }

    /// # Errors
    ///
    /// Returns an error if any writing operation fails.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn send_sysmon_to_giganto(
        &mut self,
        iter: StringRecordsIntoIter<File>,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        migration: Option<bool>,
        running: Arc<AtomicBool>,
        report: &mut Report,
    ) -> Result<u64> {
        let Some(migration) = migration else {
            bail!("export_from_giganto parameter is required");
        };
        match self.giganto.giganto_info.kind.as_str() {
            "process_create" => {
                if migration {
                    self.giganto
                        .migration::<ProcessCreate>(
                            iter,
                            RawEventKind::ProcessCreate,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<ProcessCreate>(
                            iter,
                            RawEventKind::ProcessCreate,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "file_create_time" => {
                if migration {
                    self.giganto
                        .migration::<FileCreationTimeChanged>(
                            iter,
                            RawEventKind::FileCreateTime,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<FileCreationTimeChanged>(
                            iter,
                            RawEventKind::FileCreateTime,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "network_connect" => {
                if migration {
                    self.giganto
                        .migration::<NetworkConnection>(
                            iter,
                            RawEventKind::NetworkConnect,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<NetworkConnection>(
                            iter,
                            RawEventKind::NetworkConnect,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "process_terminate" => {
                if migration {
                    self.giganto
                        .migration::<ProcessTerminated>(
                            iter,
                            RawEventKind::ProcessTerminate,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<ProcessTerminated>(
                            iter,
                            RawEventKind::ProcessTerminate,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "image_load" => {
                if migration {
                    self.giganto
                        .migration::<ImageLoaded>(
                            iter,
                            RawEventKind::ImageLoad,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<ImageLoaded>(
                            iter,
                            RawEventKind::ImageLoad,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "file_create" => {
                if migration {
                    self.giganto
                        .migration::<FileCreate>(
                            iter,
                            RawEventKind::FileCreate,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<FileCreate>(
                            iter,
                            RawEventKind::FileCreate,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "registry_value_set" => {
                if migration {
                    self.giganto
                        .migration::<RegistryValueSet>(
                            iter,
                            RawEventKind::RegistryValueSet,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<RegistryValueSet>(
                            iter,
                            RawEventKind::RegistryValueSet,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "registry_key_rename" => {
                if migration {
                    self.giganto
                        .migration::<RegistryKeyValueRename>(
                            iter,
                            RawEventKind::RegistryKeyRename,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<RegistryKeyValueRename>(
                            iter,
                            RawEventKind::RegistryKeyRename,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "file_create_stream_hash" => {
                if migration {
                    self.giganto
                        .migration::<FileCreateStreamHash>(
                            iter,
                            RawEventKind::FileCreateStreamHash,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<FileCreateStreamHash>(
                            iter,
                            RawEventKind::FileCreateStreamHash,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "pipe_event" => {
                if migration {
                    self.giganto
                        .migration::<PipeEvent>(
                            iter,
                            RawEventKind::PipeEvent,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<PipeEvent>(
                            iter,
                            RawEventKind::PipeEvent,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "dns_query" => {
                if migration {
                    self.giganto
                        .migration::<DnsEvent>(
                            iter,
                            RawEventKind::DnsQuery,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<DnsEvent>(
                            iter,
                            RawEventKind::DnsQuery,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "file_delete" => {
                if migration {
                    self.giganto
                        .migration::<FileDelete>(
                            iter,
                            RawEventKind::FileDelete,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<FileDelete>(
                            iter,
                            RawEventKind::FileDelete,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "process_tamper" => {
                if migration {
                    self.giganto
                        .migration::<ProcessTampering>(
                            iter,
                            RawEventKind::ProcessTamper,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<ProcessTampering>(
                            iter,
                            RawEventKind::ProcessTamper,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            "file_delete_detected" => {
                if migration {
                    self.giganto
                        .migration::<FileDeleteDetected>(
                            iter,
                            RawEventKind::FileDeleteDetected,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                } else {
                    self.giganto
                        .send_sysmon::<FileDeleteDetected>(
                            iter,
                            RawEventKind::FileDeleteDetected,
                            skip,
                            count_sent,
                            file_polling_mode,
                            dir_polling_mode,
                            running,
                            report,
                        )
                        .await
                }
            }
            _ => bail!("unknown sysmon kind"),
        }
    }

    /// # Errors
    ///
    /// Returns an error if it failed to parse netflow pcap.
    pub(crate) async fn send_netflow_to_giganto(
        &mut self,
        filename: &Path,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
        report: &mut Report,
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
                        report,
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
                        report,
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
    pub(crate) async fn send_seculog_to_giganto(
        &mut self,
        reader: BufReader<File>,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
        report: &mut Report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
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
                        report,
                    )
                    .await
            }
            _ => bail!("invalid security log kind"),
        }
    }

    /// # Errors
    ///
    /// Returns an error if any writing log fails.
    pub(crate) async fn send_log_to_giganto(
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
pub(crate) struct Giganto {
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

/// Applies timestamp deduplication by incrementing offset for consecutive identical timestamps.
///
/// Returns the deduplicated timestamp (original + offset). When a new timestamp is encountered,
/// the reference is updated and offset resets to 0. For identical consecutive timestamps,
/// offset increments by 1 for each occurrence.
#[cfg(test)]
pub(crate) fn apply_timestamp_dedup(
    current_timestamp: i64,
    reference_timestamp: &mut Option<i64>,
    timestamp_offset: &mut i64,
) -> i64 {
    if let Some(ref_ts) = *reference_timestamp {
        if current_timestamp == ref_ts {
            // Same timestamp, increment offset
            *timestamp_offset += 1;
        } else {
            // Different timestamp, update reference and reset offset
            *reference_timestamp = Some(current_timestamp);
            *timestamp_offset = 0;
        }
    } else {
        // First event, set reference timestamp
        *reference_timestamp = Some(current_timestamp);
    }
    current_timestamp + *timestamp_offset
}

#[cfg(not(test))]
fn apply_timestamp_dedup(
    current_timestamp: i64,
    reference_timestamp: &mut Option<i64>,
    timestamp_offset: &mut i64,
) -> i64 {
    if let Some(ref_ts) = *reference_timestamp {
        if current_timestamp == ref_ts {
            // Same timestamp, increment offset
            *timestamp_offset += 1;
        } else {
            // Different timestamp, update reference and reset offset
            *reference_timestamp = Some(current_timestamp);
            *timestamp_offset = 0;
        }
    } else {
        // First event, set reference timestamp
        *reference_timestamp = Some(current_timestamp);
    }
    current_timestamp + *timestamp_offset
}

impl Giganto {
    #[allow(clippy::too_many_lines)]
    async fn send_zeek<T>(
        &mut self,
        mut zeek_iter: StringRecordsIntoIter<File>,
        protocol: RawEventKind,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        running: Arc<AtomicBool>,
        report: &mut Report,
    ) -> Result<u64>
    where
        T: Serialize + TryFromZeekRecord + Unpin + Debug,
    {
        info!("Send zeek-generated network event");
        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        let mut pos = Position::new();
        let mut last_record = StringRecord::new();
        let mut reference_timestamp: Option<i64> = None;
        let mut timestamp_offset = 0_i64;
        let mut buf = Vec::new();
        report.start();

        while running.load(Ordering::SeqCst) {
            let next_pos = zeek_iter.reader().position().clone();
            if let Some(result) = zeek_iter.next() {
                if next_pos.line() <= skip {
                    continue;
                }
                match result {
                    Ok(record) if record != last_record => {
                        last_record = record.clone();

                        // Extract timestamp from record and implement deduplication logic
                        let current_timestamp = if let Some(timestamp) = record.get(0) {
                            match crate::zeek::parse_zeek_timestamp(timestamp) {
                                Ok(ts) => match i64::try_from(ts.as_nanosecond()) {
                                    Ok(timestamp) => timestamp,
                                    Err(_) => {
                                        failed_cnt += 1;
                                        error!("timestamp conversion failed #{}", next_pos.line());
                                        continue;
                                    }
                                },
                                Err(e) => {
                                    failed_cnt += 1;
                                    error!("timestamp parsing failed #{}: {e}", next_pos.line());
                                    continue;
                                }
                            }
                        } else {
                            failed_cnt += 1;
                            error!("missing timestamp field #{}", next_pos.line());
                            continue;
                        };

                        // Apply timestamp deduplication
                        let deduped_timestamp = apply_timestamp_dedup(
                            current_timestamp,
                            &mut reference_timestamp,
                            &mut timestamp_offset,
                        );

                        match T::try_from_zeek_record(&record) {
                            Ok((event, _)) => {
                                let timestamp = deduped_timestamp;
                                if self.init_msg {
                                    send_record_header(&mut self.giganto_sender, protocol).await?;
                                    self.init_msg = false;
                                }

                                let record_data = bincode::serialize(&event)?;
                                report.process(record.as_slice().len());

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
                                warn!("Failed to convert data #{}: {e}", next_pos.line());
                            }
                        }
                    }
                    Ok(_) => {
                        continue;
                    }
                    Err(e) => {
                        failed_cnt += 1;
                        warn!("Invalid record: {e}");
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

        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
        }

        info!(
            "Sent zeek-generated network events to data store.\n\
            Last line: {}, Success: {}, Failed: {}",
            pos.line(),
            success_cnt,
            failed_cnt
        );

        if let Err(e) = report.end() {
            warn!("Cannot write report: {e}");
        }

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
        report: &mut Report,
    ) -> Result<u64>
    where
        T: Serialize + TryFromGigantoRecord + Unpin + Debug,
    {
        let type_name = type_name::<T>();
        let short_type_name = type_name.rsplit("::").next().unwrap_or(type_name);
        info!("Migration {}", short_type_name);

        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        let mut pos = Position::new();
        let mut last_record = StringRecord::new();
        let mut buf = Vec::new();
        report.start();

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

                                let record_data = bincode::serialize(&event)?;
                                report.process(record.as_slice().len());

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
                                warn!("Failed to convert data #{}: {e}", next_pos.line());
                            }
                        }
                    }
                    Ok(_) => {
                        continue;
                    }
                    Err(e) => {
                        failed_cnt += 1;
                        warn!("Invalid record: {e}");
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

        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
        }

        info!(
            "Last line: {}, Success: {}, Failed: {}",
            pos.line(),
            success_cnt,
            failed_cnt
        );

        if let Err(e) = report.end() {
            warn!("Cannot write report: {e}");
        }

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
        report: &mut Report,
    ) -> Result<u64> {
        info!("Send oplog");
        let mut lines = reader.lines();
        let mut cnt = 0;
        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        let mut buf = Vec::new();
        report.start();

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

                let record_data = bincode::serialize(&oplog_data)?;
                report.process(line.len());

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

        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
        }

        info!(
            "Sent operation logs to data store.\n\
            Last line: {}, Success: {}, Failed: {}",
            cnt, success_cnt, failed_cnt
        );

        if let Err(e) = report.end() {
            warn!("Cannot write report: {e}");
        }

        Ok(cnt)
    }

    #[allow(clippy::too_many_lines)]
    async fn send_sysmon<T>(
        &mut self,
        mut sysmon_iter: StringRecordsIntoIter<File>,
        protocol: RawEventKind,
        skip: u64,
        count_sent: u64,
        file_polling_mode: bool,
        dir_polling_mode: bool,
        running: Arc<AtomicBool>,
        report: &mut Report,
    ) -> Result<u64>
    where
        T: Serialize + TryFromSysmonRecord + Unpin + Debug,
    {
        info!("Send sysmon, {protocol:?}");
        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        let mut pos = Position::new();
        let mut last_record = StringRecord::new();
        let mut reference_timestamp: Option<i64> = None;
        let mut timestamp_offset = 0_i64;
        let mut buf = Vec::new();
        report.start();

        while running.load(Ordering::SeqCst) {
            let next_pos = sysmon_iter.reader().position().clone();
            if let Some(result) = sysmon_iter.next() {
                if next_pos.line() <= skip {
                    continue;
                }
                match result {
                    Ok(record) if record != last_record => {
                        last_record = record.clone();

                        // Extract timestamp from record and implement deduplication logic
                        let current_timestamp = if let Some(utc_time) = record.get(3) {
                            match crate::syslog::parse_sysmon_time(utc_time) {
                                Ok(ts) => match i64::try_from(ts.as_nanosecond()) {
                                    Ok(timestamp) => timestamp,
                                    Err(_) => {
                                        failed_cnt += 1;
                                        error!(
                                            "failed to convert timestamp to nanos #{}",
                                            next_pos.line()
                                        );
                                        continue;
                                    }
                                },
                                Err(e) => {
                                    failed_cnt += 1;
                                    error!("failed to parse sysmon time #{}: {e}", next_pos.line());
                                    continue;
                                }
                            }
                        } else {
                            failed_cnt += 1;
                            error!("missing time field #{}", next_pos.line());
                            continue;
                        };

                        // Implement timestamp deduplication logic
                        if let Some(ref_ts) = reference_timestamp {
                            if current_timestamp == ref_ts {
                                // Same timestamp, increment offset
                                timestamp_offset += 1;
                            } else {
                                // Different timestamp, update reference and reset offset
                                reference_timestamp = Some(current_timestamp);
                                timestamp_offset = 0;
                            }
                        } else {
                            // First event, set reference timestamp
                            reference_timestamp = Some(current_timestamp);
                        }

                        match T::try_from_sysmon_record(&record, timestamp_offset) {
                            Ok((event, timestamp)) => {
                                if self.init_msg {
                                    send_record_header(&mut self.giganto_sender, protocol).await?;
                                    self.init_msg = false;
                                }

                                let record_data = bincode::serialize(&event)?;
                                report.process(record.as_slice().len());

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
                                warn!("Failed to convert data #{}: {e}", next_pos.line());
                            }
                        }
                    }
                    Ok(_) => {
                        continue;
                    }
                    Err(e) => {
                        failed_cnt += 1;
                        warn!("Invalid record: {e}");
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

        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
        }

        self.init_msg = true;
        info!(
            "Sent sysmon events to data store.\n\
            Last line: {}, Success: {}, Failed: {}",
            pos.line(),
            success_cnt,
            failed_cnt
        );

        if let Err(e) = report.end() {
            warn!("Cannot write report: {e}");
        }

        Ok(pos.line())
    }

    #[allow(clippy::too_many_lines)]
    async fn send_netflow<T>(
        &mut self,
        protocol: RawEventKind,
        filename: &Path,
        skip: u64,
        count_sent: u64,
        running: Arc<AtomicBool>,
        report: &mut Report,
    ) -> Result<u64>
    where
        T: Serialize + ParseNetflowDatasets + Unpin + Debug,
    {
        info!("Send netflow");
        let tmpl_path = env::var("NETFLOW_TEMPLATES_PATH");
        let mut templates = if let Ok(tmpl_path) = tmpl_path.as_ref() {
            TemplatesBox::from_path(tmpl_path).unwrap_or_default()
        } else {
            TemplatesBox::new()
        };
        let mut handle = pcap::Capture::from_file(filename)?;
        if handle.get_datalink() != pcap::Linktype::ETHERNET {
            bail!(
                "Error: unknown datalink {:?} in {}",
                handle.get_datalink().get_name(),
                filename.display()
            );
        }

        let mut stats = Stats::new();
        let mut pkt_cnt = 0_u64;
        let mut timestamp_old = 0_u32;
        let mut nanos = 1_u32;
        let mut buf = Vec::new();
        report.start();

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
                let record_data = bincode::serialize(&event)?;
                report.process(pkt.len());

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
        info!(
            "Sent netflows to data store.\n\
            Statistics: {:?}",
            stats
        );
        if !templates.is_empty()
            && let Ok(tmpl_path) = tmpl_path.as_ref()
            && let Err(e) = templates.save(tmpl_path)
        {
            error!("{}. {}", e, tmpl_path);
        }

        if let Err(e) = report.end() {
            warn!("Cannot write report: {e}");
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
        report: &mut Report,
    ) -> Result<u64>
    where
        T: Serialize + ParseSecurityLog + Unpin + Debug,
    {
        info!("Send seculog");
        let mut lines = reader.lines();
        let mut cnt = 0;
        let mut success_cnt = 0u64;
        let mut failed_cnt = 0u64;
        let mut time_serial = 0_i64;
        let mut buf = Vec::new();
        report.start();

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

                let record_data = bincode::serialize(&seculog_data)?;
                report.process(line.len());

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
        if !buf.is_empty() {
            self.send_event_in_batch(&buf).await?;
        }
        info!(
            "Sent security logs to data store.\n\
            Last line: {}, Success: {}, Failed: {}",
            cnt, success_cnt, failed_cnt
        );

        if let Err(e) = report.end() {
            warn!("Cannot write report: {e}");
        }

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
        let log_file = open_log(file_name).map_err(|e| anyhow!("failed to open: {e}"))?;
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
                    error!("Failed to convert input data: {e}");
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
            warn!("Cannot write report: {e}");
        }
        Ok(conv_cnt + skip)
    }

    async fn send(&mut self, msg: &[u8]) -> Result<()> {
        let send_log: Log = Log {
            kind: self.giganto_info.kind.clone(),
            log: msg.to_vec(),
        };

        if self.init_msg {
            send_record_header(&mut self.giganto_sender, RawEventKind::Log).await?;
            self.init_msg = false;
        }

        let timestamp = i64::try_from(Timestamp::now().as_nanosecond())
            .context("timestamp nanoseconds overflow")?;
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

    pub(crate) async fn finish(&mut self) -> Result<()> {
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
        info!("Data Store ended");
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
                    info!("Server timeout, reconnecting...");
                    tokio::time::sleep(Duration::from_secs(INTERVAL)).await;
                    continue;
                }
                Err(e) => panic!("{}", e),
            };

            client_handshake(&conn, REQUIRED_GIGANTO_VERSION).await?;

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

fn init_giganto(cert: &str, key: &str, ca_certs: &[String]) -> Result<Endpoint> {
    let Ok((cert_pem, key_pem)) = fs::read(cert).and_then(|x| Ok((x, fs::read(key)?))) else {
        bail!("failed to read (cert, key) file. cert_path:{cert}, key_path:{key}");
    };

    let pv_key = if Path::new(key).extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pem))
    } else {
        rustls_pemfile::private_key(&mut &*key_pem)
            .expect("malformed PKCS #1 private key")
            .expect("no private keys found")
    };

    let cert_chain = if Path::new(cert).extension().is_some_and(|x| x == "der") {
        vec![CertificateDer::from(cert_pem)]
    } else {
        rustls_pemfile::certs(&mut &*cert_pem)
            .collect::<Result<_, _>>()
            .expect("invalid PEM-encoded certificate")
    };

    let server_root = to_root_cert(ca_certs)?;

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
                    info!("Finish ACK: {timestamp}");
                } else {
                    info!("ACK: {timestamp}");
                }
            }
            Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_))) => {
                warn!("Finished early");
                break;
            }
            Err(e) => bail!("receive ACK err: {e}"),
        }
    }
    Ok(())
}

fn to_root_cert(ca_certs_paths: &[String]) -> Result<rustls::RootCertStore> {
    let mut ca_certs_files = Vec::new();

    for ca_cert in ca_certs_paths {
        let file = fs::read(ca_cert)
            .with_context(|| format!("failed to read root certificate file: {ca_cert}"))?;

        ca_certs_files.push(file);
    }
    let mut root_cert = rustls::RootCertStore::empty();
    for file in ca_certs_files {
        let root_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &*file)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?;
        if let Some(cert) = root_certs.first() {
            root_cert
                .add(cert.to_owned())
                .context("failed to add root cert")?;
        }
    }

    Ok(root_cert)
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        net::{IpAddr, Ipv6Addr, SocketAddr},
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use csv::{ReaderBuilder, StringRecord};
    use giganto_client::{RawEventKind, connection::server_handshake, ingest::network::Conn};
    use quinn::{ServerConfig, crypto::rustls::QuicServerConfig};

    use super::*;

    const TEST_CERT_PATH: &str = "tests/cert.pem";
    const TEST_KEY_PATH: &str = "tests/key.pem";
    const TEST_ROOT_PATH: &str = "tests/root.pem";
    const TEST_SERVER_NAME: &str = "localhost";
    type TestServerHandle = tokio::task::JoinHandle<(RawEventKind, Vec<(i64, Vec<u8>)>)>;
    type TestServer = (SocketAddr, TestServerHandle);

    fn zeek_conn_line(timestamp: &str, uid: &str) -> String {
        format!(
            "{timestamp}\t{uid}\t192.168.1.77\t57655\t209.197.168.151\t1024\ttcp\tirc-dcc-data\t2.256935\t124\t42208\tSF\t-\t-\t0\tShAdDaFf\t28\t1592\t43\t44452\t-"
        )
    }

    fn create_zeek_record(timestamp: &str, uid: &str) -> StringRecord {
        let data = zeek_conn_line(timestamp, uid);
        ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(data.as_bytes())
            .into_records()
            .next()
            .expect("record")
            .expect("parsed record")
    }

    fn test_server_config() -> ServerConfig {
        let cert_pem = fs::read(TEST_CERT_PATH).expect("read cert");
        let key_pem = fs::read(TEST_KEY_PATH).expect("read key");

        let cert_chain = rustls_pemfile::certs(&mut &*cert_pem)
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("invalid PEM-encoded certificate");
        let key = rustls_pemfile::private_key(&mut &*key_pem)
            .expect("malformed private key")
            .expect("no private key found");

        let root = to_root_cert(&[TEST_ROOT_PATH.to_string()]).expect("root cert");
        let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(root))
            .build()
            .expect("client verifier");

        let server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(cert_chain, key)
            .expect("server config");

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).expect("quic server config"),
        ));

        Arc::get_mut(&mut server_config.transport)
            .expect("transport")
            .max_concurrent_uni_streams(0_u8.into());

        server_config
    }

    fn spawn_test_server(expected_events: usize) -> TestServer {
        let server_config = test_server_config();
        let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let endpoint = Endpoint::server(server_config, server_addr).expect("endpoint");
        let local_addr = endpoint.local_addr().expect("server address");

        let handle = tokio::spawn(async move {
            let incoming = endpoint.accept().await.expect("incoming connection");
            let conn = incoming.await.expect("connection");
            server_handshake(&conn, REQUIRED_GIGANTO_VERSION)
                .await
                .expect("handshake");

            let (_send, mut recv) = conn.accept_bi().await.expect("event stream");

            let mut header_buf = [0u8; std::mem::size_of::<u32>()];
            recv.read_exact(&mut header_buf)
                .await
                .expect("record header");
            let kind = RawEventKind::try_from(u32::from_le_bytes(header_buf)).expect("record kind");

            let mut events = Vec::new();
            while events.len() < expected_events {
                let mut len_buf = [0u8; std::mem::size_of::<u32>()];
                recv.read_exact(&mut len_buf).await.expect("batch length");
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut payload = vec![0u8; len];
                recv.read_exact(&mut payload).await.expect("batch payload");

                let batch: Vec<(i64, Vec<u8>)> = bincode::deserialize(&payload).expect("events");
                events.extend(batch);
            }

            (kind, events)
        });

        (local_addr, handle)
    }

    fn write_temp_zeek_log(lines: &[String]) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let log_path = std::env::temp_dir().join(format!("reproduce-zeek-{suffix}.log"));
        let mut log_file = fs::File::create(&log_path).expect("create log file");
        log_file
            .write_all(lines.join("\n").as_bytes())
            .expect("write log file");
        log_file.write_all(b"\n").expect("newline");
        log_file.flush().expect("flush log file");
        drop(log_file);
        log_path
    }

    #[test]
    fn test_parse_zeek_timestamp_public() {
        // Test that parse_zeek_timestamp is accessible
        let timestamp = "1562093121.655728";
        let result = crate::zeek::parse_zeek_timestamp(timestamp);
        assert!(result.is_ok());

        let ts = result.unwrap();
        assert_eq!(ts.as_second(), 1_562_093_121);
        assert_eq!(ts.subsec_microsecond(), 655_728);
    }

    // ==========================================================================
    // Zeek Timestamp Deduplication Tests
    //
    // Acceptance Criteria: Identical timestamps result in incremental offset
    // application during send.
    //
    // These tests verify the helper logic and exercise the real `send_zeek`
    // path against an in-process QUIC server.
    // ==========================================================================

    /// Tests that offset resets when a different timestamp is encountered.
    ///
    /// Scenario: Events with timestamps [A, A, B, B, B]
    /// Expected: [A+0, A+1, B+0, B+1, B+2]
    #[test]
    #[allow(clippy::similar_names)]
    fn test_zeek_timestamp_deduplication_offset_resets() {
        let timestamp_a = "1562093121.655728";
        let timestamp_b = "1562093122.000000";

        // Create records: 2 with timestamp A, 3 with timestamp B
        let record_a1 = create_zeek_record(timestamp_a, "UID_A1");
        let record_a2 = create_zeek_record(timestamp_a, "UID_A2");
        let record_b1 = create_zeek_record(timestamp_b, "UID_B1");
        let record_b2 = create_zeek_record(timestamp_b, "UID_B2");
        let record_b3 = create_zeek_record(timestamp_b, "UID_B3");

        let (_, ts_a1) = Conn::try_from_zeek_record(&record_a1).unwrap();
        let (_, ts_a2) = Conn::try_from_zeek_record(&record_a2).unwrap();
        let (_, ts_b1) = Conn::try_from_zeek_record(&record_b1).unwrap();
        let (_, ts_b2) = Conn::try_from_zeek_record(&record_b2).unwrap();
        let (_, ts_b3) = Conn::try_from_zeek_record(&record_b3).unwrap();

        // Verify initial timestamps match expectations
        assert_eq!(ts_a1, ts_a2, "A timestamps should be identical");
        assert_eq!(ts_b1, ts_b2, "B timestamps should be identical");
        assert_eq!(ts_b2, ts_b3, "B timestamps should be identical");
        assert_ne!(ts_a1, ts_b1, "A and B timestamps should differ");

        // Apply deduplication using the production helper
        let mut reference_timestamp: Option<i64> = None;
        let mut timestamp_offset = 0_i64;
        let timestamps = [ts_a1, ts_a2, ts_b1, ts_b2, ts_b3];
        let final_timestamps: Vec<i64> = timestamps
            .iter()
            .map(|&ts| apply_timestamp_dedup(ts, &mut reference_timestamp, &mut timestamp_offset))
            .collect();

        // Verify: A timestamps get offsets 0, 1
        assert_eq!(final_timestamps[0], ts_a1, "First A event: no offset");
        assert_eq!(final_timestamps[1], ts_a1 + 1, "Second A event: offset +1");

        // Verify: B timestamps get offsets 0, 1, 2 (offset resets for new timestamp)
        assert_eq!(
            final_timestamps[2], ts_b1,
            "First B event: offset resets to 0"
        );
        assert_eq!(final_timestamps[3], ts_b1 + 1, "Second B event: offset +1");
        assert_eq!(final_timestamps[4], ts_b1 + 2, "Third B event: offset +2");
    }

    #[tokio::test]
    async fn test_send_zeek_timestamp_deduplication_end_to_end() {
        let (server_addr, server_handle) = spawn_test_server(4);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "conn".to_string(),
            input: "test".to_string(),
            report: false,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        let timestamp_a = "1562093121.655728";
        let timestamp_b = "1562093122.000000";
        let lines = vec![
            zeek_conn_line(timestamp_a, "UID_A1"),
            zeek_conn_line(timestamp_a, "UID_A2"),
            zeek_conn_line(timestamp_b, "UID_B1"),
            zeek_conn_line(timestamp_b, "UID_B2"),
        ];

        let log_path = write_temp_zeek_log(&lines);

        let file = File::open(&log_path).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
            .giganto
            .send_zeek::<Conn>(
                iter,
                RawEventKind::Conn,
                0,
                0,
                false,
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_zeek");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::Conn);
        assert_eq!(events.len(), 4);

        let (_, base_a) = Conn::try_from_zeek_record(&create_zeek_record(timestamp_a, "UID_A1"))
            .expect("parse A");
        let (_, base_b) = Conn::try_from_zeek_record(&create_zeek_record(timestamp_b, "UID_B1"))
            .expect("parse B");

        let timestamps: Vec<i64> = events.into_iter().map(|(ts, _)| ts).collect();
        assert_eq!(timestamps, vec![base_a, base_a + 1, base_b, base_b + 1]);

        let _ = fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn test_send_zeek_timestamp_deduplication_across_batches() {
        let expected_events = BATCH_SIZE + 1;
        let (server_addr, server_handle) = spawn_test_server(expected_events);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "conn".to_string(),
            input: "test".to_string(),
            report: false,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        let timestamp = "1562093121.655728";
        let lines: Vec<String> = (0..expected_events)
            .map(|i| zeek_conn_line(timestamp, &format!("UID_{i:04}")))
            .collect();
        let log_path = write_temp_zeek_log(&lines);

        let file = File::open(&log_path).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
            .giganto
            .send_zeek::<Conn>(
                iter,
                RawEventKind::Conn,
                0,
                0,
                false,
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_zeek");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::Conn);
        assert_eq!(events.len(), expected_events);

        let (_, base_ts) = Conn::try_from_zeek_record(&create_zeek_record(timestamp, "UID_0000"))
            .expect("parse timestamp");
        for (idx, (timestamp, _)) in events.iter().enumerate() {
            let offset = i64::try_from(idx).expect("offset fits i64");
            assert_eq!(*timestamp, base_ts + offset);
        }

        let _ = fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn test_send_zeek_deduplication_skips_invalid_timestamps() {
        let (server_addr, server_handle) = spawn_test_server(2);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "conn".to_string(),
            input: "test".to_string(),
            report: false,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        let timestamp = "1562093121.655728";
        let lines = vec![
            zeek_conn_line(timestamp, "UID_A1"),
            zeek_conn_line("invalid.123", "UID_BAD"),
            zeek_conn_line(timestamp, "UID_A2"),
        ];
        let log_path = write_temp_zeek_log(&lines);

        let file = File::open(&log_path).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
            .giganto
            .send_zeek::<Conn>(
                iter,
                RawEventKind::Conn,
                0,
                0,
                false,
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_zeek");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::Conn);
        assert_eq!(events.len(), 2);

        let (_, base_ts) = Conn::try_from_zeek_record(&create_zeek_record(timestamp, "UID_A1"))
            .expect("parse timestamp");
        let timestamps: Vec<i64> = events.into_iter().map(|(ts, _)| ts).collect();
        assert_eq!(timestamps, vec![base_ts, base_ts + 1]);

        let _ = fs::remove_file(&log_path);
    }

    // ==========================================================================
    // Option Behavior Tests
    //
    // These tests verify the behavior of skip, count_sent, and file_polling_mode
    // options in send_zeek.
    // ==========================================================================

    /// Tests that the `skip` option ignores the first N lines.
    ///
    /// Scenario: 5 events, skip=2
    /// Expected: Only events 3, 4, 5 are sent (3 events total)
    #[tokio::test]
    async fn test_send_zeek_skip_ignores_first_n_lines() {
        let (server_addr, server_handle) = spawn_test_server(3);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "conn".to_string(),
            input: "test".to_string(),
            report: false,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        let lines: Vec<String> = (0..5)
            .map(|i| zeek_conn_line(&format!("156209312{i}.000000"), &format!("UID_{i}")))
            .collect();
        let log_path = write_temp_zeek_log(&lines);

        let file = File::open(&log_path).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
            .giganto
            .send_zeek::<Conn>(
                iter,
                RawEventKind::Conn,
                2, // skip first 2 lines
                0,
                false,
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_zeek");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::Conn);
        assert_eq!(events.len(), 3, "Should have skipped first 2 lines");

        // Verify we got events 3, 4, 5 (indices 2, 3, 4 in original)
        let (_, ts_2) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093122.000000", "UID_2"))
                .expect("parse");
        let (_, ts_3) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093123.000000", "UID_3"))
                .expect("parse");
        let (_, ts_4) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093124.000000", "UID_4"))
                .expect("parse");

        let timestamps: Vec<i64> = events.into_iter().map(|(ts, _)| ts).collect();
        assert_eq!(timestamps, vec![ts_2, ts_3, ts_4]);

        let _ = fs::remove_file(&log_path);
    }

    /// Tests that the `count_sent` option stops after exactly N events are sent.
    ///
    /// Scenario: 10 events, `count_sent=4`
    /// Expected: Only the first 4 events are sent
    #[tokio::test]
    async fn test_send_zeek_count_sent_stops_after_n_events() {
        let (server_addr, server_handle) = spawn_test_server(4);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "conn".to_string(),
            input: "test".to_string(),
            report: false,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        let lines: Vec<String> = (0..10)
            .map(|i| zeek_conn_line(&format!("156209312{i}.000000"), &format!("UID_{i}")))
            .collect();
        let log_path = write_temp_zeek_log(&lines);

        let file = File::open(&log_path).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
            .giganto
            .send_zeek::<Conn>(
                iter,
                RawEventKind::Conn,
                0,
                4, // stop after 4 events
                false,
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_zeek");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::Conn);
        assert_eq!(events.len(), 4, "Should have sent exactly 4 events");

        // Verify we got events 0, 1, 2, 3
        let (_, ts_0) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093120.000000", "UID_0"))
                .expect("parse");
        let (_, ts_1) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093121.000000", "UID_1"))
                .expect("parse");
        let (_, ts_2) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093122.000000", "UID_2"))
                .expect("parse");
        let (_, ts_3) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093123.000000", "UID_3"))
                .expect("parse");

        let timestamps: Vec<i64> = events.into_iter().map(|(ts, _)| ts).collect();
        assert_eq!(timestamps, vec![ts_0, ts_1, ts_2, ts_3]);

        let _ = fs::remove_file(&log_path);
    }

    /// Tests that `file_polling_mode` resumes processing when new data is appended after EOF.
    ///
    /// Scenario: Initial file has 2 events, then 2 more are appended
    /// Expected: All 4 events are eventually sent
    #[tokio::test]
    async fn test_send_zeek_file_polling_mode_resumes_on_append() {
        let (server_addr, server_handle) = spawn_test_server(4);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "conn".to_string(),
            input: "test".to_string(),
            report: false,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        // Create initial file with 2 events
        let initial_lines = vec![
            zeek_conn_line("1562093120.000000", "UID_0"),
            zeek_conn_line("1562093121.000000", "UID_1"),
        ];
        let log_path = write_temp_zeek_log(&initial_lines);
        let log_path_clone = log_path.clone();

        let file = File::open(&log_path).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));

        // Spawn a task to append more data after a short delay
        let append_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(&log_path_clone)
                .expect("open for append");
            let additional_lines = [
                zeek_conn_line("1562093122.000000", "UID_2"),
                zeek_conn_line("1562093123.000000", "UID_3"),
            ];
            file.write_all(additional_lines.join("\n").as_bytes())
                .expect("append");
            file.write_all(b"\n").expect("newline");
            file.flush().expect("flush");
        });

        producer
            .giganto
            .send_zeek::<Conn>(
                iter,
                RawEventKind::Conn,
                0,
                4,    // stop after 4 events (initial 2 + appended 2)
                true, // file_polling_mode enabled
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_zeek");

        append_handle.await.expect("append task");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::Conn);
        assert_eq!(
            events.len(),
            4,
            "Should have received all 4 events including appended ones"
        );

        // Verify we got all 4 events
        let (_, ts_0) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093120.000000", "UID_0"))
                .expect("parse");
        let (_, ts_1) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093121.000000", "UID_1"))
                .expect("parse");
        let (_, ts_2) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093122.000000", "UID_2"))
                .expect("parse");
        let (_, ts_3) =
            Conn::try_from_zeek_record(&create_zeek_record("1562093123.000000", "UID_3"))
                .expect("parse");

        let timestamps: Vec<i64> = events.into_iter().map(|(ts, _)| ts).collect();
        assert_eq!(timestamps, vec![ts_0, ts_1, ts_2, ts_3]);

        let _ = fs::remove_file(&log_path);
    }
}
