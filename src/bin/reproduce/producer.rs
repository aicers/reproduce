#![allow(
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::single_match_else
)]
use std::{
    any::type_name,
    env,
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader},
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
    frame::SendError,
    ingest::{
        log::Log,
        netflow::{Netflow5, Netflow9},
        network::{
            Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Kerberos, Ldap, MalformedDns, Mqtt, Nfs,
            Ntlm, Radius, Rdp, Smb, Smtp, Ssh, Tls,
        },
        sysmon::{
            DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
            FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
            ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
        },
    },
};
use jiff::Timestamp;
use reproduce::sender::{BATCH_SIZE, GigantoSender, apply_timestamp_dedup};
use serde::Serialize;
use tracing::{error, info, warn};

use reproduce::config::Config;
use reproduce::parser::migration::TryFromGigantoRecord;
use reproduce::parser::netflow::{
    NetflowHeader, ParseNetflowDatasets, PktBuf, ProcessStats, Stats, TemplatesBox,
};
use reproduce::parser::operation_log;
use reproduce::parser::security_log::{
    Aiwaf, Axgate, Fgt, Mf2, Nginx, ParseSecurityLog, SecurityLogInfo, ShadowWall, SniperIps,
    SonicWall, Srx, Tg, Ubuntu, Vforce, Wapples,
};
use reproduce::parser::sysmon_csv::TryFromSysmonRecord;
use reproduce::parser::zeek::TryFromZeekRecord;

use crate::report::Report;

pub(crate) struct Producer {
    pub(crate) giganto: GigantoSender,
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
        let giganto = GigantoSender::new(
            &config.cert,
            &config.key,
            &config.ca_certs,
            config.giganto_ingest_srv_addr,
            &config.giganto_name,
            &config.kind,
        )
        .await?;
        Ok(Self { giganto })
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
        match self.giganto.kind() {
            "conn" => {
                if migration {
                    self.migration::<Conn>(
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
                    self.send_zeek::<Conn>(
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
                    self.migration::<Http>(
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
                    self.send_zeek::<Http>(
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
                    self.migration::<Rdp>(
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
                    self.send_zeek::<Rdp>(
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
                    self.migration::<Smtp>(
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
                    self.send_zeek::<Smtp>(
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
                    self.migration::<Dns>(
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
                    self.send_zeek::<Dns>(
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
                    self.migration::<Ntlm>(
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
                    self.send_zeek::<Ntlm>(
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
                    self.migration::<Kerberos>(
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
                    self.send_zeek::<Kerberos>(
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
                    self.migration::<Ssh>(
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
                    self.send_zeek::<Ssh>(
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
                    self.migration::<DceRpc>(
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
                    self.send_zeek::<DceRpc>(
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
                    self.migration::<Ftp>(
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
                    self.send_zeek::<Ftp>(
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
                    self.migration::<Mqtt>(
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
                    self.migration::<Ldap>(
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
                    self.send_zeek::<Ldap>(
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
                    self.migration::<Tls>(
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
                    self.send_zeek::<Tls>(
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
                    self.migration::<Smb>(
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
                    self.migration::<Nfs>(
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
                    self.migration::<Bootp>(
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
                    self.migration::<Dhcp>(
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
                    self.migration::<Radius>(
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
                    self.migration::<MalformedDns>(
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
        self.send_oplog(
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
        match self.giganto.kind() {
            "process_create" => {
                if migration {
                    self.migration::<ProcessCreate>(
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
                    self.send_sysmon::<ProcessCreate>(
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
                    self.migration::<FileCreationTimeChanged>(
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
                    self.send_sysmon::<FileCreationTimeChanged>(
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
                    self.migration::<NetworkConnection>(
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
                    self.send_sysmon::<NetworkConnection>(
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
                    self.migration::<ProcessTerminated>(
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
                    self.send_sysmon::<ProcessTerminated>(
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
                    self.migration::<ImageLoaded>(
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
                    self.send_sysmon::<ImageLoaded>(
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
                    self.migration::<FileCreate>(
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
                    self.send_sysmon::<FileCreate>(
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
                    self.migration::<RegistryValueSet>(
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
                    self.send_sysmon::<RegistryValueSet>(
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
                    self.migration::<RegistryKeyValueRename>(
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
                    self.send_sysmon::<RegistryKeyValueRename>(
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
                    self.migration::<FileCreateStreamHash>(
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
                    self.send_sysmon::<FileCreateStreamHash>(
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
                    self.migration::<PipeEvent>(
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
                    self.send_sysmon::<PipeEvent>(
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
                    self.migration::<DnsEvent>(
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
                    self.send_sysmon::<DnsEvent>(
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
                    self.migration::<FileDelete>(
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
                    self.send_sysmon::<FileDelete>(
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
                    self.migration::<ProcessTampering>(
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
                    self.send_sysmon::<ProcessTampering>(
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
                    self.migration::<FileDeleteDetected>(
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
                    self.send_sysmon::<FileDeleteDetected>(
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
        match self.giganto.kind() {
            "netflow5" => {
                self.send_netflow::<Netflow5>(
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
                self.send_netflow::<Netflow9>(
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
        match self.giganto.kind() {
            "wapples_fw_6.0" => {
                self.send_seculog::<Wapples>(
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
                self.send_seculog::<Mf2>(
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
                self.send_seculog::<SniperIps>(
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
                self.send_seculog::<Aiwaf>(
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
                self.send_seculog::<Tg>(
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
                self.send_seculog::<Vforce>(
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
                self.send_seculog::<Srx>(
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
                self.send_seculog::<SonicWall>(
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
                self.send_seculog::<Fgt>(
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
                self.send_seculog::<ShadowWall>(
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
                self.send_seculog::<Axgate>(
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
                self.send_seculog::<Ubuntu>(
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
                self.send_seculog::<Nginx>(
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
        self.send_log(
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

    pub(crate) async fn finish(&mut self) -> Result<()> {
        self.giganto.finish().await
    }

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
                            match reproduce::parser::zeek::parse_zeek_timestamp(timestamp) {
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
                                self.giganto.ensure_header_sent(protocol).await?;

                                let record_data = bincode::serialize(&event)?;
                                report.process(record.as_slice().len());

                                buf.push((timestamp, record_data));
                                if buf.len() >= BATCH_SIZE {
                                    match self.giganto.send_batch(&buf).await {
                                        Err(SendError::WriteError(_)) => {
                                            self.giganto.reconnect().await?;
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
            self.giganto.send_batch(&buf).await?;
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
                                self.giganto.ensure_header_sent(protocol).await?;

                                let record_data = bincode::serialize(&event)?;
                                report.process(record.as_slice().len());

                                buf.push((timestamp, record_data));
                                if buf.len() >= BATCH_SIZE {
                                    match self.giganto.send_batch(&buf).await {
                                        Err(SendError::WriteError(_)) => {
                                            self.giganto.reconnect().await?;
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
            self.giganto.send_batch(&buf).await?;
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

                self.giganto.ensure_header_sent(RawEventKind::OpLog).await?;

                let record_data = bincode::serialize(&oplog_data)?;
                report.process(line.len());

                buf.push((timestamp, record_data));
                if buf.len() >= BATCH_SIZE {
                    match self.giganto.send_batch(&buf).await {
                        Err(SendError::WriteError(_)) => {
                            self.giganto.reconnect().await?;
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
            self.giganto.send_batch(&buf).await?;
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
                            match reproduce::parser::sysmon_csv::parse_sysmon_time(utc_time) {
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

                        // Apply timestamp deduplication
                        let deduped_timestamp = apply_timestamp_dedup(
                            current_timestamp,
                            &mut reference_timestamp,
                            &mut timestamp_offset,
                        );

                        match T::try_from_sysmon_record(&record) {
                            Ok((event, _)) => {
                                let timestamp = deduped_timestamp;
                                self.giganto.ensure_header_sent(protocol).await?;

                                let record_data = bincode::serialize(&event)?;
                                report.process(record.as_slice().len());

                                buf.push((timestamp, record_data));
                                if buf.len() >= BATCH_SIZE {
                                    match self.giganto.send_batch(&buf).await {
                                        Err(SendError::WriteError(_)) => {
                                            self.giganto.reconnect().await?;
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
            self.giganto.send_batch(&buf).await?;
        }

        self.giganto.reset_header();
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
            self.giganto.ensure_header_sent(protocol).await?;
            for (timestamp, event) in events {
                let record_data = bincode::serialize(&event)?;
                report.process(pkt.len());

                buf.push((timestamp, record_data));
                if buf.len() >= BATCH_SIZE {
                    match self.giganto.send_batch(&buf).await {
                        Err(SendError::WriteError(_)) => {
                            self.giganto.reconnect().await?;
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
                self.giganto.send_batch(&buf).await?;
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
                    SecurityLogInfo::new(self.giganto.kind()),
                ) {
                    success_cnt += 1;
                    r
                } else {
                    failed_cnt += 1;
                    continue;
                };

                self.giganto
                    .ensure_header_sent(RawEventKind::SecuLog)
                    .await?;

                let record_data = bincode::serialize(&seculog_data)?;
                report.process(line.len());

                buf.push((timestamp, record_data));
                if buf.len() >= BATCH_SIZE {
                    match self.giganto.send_batch(&buf).await {
                        Err(SendError::WriteError(_)) => {
                            self.giganto.reconnect().await?;
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
            self.giganto.send_batch(&buf).await?;
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
            self.send_single_log(giganto_msg.as_slice())
                .await
                .context("failed to send message to Giganto")?;
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

    async fn send_single_log(&mut self, msg: &[u8]) -> Result<()> {
        let send_log: Log = Log {
            kind: self.giganto.kind().to_string(),
            log: msg.to_vec(),
        };

        self.giganto.ensure_header_sent(RawEventKind::Log).await?;

        let timestamp = i64::try_from(Timestamp::now().as_nanosecond())
            .context("timestamp nanoseconds overflow")?;
        let record_data = bincode::serialize(&send_log)?;
        let buf = vec![(timestamp, record_data)];

        match self.giganto.send_batch(&buf).await {
            Err(SendError::WriteError(_)) => {
                self.giganto.reconnect().await?;
            }
            Err(e) => {
                bail!("{e:?}");
            }
            Ok(()) => {}
        }
        Ok(())
    }
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
    };

    use csv::{ReaderBuilder, StringRecord};
    use giganto_client::{
        RawEventKind,
        connection::server_handshake,
        ingest::{network::Conn, sysmon::ProcessCreate},
    };
    use quinn::{Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
    use reproduce::sender::REQUIRED_GIGANTO_VERSION;
    use tempfile::NamedTempFile;

    use super::*;
    use reproduce::parser::sysmon_csv::TryFromSysmonRecord;

    const TEST_CERT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/cert.pem");
    const TEST_KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/key.pem");
    const TEST_ROOT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/root.pem");
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

        let root =
            reproduce::sender::to_root_cert(&[TEST_ROOT_PATH.to_string()]).expect("root cert");
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

    fn write_temp_log(lines: &[String]) -> NamedTempFile {
        let mut log_file = NamedTempFile::new().expect("create temp file");
        log_file
            .write_all(lines.join("\n").as_bytes())
            .expect("write log file");
        log_file.write_all(b"\n").expect("newline");
        log_file.flush().expect("flush log file");
        log_file
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
            report_dir: None,
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

        let log_file = write_temp_log(&lines);

        let file = File::open(log_file.path()).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
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
            report_dir: None,
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
        let log_file = write_temp_log(&lines);

        let file = File::open(log_file.path()).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
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
            report_dir: None,
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
        let log_file = write_temp_log(&lines);

        let file = File::open(log_file.path()).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
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
            report_dir: None,
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
        let log_file = write_temp_log(&lines);

        let file = File::open(log_file.path()).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
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
            report_dir: None,
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
        let log_file = write_temp_log(&lines);

        let file = File::open(log_file.path()).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
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
            report_dir: None,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        // Use tempdir for path-based reopen/append scenario to avoid file-locking issues
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let log_path = temp_dir.path().join("zeek.log");
        let log_path_clone = log_path.clone();

        // Create initial file with 2 events
        {
            let mut log_file = fs::File::create(&log_path).expect("create log file");
            let initial_lines = [
                zeek_conn_line("1562093120.000000", "UID_0"),
                zeek_conn_line("1562093121.000000", "UID_1"),
            ];
            log_file
                .write_all(initial_lines.join("\n").as_bytes())
                .expect("write log file");
            log_file.write_all(b"\n").expect("newline");
            log_file.flush().expect("flush log file");
        }

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
        // temp_dir is automatically cleaned up when dropped
    }

    fn sysmon_process_create_line(timestamp: &str, process_guid: &str) -> String {
        format!(
            "test-agent\tagent-001\t1\t{timestamp}\t{process_guid}\t1234\t\
             C:\\Windows\\System32\\cmd.exe\t10.0.0.0\tCommand Prompt\tWindows\t\
             Microsoft\tcmd.exe\tcmd.exe /c test\tC:\\Windows\tNT AUTHORITY\\SYSTEM\t\
             {{00000000-0000-0000-0000-000000000000}}\t0x3e7\t1\tSystem\t\
             SHA256=abc123\t{{00000000-0000-0000-0000-000000000001}}\t0\t\
             C:\\Windows\\explorer.exe\texplorer.exe\tNT AUTHORITY\\SYSTEM"
        )
    }

    // Sysmon timestamp deduplication tests
    // These mirror the Zeek tests above but for the Sysmon conversion pipeline

    fn create_sysmon_process_create_record(timestamp: &str, process_guid: &str) -> StringRecord {
        let data = sysmon_process_create_line(timestamp, process_guid);
        ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(data.as_bytes())
            .into_records()
            .next()
            .unwrap()
            .unwrap()
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn test_sysmon_timestamp_deduplication_offset_resets() {
        let timestamp_a = "2023-01-15 14:30:45.123456";
        let timestamp_b = "2023-01-15 14:30:46.654321";

        let record_a1 = create_sysmon_process_create_record(
            timestamp_a,
            "{00000000-0000-0000-0000-000000000001}",
        );
        let record_a2 = create_sysmon_process_create_record(
            timestamp_a,
            "{00000000-0000-0000-0000-000000000002}",
        );
        let record_b1 = create_sysmon_process_create_record(
            timestamp_b,
            "{00000000-0000-0000-0000-000000000003}",
        );
        let record_b2 = create_sysmon_process_create_record(
            timestamp_b,
            "{00000000-0000-0000-0000-000000000004}",
        );
        let record_b3 = create_sysmon_process_create_record(
            timestamp_b,
            "{00000000-0000-0000-0000-000000000005}",
        );

        let (_, ts_a1) = ProcessCreate::try_from_sysmon_record(&record_a1).unwrap();
        let (_, ts_a2) = ProcessCreate::try_from_sysmon_record(&record_a2).unwrap();
        let (_, ts_b1) = ProcessCreate::try_from_sysmon_record(&record_b1).unwrap();
        let (_, ts_b2) = ProcessCreate::try_from_sysmon_record(&record_b2).unwrap();
        let (_, ts_b3) = ProcessCreate::try_from_sysmon_record(&record_b3).unwrap();

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
    async fn test_send_sysmon_timestamp_deduplication_end_to_end() {
        let expected_events = 3;
        let (server_addr, server_handle) = spawn_test_server(expected_events);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "process_create".to_string(),
            input: "test".to_string(),
            report: false,
            report_dir: None,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        let timestamp = "2023-01-15 14:30:45.123456";
        let lines = vec![
            sysmon_process_create_line(timestamp, "{00000000-0000-0000-0000-000000000001}"),
            sysmon_process_create_line(timestamp, "{00000000-0000-0000-0000-000000000002}"),
            sysmon_process_create_line(timestamp, "{00000000-0000-0000-0000-000000000003}"),
        ];
        let log_file = write_temp_log(&lines);

        let file = File::open(log_file.path()).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
            .send_sysmon::<ProcessCreate>(
                iter,
                RawEventKind::ProcessCreate,
                0,
                0,
                false,
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_sysmon");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::ProcessCreate);
        assert_eq!(events.len(), expected_events);

        let (_, base_ts) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                timestamp,
                "{00000000-0000-0000-0000-000000000001}",
            ))
            .expect("parse timestamp");

        let timestamps: Vec<i64> = events.into_iter().map(|(ts, _)| ts).collect();
        assert_eq!(timestamps, vec![base_ts, base_ts + 1, base_ts + 2]);
    }

    // ==========================================================================
    // Sysmon Option Behavior Tests
    //
    // These tests verify the behavior of skip, count_sent, and file_polling_mode
    // options in send_sysmon, mirroring the existing Zeek tests.
    // ==========================================================================

    /// Tests that the `skip` option ignores the first N lines.
    ///
    /// Scenario: 5 events, skip=2
    /// Expected: Only events 3, 4, 5 are sent (3 events total)
    #[tokio::test]
    async fn test_send_sysmon_skip_ignores_first_n_lines() {
        let (server_addr, server_handle) = spawn_test_server(3);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "process_create".to_string(),
            input: "test".to_string(),
            report: false,
            report_dir: None,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        let lines: Vec<String> = (0..5)
            .map(|i| {
                sysmon_process_create_line(
                    &format!("2023-01-15 14:30:4{i}.000000"),
                    &format!("{{0000000{i}-0000-0000-0000-000000000000}}"),
                )
            })
            .collect();
        let log_file = write_temp_log(&lines);

        let file = File::open(log_file.path()).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
            .send_sysmon::<ProcessCreate>(
                iter,
                RawEventKind::ProcessCreate,
                2, // skip first 2 lines
                0,
                false,
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_sysmon");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::ProcessCreate);
        assert_eq!(events.len(), 3, "Should have skipped first 2 lines");

        // Verify we got events 3, 4, 5 (indices 2, 3, 4 in original)
        let (_, ts_2) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:42.000000",
                "{00000002-0000-0000-0000-000000000000}",
            ))
            .expect("parse");
        let (_, ts_3) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:43.000000",
                "{00000003-0000-0000-0000-000000000000}",
            ))
            .expect("parse");
        let (_, ts_4) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:44.000000",
                "{00000004-0000-0000-0000-000000000000}",
            ))
            .expect("parse");

        let timestamps: Vec<i64> = events.into_iter().map(|(ts, _)| ts).collect();
        assert_eq!(timestamps, vec![ts_2, ts_3, ts_4]);
    }

    /// Tests that the `count_sent` option stops after exactly N events are sent.
    ///
    /// Scenario: 10 events, `count_sent=4`
    /// Expected: Only the first 4 events are sent
    #[tokio::test]
    async fn test_send_sysmon_count_sent_stops_after_n_events() {
        let (server_addr, server_handle) = spawn_test_server(4);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "process_create".to_string(),
            input: "test".to_string(),
            report: false,
            report_dir: None,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        let lines: Vec<String> = (0..10)
            .map(|i| {
                sysmon_process_create_line(
                    &format!("2023-01-15 14:30:4{i}.000000"),
                    &format!("{{0000000{i}-0000-0000-0000-000000000000}}"),
                )
            })
            .collect();
        let log_file = write_temp_log(&lines);

        let file = File::open(log_file.path()).expect("open log file");
        let iter = ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(file)
            .into_records();

        let mut report = Report::new(config.clone());
        let running = Arc::new(AtomicBool::new(true));
        producer
            .send_sysmon::<ProcessCreate>(
                iter,
                RawEventKind::ProcessCreate,
                0,
                4, // stop after 4 events
                false,
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_sysmon");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::ProcessCreate);
        assert_eq!(events.len(), 4, "Should have sent exactly 4 events");

        // Verify we got events 0, 1, 2, 3
        let (_, ts_0) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:40.000000",
                "{00000000-0000-0000-0000-000000000000}",
            ))
            .expect("parse");
        let (_, ts_1) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:41.000000",
                "{00000001-0000-0000-0000-000000000000}",
            ))
            .expect("parse");
        let (_, ts_2) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:42.000000",
                "{00000002-0000-0000-0000-000000000000}",
            ))
            .expect("parse");
        let (_, ts_3) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:43.000000",
                "{00000003-0000-0000-0000-000000000000}",
            ))
            .expect("parse");

        let timestamps: Vec<i64> = events.into_iter().map(|(ts, _)| ts).collect();
        assert_eq!(timestamps, vec![ts_0, ts_1, ts_2, ts_3]);
    }

    /// Tests that `file_polling_mode` resumes processing when new data is appended after EOF.
    ///
    /// Scenario: Initial file has 2 events, then 2 more are appended
    /// Expected: All 4 events are eventually sent
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_send_sysmon_file_polling_mode_resumes_on_append() {
        let (server_addr, server_handle) = spawn_test_server(4);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "process_create".to_string(),
            input: "test".to_string(),
            report: false,
            report_dir: None,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("giganto producer");

        // Use tempdir for path-based reopen/append scenario to avoid file-locking issues
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let log_path = temp_dir.path().join("sysmon.log");
        let log_path_clone = log_path.clone();

        // Create initial file with 2 events
        {
            let mut log_file = fs::File::create(&log_path).expect("create log file");
            let initial_lines = [
                sysmon_process_create_line(
                    "2023-01-15 14:30:40.000000",
                    "{00000000-0000-0000-0000-000000000000}",
                ),
                sysmon_process_create_line(
                    "2023-01-15 14:30:41.000000",
                    "{00000001-0000-0000-0000-000000000000}",
                ),
            ];
            log_file
                .write_all(initial_lines.join("\n").as_bytes())
                .expect("write log file");
            log_file.write_all(b"\n").expect("newline");
            log_file.flush().expect("flush log file");
        }

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
                sysmon_process_create_line(
                    "2023-01-15 14:30:42.000000",
                    "{00000002-0000-0000-0000-000000000000}",
                ),
                sysmon_process_create_line(
                    "2023-01-15 14:30:43.000000",
                    "{00000003-0000-0000-0000-000000000000}",
                ),
            ];
            file.write_all(additional_lines.join("\n").as_bytes())
                .expect("append");
            file.write_all(b"\n").expect("newline");
            file.flush().expect("flush");
        });

        producer
            .send_sysmon::<ProcessCreate>(
                iter,
                RawEventKind::ProcessCreate,
                0,
                4,    // stop after 4 events (initial 2 + appended 2)
                true, // file_polling_mode enabled
                false,
                running,
                &mut report,
            )
            .await
            .expect("send_sysmon");

        append_handle.await.expect("append task");

        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::ProcessCreate);
        assert_eq!(
            events.len(),
            4,
            "Should have received all 4 events including appended ones"
        );

        // Verify we got all 4 events
        let (_, ts_0) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:40.000000",
                "{00000000-0000-0000-0000-000000000000}",
            ))
            .expect("parse");
        let (_, ts_1) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:41.000000",
                "{00000001-0000-0000-0000-000000000000}",
            ))
            .expect("parse");
        let (_, ts_2) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:42.000000",
                "{00000002-0000-0000-0000-000000000000}",
            ))
            .expect("parse");
        let (_, ts_3) =
            ProcessCreate::try_from_sysmon_record(&create_sysmon_process_create_record(
                "2023-01-15 14:30:43.000000",
                "{00000003-0000-0000-0000-000000000000}",
            ))
            .expect("parse");

        let timestamps: Vec<i64> = events.into_iter().map(|(ts, _)| ts).collect();
        assert_eq!(timestamps, vec![ts_0, ts_1, ts_2, ts_3]);
        // temp_dir is automatically cleaned up when dropped
    }

    fn create_non_ethernet_pcap_file() -> NamedTempFile {
        use std::io::Write;

        // Create a PCAP file manually with a non-ETHERNET link type
        // PCAP global header format (24 bytes):
        // - Magic number (little-endian): bytes d4 c3 b2 a1 (4 bytes)
        // - Major version: 2 (2 bytes)
        // - Minor version: 4 (2 bytes)
        // - Timezone offset: 0 (4 bytes)
        // - Timestamp accuracy: 0 (4 bytes)
        // - Snapshot length: 65535 (4 bytes)
        // - Link type: 113 = DLT_LINUX_SLL (Linux cooked capture, non-ETHERNET)
        let mut pcap_data = Vec::new();

        // PCAP global header (little endian)
        pcap_data.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
        pcap_data.extend_from_slice(&2_u16.to_le_bytes()); // major version
        pcap_data.extend_from_slice(&4_u16.to_le_bytes()); // minor version
        pcap_data.extend_from_slice(&0_i32.to_le_bytes()); // timezone
        pcap_data.extend_from_slice(&0_u32.to_le_bytes()); // timestamp accuracy
        pcap_data.extend_from_slice(&65535_u32.to_le_bytes()); // snapshot length
        // Link type: 113 = DLT_LINUX_SLL (Linux cooked capture)
        pcap_data.extend_from_slice(&113_u32.to_le_bytes());

        // Packet header (16 bytes) + minimal data
        // ts_sec, ts_usec, caplen, len
        pcap_data.extend_from_slice(&0_u32.to_le_bytes()); // ts_sec
        pcap_data.extend_from_slice(&0_u32.to_le_bytes()); // ts_usec
        pcap_data.extend_from_slice(&20_u32.to_le_bytes()); // caplen
        pcap_data.extend_from_slice(&20_u32.to_le_bytes()); // len

        // Dummy packet data (20 bytes)
        pcap_data.extend_from_slice(&[0u8; 20]);

        // Write to temp file
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file
            .write_all(&pcap_data)
            .expect("Failed to write pcap data");
        temp_file.flush().expect("Failed to flush temp file");
        temp_file
    }

    /// Tests that opening a PCAP file with a non-ETHERNET link type
    /// returns an error from `send_netflow`. This exercises the error
    /// branch in `send_netflow` that validates the datalink type.
    #[tokio::test]
    async fn send_netflow_rejects_non_ethernet_linktype() {
        let (server_addr, server_handle) = spawn_test_server(0);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "netflow9".to_string(),
            input: "/tmp/unused".to_string(),
            report: false,
            report_dir: None,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("create test producer");
        let temp_file = create_non_ethernet_pcap_file();
        let running = Arc::new(AtomicBool::new(true));
        let mut report = Report::new(config);

        let result = producer
            .send_netflow_to_giganto(temp_file.path(), 0, 0, running, &mut report)
            .await;

        let err = result.expect_err("Expected non-ETHERNET datalink to return an error");
        assert!(
            err.to_string().contains("Error: unknown datalink"),
            "Unexpected error message: {err}"
        );

        server_handle.abort();
        let _ = server_handle.await;
    }

    // ==========================================================================
    // NetFlow send_netflow Branch Coverage Tests
    //
    // These tests exercise the remaining untested branches inside
    // `send_netflow` in `src/producer.rs`:
    //   1. Non-NetFlow skip path (is_netflow != YesNetflowPackets)
    //   2. NetFlow header parse failure path
    //   3. Normal parse/send flow (V5 happy path)
    // ==========================================================================

    /// Build a minimal PCAP file (link type = ETHERNET) containing the
    /// given raw Ethernet frames.  Each entry in `packets` is a complete
    /// Ethernet frame (starting from the destination MAC).
    fn create_ethernet_pcap(packets: &[Vec<u8>]) -> tempfile::NamedTempFile {
        use std::io::Write;

        let mut pcap_data = Vec::new();

        // PCAP global header (24 bytes, little-endian)
        pcap_data.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes()); // magic
        pcap_data.extend_from_slice(&2_u16.to_le_bytes()); // major version
        pcap_data.extend_from_slice(&4_u16.to_le_bytes()); // minor version
        pcap_data.extend_from_slice(&0_i32.to_le_bytes()); // timezone
        pcap_data.extend_from_slice(&0_u32.to_le_bytes()); // timestamp accuracy
        pcap_data.extend_from_slice(&65535_u32.to_le_bytes()); // snapshot length
        pcap_data.extend_from_slice(&1_u32.to_le_bytes()); // link type = ETHERNET

        for pkt in packets {
            let cap_len = u32::try_from(pkt.len()).expect("packet too large");
            pcap_data.extend_from_slice(&1_u32.to_le_bytes()); // ts_sec
            pcap_data.extend_from_slice(&0_u32.to_le_bytes()); // ts_usec
            pcap_data.extend_from_slice(&cap_len.to_le_bytes()); // caplen
            pcap_data.extend_from_slice(&cap_len.to_le_bytes()); // len
            pcap_data.extend_from_slice(pkt);
        }

        let mut temp_file = NamedTempFile::new().expect("create temp pcap file");
        temp_file.write_all(&pcap_data).expect("write pcap data");
        temp_file.flush().expect("flush pcap file");
        temp_file
    }

    /// Build a complete Ethernet + IPv4 + UDP frame with the given payload
    /// and UDP destination port.
    fn build_ethernet_udp_frame(payload: &[u8], dst_port: u16) -> Vec<u8> {
        let mut frame = Vec::new();

        // Ethernet header (14 bytes)
        frame.extend_from_slice(&[0u8; 6]); // dst MAC
        frame.extend_from_slice(&[1, 2, 3, 4, 5, 6]); // src MAC
        frame.extend_from_slice(&0x0800_u16.to_be_bytes()); // EtherType = IPv4

        // IPv4 header (20 bytes)
        let total_len = 20_u16 + 8 + u16::try_from(payload.len()).unwrap_or(0);
        frame.push(0x45); // version=4, IHL=5
        frame.push(0); // DSCP/ECN
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&0x1234_u16.to_be_bytes()); // identification
        frame.extend_from_slice(&0_u16.to_be_bytes()); // flags/fragment
        frame.push(64); // TTL
        frame.push(0x11); // protocol = UDP
        frame.extend_from_slice(&0_u16.to_be_bytes()); // checksum
        frame.extend_from_slice(&[10, 0, 0, 1]); // src IP
        frame.extend_from_slice(&[10, 0, 0, 2]); // dst IP

        // UDP header (8 bytes)
        let udp_len = 8_u16 + u16::try_from(payload.len()).unwrap_or(0);
        frame.extend_from_slice(&1000_u16.to_be_bytes()); // src port
        frame.extend_from_slice(&dst_port.to_be_bytes()); // dst port
        frame.extend_from_slice(&udp_len.to_be_bytes()); // length
        frame.extend_from_slice(&0_u16.to_be_bytes()); // checksum

        frame.extend_from_slice(payload);
        frame
    }

    /// Build a complete Ethernet + IPv4 frame with a non-UDP protocol
    /// (TCP, proto 0x06). No transport-layer payload is included.
    fn build_ethernet_tcp_frame() -> Vec<u8> {
        let mut frame = Vec::new();

        // Ethernet header
        frame.extend_from_slice(&[0u8; 6]); // dst MAC
        frame.extend_from_slice(&[1, 2, 3, 4, 5, 6]); // src MAC
        frame.extend_from_slice(&0x0800_u16.to_be_bytes()); // EtherType = IPv4

        // IPv4 header (20 bytes) with protocol = TCP (0x06)
        let total_len = 20_u16;
        frame.push(0x45);
        frame.push(0);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&0x1234_u16.to_be_bytes());
        frame.extend_from_slice(&0_u16.to_be_bytes());
        frame.push(64);
        frame.push(0x06); // TCP
        frame.extend_from_slice(&0_u16.to_be_bytes());
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&[10, 0, 0, 2]);

        frame
    }

    /// Build a `NetFlow` V5 header (24 bytes) with the given record count.
    fn netflow_v5_header(count: u16) -> Vec<u8> {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&5_u16.to_be_bytes()); // version
        hdr.extend_from_slice(&count.to_be_bytes()); // count
        hdr.extend_from_slice(&1000_u32.to_be_bytes()); // sys_uptime
        hdr.extend_from_slice(&1_000_000_u32.to_be_bytes()); // unix_secs
        hdr.extend_from_slice(&0_u32.to_be_bytes()); // unix_nanos
        hdr.extend_from_slice(&1_u32.to_be_bytes()); // flow_sequence
        hdr.push(0); // engine_type
        hdr.push(0); // engine_id
        hdr.extend_from_slice(&0_u16.to_be_bytes()); // sampling_interval
        hdr
    }

    /// Build a single `NetFlow` V5 flow record (48 bytes).
    fn netflow_v5_record() -> Vec<u8> {
        let mut rec = Vec::new();
        rec.extend_from_slice(&[192, 168, 1, 1]); // src_addr
        rec.extend_from_slice(&[10, 0, 0, 1]); // dst_addr
        rec.extend_from_slice(&[0, 0, 0, 0]); // next_hop
        rec.extend_from_slice(&1_u16.to_be_bytes()); // input
        rec.extend_from_slice(&2_u16.to_be_bytes()); // output
        rec.extend_from_slice(&100_u32.to_be_bytes()); // d_pkts
        rec.extend_from_slice(&5000_u32.to_be_bytes()); // d_octets
        rec.extend_from_slice(&500_u32.to_be_bytes()); // first
        rec.extend_from_slice(&600_u32.to_be_bytes()); // last
        rec.extend_from_slice(&80_u16.to_be_bytes()); // src_port
        rec.extend_from_slice(&443_u16.to_be_bytes()); // dst_port
        rec.push(0); // pad1
        rec.push(0x02); // tcp_flags
        rec.push(6); // prot (TCP)
        rec.push(0); // tos
        rec.extend_from_slice(&100_u16.to_be_bytes()); // src_as
        rec.extend_from_slice(&200_u16.to_be_bytes()); // dst_as
        rec.push(24); // src_mask
        rec.push(24); // dst_mask
        rec.extend_from_slice(&0_u16.to_be_bytes()); // pad2
        assert_eq!(rec.len(), 48);
        rec
    }

    /// Tests the non-NetFlow skip path in `send_netflow`.
    ///
    /// Provides a packet that is valid Ethernet/IPv4 but uses TCP (not UDP),
    /// so `is_netflow()` returns `NoNetflowPackets`.  The function should
    /// continue without error and not attempt `NetFlow` parsing or sending.
    ///
    /// Verifies that no record header or event data is sent to the server
    /// by asserting that the server receives nothing after the producer
    /// finishes.
    #[tokio::test]
    async fn send_netflow_skips_non_netflow_packets() {
        let tcp_frame = build_ethernet_tcp_frame();
        let temp_file = create_ethernet_pcap(&[tcp_frame]);

        let (server_addr, server_handle) = spawn_test_server(0);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "netflow5".to_string(),
            input: "test".to_string(),
            report: false,
            report_dir: None,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("create test producer");
        let mut report = Report::new(config);
        let running = Arc::new(AtomicBool::new(true));

        let result = producer
            .send_netflow_to_giganto(temp_file.path(), 0, 0, running, &mut report)
            .await;

        // The function should succeed (no error) and report that 1 packet
        // was processed (even though it was skipped as non-NetFlow).
        let pkt_cnt = result.expect("send_netflow should succeed for non-NetFlow packets");
        assert_eq!(pkt_cnt, 1, "one packet should have been counted");

        // Prove that no record header or event was sent: the producer has
        // finished, so any data it might have written is already in-flight.
        // The server blocks on reading a record header; a short timeout
        // expiring confirms that nothing was sent.
        let no_send = tokio::time::timeout(Duration::from_millis(200), server_handle).await;
        assert!(
            no_send.is_err(),
            "server should not have received any data (no record header sent)"
        );
    }

    /// Tests the `NetFlow` header parse failure path in `send_netflow`.
    ///
    /// Provides two packets: the first passes `is_netflow()` detection
    /// (Ethernet + IPv4 + UDP on port 2055) but has a truncated payload so
    /// that `parse_netflow_header()` fails — exercising the
    /// `InvalidNetflowPackets` path.  The second packet is a valid V5
    /// flow to prove that processing continued past the failure.
    ///
    /// Verifies that:
    /// - Both packets are processed (`pkt_cnt == 2`).
    /// - Exactly one event is received by the server (from the valid
    ///   packet), proving the truncated packet produced no send and was
    ///   skipped via the `InvalidNetflowPackets` branch.
    #[tokio::test]
    async fn send_netflow_handles_header_parse_failure() {
        // Packet 1: truncated NetFlow payload (only 2 bytes instead of the
        // required 24 bytes for a V5 header). Passes is_netflow() but fails
        // parse_netflow_header(), exercising the InvalidNetflowPackets path.
        let truncated_payload = vec![0x00, 0x05]; // version=5 but nothing else
        let bad_frame = build_ethernet_udp_frame(&truncated_payload, 2055);

        // Packet 2: valid V5 flow that should be processed normally.
        let mut valid_payload = netflow_v5_header(1);
        valid_payload.extend_from_slice(&netflow_v5_record());
        let good_frame = build_ethernet_udp_frame(&valid_payload, 2055);

        let temp_file = create_ethernet_pcap(&[bad_frame, good_frame]);

        let (server_addr, server_handle) = spawn_test_server(1);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "netflow5".to_string(),
            input: "test".to_string(),
            report: false,
            report_dir: None,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("create test producer");
        let mut report = Report::new(config);
        let running = Arc::new(AtomicBool::new(true));

        let result = producer
            .send_netflow_to_giganto(temp_file.path(), 0, 0, running, &mut report)
            .await;

        // Both packets should be processed: the truncated one is skipped
        // via the `let Ok(header) = ... else { continue }` branch
        // (incrementing InvalidNetflowPackets), and the valid one is sent.
        let pkt_cnt = result.expect("send_netflow should handle parse failure gracefully");
        assert_eq!(pkt_cnt, 2, "both packets should have been counted");

        // The server should receive exactly one event — from the valid V5
        // packet.  This proves the truncated packet triggered the
        // InvalidNetflowPackets skip path and produced no send.
        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::Netflow5);
        assert_eq!(
            events.len(),
            1,
            "only the valid packet should produce an event"
        );
    }

    /// Tests the happy path in `send_netflow` with a valid `NetFlow` V5 packet.
    ///
    /// Provides a complete, well-formed `NetFlow` V5 packet containing one
    /// flow record.  Verifies that the parse succeeds and the event is
    /// transmitted to the test server.
    #[tokio::test]
    async fn send_netflow_v5_happy_path() {
        // Build a valid V5 payload: header (24 bytes) + one record (48 bytes)
        let mut payload = netflow_v5_header(1);
        payload.extend_from_slice(&netflow_v5_record());
        let frame = build_ethernet_udp_frame(&payload, 2055);
        let temp_file = create_ethernet_pcap(&[frame]);

        let (server_addr, server_handle) = spawn_test_server(1);
        let config = Config {
            cert: TEST_CERT_PATH.to_string(),
            key: TEST_KEY_PATH.to_string(),
            ca_certs: vec![TEST_ROOT_PATH.to_string()],
            giganto_ingest_srv_addr: server_addr,
            giganto_name: TEST_SERVER_NAME.to_string(),
            kind: "netflow5".to_string(),
            input: "test".to_string(),
            report: false,
            report_dir: None,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        };

        let mut producer = Producer::new_giganto(&config)
            .await
            .expect("create test producer");
        let mut report = Report::new(config);
        let running = Arc::new(AtomicBool::new(true));

        let result = producer
            .send_netflow_to_giganto(temp_file.path(), 0, 0, running, &mut report)
            .await;

        let pkt_cnt = result.expect("send_netflow should succeed for valid V5 packet");
        assert_eq!(pkt_cnt, 1, "one packet should have been processed");

        // Verify the server received exactly one event with the correct kind.
        let (kind, events) = server_handle.await.expect("server task");
        assert_eq!(kind, RawEventKind::Netflow5);
        assert_eq!(events.len(), 1, "server should receive exactly one event");
    }
}
