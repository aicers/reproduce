use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use giganto_client::{
    RawEventKind,
    ingest::{
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
use reproduce::checkpoint::Checkpoint;
use reproduce::collector::Collector;
use reproduce::collector::log::LogCollector;
use reproduce::collector::migration::MigrationCollector;
use reproduce::collector::netflow::NetflowCollector;
use reproduce::collector::operation_log::OplogCollector;
use reproduce::collector::security_log::SecurityLogCollector;
use reproduce::collector::sysmon_csv::SysmonCollector;
use reproduce::collector::zeek::ZeekCollector;
use reproduce::config::{Config, InputType};
use reproduce::parser::security_log::{
    Aiwaf, Axgate, Fgt, Mf2, Nginx, ShadowWall, SniperIps, SonicWall, Srx, Tg, Ubuntu, Vforce,
    Wapples,
};
use reproduce::parser::sysmon_csv::open_sysmon_csv_file;
use reproduce::parser::zeek::open_raw_event_log_file;
use reproduce::pipeline::run_pipeline;
use reproduce::sender::GigantoSender;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

use crate::report::Report;

const GIGANTO_ZEEK_KINDS: [&str; 19] = [
    "conn",
    "http",
    "rdp",
    "smtp",
    "dns",
    "ntlm",
    "kerberos",
    "ssh",
    "dce_rpc",
    "ftp",
    "mqtt",
    "ldap",
    "tls",
    "smb",
    "nfs",
    "bootp",
    "dhcp",
    "radius",
    "malformed_dns",
];
const AGENTS_LIST: [&str; 7] = [
    "manager",
    "data_store",
    "sensor",
    "semi_supervised",
    "time_series_generator",
    "unsupervised",
    "ti_container",
];
const OPERATION_LOG: &str = "oplog";
const SYSMON_KINDS: [&str; 14] = [
    "process_create",
    "file_create_time",
    "network_connect",
    "process_terminate",
    "image_load",
    "file_create",
    "registry_value_set",
    "registry_key_rename",
    "file_create_stream_hash",
    "pipe_event",
    "dns_query",
    "file_delete",
    "process_tamper",
    "file_delete_detected",
];
const NETFLOW_KIND: [&str; 2] = ["netflow5", "netflow9"];
const SUPPORTED_SECURITY_KIND: [&str; 13] = [
    "wapples_fw_6.0",
    "mf2_ips_4.0",
    "sniper_ips_8.0",
    "aiwaf_waf_4.1",
    "tg_ips_2.7",
    "vforce_ips_4.6",
    "srx_ips_15.1",
    "sonicwall_fw_6.5",
    "fgt_ips_6.2",
    "shadowwall_ips_5.0",
    "axgate_fw_2.1",
    "ubuntu_syslog_20.04",
    "nginx_accesslog_1.25.2",
];

/// Runs a collector through the pipeline, wrapping with report start/end
/// and returning the final position for checkpointing.
macro_rules! run_collector {
    ($collector:expr, $sender:expr, $report:expr) => {{
        let mut c = $collector;
        $report.start();
        run_pipeline(&mut c, $sender, |bytes| $report.process(bytes)).await?;
        if let Err(e) = $report.end() {
            warn!("Cannot write report: {e}");
        }
        c.position()
    }};
}

/// Creates and runs a zeek or migration collector based on the `migration` flag.
macro_rules! zeek_or_migration {
    ($iter:expr, $type:ty, $protocol:expr, $migration:expr,
     $skip:expr, $count_sent:expr, $fpm:expr, $dpm:expr, $running:expr,
     $sender:expr, $report:expr) => {{
        if $migration {
            run_collector!(
                MigrationCollector::<$type>::new(
                    $iter,
                    $protocol,
                    $skip,
                    $count_sent,
                    $fpm,
                    $dpm,
                    $running,
                ),
                $sender,
                $report
            )
        } else {
            run_collector!(
                ZeekCollector::<$type>::new(
                    $iter,
                    $protocol,
                    $skip,
                    $count_sent,
                    $fpm,
                    $dpm,
                    $running,
                ),
                $sender,
                $report
            )
        }
    }};
}

/// Same as `zeek_or_migration` but bails if not in migration mode.
macro_rules! migration_only {
    ($iter:expr, $type:ty, $protocol:expr, $migration:expr,
     $skip:expr, $count_sent:expr, $fpm:expr, $dpm:expr, $running:expr,
     $sender:expr, $report:expr, $name:literal) => {{
        if !$migration {
            bail!(concat!($name, " zeek log is not supported"));
        }
        run_collector!(
            MigrationCollector::<$type>::new(
                $iter,
                $protocol,
                $skip,
                $count_sent,
                $fpm,
                $dpm,
                $running,
            ),
            $sender,
            $report
        )
    }};
}

/// Creates and runs a sysmon or migration collector.
macro_rules! sysmon_or_migration {
    ($iter:expr, $type:ty, $protocol:expr, $migration:expr,
     $skip:expr, $count_sent:expr, $fpm:expr, $dpm:expr, $running:expr,
     $sender:expr, $report:expr) => {{
        if $migration {
            run_collector!(
                MigrationCollector::<$type>::new(
                    $iter,
                    $protocol,
                    $skip,
                    $count_sent,
                    $fpm,
                    $dpm,
                    $running,
                ),
                $sender,
                $report
            )
        } else {
            run_collector!(
                SysmonCollector::<$type>::new(
                    $iter,
                    $protocol,
                    $skip,
                    $count_sent,
                    $fpm,
                    $dpm,
                    $running,
                ),
                $sender,
                $report
            )
        }
    }};
}

pub struct Controller {
    config: Config,
}

impl Controller {
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// # Errors
    ///
    /// Returns an error if creating a converter fails.
    ///
    /// # Panics
    ///
    /// Stream finish / Connection close error
    pub async fn run(&self) -> Result<()> {
        let input_type = input_type(&self.config.input);

        if input_type == InputType::Elastic {
            self.run_elastic().await?;
        } else {
            let mut sender = create_sender(&self.config).await;

            match input_type {
                InputType::Dir => {
                    self.run_split(&mut sender).await?;
                }
                InputType::Log => {
                    let file_name = Path::new(&self.config.input).to_path_buf();
                    self.run_single(
                        file_name.as_ref(),
                        &mut sender,
                        &self.config.kind.clone(),
                        false,
                    )
                    .await?;
                }
                InputType::Elastic => {}
            }
            sender.finish().await.expect("failed to finish stream");
        }

        Ok(())
    }

    async fn run_split(&self, sender: &mut GigantoSender) -> Result<()> {
        let mut processed = Vec::new();
        let Some(ref dir_option) = self.config.directory else {
            bail!("directory's parameters is required");
        };
        loop {
            let mut files = files_in_dir(
                &self.config.input,
                dir_option.file_prefix.as_deref(),
                &processed,
            );
            if files.is_empty() {
                if dir_option.polling_mode {
                    tokio::time::sleep(Duration::from_millis(10_000)).await;
                    continue;
                }
                error!("No input file");
                break;
            }

            files.sort_unstable();
            for file in files {
                info!("File: {file:?}");
                self.run_single(
                    file.as_path(),
                    sender,
                    &self.config.kind,
                    dir_option.polling_mode,
                )
                .await?;
                processed.push(file);
            }

            if !dir_option.polling_mode {
                break;
            }
        }
        Ok(())
    }

    async fn run_elastic(&self) -> Result<()> {
        let Some(ref elastic) = self.config.elastic else {
            bail!("elastic parameters is required");
        };
        let dir = reproduce::parser::sysmon_csv::fetch_elastic_search(elastic).await?;

        let mut files = files_in_dir(&dir, None, &[]);
        if files.is_empty() {
            bail!("no data with elastic");
        }

        files.sort_unstable();
        for file in files {
            let mut sender = create_sender(&self.config).await;
            info!("File: {file:?}");
            let kind = file_to_kind(&file)?;
            self.run_single(file.as_path(), &mut sender, kind, false)
                .await?;
            std::fs::remove_file(&file)?;
            sender.finish().await.expect("failed to finish stream");
        }
        std::fs::remove_dir(&dir)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn run_single(
        &self,
        filename: &Path,
        sender: &mut GigantoSender,
        kind: &str,
        dir_polling_mode: bool,
    ) -> Result<()> {
        let input_type = input_type(&filename.to_string_lossy());
        if input_type == InputType::Dir {
            return Err(anyhow!("invalid input type"));
        }
        let Some(ref file) = self.config.file else {
            return Err(anyhow!("file's parameters is required"));
        };

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        if let Err(ctrlc::Error::System(e)) =
            ctrlc::set_handler(move || r.store(false, Ordering::SeqCst))
        {
            return Err(anyhow!("failed to set signal handler: {e}"));
        }

        let mut report = Report::new(self.config.clone());

        let checkpoint = file
            .last_transfer_line_suffix
            .as_ref()
            .map(|suffix| Checkpoint::from_input_and_suffix(&self.config.input, suffix));

        let offset = if let Some(count_skip) = file.transfer_skip_count {
            count_skip
        } else if let Some(ref cp) = checkpoint {
            cp.load()
        } else {
            0
        };
        let count_sent = file.transfer_count.unwrap_or(0);

        let last_line = match input_type {
            InputType::Log => {
                let fpm = file.polling_mode;
                let dpm = dir_polling_mode;

                if GIGANTO_ZEEK_KINDS.contains(&kind) {
                    let Some(migration) = file.export_from_giganto else {
                        bail!("export_from_giganto parameter is required");
                    };
                    let rdr = open_raw_event_log_file(filename)?;
                    let iter = rdr.into_records();
                    match kind {
                        "conn" => zeek_or_migration!(
                            iter,
                            Conn,
                            RawEventKind::Conn,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "http" => zeek_or_migration!(
                            iter,
                            Http,
                            RawEventKind::Http,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "rdp" => zeek_or_migration!(
                            iter,
                            Rdp,
                            RawEventKind::Rdp,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "smtp" => zeek_or_migration!(
                            iter,
                            Smtp,
                            RawEventKind::Smtp,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "dns" => zeek_or_migration!(
                            iter,
                            Dns,
                            RawEventKind::Dns,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "ntlm" => zeek_or_migration!(
                            iter,
                            Ntlm,
                            RawEventKind::Ntlm,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "kerberos" => zeek_or_migration!(
                            iter,
                            Kerberos,
                            RawEventKind::Kerberos,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "ssh" => zeek_or_migration!(
                            iter,
                            Ssh,
                            RawEventKind::Ssh,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "dce_rpc" => zeek_or_migration!(
                            iter,
                            DceRpc,
                            RawEventKind::DceRpc,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "ftp" => zeek_or_migration!(
                            iter,
                            Ftp,
                            RawEventKind::Ftp,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "ldap" => zeek_or_migration!(
                            iter,
                            Ldap,
                            RawEventKind::Ldap,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "tls" => zeek_or_migration!(
                            iter,
                            Tls,
                            RawEventKind::Tls,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "mqtt" => migration_only!(
                            iter,
                            Mqtt,
                            RawEventKind::Mqtt,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report,
                            "mqtt"
                        ),
                        "smb" => migration_only!(
                            iter,
                            Smb,
                            RawEventKind::Smb,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report,
                            "smb"
                        ),
                        "nfs" => migration_only!(
                            iter,
                            Nfs,
                            RawEventKind::Nfs,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report,
                            "nfs"
                        ),
                        "bootp" => migration_only!(
                            iter,
                            Bootp,
                            RawEventKind::Bootp,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report,
                            "bootp"
                        ),
                        "dhcp" => migration_only!(
                            iter,
                            Dhcp,
                            RawEventKind::Dhcp,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report,
                            "dhcp"
                        ),
                        "radius" => migration_only!(
                            iter,
                            Radius,
                            RawEventKind::Radius,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report,
                            "radius"
                        ),
                        "malformed_dns" => migration_only!(
                            iter,
                            MalformedDns,
                            RawEventKind::MalformedDns,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report,
                            "malformed_dns"
                        ),
                        _ => bail!("unknown zeek/migration kind"),
                    }
                } else if kind == OPERATION_LOG {
                    let agent = filename
                        .file_name()
                        .expect("input file name")
                        .to_str()
                        .expect("tostr")
                        .split_once('.')
                        .expect("filename must have an extension")
                        .0;
                    if !AGENTS_LIST.contains(&agent) {
                        bail!("invalid agent name `{agent}.log`");
                    }
                    let oplog = File::open(filename)?;
                    let rdr = BufReader::new(oplog);
                    run_collector!(
                        OplogCollector::new(
                            rdr,
                            agent.to_string(),
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running.clone(),
                        ),
                        sender,
                        report
                    )
                } else if SYSMON_KINDS.contains(&kind) {
                    let Some(migration) = file.export_from_giganto else {
                        bail!("export_from_giganto parameter is required");
                    };
                    let rdr = open_sysmon_csv_file(filename)?;
                    let iter = rdr.into_records();
                    let pos = match kind {
                        "process_create" => sysmon_or_migration!(
                            iter,
                            ProcessCreate,
                            RawEventKind::ProcessCreate,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "file_create_time" => sysmon_or_migration!(
                            iter,
                            FileCreationTimeChanged,
                            RawEventKind::FileCreateTime,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "network_connect" => sysmon_or_migration!(
                            iter,
                            NetworkConnection,
                            RawEventKind::NetworkConnect,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "process_terminate" => sysmon_or_migration!(
                            iter,
                            ProcessTerminated,
                            RawEventKind::ProcessTerminate,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "image_load" => sysmon_or_migration!(
                            iter,
                            ImageLoaded,
                            RawEventKind::ImageLoad,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "file_create" => sysmon_or_migration!(
                            iter,
                            FileCreate,
                            RawEventKind::FileCreate,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "registry_value_set" => sysmon_or_migration!(
                            iter,
                            RegistryValueSet,
                            RawEventKind::RegistryValueSet,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "registry_key_rename" => sysmon_or_migration!(
                            iter,
                            RegistryKeyValueRename,
                            RawEventKind::RegistryKeyRename,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "file_create_stream_hash" => sysmon_or_migration!(
                            iter,
                            FileCreateStreamHash,
                            RawEventKind::FileCreateStreamHash,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "pipe_event" => sysmon_or_migration!(
                            iter,
                            PipeEvent,
                            RawEventKind::PipeEvent,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "dns_query" => sysmon_or_migration!(
                            iter,
                            DnsEvent,
                            RawEventKind::DnsQuery,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "file_delete" => sysmon_or_migration!(
                            iter,
                            FileDelete,
                            RawEventKind::FileDelete,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "process_tamper" => sysmon_or_migration!(
                            iter,
                            ProcessTampering,
                            RawEventKind::ProcessTamper,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        "file_delete_detected" => sysmon_or_migration!(
                            iter,
                            FileDeleteDetected,
                            RawEventKind::FileDeleteDetected,
                            migration,
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running,
                            sender,
                            report
                        ),
                        _ => bail!("unknown sysmon kind"),
                    };
                    sender.reset_header();
                    pos
                } else if NETFLOW_KIND.contains(&kind) {
                    match kind {
                        "netflow5" => {
                            run_collector!(
                                NetflowCollector::<Netflow5>::new(
                                    filename,
                                    RawEventKind::Netflow5,
                                    offset,
                                    count_sent,
                                    running.clone(),
                                )?,
                                sender,
                                report
                            )
                        }
                        "netflow9" => {
                            run_collector!(
                                NetflowCollector::<Netflow9>::new(
                                    filename,
                                    RawEventKind::Netflow9,
                                    offset,
                                    count_sent,
                                    running.clone(),
                                )?,
                                sender,
                                report
                            )
                        }
                        _ => bail!("unknown netflow kind"),
                    }
                } else if SUPPORTED_SECURITY_KIND.contains(&kind) {
                    let seculog = File::open(filename)?;
                    let rdr = BufReader::new(seculog);
                    match kind {
                        "wapples_fw_6.0" => run_collector!(
                            SecurityLogCollector::<Wapples>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "mf2_ips_4.0" => run_collector!(
                            SecurityLogCollector::<Mf2>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "sniper_ips_8.0" => run_collector!(
                            SecurityLogCollector::<SniperIps>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "aiwaf_waf_4.1" => run_collector!(
                            SecurityLogCollector::<Aiwaf>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "tg_ips_2.7" => run_collector!(
                            SecurityLogCollector::<Tg>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "vforce_ips_4.6" => run_collector!(
                            SecurityLogCollector::<Vforce>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "srx_ips_15.1" => run_collector!(
                            SecurityLogCollector::<Srx>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "sonicwall_fw_6.5" => run_collector!(
                            SecurityLogCollector::<SonicWall>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "fgt_ips_6.2" => run_collector!(
                            SecurityLogCollector::<Fgt>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "shadowwall_ips_5.0" => run_collector!(
                            SecurityLogCollector::<ShadowWall>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "axgate_fw_2.1" => run_collector!(
                            SecurityLogCollector::<Axgate>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "ubuntu_syslog_20.04" => run_collector!(
                            SecurityLogCollector::<Ubuntu>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        "nginx_accesslog_1.25.2" => run_collector!(
                            SecurityLogCollector::<Nginx>::new(
                                rdr,
                                kind.to_string(),
                                offset,
                                count_sent,
                                fpm,
                                dpm,
                                running.clone()
                            ),
                            sender,
                            report
                        ),
                        _ => bail!("unknown security log kind"),
                    }
                } else {
                    run_collector!(
                        LogCollector::new(
                            filename,
                            kind.to_string(),
                            offset,
                            count_sent,
                            fpm,
                            dpm,
                            running.clone(),
                        )?,
                        sender,
                        report
                    )
                }
            }
            InputType::Dir | InputType::Elastic => {
                bail!("invalid input type: {input_type:?}");
            }
        };

        if let Some(ref cp) = checkpoint
            && let Err(e) = cp.save(last_line)
        {
            warn!("Cannot write to offset file: {e}");
        }

        Ok(())
    }
}

fn file_to_kind(path: &Path) -> Result<&str> {
    let re = regex::Regex::new(r"event(\d+)_log.csv")?;
    let file_name = path
        .file_name()
        .with_context(|| format!("invalid file path: {}", path.display()))?
        .to_str()
        .with_context(|| format!("invalid unicode: {}", path.display()))?;
    if let Some(cap) = re.captures(file_name) {
        let num = &cap[1];
        return Ok(match num {
            "1" => "process_create",
            "2" => "file_create_time",
            "3" => "network_connect",
            "5" => "process_terminate",
            "7" => "image_load",
            "11" => "file_create",
            "13" => "registry_value_set",
            "14" => "registry_key_rename",
            "15" => "file_create_stream_hash",
            "17" => "pipe_event",
            "22" => "dns_query",
            "23" => "file_delete",
            "25" => "process_tamper",
            "26" => "file_delete_detected",
            _ => "",
        });
    }
    Ok("")
}

fn files_in_dir(path: &str, prefix: Option<&str>, skip: &[PathBuf]) -> Vec<PathBuf> {
    WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|entry| {
            if let Ok(entry) = entry {
                if !entry.file_type().is_file() {
                    return None;
                }
                if let Some(prefix) = prefix
                    && let Some(name) = entry.path().file_name()
                    && !name.to_string_lossy().starts_with(prefix)
                {
                    return None;
                }

                let entry = entry.into_path();
                if skip.contains(&entry) {
                    None
                } else {
                    Some(entry)
                }
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn input_type(input: &str) -> InputType {
    if input == "elastic" {
        InputType::Elastic
    } else {
        let path = Path::new(input);
        if path.is_dir() {
            InputType::Dir
        } else {
            InputType::Log
        }
    }
}

async fn create_sender(config: &Config) -> GigantoSender {
    debug!("output type=GIGANTO");
    match GigantoSender::new(
        &config.cert,
        &config.key,
        &config.ca_certs,
        config.giganto_ingest_srv_addr,
        &config.giganto_name,
        &config.kind,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            error!("Cannot create sender: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn input_type_elastic() {
        // When input string is "elastic", it should return InputType::Elastic
        let result = input_type("elastic");
        assert_eq!(result, InputType::Elastic);
    }

    #[test]
    fn input_type_directory() {
        // Create a temporary directory
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path().to_string_lossy().to_string();

        // When input is a directory path, it should return InputType::Dir
        let result = input_type(&dir_path);
        assert_eq!(result, InputType::Dir);
    }

    #[test]
    fn input_type_file() {
        // Create a temporary directory and file
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir.path().join("test_file.csv");
        File::create(&file_path).expect("Failed to create temp file");

        // When input is a file path, it should return InputType::Log
        let result = input_type(&file_path.to_string_lossy());
        assert_eq!(result, InputType::Log);
    }

    #[test]
    fn input_type_nonexistent_path() {
        // Create a temporary directory, then construct a path to a non-existent file within it
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let nonexistent_path = temp_dir.path().join("does_not_exist.log");

        // When input is a non-existent path, it should return InputType::Log
        // (since Path::is_dir() returns false for non-existent paths)
        let result = input_type(&nonexistent_path.to_string_lossy());
        assert_eq!(result, InputType::Log);
    }

    #[test]
    fn files_in_dir_returns_all_files() {
        // Create a temporary directory with multiple files
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path();

        // Create test files
        File::create(dir_path.join("a.csv")).expect("Failed to create file");
        File::create(dir_path.join("b.csv")).expect("Failed to create file");
        File::create(dir_path.join("c.txt")).expect("Failed to create file");

        // Call files_in_dir without prefix filter
        let result = files_in_dir(&dir_path.to_string_lossy(), None, &[]);

        // Should return all 3 files
        assert_eq!(result.len(), 3);
        assert!(result.contains(&dir_path.join("a.csv")));
        assert!(result.contains(&dir_path.join("b.csv")));
        assert!(result.contains(&dir_path.join("c.txt")));
    }

    #[test]
    fn files_in_dir_prefix_filtering() {
        // Create a temporary directory with files that have different prefixes
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path();

        // Create test files with different prefixes
        File::create(dir_path.join("keep_a.csv")).expect("Failed to create file");
        File::create(dir_path.join("keep_b.csv")).expect("Failed to create file");
        File::create(dir_path.join("drop_a.csv")).expect("Failed to create file");
        File::create(dir_path.join("other.txt")).expect("Failed to create file");

        // Call files_in_dir with prefix filter "keep_"
        let result = files_in_dir(&dir_path.to_string_lossy(), Some("keep_"), &[]);

        // Should return only files starting with "keep_"
        assert_eq!(result.len(), 2);
        assert!(result.contains(&dir_path.join("keep_a.csv")));
        assert!(result.contains(&dir_path.join("keep_b.csv")));
        assert!(!result.contains(&dir_path.join("drop_a.csv")));
        assert!(!result.contains(&dir_path.join("other.txt")));
    }

    #[test]
    fn files_in_dir_skip_processed_files() {
        // Create a temporary directory with files
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path();

        // Create test files
        File::create(dir_path.join("file1.csv")).expect("Failed to create file");
        File::create(dir_path.join("file2.csv")).expect("Failed to create file");
        File::create(dir_path.join("file3.csv")).expect("Failed to create file");

        // Mark file1.csv and file2.csv as already processed
        let skip = vec![dir_path.join("file1.csv"), dir_path.join("file2.csv")];

        // Call files_in_dir with skip list
        let result = files_in_dir(&dir_path.to_string_lossy(), None, &skip);

        // Should return only file3.csv
        assert_eq!(result.len(), 1);
        assert!(result.contains(&dir_path.join("file3.csv")));
    }

    #[test]
    fn files_in_dir_empty_directory() {
        // Create an empty temporary directory
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path();

        // Call files_in_dir on empty directory
        let result = files_in_dir(&dir_path.to_string_lossy(), None, &[]);

        // Should return empty vector
        assert!(result.is_empty());
    }

    #[test]
    fn files_in_dir_prefix_matches_nothing() {
        // Create a temporary directory with files
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path();

        // Create test files
        File::create(dir_path.join("a.csv")).expect("Failed to create file");
        File::create(dir_path.join("b.csv")).expect("Failed to create file");

        // Call files_in_dir with prefix that matches nothing
        let result = files_in_dir(&dir_path.to_string_lossy(), Some("nonexistent_"), &[]);

        // Should return empty vector
        assert!(result.is_empty());
    }

    #[test]
    fn files_in_dir_excludes_directories() {
        // Create a temporary directory with files and a subdirectory
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path();

        // Create a file
        File::create(dir_path.join("file.csv")).expect("Failed to create file");

        // Create a subdirectory
        std::fs::create_dir(dir_path.join("subdir")).expect("Failed to create subdir");

        // Call files_in_dir
        let result = files_in_dir(&dir_path.to_string_lossy(), None, &[]);

        // Should return only the file, not the directory
        assert_eq!(result.len(), 1);
        assert!(result.contains(&dir_path.join("file.csv")));
    }

    #[test]
    fn files_in_dir_with_nested_files() {
        // Create a temporary directory with nested structure
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path();

        // Create files at root level
        File::create(dir_path.join("root.csv")).expect("Failed to create file");

        // Create subdirectory with files
        let subdir = dir_path.join("subdir");
        std::fs::create_dir(&subdir).expect("Failed to create subdir");
        File::create(subdir.join("nested.csv")).expect("Failed to create nested file");

        // Call files_in_dir
        let result = files_in_dir(&dir_path.to_string_lossy(), None, &[]);

        // Should return both files (WalkDir follows into subdirectories)
        assert_eq!(result.len(), 2);
        assert!(result.contains(&dir_path.join("root.csv")));
        assert!(result.contains(&subdir.join("nested.csv")));
    }

    #[test]
    fn files_in_dir_prefix_filtering_with_skip() {
        // Test combination of prefix filtering and skip list
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path();

        // Create test files
        File::create(dir_path.join("keep_a.csv")).expect("Failed to create file");
        File::create(dir_path.join("keep_b.csv")).expect("Failed to create file");
        File::create(dir_path.join("keep_c.csv")).expect("Failed to create file");
        File::create(dir_path.join("drop_a.csv")).expect("Failed to create file");

        // Skip one of the "keep_" files
        let skip = vec![dir_path.join("keep_a.csv")];

        // Call files_in_dir with prefix filter and skip list
        let result = files_in_dir(&dir_path.to_string_lossy(), Some("keep_"), &skip);

        // Should return only keep_b.csv and keep_c.csv
        assert_eq!(result.len(), 2);
        assert!(result.contains(&dir_path.join("keep_b.csv")));
        assert!(result.contains(&dir_path.join("keep_c.csv")));
        assert!(!result.contains(&dir_path.join("keep_a.csv")));
    }

    /// Helper to extract agent name from filename, replicating the validation
    /// logic in `run_single`.
    fn validate_agent_filename(filename: &Path) -> Option<&str> {
        let agent = filename
            .file_name()
            .expect("input file name")
            .to_str()
            .expect("tostr")
            .split_once('.')
            .expect("filename must have an extension")
            .0;
        if AGENTS_LIST.contains(&agent) {
            Some(agent)
        } else {
            None
        }
    }

    #[test]
    fn valid_agent_filenames() {
        let valid_filenames = [
            "manager.log",
            "data_store.txt",
            "sensor.csv",
            "semi_supervised.json",
            "time_series_generator.log.1",
            "unsupervised.dat",
            "ti_container.out",
        ];

        for filename in valid_filenames {
            let path = Path::new(filename);
            let result = validate_agent_filename(path);
            assert!(
                result.is_some(),
                "Expected valid agent filename: {filename}"
            );
        }
    }

    #[test]
    fn valid_agent_filenames_with_directory() {
        let valid_paths = [
            "/var/log/manager.txt",
            "/home/user/logs/data_store.csv",
            "relative/path/sensor.json",
            "./semi_supervised.dat",
            "../time_series_generator.out",
        ];

        for path_str in valid_paths {
            let path = Path::new(path_str);
            let result = validate_agent_filename(path);
            assert!(
                result.is_some(),
                "Expected valid agent filename with path: {path_str}"
            );
        }
    }

    #[test]
    fn invalid_agent_name_returns_none() {
        let invalid_agent_filenames = [
            "unknown_agent.txt",
            "invalid.csv",
            "test.json",
            "other_service.dat",
            "agent.out",
        ];

        for filename in invalid_agent_filenames {
            let path = Path::new(filename);
            let result = validate_agent_filename(path);
            assert!(
                result.is_none(),
                "Expected invalid agent name to return None: {filename}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "filename must have an extension")]
    fn panic_on_filename_without_dot() {
        let path = Path::new("manager_no_extension");
        let _ = validate_agent_filename(path);
    }

    #[test]
    #[should_panic(expected = "input file name")]
    fn panic_on_empty_path() {
        let path = Path::new("/");
        let _ = validate_agent_filename(path);
    }

    #[test]
    fn valid_agent_with_different_extensions() {
        let valid_with_other_ext = [
            "manager.txt",
            "sensor.csv",
            "data_store.json",
            "unsupervised.log.1",
        ];

        for filename in valid_with_other_ext {
            let path = Path::new(filename);
            let result = validate_agent_filename(path);
            assert!(
                result.is_some(),
                "Expected valid agent name regardless of extension: {filename}"
            );
        }
    }
}
