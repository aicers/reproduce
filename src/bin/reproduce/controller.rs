use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
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
use reproduce::collector::log::LogCollector;
use reproduce::collector::migration::MigrationCollector;
use reproduce::collector::netflow::NetflowCollector;
use reproduce::collector::operation_log::OplogCollector;
use reproduce::collector::security_log::SecurityLogCollector;
use reproduce::collector::sysmon_csv::SysmonCollector;
use reproduce::collector::zeek::ZeekCollector;
use reproduce::config::{Config, File as FileConfig, InputType};
use reproduce::parser::security_log::{
    Aiwaf, Axgate, Fgt, Mf2, Nginx, ShadowWall, SniperIps, SonicWall, Srx, Tg, Ubuntu, Vforce,
    Wapples,
};
use reproduce::parser::sysmon_csv::open_sysmon_csv_file;
use reproduce::parser::zeek::open_raw_event_log_file;
use reproduce::pipeline::{PipelineSender, run_pipeline_with_sender};
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
/// and returning the last successfully sent position for checkpointing.
macro_rules! run_collector {
    ($collector:expr, $sender:expr, $checkpoint:expr, $report:expr) => {{
        let mut c = $collector;
        $report.start();
        let pos = run_pipeline_with_sender(&mut c, $sender, $checkpoint, &mut |bytes| {
            $report.process(bytes)
        })
        .await?;
        if let Err(e) = $report.end() {
            warn!("Cannot write report: {e}");
        }
        pos
    }};
}

#[async_trait]
trait ControllerSender: PipelineSender {
    async fn finish(&mut self) -> Result<()>;
    fn reset_header(&mut self);
}

#[async_trait]
impl ControllerSender for GigantoSender {
    async fn finish(&mut self) -> Result<()> {
        Ok(GigantoSender::finish(self).await?)
    }

    fn reset_header(&mut self) {
        GigantoSender::reset_header(self);
    }
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
                $skip,
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
                $skip,
                $report
            )
        }
    }};
}

/// Creates a migration collector and bails if not in migration mode.
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
            $skip,
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
                $skip,
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
                $skip,
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
    pub async fn run(&self) -> Result<()> {
        let input_type = input_type(&self.config.input);

        if input_type == InputType::Elastic {
            self.run_elastic().await?;
        } else {
            let mut sender = create_sender(&self.config).await;
            self.run_with_sender(&mut sender).await?;
        }

        Ok(())
    }

    async fn run_with_sender<S>(&self, sender: &mut S) -> Result<()>
    where
        S: ControllerSender + ?Sized,
    {
        match input_type(&self.config.input) {
            InputType::Dir => self.run_split(sender).await?,
            InputType::Log => {
                let file_name = Path::new(&self.config.input).to_path_buf();
                self.run_single(file_name.as_ref(), sender, &self.config.kind, false)
                    .await?;
            }
            InputType::Elastic => bail!("elastic input requires a concrete sender factory"),
        }

        sender.finish().await.context("failed to finish stream")?;
        Ok(())
    }

    async fn run_split<S>(&self, sender: &mut S) -> Result<()>
    where
        S: ControllerSender + ?Sized,
    {
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
            sender.finish().await.context("failed to finish stream")?;
        }
        std::fs::remove_dir(&dir)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn run_single<S>(
        &self,
        filename: &Path,
        sender: &mut S,
        kind: &str,
        dir_polling_mode: bool,
    ) -> Result<()>
    where
        S: ControllerSender + ?Sized,
    {
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

        let report = Report::new(self.config.clone());

        let checkpoint = checkpoint_for_input(
            &self.config.input,
            file.last_transfer_line_suffix.as_deref(),
        );
        let offset = resolve_offset(file, checkpoint.as_ref());
        let count_sent = file.transfer_count.unwrap_or(0);

        let last_line = match input_type {
            InputType::Log => {
                let options = CollectorRunOptions {
                    offset,
                    count_sent,
                    file_polling_mode: file.polling_mode,
                    dir_polling_mode,
                    running,
                };

                if GIGANTO_ZEEK_KINDS.contains(&kind) {
                    run_zeek_kind(
                        filename,
                        kind,
                        migration_enabled(file)?,
                        options,
                        sender,
                        report,
                    )
                    .await?
                } else if kind == OPERATION_LOG {
                    run_operation_log(filename, options, sender, report).await?
                } else if SYSMON_KINDS.contains(&kind) {
                    let pos = run_sysmon_kind(
                        filename,
                        kind,
                        migration_enabled(file)?,
                        options,
                        sender,
                        report,
                    )
                    .await?;
                    sender.reset_header();
                    pos
                } else if NETFLOW_KIND.contains(&kind) {
                    run_netflow_kind(filename, kind, options, sender, report).await?
                } else if SUPPORTED_SECURITY_KIND.contains(&kind) {
                    run_security_kind(filename, kind, options, sender, report).await?
                } else {
                    run_log_kind(filename, kind, options, sender, report).await?
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

fn migration_enabled(file: &FileConfig) -> Result<bool> {
    file.export_from_giganto
        .context("export_from_giganto parameter is required")
}

struct CollectorRunOptions {
    offset: u64,
    count_sent: u64,
    file_polling_mode: bool,
    dir_polling_mode: bool,
    running: Arc<AtomicBool>,
}

// The kind-to-collector mapping is intentionally explicit so supported formats
// stay visible in one place.
#[allow(clippy::too_many_lines)]
async fn run_zeek_kind<S>(
    filename: &Path,
    kind: &str,
    migration: bool,
    options: CollectorRunOptions,
    sender: &mut S,
    mut report: Report,
) -> Result<u64>
where
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        running,
    } = options;
    let rdr = open_raw_event_log_file(filename)?;
    let iter = rdr.into_records();
    match kind {
        "conn" => Ok(zeek_or_migration!(
            iter,
            Conn,
            RawEventKind::Conn,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "http" => Ok(zeek_or_migration!(
            iter,
            Http,
            RawEventKind::Http,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "rdp" => Ok(zeek_or_migration!(
            iter,
            Rdp,
            RawEventKind::Rdp,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "smtp" => Ok(zeek_or_migration!(
            iter,
            Smtp,
            RawEventKind::Smtp,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "dns" => Ok(zeek_or_migration!(
            iter,
            Dns,
            RawEventKind::Dns,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "ntlm" => Ok(zeek_or_migration!(
            iter,
            Ntlm,
            RawEventKind::Ntlm,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "kerberos" => Ok(zeek_or_migration!(
            iter,
            Kerberos,
            RawEventKind::Kerberos,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "ssh" => Ok(zeek_or_migration!(
            iter,
            Ssh,
            RawEventKind::Ssh,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "dce_rpc" => Ok(zeek_or_migration!(
            iter,
            DceRpc,
            RawEventKind::DceRpc,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "ftp" => Ok(zeek_or_migration!(
            iter,
            Ftp,
            RawEventKind::Ftp,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "ldap" => Ok(zeek_or_migration!(
            iter,
            Ldap,
            RawEventKind::Ldap,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "tls" => Ok(zeek_or_migration!(
            iter,
            Tls,
            RawEventKind::Tls,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "mqtt" => Ok(migration_only!(
            iter,
            Mqtt,
            RawEventKind::Mqtt,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report,
            "mqtt"
        )),
        "smb" => Ok(migration_only!(
            iter,
            Smb,
            RawEventKind::Smb,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report,
            "smb"
        )),
        "nfs" => Ok(migration_only!(
            iter,
            Nfs,
            RawEventKind::Nfs,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report,
            "nfs"
        )),
        "bootp" => Ok(migration_only!(
            iter,
            Bootp,
            RawEventKind::Bootp,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report,
            "bootp"
        )),
        "dhcp" => Ok(migration_only!(
            iter,
            Dhcp,
            RawEventKind::Dhcp,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report,
            "dhcp"
        )),
        "radius" => Ok(migration_only!(
            iter,
            Radius,
            RawEventKind::Radius,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report,
            "radius"
        )),
        "malformed_dns" => Ok(migration_only!(
            iter,
            MalformedDns,
            RawEventKind::MalformedDns,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report,
            "malformed_dns"
        )),
        _ => bail!("unknown zeek/migration kind"),
    }
}

async fn run_operation_log<S>(
    filename: &Path,
    options: CollectorRunOptions,
    sender: &mut S,
    mut report: Report,
) -> Result<u64>
where
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        running,
    } = options;
    let agent = operation_log_agent_name(filename)?;
    let oplog = File::open(filename)?;
    let rdr = BufReader::new(oplog);
    Ok(run_collector!(
        OplogCollector::new(
            rdr,
            agent.to_string(),
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
        ),
        sender,
        offset,
        report
    ))
}

// The kind-to-collector mapping is intentionally explicit so supported formats
// stay visible in one place.
#[allow(clippy::too_many_lines)]
async fn run_sysmon_kind<S>(
    filename: &Path,
    kind: &str,
    migration: bool,
    options: CollectorRunOptions,
    sender: &mut S,
    mut report: Report,
) -> Result<u64>
where
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        running,
    } = options;
    let rdr = open_sysmon_csv_file(filename)?;
    let iter = rdr.into_records();
    match kind {
        "process_create" => Ok(sysmon_or_migration!(
            iter,
            ProcessCreate,
            RawEventKind::ProcessCreate,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "file_create_time" => Ok(sysmon_or_migration!(
            iter,
            FileCreationTimeChanged,
            RawEventKind::FileCreateTime,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "network_connect" => Ok(sysmon_or_migration!(
            iter,
            NetworkConnection,
            RawEventKind::NetworkConnect,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "process_terminate" => Ok(sysmon_or_migration!(
            iter,
            ProcessTerminated,
            RawEventKind::ProcessTerminate,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "image_load" => Ok(sysmon_or_migration!(
            iter,
            ImageLoaded,
            RawEventKind::ImageLoad,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "file_create" => Ok(sysmon_or_migration!(
            iter,
            FileCreate,
            RawEventKind::FileCreate,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "registry_value_set" => Ok(sysmon_or_migration!(
            iter,
            RegistryValueSet,
            RawEventKind::RegistryValueSet,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "registry_key_rename" => Ok(sysmon_or_migration!(
            iter,
            RegistryKeyValueRename,
            RawEventKind::RegistryKeyRename,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "file_create_stream_hash" => Ok(sysmon_or_migration!(
            iter,
            FileCreateStreamHash,
            RawEventKind::FileCreateStreamHash,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "pipe_event" => Ok(sysmon_or_migration!(
            iter,
            PipeEvent,
            RawEventKind::PipeEvent,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "dns_query" => Ok(sysmon_or_migration!(
            iter,
            DnsEvent,
            RawEventKind::DnsQuery,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "file_delete" => Ok(sysmon_or_migration!(
            iter,
            FileDelete,
            RawEventKind::FileDelete,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "process_tamper" => Ok(sysmon_or_migration!(
            iter,
            ProcessTampering,
            RawEventKind::ProcessTamper,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        "file_delete_detected" => Ok(sysmon_or_migration!(
            iter,
            FileDeleteDetected,
            RawEventKind::FileDeleteDetected,
            migration,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
            sender,
            report
        )),
        _ => bail!("unknown sysmon kind"),
    }
}

async fn run_netflow_kind<S>(
    filename: &Path,
    kind: &str,
    options: CollectorRunOptions,
    sender: &mut S,
    mut report: Report,
) -> Result<u64>
where
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        running,
        ..
    } = options;
    match kind {
        "netflow5" => Ok(run_collector!(
            NetflowCollector::<Netflow5>::new(
                filename,
                RawEventKind::Netflow5,
                offset,
                count_sent,
                running,
            )?,
            sender,
            offset,
            report
        )),
        "netflow9" => Ok(run_collector!(
            NetflowCollector::<Netflow9>::new(
                filename,
                RawEventKind::Netflow9,
                offset,
                count_sent,
                running,
            )?,
            sender,
            offset,
            report
        )),
        _ => bail!("unknown netflow kind"),
    }
}

// The kind-to-collector mapping is intentionally explicit so supported formats
// stay visible in one place.
#[allow(clippy::too_many_lines)]
async fn run_security_kind<S>(
    filename: &Path,
    kind: &str,
    options: CollectorRunOptions,
    sender: &mut S,
    mut report: Report,
) -> Result<u64>
where
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        running,
    } = options;
    let seculog = File::open(filename)?;
    let rdr = BufReader::new(seculog);
    match kind {
        "wapples_fw_6.0" => Ok(run_collector!(
            SecurityLogCollector::<Wapples>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "mf2_ips_4.0" => Ok(run_collector!(
            SecurityLogCollector::<Mf2>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "sniper_ips_8.0" => Ok(run_collector!(
            SecurityLogCollector::<SniperIps>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "aiwaf_waf_4.1" => Ok(run_collector!(
            SecurityLogCollector::<Aiwaf>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "tg_ips_2.7" => Ok(run_collector!(
            SecurityLogCollector::<Tg>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "vforce_ips_4.6" => Ok(run_collector!(
            SecurityLogCollector::<Vforce>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "srx_ips_15.1" => Ok(run_collector!(
            SecurityLogCollector::<Srx>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "sonicwall_fw_6.5" => Ok(run_collector!(
            SecurityLogCollector::<SonicWall>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "fgt_ips_6.2" => Ok(run_collector!(
            SecurityLogCollector::<Fgt>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "shadowwall_ips_5.0" => Ok(run_collector!(
            SecurityLogCollector::<ShadowWall>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "axgate_fw_2.1" => Ok(run_collector!(
            SecurityLogCollector::<Axgate>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "ubuntu_syslog_20.04" => Ok(run_collector!(
            SecurityLogCollector::<Ubuntu>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        "nginx_accesslog_1.25.2" => Ok(run_collector!(
            SecurityLogCollector::<Nginx>::new(
                rdr,
                kind.to_string(),
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                running
            ),
            sender,
            offset,
            report
        )),
        _ => bail!("unknown security log kind"),
    }
}

async fn run_log_kind<S>(
    filename: &Path,
    kind: &str,
    options: CollectorRunOptions,
    sender: &mut S,
    mut report: Report,
) -> Result<u64>
where
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        running,
    } = options;
    Ok(run_collector!(
        LogCollector::new(
            filename,
            kind.to_string(),
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            running,
        )?,
        sender,
        offset,
        report
    ))
}

fn checkpoint_for_input(input: &str, suffix: Option<&str>) -> Option<Checkpoint> {
    suffix.map(|value| Checkpoint::from_input_and_suffix(input, value))
}

fn resolve_offset(file: &FileConfig, checkpoint: Option<&Checkpoint>) -> u64 {
    if let Some(count_skip) = file.transfer_skip_count {
        count_skip
    } else if let Some(cp) = checkpoint {
        cp.load()
    } else {
        0
    }
}

fn operation_log_agent_name(path: &Path) -> Result<&str> {
    let file_name = path
        .file_name()
        .with_context(|| format!("missing file name in {}", path.display()))?;
    let file_name = file_name
        .to_str()
        .with_context(|| format!("invalid unicode in {}", path.display()))?;
    let (agent, _) = file_name
        .split_once('.')
        .with_context(|| format!("operation log file must have an extension: {file_name}"))?;
    if AGENTS_LIST.contains(&agent) {
        Ok(agent)
    } else {
        bail!("invalid agent name `{file_name}`");
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
        let Some(num) = cap.get(1).map(|m| m.as_str()) else {
            return Ok("");
        };
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
    use std::fs::{self, File};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use async_trait::async_trait;
    use giganto_client::{
        RawEventKind,
        connection::server_handshake,
        frame::{RecvError, SendError, recv_raw},
        ingest::{log::Log as GigantoLog, receive_record_header},
    };
    use quinn::Endpoint;
    use reproduce::config::Directory;
    use reproduce::sender::{CHANNEL_CLOSE_TIMESTAMP, REQUIRED_GIGANTO_VERSION};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tempfile::tempdir;
    use tokio::time::timeout;

    use super::*;

    const ETHERNET_DATALINK: u32 = 1;
    const PROTO_UDP: u8 = 17;
    const TEST_ROOT_PEM: &str = "tests/root.pem";
    const TEST_CERT_PEM: &str = "tests/cert.pem";
    const TEST_KEY_PEM: &str = "tests/key.pem";
    const TEST_SERVER_NAME: &str = "localhost";
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const SYSMON_HEADER: &str = "agent_name\tagent_id\tevent_action\tutc_time\tprocess_guid\tprocess_id\timage\t\
         file_version\tdescription\tproduct\tcompany\toriginal_file_name\tcommand_line\t\
         current_directory\tuser\tlogon_guid\tlogon_id\tterminal_session_id\t\
         integrity_level\thashes\tparent_process_guid\tparent_process_id\t\
         parent_image\tparent_command_line\tparent_user";
    const SYSMON_PC_1: &str = "sensor\tagent001\tProcess Create\t2023-01-15 14:30:45.123456\t{AAAA-0001}\t1234\tC:\\notepad.exe\t1.0\tdesc\tprod\tco\torig.exe\tnotepad.exe /f\tC:\\Windows\\\tSYSTEM\t{BBBB-0001}\t0x3e7\t0\tSystem\tSHA256=abc123\t{CCCC-0001}\t5678\tC:\\explorer.exe\texplorer.exe\tSYSTEM";
    const ZEEK_CONN_1: &str = "1669773412.689790\tuid001aaa\t192.168.1.77\t57655\t209.197.168.151\t1024\ttcp\tirc-dcc-data\t2.256935\t124\t42208\tSF\t-\t-\t0\tShAdDaFf\t28\t1592\t43\t44452\t-";
    const MIGR_CONN_1: &str = "1669773412.655728000\tsrc1\t192.168.1.77\t57655\t209.197.168.151\t1024\t6\tSF\t1669773412.655728000\t2256935000\tirc-dcc-data\t124\t42208\t28\t43\t1592\t44452";
    const OPLOG_LINE: &str = "2023-01-02T07:36:17Z INFO msg1";
    const WAPPLES_LINE: &str = "<182>Jan 9 09:26:09 host wplogd: WAPPLES INTRUSION WAPPLES \
        DETECTION TIME : 2020-01-09 09:26:09 +0900 WAPPLES RULE NAME : \
        SQL Injection WAPPLES (client 192.168.1.100 WAPPLES) -> \
        (server 10.0.0.1:80)";

    struct MockSender {
        batch_sizes: Vec<usize>,
        ensured_protocols: Vec<RawEventKind>,
        finish_calls: usize,
        reconnect_calls: usize,
        reset_header_calls: usize,
        header_pending: bool,
    }

    impl Default for MockSender {
        fn default() -> Self {
            Self {
                batch_sizes: Vec::new(),
                ensured_protocols: Vec::new(),
                finish_calls: 0,
                reconnect_calls: 0,
                reset_header_calls: 0,
                header_pending: true,
            }
        }
    }

    #[async_trait]
    impl PipelineSender for MockSender {
        async fn ensure_header_sent(
            &mut self,
            protocol: RawEventKind,
        ) -> std::result::Result<(), reproduce::sender::SenderError> {
            if self.header_pending {
                self.ensured_protocols.push(protocol);
                self.header_pending = false;
            }
            Ok(())
        }

        async fn send_batch(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
            self.batch_sizes.push(events.len());
            Ok(())
        }

        async fn reconnect(&mut self) -> std::result::Result<(), reproduce::sender::SenderError> {
            self.reconnect_calls += 1;
            Ok(())
        }
    }

    #[async_trait]
    impl ControllerSender for MockSender {
        async fn finish(&mut self) -> Result<()> {
            self.finish_calls += 1;
            Ok(())
        }

        fn reset_header(&mut self) {
            self.reset_header_calls += 1;
            self.header_pending = true;
        }
    }

    fn file_config(
        transfer_skip_count: Option<u64>,
        last_transfer_line_suffix: Option<&str>,
    ) -> FileConfig {
        FileConfig {
            export_from_giganto: Some(false),
            polling_mode: false,
            transfer_count: None,
            transfer_skip_count,
            last_transfer_line_suffix: last_transfer_line_suffix.map(str::to_string),
        }
    }

    fn test_config(input: &Path, kind: &str) -> Config {
        Config {
            cert: String::new(),
            key: String::new(),
            ca_certs: Vec::new(),
            giganto_ingest_srv_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
            giganto_name: "giganto".to_string(),
            kind: kind.to_string(),
            input: input.to_string_lossy().into_owned(),
            report: false,
            report_dir: None,
            log_path: None,
            file: Some(FileConfig {
                export_from_giganto: Some(false),
                polling_mode: false,
                transfer_count: None,
                transfer_skip_count: None,
                last_transfer_line_suffix: None,
            }),
            directory: None,
            elastic: None,
        }
    }

    fn controller_for_file(
        input: &Path,
        kind: &str,
        export_from_giganto: Option<bool>,
        last_transfer_line_suffix: Option<&str>,
    ) -> Controller {
        let mut config = test_config(input, kind);
        config.file = Some(FileConfig {
            export_from_giganto,
            polling_mode: false,
            transfer_count: None,
            transfer_skip_count: None,
            last_transfer_line_suffix: last_transfer_line_suffix.map(str::to_string),
        });
        Controller::new(config)
    }

    fn controller_for_directory(input: &Path, kind: &str, prefix: Option<&str>) -> Controller {
        let mut config = test_config(input, kind);
        config.directory = Some(Directory {
            file_prefix: prefix.map(str::to_string),
            polling_mode: false,
        });
        Controller::new(config)
    }

    fn write_text_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("test fixture should be written");
        path
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        filtered
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("valid hex bytes"), 16)
                    .expect("valid hex pair")
            })
            .collect()
    }

    fn write_pcap(path: &Path, packets: &[Vec<u8>]) {
        let mut file = File::create(path).expect("pcap fixture should be created");
        file.write_all(&0xa1b2_c3d4_u32.to_le_bytes())
            .expect("pcap header should be written");
        file.write_all(&2u16.to_le_bytes())
            .expect("pcap version major should be written");
        file.write_all(&4u16.to_le_bytes())
            .expect("pcap version minor should be written");
        file.write_all(&0i32.to_le_bytes())
            .expect("pcap timezone should be written");
        file.write_all(&0u32.to_le_bytes())
            .expect("pcap sigfigs should be written");
        file.write_all(&65_535u32.to_le_bytes())
            .expect("pcap snaplen should be written");
        file.write_all(&ETHERNET_DATALINK.to_le_bytes())
            .expect("pcap linktype should be written");

        for packet in packets {
            let packet_len = u32::try_from(packet.len()).unwrap_or_default();
            file.write_all(&0u32.to_le_bytes())
                .expect("packet seconds should be written");
            file.write_all(&0u32.to_le_bytes())
                .expect("packet micros should be written");
            file.write_all(&packet_len.to_le_bytes())
                .expect("captured length should be written");
            file.write_all(&packet_len.to_le_bytes())
                .expect("original length should be written");
            file.write_all(packet)
                .expect("packet payload should be written");
        }
    }

    fn build_ipv4_udp_packet(payload: &[u8], dst_port: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 6]);
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        bytes.extend_from_slice(&0x0800u16.to_be_bytes());

        let total_len = 20u16 + 8u16 + u16::try_from(payload.len()).unwrap_or_default();
        bytes.push(0x45);
        bytes.push(0);
        bytes.extend_from_slice(&total_len.to_be_bytes());
        bytes.extend_from_slice(&0x1234u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.push(64);
        bytes.push(PROTO_UDP);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&[10, 0, 0, 1]);
        bytes.extend_from_slice(&[10, 0, 0, 2]);

        let udp_len = 8u16 + u16::try_from(payload.len()).unwrap_or_default();
        bytes.extend_from_slice(&1000u16.to_be_bytes());
        bytes.extend_from_slice(&dst_port.to_be_bytes());
        bytes.extend_from_slice(&udp_len.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(payload);

        bytes
    }

    fn v5_header_bytes(count: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u16.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.push(5);
        bytes.push(6);
        bytes.extend_from_slice(&0x4001u16.to_be_bytes());
        bytes
    }

    fn build_v5_packet(record_count: u16) -> Vec<u8> {
        let record = hex_to_bytes(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/netflow/v5_record.hex"
        )));

        let mut payload = v5_header_bytes(record_count);
        for _ in 0..record_count {
            payload.extend_from_slice(&record);
        }

        build_ipv4_udp_packet(&payload, 2055)
    }

    fn default_run_options() -> CollectorRunOptions {
        CollectorRunOptions {
            offset: 0,
            count_sent: 0,
            file_polling_mode: false,
            dir_polling_mode: false,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    fn report_for(input: &Path, kind: &str) -> Report {
        Report::new(test_config(input, kind))
    }

    fn fixture_path(relative: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(relative)
            .to_string_lossy()
            .into_owned()
    }

    fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
        let cert_pem = fs::read(path)
            .with_context(|| format!("test certificate should be readable: {}", path.display()))?;
        rustls_pemfile::certs(&mut &*cert_pem)
            .collect::<Result<_, _>>()
            .context("test certificate PEM should parse")
    }

    fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
        let key_pem = fs::read(path)
            .with_context(|| format!("test key should be readable: {}", path.display()))?;
        rustls_pemfile::private_key(&mut &*key_pem)
            .context("test key PEM should parse")?
            .context("test key PEM should contain a private key")
    }

    fn build_server_endpoint() -> Result<(Endpoint, SocketAddr)> {
        let cert_chain = load_cert_chain(Path::new(&fixture_path(TEST_CERT_PEM)))?;
        let private_key = load_private_key(Path::new(&fixture_path(TEST_KEY_PEM)))?;
        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("test server certificate configuration should be valid")?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .context("test server QUIC config should build")?,
        ));
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint = Endpoint::server(server_config, bind_addr)
            .context("test server endpoint should bind")?;
        let addr = endpoint
            .local_addr()
            .context("test server endpoint should have a local address")?;
        Ok((endpoint, addr))
    }

    struct ServerCapture {
        record_header: u32,
        events: Vec<(i64, Vec<u8>)>,
    }

    async fn serve_single_connection(server_endpoint: Endpoint) -> Result<ServerCapture> {
        let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
            .await
            .context("test server should accept a controller connection in time")?
            .context("test server endpoint should stay open while accepting")?;
        let connection = incoming
            .await
            .context("controller connection should complete QUIC setup")?;

        let _handshake = server_handshake(&connection, REQUIRED_GIGANTO_VERSION)
            .await
            .context("controller sender should complete the Giganto handshake")?;
        let (mut server_send, mut server_recv) = timeout(TEST_TIMEOUT, connection.accept_bi())
            .await
            .context("test server should accept the data stream in time")?
            .context("test server should accept the data stream")?;

        let mut header = [0_u8; std::mem::size_of::<u32>()];
        receive_record_header(&mut server_recv, &mut header)
            .await
            .context("test server should receive the record header")?;

        let mut events = Vec::new();
        let mut batch_buf = Vec::new();
        loop {
            match timeout(TEST_TIMEOUT, recv_raw(&mut server_recv, &mut batch_buf)).await {
                Ok(Ok(())) => {
                    let batch: Vec<(i64, Vec<u8>)> = bincode::deserialize(&batch_buf)
                        .context("server batch payload should deserialize")?;
                    let mut saw_close = false;
                    for (timestamp, payload) in batch {
                        if timestamp == CHANNEL_CLOSE_TIMESTAMP {
                            saw_close = true;
                        } else {
                            events.push((timestamp, payload));
                        }
                    }
                    if saw_close {
                        server_send
                            .write_all(&CHANNEL_CLOSE_TIMESTAMP.to_be_bytes())
                            .await
                            .context("test server should send the close ACK")?;
                        server_send
                            .finish()
                            .context("test server ACK stream should finish cleanly")?;
                        break;
                    }
                }
                Ok(Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_)))) => break,
                Ok(Err(err)) => bail!("unexpected server receive error: {err}"),
                Err(_) => bail!("timed out waiting for controller event data"),
            }
        }

        server_endpoint.wait_idle().await;
        Ok(ServerCapture {
            record_header: u32::from_le_bytes(header),
            events,
        })
    }

    fn giganto_config(input: &Path, kind: &str, server_addr: SocketAddr) -> Config {
        let mut config = test_config(input, kind);
        config.cert = fixture_path(TEST_CERT_PEM);
        config.key = fixture_path(TEST_KEY_PEM);
        config.ca_certs = vec![fixture_path(TEST_ROOT_PEM)];
        config.giganto_ingest_srv_addr = server_addr;
        config.giganto_name = TEST_SERVER_NAME.to_string();
        config
    }

    fn decode_logs(capture: &ServerCapture) -> Vec<GigantoLog> {
        capture
            .events
            .iter()
            .map(|(_, payload)| {
                bincode::deserialize(payload).expect("captured payload should deserialize as Log")
            })
            .collect()
    }

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
            let result = operation_log_agent_name(path);
            assert!(result.is_ok(), "Expected valid agent filename: {filename}");
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
            let result = operation_log_agent_name(path);
            assert!(
                result.is_ok(),
                "Expected valid agent filename with path: {path_str}"
            );
        }
    }

    #[test]
    fn invalid_agent_name_returns_error() {
        let invalid_agent_filenames = [
            "unknown_agent.txt",
            "invalid.csv",
            "test.json",
            "other_service.dat",
            "agent.out",
        ];

        for filename in invalid_agent_filenames {
            let path = Path::new(filename);
            let result = operation_log_agent_name(path);
            assert!(
                result.is_err(),
                "Expected invalid agent name to return an error: {filename}"
            );
        }
    }

    #[test]
    fn returns_error_on_filename_without_dot() {
        let path = Path::new("manager_no_extension");
        let err = operation_log_agent_name(path).expect_err("missing extension must be rejected");
        assert!(err.to_string().contains("must have an extension"));
    }

    #[test]
    fn returns_error_on_empty_path() {
        let path = Path::new("/");
        let err =
            operation_log_agent_name(path).expect_err("path without a file name must be rejected");
        assert!(err.to_string().contains("missing file name"));
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
            let result = operation_log_agent_name(path);
            assert!(
                result.is_ok(),
                "Expected valid agent name regardless of extension: {filename}"
            );
        }
    }

    #[test]
    fn file_to_kind_maps_supported_sysmon_event_codes() {
        let kind = file_to_kind(Path::new("event1_log.csv"))
            .expect("known sysmon event file name should parse");
        assert_eq!(kind, "process_create");

        let kind = file_to_kind(Path::new("event26_log.csv"))
            .expect("known sysmon event file name should parse");
        assert_eq!(kind, "file_delete_detected");
    }

    #[test]
    fn file_to_kind_returns_empty_for_unknown_event_code() {
        let kind = file_to_kind(Path::new("event999_log.csv"))
            .expect("unknown sysmon event file name should still parse");
        assert_eq!(kind, "");
    }

    #[test]
    fn file_to_kind_returns_empty_for_non_matching_file_name() {
        let kind =
            file_to_kind(Path::new("conn.log")).expect("non-sysmon file name should not error");
        assert_eq!(kind, "");
    }

    #[test]
    fn checkpoint_for_input_returns_none_without_suffix() {
        let checkpoint = checkpoint_for_input("/tmp/input.log", None);
        assert!(checkpoint.is_none());
    }

    #[test]
    fn resolve_offset_prefers_transfer_skip_count_over_checkpoint() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let input_path = temp_dir.path().join("input.log");
        let input = input_path
            .to_str()
            .expect("temporary input path must be valid UTF-8");
        let file = file_config(Some(7), Some("offset"));
        let checkpoint = checkpoint_for_input(input, file.last_transfer_line_suffix.as_deref());
        checkpoint
            .as_ref()
            .expect("checkpoint should exist when a suffix is configured")
            .save(42)
            .expect("checkpoint fixture should be written");

        assert_eq!(resolve_offset(&file, checkpoint.as_ref()), 7);
    }

    #[test]
    fn resolve_offset_falls_back_to_checkpoint_value() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let input_path = temp_dir.path().join("input.log");
        let input = input_path
            .to_str()
            .expect("temporary input path must be valid UTF-8");
        let file = file_config(None, Some("offset"));
        let checkpoint = checkpoint_for_input(input, file.last_transfer_line_suffix.as_deref());
        checkpoint
            .as_ref()
            .expect("checkpoint should exist when a suffix is configured")
            .save(42)
            .expect("checkpoint fixture should be written");

        assert_eq!(resolve_offset(&file, checkpoint.as_ref()), 42);
    }

    #[tokio::test]
    async fn run_with_sender_processes_log_input_and_finishes() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "input.log", "line1\nline2\n");
        let controller = controller_for_file(&path, "custom", Some(false), None);
        let mut sender = MockSender::default();

        controller
            .run_with_sender(&mut sender)
            .await
            .expect("log input should be processed");

        assert_eq!(sender.batch_sizes, vec![1, 1]);
        assert_eq!(sender.ensured_protocols, vec![RawEventKind::Log]);
        assert_eq!(sender.finish_calls, 1);
    }

    #[tokio::test]
    async fn run_with_sender_processes_directory_input_and_finishes() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        write_text_file(&temp_dir, "keep_b.log", "second\n");
        write_text_file(&temp_dir, "keep_a.log", "first\n");
        write_text_file(&temp_dir, "drop.log", "ignored\n");
        let controller = controller_for_directory(temp_dir.path(), "custom", Some("keep_"));
        let mut sender = MockSender::default();

        controller
            .run_with_sender(&mut sender)
            .await
            .expect("directory input should be processed");

        assert_eq!(sender.batch_sizes, vec![1, 1]);
        assert_eq!(sender.ensured_protocols, vec![RawEventKind::Log]);
        assert_eq!(sender.finish_calls, 1);
    }

    #[tokio::test]
    async fn run_single_processes_operation_log_and_saves_checkpoint() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "manager.log", &format!("{OPLOG_LINE}\n"));
        let controller = controller_for_file(&path, OPERATION_LOG, Some(false), Some("offset"));
        let mut sender = MockSender::default();

        controller
            .run_single(&path, &mut sender, OPERATION_LOG, false)
            .await
            .expect("operation log input should be processed");

        let checkpoint = PathBuf::from(format!("{}_offset", path.to_string_lossy()));
        let checkpoint_contents =
            std::fs::read_to_string(&checkpoint).expect("checkpoint file should be written");
        assert_eq!(sender.batch_sizes, vec![1]);
        assert_eq!(sender.ensured_protocols, vec![RawEventKind::OpLog]);
        assert_eq!(checkpoint_contents, "1");
    }

    #[tokio::test]
    async fn run_single_processes_sysmon_and_resets_header() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(
            &temp_dir,
            "event1_log.csv",
            &format!("{SYSMON_HEADER}\n{SYSMON_PC_1}\n"),
        );
        let controller = controller_for_file(&path, "process_create", Some(false), None);
        let mut sender = MockSender::default();

        controller
            .run_single(&path, &mut sender, "process_create", false)
            .await
            .expect("sysmon input should be processed");

        assert_eq!(sender.batch_sizes, vec![1]);
        assert_eq!(sender.ensured_protocols, vec![RawEventKind::ProcessCreate]);
        assert_eq!(sender.reset_header_calls, 1);
    }

    #[tokio::test]
    async fn run_single_processes_zeek_input() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "conn.log", &format!("{ZEEK_CONN_1}\n"));
        let controller = controller_for_file(&path, "conn", Some(false), None);
        let mut sender = MockSender::default();

        controller
            .run_single(&path, &mut sender, "conn", false)
            .await
            .expect("zeek input should be processed");

        assert_eq!(sender.batch_sizes, vec![1]);
        assert_eq!(sender.ensured_protocols, vec![RawEventKind::Conn]);
    }

    #[tokio::test]
    async fn run_single_processes_migration_input() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "conn.log", &format!("{MIGR_CONN_1}\n"));
        let controller = controller_for_file(&path, "conn", Some(true), None);
        let mut sender = MockSender::default();

        controller
            .run_single(&path, &mut sender, "conn", false)
            .await
            .expect("migration input should be processed");

        assert_eq!(sender.batch_sizes, vec![1]);
        assert_eq!(sender.ensured_protocols, vec![RawEventKind::Conn]);
    }

    #[tokio::test]
    async fn run_single_processes_security_log_input() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "seculog.log", &format!("{WAPPLES_LINE}\n"));
        let controller = controller_for_file(&path, "wapples_fw_6.0", Some(false), None);
        let mut sender = MockSender::default();

        controller
            .run_single(&path, &mut sender, "wapples_fw_6.0", false)
            .await
            .expect("security log input should be processed");

        assert_eq!(sender.batch_sizes, vec![1]);
        assert_eq!(sender.ensured_protocols, vec![RawEventKind::SecuLog]);
    }

    #[tokio::test]
    async fn run_single_processes_netflow_input() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = temp_dir.path().join("netflow5.pcap");
        write_pcap(&path, &[build_v5_packet(1)]);
        let controller = controller_for_file(&path, "netflow5", Some(false), None);
        let mut sender = MockSender::default();

        controller
            .run_single(&path, &mut sender, "netflow5", false)
            .await
            .expect("netflow input should be processed");

        assert_eq!(sender.batch_sizes, vec![1]);
        assert_eq!(sender.ensured_protocols, vec![RawEventKind::Netflow5]);
    }

    #[tokio::test]
    async fn run_uses_real_sender_for_single_log_input() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "input.log", "alpha\nbeta\n");
        let (server_endpoint, server_addr) =
            build_server_endpoint().expect("test server endpoint should be created");
        let server_task =
            tokio::spawn(async move { serve_single_connection(server_endpoint).await });
        let controller = Controller::new(giganto_config(&path, "custom", server_addr));

        controller
            .run()
            .await
            .expect("controller should send single-file log input through GigantoSender");

        let capture = server_task
            .await
            .expect("server task should join cleanly")
            .expect("server should capture controller traffic");
        let logs = decode_logs(&capture);
        let first = logs
            .first()
            .expect("server must capture the first log record");
        let second = logs
            .get(1)
            .expect("server must capture the second log record");

        assert_eq!(capture.record_header, u32::from(RawEventKind::Log));
        assert_eq!(logs.len(), 2);
        assert_eq!(first.kind, "custom");
        assert_eq!(first.log, b"alpha".to_vec());
        assert_eq!(second.kind, "custom");
        assert_eq!(second.log, b"beta".to_vec());
    }

    #[tokio::test]
    async fn run_uses_real_sender_for_directory_input() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        write_text_file(&temp_dir, "keep_b.log", "second\n");
        write_text_file(&temp_dir, "keep_a.log", "first\n");
        write_text_file(&temp_dir, "drop.log", "ignored\n");
        let (server_endpoint, server_addr) =
            build_server_endpoint().expect("test server endpoint should be created");
        let server_task =
            tokio::spawn(async move { serve_single_connection(server_endpoint).await });
        let mut config = giganto_config(temp_dir.path(), "custom", server_addr);
        config.directory = Some(Directory {
            file_prefix: Some("keep_".to_string()),
            polling_mode: false,
        });
        let controller = Controller::new(config);

        controller
            .run()
            .await
            .expect("controller should send directory input through GigantoSender");

        let capture = server_task
            .await
            .expect("server task should join cleanly")
            .expect("server should capture controller traffic");
        let logs = decode_logs(&capture);
        let first = logs
            .first()
            .expect("server must capture the first directory log");
        let second = logs
            .get(1)
            .expect("server must capture the second directory log");

        assert_eq!(capture.record_header, u32::from(RawEventKind::Log));
        assert_eq!(logs.len(), 2);
        assert_eq!(first.log, b"first".to_vec());
        assert_eq!(second.log, b"second".to_vec());
    }

    #[tokio::test]
    async fn run_zeek_kind_dispatches_all_supported_kinds_without_records() {
        let temp_dir = tempdir().expect("temporary directory should be created");

        for kind in [
            "conn", "http", "rdp", "smtp", "dns", "ntlm", "kerberos", "ssh", "dce_rpc", "ftp",
            "ldap", "tls",
        ] {
            let path = write_text_file(&temp_dir, &format!("{kind}.log"), "");
            let mut sender = MockSender::default();

            let pos = run_zeek_kind(
                &path,
                kind,
                false,
                default_run_options(),
                &mut sender,
                report_for(&path, kind),
            )
            .await
            .expect("supported zeek kind should dispatch even when there are no records");

            assert_eq!(
                pos, 0,
                "empty zeek input should keep the initial checkpoint"
            );
            assert!(
                sender.batch_sizes.is_empty(),
                "empty zeek input should not send any batches",
            );
            assert!(
                sender.ensured_protocols.is_empty(),
                "empty zeek input should not send a record header",
            );
        }

        for kind in [
            "mqtt",
            "smb",
            "nfs",
            "bootp",
            "dhcp",
            "radius",
            "malformed_dns",
        ] {
            let path = write_text_file(&temp_dir, &format!("{kind}.log"), "");
            let mut sender = MockSender::default();

            let pos = run_zeek_kind(
                &path,
                kind,
                true,
                default_run_options(),
                &mut sender,
                report_for(&path, kind),
            )
            .await
            .expect("migration-only kind should dispatch in export mode");

            assert_eq!(
                pos, 0,
                "empty migration input should keep the initial checkpoint",
            );
            assert!(
                sender.batch_sizes.is_empty(),
                "empty migration input should not send any batches",
            );
        }
    }

    #[tokio::test]
    async fn run_sysmon_kind_dispatches_all_supported_kinds_without_records() {
        let temp_dir = tempdir().expect("temporary directory should be created");

        for kind in [
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
        ] {
            let path = write_text_file(&temp_dir, &format!("{kind}.csv"), "header\n");
            let mut sender = MockSender::default();

            let pos = run_sysmon_kind(
                &path,
                kind,
                true,
                default_run_options(),
                &mut sender,
                report_for(&path, kind),
            )
            .await
            .expect("supported sysmon kind should dispatch even when there are no records");

            assert_eq!(
                pos, 0,
                "header-only sysmon input should keep the initial checkpoint",
            );
            assert!(
                sender.batch_sizes.is_empty(),
                "header-only sysmon input should not send any batches",
            );
            assert!(
                sender.ensured_protocols.is_empty(),
                "header-only sysmon input should not send a record header",
            );
        }
    }

    #[tokio::test]
    async fn run_security_kind_dispatches_all_supported_kinds() {
        let temp_dir = tempdir().expect("temporary directory should be created");

        for kind in SUPPORTED_SECURITY_KIND {
            let path = write_text_file(&temp_dir, &format!("{kind}.log"), "not-a-security-log\n");
            let mut sender = MockSender::default();

            let pos = run_security_kind(
                &path,
                kind,
                default_run_options(),
                &mut sender,
                report_for(&path, kind),
            )
            .await
            .expect("supported security kind should dispatch even if parsing fails");

            assert_eq!(
                pos, 0,
                "unsent security records must not advance checkpoints"
            );
            assert!(
                sender.batch_sizes.is_empty(),
                "invalid security logs should not send any batches",
            );
        }
    }

    #[tokio::test]
    async fn run_netflow_kind_dispatches_all_supported_kinds_without_packets() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = temp_dir.path().join("empty.pcap");
        write_pcap(&path, &[]);

        for kind in NETFLOW_KIND {
            let mut sender = MockSender::default();

            let pos = run_netflow_kind(
                &path,
                kind,
                default_run_options(),
                &mut sender,
                report_for(&path, kind),
            )
            .await
            .expect("supported netflow kind should dispatch even with no packets");

            assert_eq!(pos, 0, "empty pcap should keep the initial checkpoint");
            assert!(
                sender.batch_sizes.is_empty(),
                "empty pcap should not send any batches",
            );
        }
    }

    #[tokio::test]
    async fn run_zeek_kind_rejects_unknown_kind() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "unknown.log", "");
        let mut sender = MockSender::default();

        let err = run_zeek_kind(
            &path,
            "unknown",
            false,
            default_run_options(),
            &mut sender,
            report_for(&path, "unknown"),
        )
        .await
        .expect_err("unknown zeek kind must be rejected");
        assert!(err.to_string().contains("unknown zeek/migration kind"));
    }

    #[tokio::test]
    async fn run_sysmon_kind_rejects_unknown_kind() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "unknown.csv", "header\n");
        let mut sender = MockSender::default();

        let err = run_sysmon_kind(
            &path,
            "unknown",
            false,
            default_run_options(),
            &mut sender,
            report_for(&path, "unknown"),
        )
        .await
        .expect_err("unknown sysmon kind must be rejected");
        assert!(err.to_string().contains("unknown sysmon kind"));
    }

    #[tokio::test]
    async fn run_security_kind_rejects_unknown_kind() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "unknown.log", "invalid\n");
        let mut sender = MockSender::default();

        let err = run_security_kind(
            &path,
            "unknown",
            default_run_options(),
            &mut sender,
            report_for(&path, "unknown"),
        )
        .await
        .expect_err("unknown security kind must be rejected");
        assert!(err.to_string().contains("unknown security log kind"));
    }

    #[tokio::test]
    async fn run_netflow_kind_rejects_unknown_kind() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = temp_dir.path().join("empty.pcap");
        write_pcap(&path, &[]);
        let mut sender = MockSender::default();

        let err = run_netflow_kind(
            &path,
            "unknown",
            default_run_options(),
            &mut sender,
            report_for(&path, "unknown"),
        )
        .await
        .expect_err("unknown netflow kind must be rejected");
        assert!(err.to_string().contains("unknown netflow kind"));
    }

    #[tokio::test]
    async fn run_single_requires_export_flag_for_zeek_kinds() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "conn.log", &format!("{ZEEK_CONN_1}\n"));
        let controller = controller_for_file(&path, "conn", None, None);
        let mut sender = MockSender::default();

        let err = controller
            .run_single(&path, &mut sender, "conn", false)
            .await
            .expect_err("missing export flag must be rejected");
        assert!(
            err.to_string()
                .contains("export_from_giganto parameter is required")
        );
    }

    #[tokio::test]
    async fn run_single_rejects_directory_input() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let controller = controller_for_file(temp_dir.path(), "custom", Some(false), None);
        let mut sender = MockSender::default();

        let err = controller
            .run_single(temp_dir.path(), &mut sender, "custom", false)
            .await
            .expect_err("directory input must be rejected");
        assert!(err.to_string().contains("invalid input type"));
    }

    #[tokio::test]
    async fn run_with_sender_rejects_elastic_input() {
        let mut config = test_config(Path::new("elastic"), "process_create");
        config.input = "elastic".to_string();
        let controller = Controller::new(config);
        let mut sender = MockSender::default();

        let err = controller
            .run_with_sender(&mut sender)
            .await
            .expect_err("elastic inputs require the elastic-specific path");
        assert!(
            err.to_string()
                .contains("elastic input requires a concrete sender factory")
        );
    }

    #[tokio::test]
    async fn run_split_requires_directory_configuration() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let controller = Controller::new(test_config(temp_dir.path(), "custom"));
        let mut sender = MockSender::default();

        let err = controller
            .run_split(&mut sender)
            .await
            .expect_err("directory mode needs directory-specific options");
        assert!(
            err.to_string()
                .contains("directory's parameters is required")
        );
    }

    #[tokio::test]
    async fn run_split_returns_ok_for_empty_directory_without_polling() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let controller = controller_for_directory(temp_dir.path(), "custom", None);
        let mut sender = MockSender::default();

        controller
            .run_split(&mut sender)
            .await
            .expect("empty non-polling directories should be ignored cleanly");

        assert!(sender.batch_sizes.is_empty());
        assert_eq!(sender.finish_calls, 0);
    }

    #[tokio::test]
    async fn run_requires_elastic_configuration_for_elastic_input() {
        let mut config = test_config(Path::new("elastic"), "process_create");
        config.input = "elastic".to_string();
        let controller = Controller::new(config);

        let err = controller
            .run()
            .await
            .expect_err("elastic input without elastic config must fail");
        assert!(err.to_string().contains("elastic parameters is required"));
    }

    #[tokio::test]
    async fn run_single_rejects_elastic_pseudo_input() {
        let controller = controller_for_file(Path::new("elastic"), "custom", Some(false), None);
        let mut sender = MockSender::default();

        let err = controller
            .run_single(Path::new("elastic"), &mut sender, "custom", false)
            .await
            .expect_err("elastic pseudo-input must be rejected by run_single");
        assert!(err.to_string().contains("invalid input type: Elastic"));
    }

    #[tokio::test]
    async fn run_single_requires_file_configuration() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "input.log", "line1\n");
        let mut config = test_config(&path, "custom");
        config.file = None;
        let controller = Controller::new(config);
        let mut sender = MockSender::default();

        let err = controller
            .run_single(&path, &mut sender, "custom", false)
            .await
            .expect_err("run_single requires file-specific configuration");
        assert!(err.to_string().contains("file's parameters is required"));
    }

    #[tokio::test]
    async fn run_single_ignores_checkpoint_write_failures() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let path = write_text_file(&temp_dir, "input.log", "line1\n");
        let checkpoint_dir = PathBuf::from(format!("{}_offset", path.to_string_lossy()));
        std::fs::create_dir(&checkpoint_dir)
            .expect("checkpoint target directory should be created to force save failure");
        let controller = controller_for_file(&path, "custom", Some(false), Some("offset"));
        let mut sender = MockSender::default();

        controller
            .run_single(&path, &mut sender, "custom", false)
            .await
            .expect("checkpoint save failures should only be logged");

        assert_eq!(sender.batch_sizes, vec![1]);
        assert!(checkpoint_dir.is_dir());
    }

    #[test]
    fn migration_enabled_requires_export_setting() {
        let missing = FileConfig {
            export_from_giganto: None,
            polling_mode: false,
            transfer_count: None,
            transfer_skip_count: None,
            last_transfer_line_suffix: None,
        };
        let enabled = FileConfig {
            export_from_giganto: Some(true),
            polling_mode: false,
            transfer_count: None,
            transfer_skip_count: None,
            last_transfer_line_suffix: None,
        };

        let err =
            migration_enabled(&missing).expect_err("missing export_from_giganto must be rejected");
        assert!(
            err.to_string()
                .contains("export_from_giganto parameter is required")
        );
        assert!(migration_enabled(&enabled).expect("configured export flag should be returned"));
    }

    #[test]
    fn resolve_offset_defaults_to_zero_without_skip_count_or_checkpoint() {
        let file = file_config(None, None);
        assert_eq!(resolve_offset(&file, None), 0);
    }

    #[test]
    fn files_in_dir_ignores_broken_symlinks() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let valid_file = temp_dir.path().join("valid.log");
        File::create(&valid_file).expect("valid file should be created");
        let broken_link = temp_dir.path().join("broken.log");
        symlink(temp_dir.path().join("missing.log"), &broken_link)
            .expect("broken symlink fixture should be created");

        let files = files_in_dir(&temp_dir.path().to_string_lossy(), None, &[]);

        assert_eq!(files, vec![valid_file]);
    }
}
