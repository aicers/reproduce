use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::BufReader;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;
use std::{env, process::exit};

mod config;
mod kind_runners;
mod report;

#[cfg(test)]
mod tests;

use anyhow::{Context as _, Result, anyhow, bail};
use async_trait::async_trait;
#[cfg(feature = "netflow")]
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
use giganto_client::{
    RawEventKind,
    ingest::{
        network::{
            Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Icmp, Kerberos, Ldap, MalformedDns, Mqtt,
            Nfs, Ntlm, Radius, Rdp, Smb, Smtp, Ssh, Tls,
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
use reproduce::collector::file::files_in_dir;
use reproduce::collector::giganto_import::GigantoImportCollector;
use reproduce::collector::log::LogCollector;
#[cfg(feature = "netflow")]
use reproduce::collector::netflow::NetflowCollector;
use reproduce::collector::operation_log::OplogCollector;
use reproduce::collector::security_log::SecurityLogCollector;
use reproduce::collector::sysmon_csv::SysmonCollector;
use reproduce::collector::zeek::ZeekCollector;
use reproduce::controller::{PipelineSender, run_pipeline_with_sender};
use reproduce::parser::giganto_import::TryFromGigantoRecord;
use reproduce::parser::security_log::{
    Aiwaf, Axgate, Fgt, Mf2, Nginx, ShadowWall, SniperIps, SonicWall, Srx, Tg, Ubuntu, Vforce,
    Wapples,
};
use reproduce::parser::sysmon_csv::{
    ElasticDumpOptions, TryFromSysmonRecord, open_sysmon_csv_file,
};
use reproduce::parser::zeek::{TryFromZeekRecord, open_raw_event_log_file};
use reproduce::sender::GigantoSender;
use serde::Serialize;
use tokio::sync::watch;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(feature = "netflow")]
use crate::kind_runners::run_netflow_kind;
use crate::{
    config::{Config, File as FileConfig, InputType},
    kind_runners::{
        run_log_kind, run_operation_log, run_security_kind, run_sysmon_kind, run_zeek_kind,
    },
    report::Report,
};

const USAGE: &str = "\
USAGE:
    REproduce [CONFIG]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARG:
    <CONFIG>    A TOML config file
";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_filename = parse();
    let config = config::Config::new(config_filename.as_ref())?;
    let _guard = init_tracing(config.log_path.as_deref())?;
    let controller = Controller::new(config);
    tracing::info!("Data Broker started");
    if let Err(error) = controller.run().await {
        tracing::error!("Terminated with error: {error}");
        std::process::exit(1);
    }
    tracing::info!("Data Broker completed");
    Ok(())
}

/// Parses the command line arguments and returns the first argument.
fn parse() -> std::path::PathBuf {
    let args = env::args().collect::<Vec<_>>();
    let Some(arg) = args.get(1).map(String::as_str) else {
        eprintln!("Error: insufficient arguments");
        exit(1);
    };
    if args.get(2).is_some() {
        eprintln!("Error: too many arguments");
        exit(1);
    }

    if arg == "--help" || arg == "-h" {
        println!("{}", version());
        println!();
        print!("{USAGE}");
        exit(0);
    }
    if arg == "--version" || arg == "-V" {
        println!("{}", version());
        exit(0);
    }
    std::path::PathBuf::from(arg)
}

fn version() -> String {
    format!("REproduce {}", env!("CARGO_PKG_VERSION"))
}

/// Initializes the tracing subscriber and returns a `WorkerGuard`.
///
/// Logs will be written to the file specified by `log_path` if provided.
/// If `log_path` is `None`, logs will be printed to stdout.
fn init_tracing(log_path: Option<&std::path::Path>) -> anyhow::Result<WorkerGuard> {
    let (layer, guard) = if let Some(log_path) = log_path {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("Failed to open the log file: {}", log_path.display()))?;
        let (non_blocking, file_guard) = tracing_appender::non_blocking(file);
        (
            fmt::Layer::default()
                .with_ansi(false)
                .with_target(false)
                .with_writer(non_blocking)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
            file_guard,
        )
    } else {
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        (
            fmt::Layer::default()
                .with_ansi(true)
                .with_writer(stdout_writer)
                .with_filter(EnvFilter::from_default_env()),
            stdout_guard,
        )
    };

    tracing_subscriber::Registry::default().with(layer).init();
    tracing::info!("Initialized tracing logger");
    Ok(guard)
}

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
const DIRECTORY_POLL_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ZeekKind {
    Conn,
    Http,
    Rdp,
    Smtp,
    Dns,
    Ntlm,
    Kerberos,
    Ssh,
    DceRpc,
    Ftp,
    Mqtt,
    Ldap,
    Tls,
    Smb,
    Nfs,
    Bootp,
    Dhcp,
    Radius,
    MalformedDns,
    Icmp,
}

impl ZeekKind {
    #[cfg(test)]
    const ALL: [Self; 20] = [
        Self::Conn,
        Self::Http,
        Self::Rdp,
        Self::Smtp,
        Self::Dns,
        Self::Ntlm,
        Self::Kerberos,
        Self::Ssh,
        Self::DceRpc,
        Self::Ftp,
        Self::Mqtt,
        Self::Ldap,
        Self::Tls,
        Self::Smb,
        Self::Nfs,
        Self::Bootp,
        Self::Dhcp,
        Self::Radius,
        Self::MalformedDns,
        Self::Icmp,
    ];

    fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "conn" => Self::Conn,
            "http" => Self::Http,
            "rdp" => Self::Rdp,
            "smtp" => Self::Smtp,
            "dns" => Self::Dns,
            "ntlm" => Self::Ntlm,
            "kerberos" => Self::Kerberos,
            "ssh" => Self::Ssh,
            "dce_rpc" => Self::DceRpc,
            "ftp" => Self::Ftp,
            "mqtt" => Self::Mqtt,
            "ldap" => Self::Ldap,
            "tls" => Self::Tls,
            "smb" => Self::Smb,
            "nfs" => Self::Nfs,
            "bootp" => Self::Bootp,
            "dhcp" => Self::Dhcp,
            "radius" => Self::Radius,
            "malformed_dns" => Self::MalformedDns,
            "icmp" => Self::Icmp,
            _ => return None,
        })
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Conn => "conn",
            Self::Http => "http",
            Self::Rdp => "rdp",
            Self::Smtp => "smtp",
            Self::Dns => "dns",
            Self::Ntlm => "ntlm",
            Self::Kerberos => "kerberos",
            Self::Ssh => "ssh",
            Self::DceRpc => "dce_rpc",
            Self::Ftp => "ftp",
            Self::Mqtt => "mqtt",
            Self::Ldap => "ldap",
            Self::Tls => "tls",
            Self::Smb => "smb",
            Self::Nfs => "nfs",
            Self::Bootp => "bootp",
            Self::Dhcp => "dhcp",
            Self::Radius => "radius",
            Self::MalformedDns => "malformed_dns",
            Self::Icmp => "icmp",
        }
    }

    #[cfg(test)]
    const fn requires_giganto_import(self) -> bool {
        matches!(
            self,
            Self::Mqtt
                | Self::Smb
                | Self::Nfs
                | Self::Bootp
                | Self::Dhcp
                | Self::Radius
                | Self::MalformedDns
                | Self::Icmp
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SysmonKind {
    ProcessCreate,
    FileCreateTime,
    NetworkConnect,
    ProcessTerminate,
    ImageLoad,
    FileCreate,
    RegistryValueSet,
    RegistryKeyRename,
    FileCreateStreamHash,
    PipeEvent,
    DnsQuery,
    FileDelete,
    ProcessTamper,
    FileDeleteDetected,
}

impl SysmonKind {
    #[cfg(test)]
    const ALL: [Self; 14] = [
        Self::ProcessCreate,
        Self::FileCreateTime,
        Self::NetworkConnect,
        Self::ProcessTerminate,
        Self::ImageLoad,
        Self::FileCreate,
        Self::RegistryValueSet,
        Self::RegistryKeyRename,
        Self::FileCreateStreamHash,
        Self::PipeEvent,
        Self::DnsQuery,
        Self::FileDelete,
        Self::ProcessTamper,
        Self::FileDeleteDetected,
    ];

    fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "process_create" => Self::ProcessCreate,
            "file_create_time" => Self::FileCreateTime,
            "network_connect" => Self::NetworkConnect,
            "process_terminate" => Self::ProcessTerminate,
            "image_load" => Self::ImageLoad,
            "file_create" => Self::FileCreate,
            "registry_value_set" => Self::RegistryValueSet,
            "registry_key_rename" => Self::RegistryKeyRename,
            "file_create_stream_hash" => Self::FileCreateStreamHash,
            "pipe_event" => Self::PipeEvent,
            "dns_query" => Self::DnsQuery,
            "file_delete" => Self::FileDelete,
            "process_tamper" => Self::ProcessTamper,
            "file_delete_detected" => Self::FileDeleteDetected,
            _ => return None,
        })
    }

    fn from_event_code(code: &str) -> Option<Self> {
        Some(match code {
            "1" => Self::ProcessCreate,
            "2" => Self::FileCreateTime,
            "3" => Self::NetworkConnect,
            "5" => Self::ProcessTerminate,
            "7" => Self::ImageLoad,
            "11" => Self::FileCreate,
            "13" => Self::RegistryValueSet,
            "14" => Self::RegistryKeyRename,
            "15" => Self::FileCreateStreamHash,
            "17" => Self::PipeEvent,
            "22" => Self::DnsQuery,
            "23" => Self::FileDelete,
            "25" => Self::ProcessTamper,
            "26" => Self::FileDeleteDetected,
            _ => return None,
        })
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessCreate => "process_create",
            Self::FileCreateTime => "file_create_time",
            Self::NetworkConnect => "network_connect",
            Self::ProcessTerminate => "process_terminate",
            Self::ImageLoad => "image_load",
            Self::FileCreate => "file_create",
            Self::RegistryValueSet => "registry_value_set",
            Self::RegistryKeyRename => "registry_key_rename",
            Self::FileCreateStreamHash => "file_create_stream_hash",
            Self::PipeEvent => "pipe_event",
            Self::DnsQuery => "dns_query",
            Self::FileDelete => "file_delete",
            Self::ProcessTamper => "process_tamper",
            Self::FileDeleteDetected => "file_delete_detected",
        }
    }
}

#[cfg(feature = "netflow")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetflowKind {
    Netflow5,
    Netflow9,
}

#[cfg(feature = "netflow")]
impl NetflowKind {
    #[cfg(test)]
    const ALL: [Self; 2] = [Self::Netflow5, Self::Netflow9];

    fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "netflow5" => Self::Netflow5,
            "netflow9" => Self::Netflow9,
            _ => return None,
        })
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Netflow5 => "netflow5",
            Self::Netflow9 => "netflow9",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecurityKind {
    WapplesFw60,
    Mf2Ips40,
    SniperIps80,
    AiwafWaf41,
    TgIps27,
    VforceIps46,
    SrxIps151,
    SonicwallFw65,
    FgtIps62,
    ShadowwallIps50,
    AxgateFw21,
    UbuntuSyslog2004,
    NginxAccesslog1252,
}

impl SecurityKind {
    #[cfg(test)]
    const ALL: [Self; 13] = [
        Self::WapplesFw60,
        Self::Mf2Ips40,
        Self::SniperIps80,
        Self::AiwafWaf41,
        Self::TgIps27,
        Self::VforceIps46,
        Self::SrxIps151,
        Self::SonicwallFw65,
        Self::FgtIps62,
        Self::ShadowwallIps50,
        Self::AxgateFw21,
        Self::UbuntuSyslog2004,
        Self::NginxAccesslog1252,
    ];

    fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "wapples_fw_6.0" => Self::WapplesFw60,
            "mf2_ips_4.0" => Self::Mf2Ips40,
            "sniper_ips_8.0" => Self::SniperIps80,
            "aiwaf_waf_4.1" => Self::AiwafWaf41,
            "tg_ips_2.7" => Self::TgIps27,
            "vforce_ips_4.6" => Self::VforceIps46,
            "srx_ips_15.1" => Self::SrxIps151,
            "sonicwall_fw_6.5" => Self::SonicwallFw65,
            "fgt_ips_6.2" => Self::FgtIps62,
            "shadowwall_ips_5.0" => Self::ShadowwallIps50,
            "axgate_fw_2.1" => Self::AxgateFw21,
            "ubuntu_syslog_20.04" => Self::UbuntuSyslog2004,
            "nginx_accesslog_1.25.2" => Self::NginxAccesslog1252,
            _ => return None,
        })
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::WapplesFw60 => "wapples_fw_6.0",
            Self::Mf2Ips40 => "mf2_ips_4.0",
            Self::SniperIps80 => "sniper_ips_8.0",
            Self::AiwafWaf41 => "aiwaf_waf_4.1",
            Self::TgIps27 => "tg_ips_2.7",
            Self::VforceIps46 => "vforce_ips_4.6",
            Self::SrxIps151 => "srx_ips_15.1",
            Self::SonicwallFw65 => "sonicwall_fw_6.5",
            Self::FgtIps62 => "fgt_ips_6.2",
            Self::ShadowwallIps50 => "shadowwall_ips_5.0",
            Self::AxgateFw21 => "axgate_fw_2.1",
            Self::UbuntuSyslog2004 => "ubuntu_syslog_20.04",
            Self::NginxAccesslog1252 => "nginx_accesslog_1.25.2",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClassifiedKind<'a> {
    Zeek(ZeekKind),
    OperationLog,
    Sysmon(SysmonKind),
    #[cfg(feature = "netflow")]
    Netflow(NetflowKind),
    Security(SecurityKind),
    Log(&'a str),
}

struct FileRunPlan<'a> {
    kind: ClassifiedKind<'a>,
    import_from_giganto: Option<bool>,
    checkpoint: Option<Checkpoint>,
    options: CollectorRunOptions,
    report: Report,
}

struct KindRunResult {
    checkpoint: Vec<u8>,
    reset_header: bool,
}

fn classify_kind(kind: &str) -> ClassifiedKind<'_> {
    if let Some(kind) = ZeekKind::parse(kind) {
        ClassifiedKind::Zeek(kind)
    } else if kind == OPERATION_LOG {
        ClassifiedKind::OperationLog
    } else if let Some(kind) = SysmonKind::parse(kind) {
        ClassifiedKind::Sysmon(kind)
    } else {
        #[cfg(feature = "netflow")]
        if let Some(kind) = NetflowKind::parse(kind) {
            return ClassifiedKind::Netflow(kind);
        }
        if let Some(kind) = SecurityKind::parse(kind) {
            ClassifiedKind::Security(kind)
        } else {
            ClassifiedKind::Log(kind)
        }
    }
}

/// Runs one collector, wraps report accounting, and returns the committed
/// checkpoint position after the pipeline completes.
async fn run_collector<C, S>(
    collector: C,
    sender: &mut S,
    shutdown: watch::Receiver<bool>,
    mut report: Report,
) -> Result<Vec<u8>>
where
    C: Collector,
    S: PipelineSender + ?Sized,
{
    let mut collector = collector;
    report.start();
    run_pipeline_with_sender(sender, &mut collector, shutdown, &mut |bytes| {
        report.process(bytes);
    })
    .await?;
    let pos = collector.position();
    if let Err(error) = report.end() {
        warn!("Cannot write report: {error}");
    }
    Ok(pos)
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

async fn run_zeek_or_giganto_import_collector<T, S>(
    filename: &Path,
    protocol: RawEventKind,
    giganto_import: bool,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<Vec<u8>>
where
    T: Serialize + TryFromGigantoRecord + TryFromZeekRecord + Unpin + Debug + Send,
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        shutdown,
    } = options;
    let rdr = open_raw_event_log_file(filename)?;
    let iter = rdr.into_records();

    if giganto_import {
        run_collector(
            GigantoImportCollector::<T>::new(
                iter,
                protocol,
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                shutdown.clone(),
            ),
            sender,
            shutdown,
            report,
        )
        .await
    } else {
        run_collector(
            ZeekCollector::<T>::new(
                iter,
                protocol,
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                shutdown.clone(),
            ),
            sender,
            shutdown,
            report,
        )
        .await
    }
}

async fn run_giganto_import_only_collector<T, S>(
    filename: &Path,
    protocol: RawEventKind,
    giganto_import: bool,
    unsupported_name: &'static str,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<Vec<u8>>
where
    T: Serialize + TryFromGigantoRecord + Unpin + Debug + Send,
    S: PipelineSender + ?Sized,
{
    if !giganto_import {
        bail!("{unsupported_name} zeek log is not supported");
    }

    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        shutdown,
    } = options;
    let rdr = open_raw_event_log_file(filename)?;
    let iter = rdr.into_records();

    run_collector(
        GigantoImportCollector::<T>::new(
            iter,
            protocol,
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            shutdown.clone(),
        ),
        sender,
        shutdown,
        report,
    )
    .await
}

async fn run_sysmon_or_giganto_import_collector<T, S>(
    filename: &Path,
    protocol: RawEventKind,
    giganto_import: bool,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<Vec<u8>>
where
    T: Serialize + TryFromGigantoRecord + TryFromSysmonRecord + Unpin + Debug + Send,
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        shutdown,
    } = options;
    let rdr = open_sysmon_csv_file(filename)?;
    let iter = rdr.into_records();

    if giganto_import {
        run_collector(
            GigantoImportCollector::<T>::new(
                iter,
                protocol,
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                shutdown.clone(),
            ),
            sender,
            shutdown,
            report,
        )
        .await
    } else {
        run_collector(
            SysmonCollector::<T>::new(
                iter,
                protocol,
                offset,
                count_sent,
                file_polling_mode,
                dir_polling_mode,
                shutdown.clone(),
            ),
            sender,
            shutdown,
            report,
        )
        .await
    }
}

struct Controller {
    config: Config,
}

static SHUTDOWN_SENDER: OnceLock<watch::Sender<bool>> = OnceLock::new();

impl Controller {
    #[must_use]
    fn new(config: Config) -> Self {
        Self { config }
    }

    /// # Errors
    ///
    /// Returns an error if creating a converter fails.
    ///
    pub async fn run(&self) -> Result<()> {
        let input_type = input_type(&self.config.input);

        if input_type == InputType::Elastic {
            let shutdown = shutdown_receiver()?;
            self.run_elastic_with_shutdown(shutdown).await?;
        } else {
            let mut sender = create_sender(&self.config).await?;
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
        let shutdown = shutdown_receiver()?;
        self.run_split_with_shutdown(sender, shutdown).await
    }

    async fn run_split_with_shutdown<S>(
        &self,
        sender: &mut S,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()>
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
                    if wait_for_shutdown_or_timeout(&mut shutdown, DIRECTORY_POLL_INTERVAL).await {
                        break;
                    }
                    continue;
                }
                error!("No input file");
                break;
            }

            files.sort_unstable();
            for file in files {
                info!("File: {file:?}");
                self.run_single_with_shutdown(
                    file.as_path(),
                    sender,
                    &self.config.kind,
                    dir_option.polling_mode,
                    shutdown.clone(),
                )
                .await?;
                processed.push(file);
            }

            if !dir_option.polling_mode || shutdown_requested(&shutdown) {
                break;
            }
        }
        Ok(())
    }

    async fn run_elastic_with_shutdown(&self, shutdown: watch::Receiver<bool>) -> Result<()> {
        let Some(ref elastic) = self.config.elastic else {
            bail!("elastic parameters is required");
        };
        let dir = reproduce::parser::sysmon_csv::fetch_elastic_search(ElasticDumpOptions {
            url: &elastic.url,
            event_codes: &elastic.event_codes,
            indices: &elastic.indices,
            start_time: &elastic.start_time,
            end_time: &elastic.end_time,
            size: elastic.size,
            dump_dir: &elastic.dump_dir,
            elastic_auth: &elastic.elastic_auth,
        })
        .await?;

        let mut files = files_in_dir(&dir, None, &[]);
        if files.is_empty() {
            bail!("no data with elastic");
        }

        files.sort_unstable();
        for file in files {
            let mut sender = create_sender(&self.config).await?;
            info!("File: {file:?}");
            let kind = file_to_kind(&file)?;
            self.run_single_with_shutdown(
                file.as_path(),
                &mut sender,
                kind,
                false,
                shutdown.clone(),
            )
            .await?;
            std::fs::remove_file(&file)?;
            sender.finish().await.context("failed to finish stream")?;
        }
        std::fs::remove_dir(&dir)?;
        Ok(())
    }

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
        let shutdown = shutdown_receiver()?;
        self.run_single_with_shutdown(filename, sender, kind, dir_polling_mode, shutdown)
            .await
    }

    async fn run_single_with_shutdown<S>(
        &self,
        filename: &Path,
        sender: &mut S,
        kind: &str,
        dir_polling_mode: bool,
        shutdown: watch::Receiver<bool>,
    ) -> Result<()>
    where
        S: ControllerSender + ?Sized,
    {
        let plan = self.build_file_run_plan(filename, kind, dir_polling_mode, shutdown)?;
        self.execute_file_run(filename, sender, plan).await
    }

    fn build_file_run_plan<'a>(
        &'a self,
        filename: &Path,
        kind: &'a str,
        dir_polling_mode: bool,
        shutdown: watch::Receiver<bool>,
    ) -> Result<FileRunPlan<'a>> {
        let input_type = input_type(&filename.to_string_lossy());
        if input_type != InputType::Log {
            bail!("invalid input type: {input_type:?}");
        }

        let file = self
            .config
            .file
            .as_ref()
            .ok_or_else(|| anyhow!("file's parameters is required"))?;
        let checkpoint = checkpoint_for_input(
            &filename.to_string_lossy(),
            file.last_transfer_line_suffix.as_deref(),
        );
        let offset = resolve_offset(file, checkpoint.as_ref());
        let count_sent = file.transfer_count.unwrap_or(0);
        let options = CollectorRunOptions {
            offset,
            count_sent,
            file_polling_mode: file.polling_mode,
            dir_polling_mode,
            shutdown,
        };

        Ok(FileRunPlan {
            kind: classify_kind(kind),
            import_from_giganto: file.import_from_giganto,
            checkpoint,
            options,
            report: Report::new(self.config.clone()),
        })
    }

    async fn execute_file_run<S>(
        &self,
        filename: &Path,
        sender: &mut S,
        plan: FileRunPlan<'_>,
    ) -> Result<()>
    where
        S: ControllerSender + ?Sized,
    {
        let FileRunPlan {
            kind,
            import_from_giganto,
            checkpoint,
            options,
            report,
        } = plan;
        let result =
            run_classified_kind(filename, kind, import_from_giganto, options, sender, report)
                .await?;
        if result.reset_header {
            sender.reset_header();
        }
        save_checkpoint(checkpoint.as_ref(), &result.checkpoint);
        Ok(())
    }
}

fn giganto_import_enabled(import_from_giganto: Option<bool>) -> Result<bool> {
    import_from_giganto.context("import_from_giganto parameter is required")
}

async fn run_classified_kind<S>(
    filename: &Path,
    kind: ClassifiedKind<'_>,
    import_from_giganto: Option<bool>,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<KindRunResult>
where
    S: ControllerSender + ?Sized,
{
    let (checkpoint, reset_header) = match kind {
        ClassifiedKind::Zeek(kind) => (
            run_zeek_kind(
                filename,
                kind.as_str(),
                giganto_import_enabled(import_from_giganto)?,
                options,
                sender,
                report,
            )
            .await?,
            false,
        ),
        ClassifiedKind::OperationLog => (
            run_operation_log(filename, options, sender, report).await?,
            false,
        ),
        ClassifiedKind::Sysmon(kind) => (
            run_sysmon_kind(
                filename,
                kind.as_str(),
                giganto_import_enabled(import_from_giganto)?,
                options,
                sender,
                report,
            )
            .await?,
            true,
        ),
        #[cfg(feature = "netflow")]
        ClassifiedKind::Netflow(kind) => (
            run_netflow_kind(filename, kind.as_str(), options, sender, report).await?,
            false,
        ),
        ClassifiedKind::Security(kind) => (
            run_security_kind(filename, kind.as_str(), options, sender, report).await?,
            false,
        ),
        ClassifiedKind::Log(kind) => (
            run_log_kind(filename, kind, options, sender, report).await?,
            false,
        ),
    };

    Ok(KindRunResult {
        checkpoint,
        reset_header,
    })
}

fn save_checkpoint(checkpoint: Option<&Checkpoint>, position: &[u8]) {
    if let Some(checkpoint) = checkpoint
        && let Err(error) = checkpoint.save(position)
    {
        warn!("Cannot write to offset file: {error}");
    }
}

struct CollectorRunOptions {
    offset: u64,
    count_sent: u64,
    file_polling_mode: bool,
    dir_polling_mode: bool,
    shutdown: watch::Receiver<bool>,
}

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

async fn wait_for_shutdown_or_timeout(
    shutdown: &mut watch::Receiver<bool>,
    duration: Duration,
) -> bool {
    if shutdown_requested(shutdown) {
        return true;
    }

    tokio::select! {
        () = tokio::time::sleep(duration) => shutdown_requested(shutdown),
        changed = shutdown.changed() => changed.is_err() || shutdown_requested(shutdown),
    }
}

fn shutdown_receiver() -> Result<watch::Receiver<bool>> {
    if let Some(sender) = SHUTDOWN_SENDER.get() {
        return Ok(sender.subscribe());
    }

    let (sender, receiver) = watch::channel(false);
    let handler_sender = sender.clone();
    ctrlc::set_handler(move || {
        let _ = handler_sender.send(true);
    })
    .context("failed to install Ctrl-C handler")?;

    match SHUTDOWN_SENDER.set(sender) {
        Ok(()) => Ok(receiver),
        Err(existing) => Ok(existing.subscribe()),
    }
}

fn checkpoint_for_input(input: &str, suffix: Option<&str>) -> Option<Checkpoint> {
    suffix.map(|value| Checkpoint::from_input_and_suffix(input, value))
}

fn resolve_offset(file: &FileConfig, checkpoint: Option<&Checkpoint>) -> u64 {
    if let Some(count_skip) = file.transfer_skip_count {
        count_skip
    } else if let Some(cp) = checkpoint {
        checkpoint_offset(cp)
    } else {
        0
    }
}

fn checkpoint_offset(checkpoint: &Checkpoint) -> u64 {
    let raw = match checkpoint.load() {
        Ok(Some(raw)) => raw,
        Ok(None) => return 0,
        Err(error) => {
            warn!("Cannot read offset file: {error}");
            return 0;
        }
    };

    let text = match std::str::from_utf8(&raw) {
        Ok(text) => text,
        Err(error) => {
            warn!(
                "Invalid UTF-8 in offset file {}: {error}",
                checkpoint.path().display()
            );
            return 0;
        }
    };

    match text.parse() {
        Ok(offset) => offset,
        Err(error) => {
            warn!(
                "Invalid numeric offset in {}: {error}",
                checkpoint.path().display()
            );
            0
        }
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
        return Ok(SysmonKind::from_event_code(num).map_or("", SysmonKind::as_str));
    }
    Ok("")
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

async fn create_sender(config: &Config) -> Result<GigantoSender> {
    debug!("output type=GIGANTO");
    GigantoSender::new(
        &config.giganto.cert,
        &config.giganto.key,
        &config.giganto.ca_certs,
        config.giganto.ingest_srv_addr,
        &config.giganto.name,
    )
    .await
    .map_err(anyhow::Error::from)
}
