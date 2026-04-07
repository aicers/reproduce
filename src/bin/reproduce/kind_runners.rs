use super::*;

// The kind-to-collector mapping is intentionally explicit so supported formats
// stay visible in one place.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_zeek_kind<S>(
    filename: &Path,
    kind: &str,
    migration: bool,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<Vec<u8>>
where
    S: PipelineSender + ?Sized,
{
    let kind = ZeekKind::parse(kind).ok_or_else(|| anyhow!("unknown zeek/migration kind"))?;
    match kind {
        ZeekKind::Conn => {
            run_zeek_or_migration_collector::<Conn, _>(
                filename,
                RawEventKind::Conn,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Http => {
            run_zeek_or_migration_collector::<Http, _>(
                filename,
                RawEventKind::Http,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Rdp => {
            run_zeek_or_migration_collector::<Rdp, _>(
                filename,
                RawEventKind::Rdp,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Smtp => {
            run_zeek_or_migration_collector::<Smtp, _>(
                filename,
                RawEventKind::Smtp,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Dns => {
            run_zeek_or_migration_collector::<Dns, _>(
                filename,
                RawEventKind::Dns,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Ntlm => {
            run_zeek_or_migration_collector::<Ntlm, _>(
                filename,
                RawEventKind::Ntlm,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Kerberos => {
            run_zeek_or_migration_collector::<Kerberos, _>(
                filename,
                RawEventKind::Kerberos,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Ssh => {
            run_zeek_or_migration_collector::<Ssh, _>(
                filename,
                RawEventKind::Ssh,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::DceRpc => {
            run_zeek_or_migration_collector::<DceRpc, _>(
                filename,
                RawEventKind::DceRpc,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Ftp => {
            run_zeek_or_migration_collector::<Ftp, _>(
                filename,
                RawEventKind::Ftp,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Ldap => {
            run_zeek_or_migration_collector::<Ldap, _>(
                filename,
                RawEventKind::Ldap,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Tls => {
            run_zeek_or_migration_collector::<Tls, _>(
                filename,
                RawEventKind::Tls,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Mqtt => {
            run_migration_only_collector::<Mqtt, _>(
                filename,
                RawEventKind::Mqtt,
                migration,
                kind.as_str(),
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Smb => {
            run_migration_only_collector::<Smb, _>(
                filename,
                RawEventKind::Smb,
                migration,
                kind.as_str(),
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Nfs => {
            run_migration_only_collector::<Nfs, _>(
                filename,
                RawEventKind::Nfs,
                migration,
                kind.as_str(),
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Bootp => {
            run_migration_only_collector::<Bootp, _>(
                filename,
                RawEventKind::Bootp,
                migration,
                kind.as_str(),
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Dhcp => {
            run_migration_only_collector::<Dhcp, _>(
                filename,
                RawEventKind::Dhcp,
                migration,
                kind.as_str(),
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Radius => {
            run_migration_only_collector::<Radius, _>(
                filename,
                RawEventKind::Radius,
                migration,
                kind.as_str(),
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::MalformedDns => {
            run_migration_only_collector::<MalformedDns, _>(
                filename,
                RawEventKind::MalformedDns,
                migration,
                kind.as_str(),
                options,
                sender,
                report,
            )
            .await
        }
        ZeekKind::Icmp => {
            run_migration_only_collector::<Icmp, _>(
                filename,
                RawEventKind::Icmp,
                migration,
                kind.as_str(),
                options,
                sender,
                report,
            )
            .await
        }
    }
}

pub(super) async fn run_operation_log<S>(
    filename: &Path,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<Vec<u8>>
where
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        shutdown,
    } = options;
    let agent = operation_log_agent_name(filename)?;
    let oplog = File::open(filename)?;
    let rdr = BufReader::new(oplog);
    run_collector(
        OplogCollector::new(
            rdr,
            agent.to_string(),
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

// The kind-to-collector mapping is intentionally explicit so supported formats
// stay visible in one place.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_sysmon_kind<S>(
    filename: &Path,
    kind: &str,
    migration: bool,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<Vec<u8>>
where
    S: PipelineSender + ?Sized,
{
    let kind = SysmonKind::parse(kind).ok_or_else(|| anyhow!("unknown sysmon kind"))?;
    match kind {
        SysmonKind::ProcessCreate => {
            run_sysmon_or_migration_collector::<ProcessCreate, _>(
                filename,
                RawEventKind::ProcessCreate,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::FileCreateTime => {
            run_sysmon_or_migration_collector::<FileCreationTimeChanged, _>(
                filename,
                RawEventKind::FileCreateTime,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::NetworkConnect => {
            run_sysmon_or_migration_collector::<NetworkConnection, _>(
                filename,
                RawEventKind::NetworkConnect,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::ProcessTerminate => {
            run_sysmon_or_migration_collector::<ProcessTerminated, _>(
                filename,
                RawEventKind::ProcessTerminate,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::ImageLoad => {
            run_sysmon_or_migration_collector::<ImageLoaded, _>(
                filename,
                RawEventKind::ImageLoad,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::FileCreate => {
            run_sysmon_or_migration_collector::<FileCreate, _>(
                filename,
                RawEventKind::FileCreate,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::RegistryValueSet => {
            run_sysmon_or_migration_collector::<RegistryValueSet, _>(
                filename,
                RawEventKind::RegistryValueSet,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::RegistryKeyRename => {
            run_sysmon_or_migration_collector::<RegistryKeyValueRename, _>(
                filename,
                RawEventKind::RegistryKeyRename,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::FileCreateStreamHash => {
            run_sysmon_or_migration_collector::<FileCreateStreamHash, _>(
                filename,
                RawEventKind::FileCreateStreamHash,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::PipeEvent => {
            run_sysmon_or_migration_collector::<PipeEvent, _>(
                filename,
                RawEventKind::PipeEvent,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::DnsQuery => {
            run_sysmon_or_migration_collector::<DnsEvent, _>(
                filename,
                RawEventKind::DnsQuery,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::FileDelete => {
            run_sysmon_or_migration_collector::<FileDelete, _>(
                filename,
                RawEventKind::FileDelete,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::ProcessTamper => {
            run_sysmon_or_migration_collector::<ProcessTampering, _>(
                filename,
                RawEventKind::ProcessTamper,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
        SysmonKind::FileDeleteDetected => {
            run_sysmon_or_migration_collector::<FileDeleteDetected, _>(
                filename,
                RawEventKind::FileDeleteDetected,
                migration,
                options,
                sender,
                report,
            )
            .await
        }
    }
}

pub(super) async fn run_netflow_kind<S>(
    filename: &Path,
    kind: &str,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<Vec<u8>>
where
    S: PipelineSender + ?Sized,
{
    let kind = NetflowKind::parse(kind).ok_or_else(|| anyhow!("unknown netflow kind"))?;
    let CollectorRunOptions {
        offset,
        count_sent,
        shutdown,
        ..
    } = options;
    match kind {
        NetflowKind::Netflow5 => {
            run_collector(
                NetflowCollector::<Netflow5>::new(
                    filename,
                    RawEventKind::Netflow5,
                    offset,
                    count_sent,
                    shutdown.clone(),
                )?,
                sender,
                shutdown,
                report,
            )
            .await
        }
        NetflowKind::Netflow9 => {
            run_collector(
                NetflowCollector::<Netflow9>::new(
                    filename,
                    RawEventKind::Netflow9,
                    offset,
                    count_sent,
                    shutdown.clone(),
                )?,
                sender,
                shutdown,
                report,
            )
            .await
        }
    }
}

// The kind-to-collector mapping is intentionally explicit so supported formats
// stay visible in one place.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_security_kind<S>(
    filename: &Path,
    kind: &str,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<Vec<u8>>
where
    S: PipelineSender + ?Sized,
{
    let kind = SecurityKind::parse(kind).ok_or_else(|| anyhow!("unknown security log kind"))?;
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        shutdown,
    } = options;
    let seculog = File::open(filename)?;
    let rdr = BufReader::new(seculog);
    match kind {
        SecurityKind::WapplesFw60 => {
            run_collector(
                SecurityLogCollector::<Wapples>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::Mf2Ips40 => {
            run_collector(
                SecurityLogCollector::<Mf2>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::SniperIps80 => {
            run_collector(
                SecurityLogCollector::<SniperIps>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::AiwafWaf41 => {
            run_collector(
                SecurityLogCollector::<Aiwaf>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::TgIps27 => {
            run_collector(
                SecurityLogCollector::<Tg>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::VforceIps46 => {
            run_collector(
                SecurityLogCollector::<Vforce>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::SrxIps151 => {
            run_collector(
                SecurityLogCollector::<Srx>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::SonicwallFw65 => {
            run_collector(
                SecurityLogCollector::<SonicWall>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::FgtIps62 => {
            run_collector(
                SecurityLogCollector::<Fgt>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::ShadowwallIps50 => {
            run_collector(
                SecurityLogCollector::<ShadowWall>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::AxgateFw21 => {
            run_collector(
                SecurityLogCollector::<Axgate>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::UbuntuSyslog2004 => {
            run_collector(
                SecurityLogCollector::<Ubuntu>::new(
                    rdr,
                    kind.as_str().to_string(),
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
        SecurityKind::NginxAccesslog1252 => {
            run_collector(
                SecurityLogCollector::<Nginx>::new(
                    rdr,
                    kind.as_str().to_string(),
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
}

pub(super) async fn run_log_kind<S>(
    filename: &Path,
    kind: &str,
    options: CollectorRunOptions,
    sender: &mut S,
    report: Report,
) -> Result<Vec<u8>>
where
    S: PipelineSender + ?Sized,
{
    let CollectorRunOptions {
        offset,
        count_sent,
        file_polling_mode,
        dir_polling_mode,
        shutdown,
    } = options;
    run_collector(
        LogCollector::new(
            filename,
            kind.to_string(),
            offset,
            count_sent,
            file_polling_mode,
            dir_polling_mode,
            shutdown.clone(),
        )?,
        sender,
        shutdown,
        report,
    )
    .await
}
