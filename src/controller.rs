use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

use crate::syslog::open_sysmon_csv_file;
use crate::zeek::open_raw_event_log_file;
use crate::{Config, InputType, Producer, Report};

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

pub(crate) struct Controller {
    config: Config,
}

impl Controller {
    #[must_use]
    pub(crate) fn new(config: Config) -> Self {
        Self { config }
    }

    /// # Errors
    ///
    /// Returns an error if creating a converter fails.
    ///
    /// # Panics
    ///
    /// Stream finish / Connection close error
    pub(crate) async fn run(&self) -> Result<()> {
        let input_type = input_type(&self.config.input);

        if input_type == InputType::Elastic {
            self.run_elastic().await?;
        } else {
            let mut producer = producer(&self.config).await;

            match input_type {
                InputType::Dir => {
                    self.run_split(&mut producer).await?;
                }
                InputType::Log => {
                    let file_name = Path::new(&self.config.input).to_path_buf();
                    self.run_single(
                        file_name.as_ref(),
                        &mut producer,
                        &self.config.kind.clone(),
                        false,
                    )
                    .await?;
                }
                InputType::Elastic => {}
            }
            producer
                .giganto
                .finish()
                .await
                .expect("failed to finish stream");
        }

        Ok(())
    }

    async fn run_split(&self, producer: &mut Producer) -> Result<()> {
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
                    producer,
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
        let dir = crate::syslog::fetch_elastic_search(elastic).await?;

        let mut files = files_in_dir(&dir, None, &[]);
        if files.is_empty() {
            bail!("no data with elastic");
        }

        files.sort_unstable();
        for file in files {
            let mut producer = producer(&self.config).await;
            info!("File: {file:?}");
            let kind = file_to_kind(&file)?;
            self.run_single(file.as_path(), &mut producer, kind, false)
                .await?;
            std::fs::remove_file(&file)?;
            producer
                .giganto
                .finish()
                .await
                .expect("failed to finish stream");
        }
        std::fs::remove_dir(&dir)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn run_single(
        &self,
        filename: &Path,
        producer: &mut Producer,
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

        let offset = if let Some(count_skip) = file.transfer_skip_count {
            count_skip
        } else if let Some(ref offset_suffix) = file.last_transfer_line_suffix {
            let filename = self.config.input.clone() + "_" + offset_suffix;
            u64::try_from(read_offset(&filename))?
        } else {
            0
        };
        let count_sent = file.transfer_count.unwrap_or(0);

        let last_line = match input_type {
            InputType::Log => {
                if GIGANTO_ZEEK_KINDS.contains(&kind) {
                    let rdr = open_raw_event_log_file(filename)?;
                    let zeek_iter = rdr.into_records();
                    producer
                        .send_raw_to_giganto(
                            zeek_iter,
                            offset,
                            count_sent,
                            file.polling_mode,
                            dir_polling_mode,
                            file.export_from_giganto,
                            running,
                            &mut report,
                        )
                        .await?
                } else if kind == OPERATION_LOG {
                    let agent = filename
                        .file_name()
                        .expect("input file name")
                        .to_str()
                        .expect("tostr")
                        .split_once('.')
                        .expect("agent.log")
                        .0;
                    if !AGENTS_LIST.contains(&agent) {
                        bail!("invalid agent name `{agent}.log`");
                    }
                    let oplog = File::open(filename)?;
                    let rdr = BufReader::new(oplog);
                    producer
                        .send_oplog_to_giganto(
                            rdr,
                            agent,
                            file.polling_mode,
                            dir_polling_mode,
                            offset,
                            count_sent,
                            running,
                            &mut report,
                        )
                        .await?
                } else if SYSMON_KINDS.contains(&kind) {
                    let rdr = open_sysmon_csv_file(filename)?;
                    let iter = rdr.into_records();
                    producer
                        .send_sysmon_to_giganto(
                            iter,
                            offset,
                            count_sent,
                            file.polling_mode,
                            dir_polling_mode,
                            kind,
                            running,
                            &mut report,
                        )
                        .await?
                } else if NETFLOW_KIND.contains(&kind) {
                    producer
                        .send_netflow_to_giganto(filename, offset, count_sent, running, &mut report)
                        .await?
                } else if SUPPORTED_SECURITY_KIND.contains(&kind) {
                    let seculog = File::open(filename)?;
                    let rdr = BufReader::new(seculog);
                    producer
                        .send_seculog_to_giganto(
                            rdr,
                            file.polling_mode,
                            dir_polling_mode,
                            offset,
                            count_sent,
                            running,
                            &mut report,
                        )
                        .await?
                } else {
                    producer
                        .send_log_to_giganto(
                            filename,
                            file.polling_mode,
                            dir_polling_mode,
                            offset,
                            count_sent,
                            &mut report,
                            running,
                        )
                        .await?
                }
            }
            InputType::Dir | InputType::Elastic => {
                bail!("invalid input type: {input_type:?}");
            }
        };

        if let Some(ref offset_suffix) = file.last_transfer_line_suffix
            && let Err(e) = write_offset(
                &(self.config.input.clone() + "_" + offset_suffix),
                last_line,
            )
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

fn read_offset(filename: &str) -> usize {
    if let Ok(mut f) = File::open(filename) {
        let mut content = String::new();
        if f.read_to_string(&mut content).is_ok()
            && let Ok(offset) = content.parse()
        {
            info!("Found offset file, skipping {offset} entries");
            return offset;
        }
    }
    0
}

fn write_offset(filename: &str, offset: u64) -> Result<()> {
    let mut f = File::create(filename)?;
    f.write_all(offset.to_string().as_bytes())?;
    Ok(())
}

async fn producer(config: &Config) -> Producer {
    debug!("output type=GIGANTO");
    match Producer::new_giganto(config).await {
        Ok(p) => p,
        Err(e) => {
            error!("Cannot create producer: {e}");
            std::process::exit(1);
        }
    }
}
