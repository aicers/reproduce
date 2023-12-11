use crate::syslog::open_sysmon_csv_file;
use crate::zeek::open_raw_event_log_file;
use crate::{Config, InputType, OutputType, Producer, Report};
use anyhow::{anyhow, bail, Result};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tracing::{error, info, warn};
use walkdir::WalkDir;

const GIGANTO_ZEEK_KINDS: [&str; 15] = [
    "conn", "http", "rdp", "smtp", "dns", "ntlm", "kerberos", "ssh", "dce_rpc", "ftp", "mqtt",
    "ldap", "tls", "smb", "nfs",
];
const AGENTS_LIST: [&str; 7] = [
    "review",
    "giganto",
    "piglet",
    "hog",
    "crusher",
    "reconverge",
    "tivan",
];
const OPERATION_LOG: &str = "oplog";
const SYSMON_KINDS: [&str; 15] = [
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
    "pe_file",
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
    pub async fn run(&mut self) -> Result<()> {
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
                        &self.config.giganto_kind.clone(),
                    )
                    .await?;
                }
                InputType::Elastic => {}
            }

            if let Producer::Giganto(mut giganto) = producer {
                giganto.finish().await.expect("failed to finish stream");
            }
        }

        Ok(())
    }

    async fn run_split(&mut self, producer: &mut Producer) -> Result<()> {
        let mut processed = Vec::new();
        loop {
            let mut files = files_in_dir(&self.config.input, &self.config.file_prefix, &processed);

            if files.is_empty() {
                if self.config.mode_polling_dir {
                    tokio::time::sleep(Duration::from_millis(10_000)).await;
                    continue;
                }
                error!("no input file");
                break;
            }

            files.sort_unstable();
            for file in files {
                info!("{file:?}");
                self.run_single(file.as_path(), producer, &self.config.giganto_kind.clone())
                    .await?;
                processed.push(file);
            }

            if !self.config.mode_polling_dir {
                break;
            }
        }
        Ok(())
    }

    async fn run_elastic(&mut self) -> Result<()> {
        let dir = crate::syslog::fetch_elastic_search(
            &self.config.elastic_auth,
            &self.config.config_toml,
        )
        .await?;

        let mut files = files_in_dir(&dir, "", &[]);
        if files.is_empty() {
            bail!("no data with elastic");
        }

        files.sort_unstable();
        for file in files {
            let mut producer = producer(&self.config).await;
            info!("{file:?}");
            let kind = file_to_kind(&file).to_string();
            self.run_single(file.as_path(), &mut producer, &kind)
                .await?;
            std::fs::remove_file(&file)?;
            if let Producer::Giganto(mut giganto) = producer {
                giganto.finish().await.expect("failed to finish stream");
            }
        }
        std::fs::remove_dir(&dir)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn run_single(
        &mut self,
        filename: &Path,
        producer: &mut Producer,
        kind: &str,
    ) -> Result<()> {
        let input_type = input_type(&filename.to_string_lossy());
        if input_type == InputType::Dir {
            return Err(anyhow!("invalid input type"));
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        if let Err(ctrlc::Error::System(e)) =
            ctrlc::set_handler(move || r.store(false, Ordering::SeqCst))
        {
            return Err(anyhow!("failed to set signal handler: {}", e));
        }

        let mut report = Report::new(self.config.clone());

        let offset = if self.config.count_skip > 0 {
            self.config.count_skip
        } else if self.config.offset_prefix.is_empty() {
            0
        } else {
            let filename = self.config.input.clone() + "_" + &self.config.offset_prefix;
            read_offset(&filename)
        };

        let mut conv_cnt = 0;
        report.start();
        let mut giganto_msg: Vec<u8> = Vec::new();

        match input_type {
            InputType::Log => {
                if self.config.output.as_str() == "giganto" && GIGANTO_ZEEK_KINDS.contains(&kind) {
                    let rdr = open_raw_event_log_file(filename)?;
                    let zeek_iter = rdr.into_records();
                    producer
                        .send_raw_to_giganto(
                            zeek_iter,
                            self.config.send_from,
                            self.config.mode_grow,
                            self.config.migration,
                            running.clone(),
                        )
                        .await?;
                } else if self.config.output.as_str() == "giganto" && kind == OPERATION_LOG {
                    let agent = filename
                        .file_name()
                        .expect("input file name")
                        .to_str()
                        .expect("tostr")
                        .split_once('.')
                        .expect("agent.log")
                        .0;
                    if !AGENTS_LIST.contains(&agent) {
                        bail!("invalid agent name `{}.log`", agent);
                    }
                    let oplog = File::open(filename)?;
                    let rdr = BufReader::new(oplog);
                    producer
                        .send_oplog_to_giganto(
                            rdr,
                            agent,
                            self.config.mode_grow,
                            self.config.send_from,
                            running.clone(),
                        )
                        .await?;
                } else if self.config.output.as_str() == "giganto" && SYSMON_KINDS.contains(&kind) {
                    let rdr = open_sysmon_csv_file(filename)?;
                    let iter = rdr.into_records();
                    producer
                        .send_sysmon_to_giganto(
                            iter,
                            self.config.send_from,
                            self.config.mode_grow,
                            kind,
                            running,
                        )
                        .await?;
                } else if self.config.output.as_str() == "giganto" && NETFLOW_KIND.contains(&kind) {
                    producer
                        .send_netflow_to_giganto(filename, self.config.send_from, running)
                        .await?;
                } else if self.config.output.as_str() == "giganto"
                    && SUPPORTED_SECURITY_KIND.contains(&kind)
                {
                    let seculog = File::open(filename)?;
                    let rdr = BufReader::new(seculog);
                    producer
                        .send_seculog_to_giganto(
                            rdr,
                            self.config.mode_grow,
                            self.config.send_from,
                            running,
                        )
                        .await?;
                } else {
                    let log_file =
                        open_log(filename).map_err(|e| anyhow!("failed to open: {}", e))?;
                    let mut lines = BinaryLines::new(BufReader::new(log_file)).skip(offset);
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
                                if self.config.mode_grow && !self.config.mode_polling_dir {
                                    tokio::time::sleep(Duration::from_millis(3_000)).await;
                                    continue;
                                }
                                break;
                            }
                        };
                        if let Producer::Giganto(_) = producer {
                            giganto_msg.extend(&line);
                            if let Err(e) = producer.produce(giganto_msg.as_slice(), true).await {
                                error!("failed to produce message to Giganto. {e}");
                                break;
                            }
                            giganto_msg.clear();
                        }
                        conv_cnt += 1;
                        report.process(line.len());
                        if self.config.count_sent != 0 && conv_cnt >= self.config.count_sent {
                            break;
                        }
                    }
                }
            }
            InputType::Dir | InputType::Elastic => {
                error!("invalid input type: {input_type:?}");
            }
        }
        if let Err(e) = write_offset(
            &(self.config.input.clone() + "_" + &self.config.offset_prefix),
            offset + conv_cnt,
        ) {
            warn!("cannot write to offset file: {e}");
        }

        if let Err(e) = report.end() {
            warn!("cannot write report: {e}");
        }
        Ok(())
    }
}

fn file_to_kind(path: &Path) -> &'static str {
    let re = regex::Regex::new(r"event(\d+)_log.csv").unwrap();
    let file_name = path.file_name().unwrap().to_str().unwrap();
    if let Some(cap) = re.captures(file_name) {
        let num = &cap[1];
        match num {
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
        }
    } else {
        ""
    }
}

fn files_in_dir(path: &str, prefix: &str, skip: &[PathBuf]) -> Vec<PathBuf> {
    WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|entry| {
            if let Ok(entry) = entry {
                if !entry.file_type().is_file() {
                    return None;
                }
                if !prefix.is_empty() {
                    if let Some(name) = entry.path().file_name() {
                        if !name.to_string_lossy().starts_with(prefix) {
                            return None;
                        }
                    }
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

fn input_type(input: &str) -> InputType {
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

fn output_type(output: &str) -> OutputType {
    if output == "none" {
        OutputType::None
    } else if output == "giganto" {
        OutputType::Giganto
    } else {
        OutputType::File
    }
}

fn read_offset(filename: &str) -> usize {
    if let Ok(mut f) = File::open(filename) {
        let mut content = String::new();
        if f.read_to_string(&mut content).is_ok() {
            if let Ok(offset) = content.parse() {
                info!("offset file found. Skipping {offset} entries.");
                return offset;
            }
        }
    }
    0
}

fn write_offset(filename: &str, offset: usize) -> Result<()> {
    let mut f = File::create(filename)?;
    f.write_all(offset.to_string().as_bytes())?;
    Ok(())
}

fn open_log<P: AsRef<Path>>(input: P) -> Result<File> {
    let log_file = File::open(input.as_ref())?;
    info!("input={:?}, input type=LOG", input.as_ref());

    Ok(log_file)
}

async fn producer(config: &Config) -> Producer {
    match output_type(&config.output) {
        OutputType::File => {
            info!("output={}, output type=FILE", &config.output);
            match Producer::new_file(&config.output) {
                Ok(p) => p,
                Err(e) => {
                    error!("cannot create File producer: {e}");
                    std::process::exit(1);
                }
            }
        }
        OutputType::Giganto => {
            info!("output={}, output type=GIGANTO", &config.output);
            match Producer::new_giganto(
                &config.giganto_addr,
                &config.giganto_name,
                &config.config_toml,
                &config.giganto_kind,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    error!("cannot create Giganto producer: {e}");
                    std::process::exit(1);
                }
            }
        }
        OutputType::None => {
            info!("output={}, output type=NONE", &config.output);
            Producer::new_null()
        }
    }
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
    type Item = Result<Vec<u8>, io::Error>;

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
