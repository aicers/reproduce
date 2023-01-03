use crate::config::{Config, InputType, OutputType};
use crate::zeek::open_zeek_log_file;
use crate::{Producer, Report};
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

const GIGANTO_ZEEK_KINDS: [&str; 9] = [
    "conn", "http", "rdp", "smtp", "dns", "ntlm", "kerberos", "ssh", "dce_rpc",
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
    pub async fn run(&mut self) -> Result<()> {
        let input_type = input_type(&self.config.input);
        let mut producer = producer(&self.config).await;

        if input_type == InputType::Dir {
            self.run_split(&mut producer).await?;
        } else {
            let filename = Path::new(&self.config.input).to_path_buf();
            self.run_single(filename.as_ref(), &mut producer).await?;
        }

        if let Producer::Giganto(mut giganto) = producer {
            giganto.finish().await.expect("failed to finish stream");
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
                self.run_single(file.as_path(), producer).await?;
                processed.push(file);
            }

            if !self.config.mode_polling_dir {
                break;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn run_single(&mut self, filename: &Path, producer: &mut Producer) -> Result<()> {
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
                if self.config.output.as_str() == "giganto"
                    && GIGANTO_ZEEK_KINDS.contains(&self.config.giganto_kind.as_str())
                {
                    let rdr = open_zeek_log_file(filename)?;
                    let zeek_iter = rdr.into_records();
                    producer
                        .send_zeek_to_giganto(
                            zeek_iter,
                            self.config.send_from,
                            self.config.mode_grow,
                            running.clone(),
                        )
                        .await?;
                } else if self.config.output.as_str() == "giganto"
                    && self.config.giganto_kind.as_str() == OPERATION_LOG
                {
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
            InputType::Dir => {
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
    let path = Path::new(input);
    if path.is_dir() {
        InputType::Dir
    } else {
        InputType::Log
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
                &config.certs_toml,
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
