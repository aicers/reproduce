use crate::config::{Config, InputType, OutputType};
use crate::zeek::open_log_file;
use crate::{Converter, Matcher, Producer, Report, SizedForwardMode};
use anyhow::{anyhow, Result};
use csv::Position;
use rmp_serde::Serializer;
use serde::Serialize;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};
use walkdir::WalkDir;

const KAFKA_BUFFER_SAFETY_GAP: usize = 1024;
const GIGANTO_ZEEK_KINDS: [&str; 9] = [
    "conn", "http", "rdp", "smtp", "dns", "ntlm", "kerberos", "ssh", "dce_rpc",
];

pub struct Controller {
    config: Config,
    seq_no: usize,
}

impl Controller {
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self { config, seq_no: 1 }
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

        if self.seq_no == 1 {
            if self.config.initial_seq_no > 0 {
                self.seq_no = self.config.initial_seq_no;
            } else if offset > 0 {
                self.seq_no = offset + 1;
            }
        }

        let mut conv_cnt = 0;
        report.start(self.get_seq_no(0));
        let mut giganto_msg: Vec<u8> = Vec::new();
        let mut msg = SizedForwardMode::default();
        msg.set_tag("REproduce".to_string()).expect("not too long");
        let mut buf: Vec<u8> = Vec::new();
        let pattern_file = self.config.pattern_file.to_string();

        match input_type {
            InputType::Log => {
                if self.config.output.as_str() == "giganto"
                    && GIGANTO_ZEEK_KINDS.contains(&self.config.giganto_kind.as_str())
                {
                    let mut rdr = open_log_file(filename)?;
                    let pos = Position::new();
                    rdr.seek(pos)?;
                    let zeek_iter = rdr.records();
                    producer
                        .send_zeek_to_giganto(zeek_iter, self.config.zeek_from)
                        .await?;
                } else {
                    let (mut converter, log_file) = log_converter(filename, &pattern_file)
                        .map_err(|e| anyhow!("failed to set the converter: {}", e))?;
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
                        match producer {
                            Producer::Giganto(_) => {
                                giganto_msg.extend(&line);
                                if let Err(e) = producer.produce(giganto_msg.as_slice(), true).await
                                {
                                    error!("failed to produce message to Giganto. {e}");
                                    break;
                                }
                                giganto_msg.clear();
                            }
                            _ => {
                                if msg.serialized_len() + line.len()
                                    >= Producer::max_bytes() - KAFKA_BUFFER_SAFETY_GAP
                                {
                                    msg.message.serialize(&mut Serializer::new(&mut buf))?;
                                    if producer.produce(buf.as_slice(), true).await.is_err() {
                                        break;
                                    }
                                    msg.clear();
                                    buf.clear();
                                    msg.set_tag("REproduce".to_string())?;
                                }
                            }
                        }

                        self.seq_no += 1;
                        if converter.convert(self.event_id(), &line, &mut msg).is_err() {
                            // TODO: error handling for conversion failure
                            report.skip(line.len());
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
        match producer {
            Producer::Giganto(_) => {}
            _ => {
                if !msg.is_empty() {
                    msg.message.serialize(&mut Serializer::new(&mut buf))?;
                    producer.produce(buf.as_slice(), true).await?;
                }
            }
        }
        if let Err(e) = write_offset(
            &(self.config.input.clone() + "_" + &self.config.offset_prefix),
            offset + conv_cnt,
        ) {
            warn!("cannot write to offset file: {e}");
        }

        #[allow(clippy::cast_possible_truncation)] // value never exceeds 0x00ff_ffff
        if let Err(e) = report.end(((self.seq_no - 1) & 0x00ff_ffff) as u32) {
            warn!("cannot write report: {e}");
        }
        Ok(())
    }

    fn event_id(&self) -> u64 {
        let mut base_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after UNIX EPOCH")
            .as_secs();
        if self.seq_no.trailing_zeros() >= 24 {
            base_time += 1;
        }

        (base_time << 32)
            | ((self.seq_no & 0x00ff_ffff) << 8) as u64
            | u64::from(self.config.datasource_id)
    }

    fn get_seq_no(&self, num: usize) -> usize {
        (self.seq_no + num) & 0x00ff_ffff
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
    if output.is_empty() {
        OutputType::Kafka
    } else if output == "none" {
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

fn matcher(pattern_file: &str) -> Option<Matcher> {
    if pattern_file.is_empty() {
        None
    } else if let Ok(f) = File::open(pattern_file) {
        if let Ok(m) = Matcher::from_read(f) {
            Some(m)
        } else {
            None
        }
    } else {
        None
    }
}

fn log_converter<P: AsRef<Path>>(input: P, pattern_file: &str) -> Result<(Converter, File)> {
    let matcher = matcher(pattern_file);
    let log_file = File::open(input.as_ref())?;
    info!("input={:?}, input type=LOG", input.as_ref());
    if matcher.is_some() {
        info!("pattern file={pattern_file}");
    }
    Ok((Converter::new(matcher), log_file))
}

async fn producer(config: &Config) -> Producer {
    match output_type(&config.output) {
        OutputType::File => {
            info!("output={}, output type=FILE", &config.output);
            match Producer::new_file(&config.output) {
                Ok(p) => p,
                Err(e) => {
                    error!("cannot create Kafka producer: {e}");
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
        OutputType::Kafka => {
            info!("output={}, output type=KAFKA", &config.output);
            match Producer::new_kafka(
                &config.kafka_broker,
                &config.kafka_topic,
                config.queue_size,
                config.queue_period,
                config.mode_grow,
            ) {
                Ok(p) => p,
                Err(e) => {
                    error!("cannot create Kafka producer: {e}");
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
