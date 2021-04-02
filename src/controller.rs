use crate::config::{Config, InputType, OutputType};
use crate::{Converter, Matcher, Producer, Report, SizedForwardMode};
use anyhow::{anyhow, Result};
use pcap::{Active, Capture, Offline};
use rmp_serde::Serializer;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

const KAFKA_BUFFER_SAFETY_GAP: usize = 1024;

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
    pub fn run(&mut self) -> Result<()> {
        let input_type = input_type(&self.config.input);
        let is_nic = input_type == InputType::Nic;
        let mut producer = producer(&self.config, is_nic);

        if input_type == InputType::Dir {
            self.run_split(&mut producer)
        } else {
            let filename = Path::new(&self.config.input).to_path_buf();
            self.run_single(filename.as_ref(), &mut producer)
        }
    }

    fn run_split(&mut self, producer: &mut Producer) -> Result<()> {
        let mut processed = Vec::new();
        loop {
            let mut files = files_in_dir(&self.config.input, &self.config.file_prefix, &processed);

            if files.is_empty() {
                if self.config.mode_polling_dir {
                    thread::sleep(Duration::from_millis(10_000));
                    continue;
                }
                eprintln!("ERROR: no input file");
                break;
            }

            files.sort_unstable();
            for file in files {
                println!("{:?}", file);
                self.run_single(file.as_path(), producer)?;
                processed.push(file);
            }

            if !self.config.mode_polling_dir {
                break;
            }
        }
        Ok(())
    }

    #[allow(clippy::clippy::too_many_lines)]
    fn run_single(&mut self, filename: &Path, producer: &mut Producer) -> Result<()> {
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
        } else if self.config.offset_prefix.is_empty() || input_type == InputType::Nic {
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
        let mut msg = SizedForwardMode::default();
        msg.set_tag("REproduce".to_string()).expect("not too long");
        let mut buf: Vec<u8> = Vec::new();
        let pattern_file = self.config.pattern_file.to_string();

        match input_type {
            InputType::Log => {
                let (mut converter, log_file) = log_converter(filename, &pattern_file)
                    .map_err(|e| anyhow!("failed to set the converter: {}", e))?;
                let mut lines = BufReader::new(log_file).lines().skip(offset);
                while running.load(Ordering::SeqCst) {
                    let line = match lines.next() {
                        Some(Ok(line)) => line,
                        Some(Err(e)) => {
                            eprintln!("ERROR: failed to convert input data: {}", e);
                            break;
                        }
                        None => {
                            if self.config.mode_grow && !self.config.mode_polling_dir {
                                thread::sleep(Duration::from_millis(3_000));
                                continue;
                            }
                            break;
                        }
                    };
                    if msg.serialized_len() + line.len()
                        >= Producer::max_bytes() - KAFKA_BUFFER_SAFETY_GAP
                    {
                        msg.message.serialize(&mut Serializer::new(&mut buf))?;
                        if producer.produce(buf.as_slice(), true).is_err() {
                            break;
                        }
                        msg.clear();
                        msg.set_tag("REproduce".to_string())?;
                    }

                    self.seq_no += 1;
                    if converter
                        .convert(self.event_id(), line.as_bytes(), &mut msg)
                        .is_err()
                    {
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
            InputType::Nic => {
                let input = self.config.input.to_string();
                let (mut converter, mut cap) = nic_converter(&input, &pattern_file)
                    .map_err(|e| anyhow!("failed to set the converter: {}", e))?;
                while running.load(Ordering::SeqCst) {
                    let pkt = match cap.next() {
                        Ok(pkt) => pkt,
                        Err(e) => {
                            eprintln!("WARN: cannot read packet: {}", e);
                            break;
                        }
                    };
                    if msg.serialized_len() + pkt.data.len()
                        >= Producer::max_bytes() - KAFKA_BUFFER_SAFETY_GAP
                    {
                        msg.message.serialize(&mut Serializer::new(&mut buf))?;
                        if producer.produce(buf.as_slice(), true).is_err() {
                            break;
                        }
                        msg.clear();
                        msg.set_tag("REproduce".to_string())?;
                    }

                    self.seq_no += 1;
                    if converter
                        .convert(self.event_id(), pkt.data, &mut msg)
                        .is_err()
                    {
                        // TODO: error handling for conversion failure
                        report.skip(pkt.data.len());
                    }
                    conv_cnt += 1;
                    report.process(pkt.data.len());
                    if self.config.count_sent != 0 && conv_cnt >= self.config.count_sent {
                        break;
                    }
                }
            }
            InputType::Pcap => {
                let (mut converter, mut cap) = pcap_converter(filename, &pattern_file)
                    .map_err(|e| anyhow!("failed to set the converter: {}", e))?;
                for _ in 0..offset {
                    if let Err(e) = cap.next() {
                        eprintln!("failed to skip packets: {}", e);
                        break;
                    }
                }
                while running.load(Ordering::SeqCst) {
                    let pkt = match cap.next() {
                        Ok(pkt) => pkt,
                        Err(pcap::Error::NoMorePackets) => {
                            if self.config.mode_grow && !self.config.mode_polling_dir {
                                thread::sleep(Duration::from_millis(3_000));
                                continue;
                            }
                            break;
                        }
                        Err(e) => {
                            eprintln!("WARN: cannot read packet: {}", e);
                            break;
                        }
                    };
                    if msg.serialized_len() + pkt.data.len()
                        >= Producer::max_bytes() - KAFKA_BUFFER_SAFETY_GAP
                    {
                        msg.message.serialize(&mut Serializer::new(&mut buf))?;
                        if producer.produce(buf.as_slice(), true).is_err() {
                            break;
                        }
                        msg.clear();
                        msg.set_tag("REproduce".to_string())?;
                    }

                    self.seq_no += 1;
                    if converter
                        .convert(self.event_id(), pkt.data, &mut msg)
                        .is_err()
                    {
                        // TODO: error handling for conversion failure
                        report.skip(pkt.data.len());
                    }
                    conv_cnt += 1;
                    report.process(pkt.data.len());
                    if self.config.count_sent != 0 && conv_cnt >= self.config.count_sent {
                        break;
                    }
                }
            }
            InputType::Dir => {
                eprintln!("ERROR: invalide input type: {:?}", input_type);
            }
        }

        if !msg.is_empty() {
            msg.message.serialize(&mut Serializer::new(&mut buf))?;
            producer.produce(buf.as_slice(), true)?;
        }
        if let Err(e) = write_offset(
            &(self.config.input.clone() + "_" + &self.config.offset_prefix),
            offset + conv_cnt,
        ) {
            eprintln!("WARNING: cannot write to offset file: {}", e);
        }

        #[allow(clippy::cast_possible_truncation)] // value never exceeds 0x00ff_ffff
        if let Err(e) = report.end(((self.seq_no - 1) & 0x00ff_ffff) as u32) {
            eprintln!("WARNING: cannot write report: {}", e);
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
        return InputType::Dir;
    }
    if !path.is_file() {
        let cap = match Capture::from_device(input) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("failed to access {}: {}", input, e);
                std::process::exit(1);
            }
        };
        if let Err(e) = cap.open() {
            eprintln!("failed to open {}: {}", input, e);
            std::process::exit(1);
        }
        return InputType::Nic;
    }

    match Capture::from_file(path) {
        Ok(_) => InputType::Pcap,
        Err(_) => InputType::Log,
    }
}

fn output_type(output: &str) -> OutputType {
    if output.is_empty() {
        OutputType::Kafka
    } else if output == "none" {
        OutputType::None
    } else {
        OutputType::File
    }
}

fn read_offset(filename: &str) -> usize {
    if let Ok(mut f) = File::open(filename) {
        let mut content = String::new();
        if f.read_to_string(&mut content).is_ok() {
            if let Ok(offset) = content.parse() {
                println!("Offset file exists. Skipping {} entries.", offset);
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
    println!("input={:?}, input type=LOG", input.as_ref());
    if matcher.is_some() {
        println!("pattern file={}", pattern_file);
    }
    Ok((Converter::with_log(matcher), log_file))
}

fn nic_converter(input: &str, pattern_file: &str) -> Result<(Converter, Capture<Active>)> {
    let matcher = matcher(pattern_file);
    let cap = Capture::from_device(input)?.open()?;
    let l2_type = cap.get_datalink();
    println!("input={}, input type=NIC", input);
    if matcher.is_some() {
        println!("pattern file={}", pattern_file);
    }
    Ok((Converter::with_packet(l2_type, matcher), cap))
}

fn pcap_converter<P: AsRef<Path>>(
    input: P,
    pattern_file: &str,
) -> Result<(Converter, Capture<Offline>)> {
    let matcher = matcher(pattern_file);
    let cap = Capture::from_file(input.as_ref())?;
    let l2_type = cap.get_datalink();
    println!("input={:?}, input type=NIC", input.as_ref());
    if matcher.is_some() {
        println!("pattern file={}", pattern_file);
    }
    Ok((Converter::with_packet(l2_type, matcher), cap))
}

fn producer(config: &Config, is_nic: bool) -> Producer {
    match output_type(&config.output) {
        OutputType::File => {
            println!("output={}, output type=FILE", &config.output);
            match Producer::new_file(&config.output) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("cannot create Kafka producer: {}", e);
                    std::process::exit(1);
                }
            }
        }
        OutputType::Kafka => {
            println!("output={}, output type=KAFKA", &config.output);
            match Producer::new_kafka(
                &config.kafka_broker,
                &config.kafka_topic,
                config.queue_size,
                config.queue_period,
                config.mode_grow || is_nic,
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("cannot create Kafka producer: {}", e);
                    std::process::exit(1);
                }
            }
        }
        OutputType::None => {
            println!("output={}, output type=NONE", &config.output);
            Producer::new_null()
        }
    }
}
