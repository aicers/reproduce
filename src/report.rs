use crate::Config;
use crate::{config_datasource_id, config_input_type, config_mode_eval, config_output_type};
use bytesize::ByteSize;
use chrono::{DateTime, Duration, Utc};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct Report {
    config: Config,
    start_id: usize,
    end_id: u32,
    sum_bytes: usize,
    min_bytes: usize,
    max_bytes: usize,
    avg_bytes: f64,
    skip_bytes: usize,
    skip_cnt: usize,
    process_cnt: usize,
    time_start: DateTime<Utc>,
    time_now: DateTime<Utc>,
    time_diff: Duration,
}

impl Report {
    #[must_use]
    pub fn new(config: Config) -> Self {
        Report {
            config,
            start_id: 0,
            end_id: 0,
            sum_bytes: 0,
            min_bytes: 0,
            max_bytes: 0,
            avg_bytes: 0.,
            skip_bytes: 0,
            skip_cnt: 0,
            process_cnt: 0,
            time_start: Utc::now(),
            time_now: Utc::now(),
            time_diff: Duration::zero(),
        }
    }

    pub fn start(&mut self, id: usize) {
        if unsafe { config_mode_eval(&self.config) } == 0 {
            return;
        }

        self.start_id = id;
        self.time_start = Utc::now();
    }

    pub fn process(&mut self, bytes: usize) {
        if unsafe { config_mode_eval(&self.config) } == 0 {
            return;
        }

        if bytes > self.max_bytes {
            self.max_bytes = bytes;
        } else if bytes < self.min_bytes || self.min_bytes == 0 {
            self.min_bytes = bytes;
        }
        self.sum_bytes += bytes;
        self.process_cnt += 1;
    }

    pub fn skip(&mut self, bytes: usize) {
        if unsafe { config_mode_eval(&self.config) } == 0 {
            return;
        }
        self.skip_bytes += bytes;
        self.skip_cnt += 1;
    }

    /// # Errors
    ///
    /// * `io::Error` when writing to the report file fails.
    #[allow(clippy::too_many_lines)]
    pub fn end(&mut self, id: u32) -> io::Result<()> {
        const PCAP_FILE_HEADER_LEN: usize = 24;
        const PCAP_PKTHDR_LEN: usize = 8;
        const ARRANGE_VAR: usize = 28;

        if unsafe { config_mode_eval(&self.config) } == 0 {
            return Ok(());
        }

        let report_dir = Path::new("/report");
        let topic = &&self.config.kafka_topic;
        let report_path = if report_dir.is_dir() {
            report_dir.join(topic)
        } else {
            PathBuf::from(topic)
        };
        let mut report_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(report_path)?;

        self.end_id = id;
        self.time_now = Utc::now();
        self.time_diff = self.time_now - self.time_start;

        #[allow(clippy::cast_precision_loss)] // approximation is ok
        if self.process_cnt > 0 {
            self.avg_bytes = self.sum_bytes as f64 / self.process_cnt as f64;
        }

        report_file.write_all(b"--------------------------------------------------\n")?;
        report_file.write_fmt(format_args!(
            "{:width$}{}\n",
            "Time:",
            self.time_now,
            width = ARRANGE_VAR,
        ))?;
        let input_type = unsafe { config_input_type(&self.config) };
        let input = &&self.config.input;
        let (header, processed_bytes) = match input_type {
            0 => {
                let processed_bytes = (self.sum_bytes + PCAP_FILE_HEADER_LEN) as u64;
                ("Input(PCAP)", processed_bytes)
            }
            1 => {
                let processed_bytes = (self.sum_bytes + PCAP_FILE_HEADER_LEN) as u64;
                ("Input(PCAPNG)", processed_bytes)
            }
            2 => {
                let processed_bytes = (self.sum_bytes + PCAP_PKTHDR_LEN) as u64;
                ("Input(NIC)", processed_bytes)
            }
            3 => {
                // add 1 byte newline character per line
                let processed_bytes = (self.sum_bytes + self.process_cnt) as u64;
                ("Input(LOG)", processed_bytes)
            }
            _ => ("", 0),
        };
        report_file.write_fmt(format_args!(
            "{:width$}{} ({})\n",
            header,
            input,
            ByteSize(processed_bytes).to_string(),
            width = ARRANGE_VAR,
        ))?;
        report_file.write_fmt(format_args!(
            "{:width$}{}\n",
            "Data source ID:",
            u32::from(unsafe { config_datasource_id(&self.config) }),
            width = ARRANGE_VAR,
        ))?;
        report_file.write_fmt(format_args!(
            "{:width$}{}-{}\n",
            "Input ID:",
            self.start_id,
            self.end_id,
            width = ARRANGE_VAR,
        ))?;

        let output_type = unsafe { config_output_type(&self.config) };
        match output_type {
            0 => {
                report_file.write_all(b"Output(NONE):\n")?;
            }
            1 => {
                let broker = &&self.config.kafka_broker;
                report_file.write_fmt(format_args!(
                    "{:width$}{} ({})\n",
                    "Output(KAFKA):",
                    broker,
                    topic,
                    width = ARRANGE_VAR,
                ))?;
            }
            2 => {
                let output = &&self.config.output;
                let size = if let Ok(meta) = Path::new(input).metadata() {
                    ByteSize(meta.len()).to_string()
                } else {
                    "invalid".to_string()
                };
                report_file.write_fmt(format_args!(
                    "{:width$}{} ({})\n",
                    "Output(FILE):",
                    output,
                    size,
                    width = ARRANGE_VAR,
                ))?;
            }
            _ => {}
        }
        report_file.write_fmt(format_args!(
            "{:width$}{}/{}/{:.2} bytes\n",
            "Statistics (Min/Max/Avg):",
            self.min_bytes,
            self.max_bytes,
            self.avg_bytes,
            width = ARRANGE_VAR,
        ))?;
        report_file.write_fmt(format_args!(
            "{:width$}{} ({})\n",
            "Process Count:",
            self.process_cnt,
            ByteSize(processed_bytes).to_string(),
            width = ARRANGE_VAR,
        ))?;
        report_file.write_fmt(format_args!(
            "{:width$}{} ({})\n",
            "Skip Count:",
            self.skip_cnt,
            ByteSize(self.skip_cnt as u64).to_string(),
            width = ARRANGE_VAR,
        ))?;
        #[allow(clippy::cast_precision_loss)] // approximation is okay
        report_file.write_fmt(format_args!(
            "{:width$}{:.2} sec\n",
            "Elapsed Time:",
            self.time_diff.num_milliseconds() as f64 / 1_000.,
            width = ARRANGE_VAR,
        ))?;
        #[allow(clippy::cast_possible_truncation)] // rounded number
        #[allow(clippy::cast_precision_loss)] // approximation is okay
        #[allow(clippy::cast_sign_loss)] // positive number
        report_file.write_fmt(format_args!(
            "{:width$}{}/s\n",
            "Performance:",
            ByteSize(
                (processed_bytes as f64 / (self.time_diff.num_milliseconds() as f64 / 1_000.))
                    .round() as u64
            )
            .to_string(),
            width = ARRANGE_VAR,
        ))?;
        Ok(())
    }
}
