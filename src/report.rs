use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use bytesize::ByteSize;
use chrono::{DateTime, Duration, Utc};

use crate::controller::input_type;
use crate::{Config, InputType};

pub(super) struct Report {
    config: Config,
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
    pub(super) fn new(config: Config) -> Self {
        Report {
            config,
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

    pub(super) fn start(&mut self) {
        if !self.config.report {
            return;
        }

        self.time_start = Utc::now();
    }

    pub(super) fn process(&mut self, bytes: usize) {
        if !self.config.report {
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

    #[allow(dead_code)]
    fn skip(&mut self, bytes: usize) {
        if !self.config.report {
            return;
        }
        self.skip_bytes += bytes;
        self.skip_cnt += 1;
    }

    /// # Errors
    ///
    /// * `io::Error` when writing to the report file fails.
    #[allow(clippy::too_many_lines)]
    pub(super) fn end(&mut self) -> io::Result<()> {
        const ARRANGE_VAR: usize = 28;

        if !self.config.report {
            return Ok(());
        }

        let report_dir = Path::new("/report");
        let topic = format!("{}.report", &self.config.kind);
        let report_path = if report_dir.is_dir() {
            report_dir.join(topic)
        } else {
            PathBuf::from(topic)
        };
        let mut report_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(report_path)?;

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
        let input_type = input_type(&self.config.input);
        let input = &&self.config.input;
        let (header, processed_bytes) = match input_type {
            InputType::Log => {
                // add 1 byte newline character per line
                let processed_bytes = (self.sum_bytes + self.process_cnt) as u64;
                ("Input(LOG)", processed_bytes)
            }
            InputType::Dir | InputType::Elastic => ("", 0),
        };
        report_file.write_fmt(format_args!(
            "{:width$}{} ({})\n",
            header,
            input,
            ByteSize(processed_bytes),
            width = ARRANGE_VAR,
        ))?;

        report_file.write_all(b"Output(Giganto):\n")?;
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
            ByteSize(processed_bytes),
            width = ARRANGE_VAR,
        ))?;
        report_file.write_fmt(format_args!(
            "{:width$}{} ({})\n",
            "Skip Count:",
            self.skip_cnt,
            ByteSize(self.skip_cnt as u64),
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
            ),
            width = ARRANGE_VAR,
        ))?;
        Ok(())
    }
}
