use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use bytesize::ByteSize;
use jiff::{SignedDuration, Timestamp, tz::TimeZone};

use crate::controller::input_type;
use crate::{Config, InputType};

pub(crate) struct Report {
    config: Config,
    sum_bytes: usize,
    min_bytes: usize,
    max_bytes: usize,
    avg_bytes: f64,
    skip_bytes: usize,
    skip_cnt: usize,
    process_cnt: usize,
    time_start: Timestamp,
    time_now: Timestamp,
    time_diff: SignedDuration,
}

impl Report {
    #[must_use]
    pub(crate) fn new(config: Config) -> Self {
        Report {
            config,
            sum_bytes: 0,
            min_bytes: 0,
            max_bytes: 0,
            avg_bytes: 0.,
            skip_bytes: 0,
            skip_cnt: 0,
            process_cnt: 0,
            time_start: Timestamp::now(),
            time_now: Timestamp::now(),
            time_diff: SignedDuration::ZERO,
        }
    }

    pub(crate) fn start(&mut self) {
        if !self.config.report {
            return;
        }

        self.time_start = Timestamp::now();
    }

    pub(crate) fn process(&mut self, bytes: usize) {
        if !self.config.report {
            return;
        }

        if self.process_cnt == 0 {
            self.min_bytes = bytes;
            self.max_bytes = bytes;
        } else {
            if bytes > self.max_bytes {
                self.max_bytes = bytes;
            }
            if bytes < self.min_bytes {
                self.min_bytes = bytes;
            }
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
    pub(crate) fn end(&mut self) -> io::Result<()> {
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

        self.time_now = Timestamp::now();
        self.time_diff = self.time_now.duration_since(self.time_start);

        #[allow(clippy::cast_precision_loss)] // approximation is ok
        if self.process_cnt > 0 {
            self.avg_bytes = self.sum_bytes as f64 / self.process_cnt as f64;
        }

        report_file.write_all(b"--------------------------------------------------\n")?;
        let time_now_zoned = self.time_now.to_zoned(TimeZone::UTC);
        report_file.write_fmt(format_args!(
            "{:width$}{}\n",
            "Time:",
            time_now_zoned,
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
            ByteSize(self.skip_bytes as u64),
            width = ARRANGE_VAR,
        ))?;
        let elapsed_ms = self.time_diff.as_millis();
        #[allow(clippy::cast_precision_loss)]
        // approximation is okay; i128 -> f64 loses precision but that's fine for display
        let elapsed_sec = elapsed_ms as f64 / 1_000.;
        report_file.write_fmt(format_args!(
            "{:width$}{:.2} sec\n",
            "Elapsed Time:",
            elapsed_sec,
            width = ARRANGE_VAR,
        ))?;
        #[allow(clippy::cast_possible_truncation)] // rounded number
        #[allow(clippy::cast_precision_loss)] // approximation is okay
        #[allow(clippy::cast_sign_loss)] // positive number
        report_file.write_fmt(format_args!(
            "{:width$}{}/s\n",
            "Performance:",
            ByteSize((processed_bytes as f64 / (elapsed_ms as f64 / 1_000.)).round() as u64),
            width = ARRANGE_VAR,
        ))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    /// Creates a temporary TOML config file with report enabled.
    fn create_test_config(report_enabled: bool) -> Config {
        let config_content = format!(
            r#"
cert = "tests/cert.pem"
key = "tests/key.pem"
ca_certs = ["tests/root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "aicers"
kind = "test"
input = "/path/to/file"
report = {report_enabled}
"#
        );
        let mut file = NamedTempFile::with_suffix(".toml").expect("Failed to create temp file");
        file.write_all(config_content.as_bytes())
            .expect("Failed to write config");
        file.flush().expect("Failed to flush");
        Config::new(file.path()).expect("Failed to create config")
    }

    #[test]
    fn process_first_sample_sets_min_and_max() {
        let config = create_test_config(true);
        let mut report = Report::new(config);

        report.process(10);

        assert_eq!(report.min_bytes, 10);
        assert_eq!(report.max_bytes, 10);
    }

    #[test]
    fn process_updates_min_and_max_correctly() {
        let config = create_test_config(true);
        let mut report = Report::new(config);

        report.process(10);
        assert_eq!(report.min_bytes, 10);
        assert_eq!(report.max_bytes, 10);

        report.process(20);
        assert_eq!(report.min_bytes, 10);
        assert_eq!(report.max_bytes, 20);

        report.process(5);
        assert_eq!(report.min_bytes, 5);
        assert_eq!(report.max_bytes, 20);
    }

    #[test]
    fn skip_accumulates_bytes() {
        let config = create_test_config(true);
        let mut report = Report::new(config);

        report.skip(100);
        assert_eq!(report.skip_bytes, 100);
        assert_eq!(report.skip_cnt, 1);

        report.skip(200);
        assert_eq!(report.skip_bytes, 300);
        assert_eq!(report.skip_cnt, 2);
    }
}
