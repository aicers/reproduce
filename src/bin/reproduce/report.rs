use std::fs::OpenOptions;
use std::io::{self, Write};

use bytesize::ByteSize;
use jiff::{SignedDuration, Timestamp, tz::TimeZone};
use num_traits::ToPrimitive;

use crate::{
    config::{Config, InputType},
    input_type,
};

const ARRANGE_VAR: usize = 28;
const MILLIS_PER_SECOND: f64 = 1_000.0;

fn usize_to_u64(value: usize, field_name: &str) -> io::Result<u64> {
    u64::try_from(value).map_err(|_| io::Error::other(format!("{field_name} exceeds u64")))
}

fn usize_to_f64(value: usize, field_name: &str) -> io::Result<f64> {
    value
        .to_f64()
        .ok_or_else(|| io::Error::other(format!("{field_name} cannot be represented as f64")))
}

fn i128_to_f64(value: i128, field_name: &str) -> io::Result<f64> {
    value
        .to_f64()
        .ok_or_else(|| io::Error::other(format!("{field_name} cannot be represented as f64")))
}

fn f64_to_u64_rounded(value: f64, field_name: &str) -> io::Result<u64> {
    value.round().to_u64().ok_or_else(|| {
        io::Error::other(format!(
            "{field_name} cannot be represented as a rounded u64"
        ))
    })
}

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

    #[allow(dead_code)] // report skipping is preserved for future parity with the legacy report.
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
        if !self.config.report {
            return Ok(());
        }

        let report_dir = self
            .config
            .report_dir
            .as_deref()
            .ok_or_else(|| io::Error::other("report_dir must be set when report is true"))?;
        std::fs::create_dir_all(report_dir)?;
        let topic = format!("{}.report", &self.config.kind);
        let report_path = report_dir.join(topic);
        let mut report_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(report_path)?;

        self.time_now = Timestamp::now();
        self.time_diff = self.time_now.duration_since(self.time_start);

        if self.process_cnt > 0 {
            let total_bytes = usize_to_f64(self.sum_bytes, "sum_bytes")?;
            let processed_count = usize_to_f64(self.process_cnt, "process_cnt")?;
            self.avg_bytes = total_bytes / processed_count;
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
                let processed_bytes = self
                    .sum_bytes
                    .checked_add(self.process_cnt)
                    .ok_or_else(|| io::Error::other("processed bytes overflowed usize"))?;
                let processed_bytes = usize_to_u64(processed_bytes, "processed bytes")?;
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
            ByteSize(usize_to_u64(self.skip_bytes, "skip_bytes")?),
            width = ARRANGE_VAR,
        ))?;
        let elapsed_ms = self.time_diff.as_millis();
        let elapsed_sec = i128_to_f64(elapsed_ms, "elapsed milliseconds")? / MILLIS_PER_SECOND;
        report_file.write_fmt(format_args!(
            "{:width$}{:.2} sec\n",
            "Elapsed Time:",
            elapsed_sec,
            width = ARRANGE_VAR,
        ))?;
        let performance = if elapsed_ms <= 0 || processed_bytes == 0 {
            0
        } else {
            let processed_bytes_f64 = processed_bytes
                .to_f64()
                .ok_or_else(|| io::Error::other("processed bytes cannot be represented as f64"))?;
            f64_to_u64_rounded(processed_bytes_f64 / elapsed_sec, "throughput")?
        };
        report_file.write_fmt(format_args!(
            "{:width$}{}/s\n",
            "Performance:",
            ByteSize(performance),
            width = ARRANGE_VAR,
        ))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;

    use reproduce::config::GigantoConfig;

    use super::*;

    /// Creates a test `Config` with the given parameters.
    fn test_config(report: bool, kind: &str, input: &str, report_dir: Option<PathBuf>) -> Config {
        Config {
            giganto: GigantoConfig {
                cert: String::new(),
                key: String::new(),
                ca_certs: vec![],
                ingest_srv_addr: "127.0.0.1:8080"
                    .parse::<SocketAddr>()
                    .expect("test socket address literal should parse"),
                name: String::from("test"),
            },
            kind: String::from(kind),
            input: String::from(input),
            report,
            report_dir,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        }
    }

    #[test]
    fn process_first_sample_sets_min_and_max() {
        let config = test_config(
            true,
            "test",
            "/path/to/file",
            Some(PathBuf::from("/tmp/reports")),
        );
        let mut report = Report::new(config);

        report.process(10);

        assert_eq!(report.min_bytes, 10);
        assert_eq!(report.max_bytes, 10);
    }

    #[test]
    fn process_updates_min_and_max_correctly() {
        let config = test_config(
            true,
            "test",
            "/path/to/file",
            Some(PathBuf::from("/tmp/reports")),
        );
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
        let config = test_config(
            true,
            "test",
            "/path/to/file",
            Some(PathBuf::from("/tmp/reports")),
        );
        let mut report = Report::new(config);

        report.skip(100);
        assert_eq!(report.skip_bytes, 100);
        assert_eq!(report.skip_cnt, 1);

        report.skip(200);
        assert_eq!(report.skip_bytes, 300);
        assert_eq!(report.skip_cnt, 2);
    }

    #[test]
    fn report_false_avoids_file_writes() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_out = temp_dir.path().join("report_output");

        let config = test_config(false, "test_kind", "test.log", Some(report_out.clone()));
        let mut report = Report::new(config);

        report.start();
        report.process(100);
        report.process(200);
        let result = report.end();

        assert!(result.is_ok());
        assert!(
            !report_out.exists(),
            "No directory should be created when report=false"
        );
    }

    #[test]
    fn report_false_does_not_update_time_start() {
        let config = test_config(false, "test_kind", "test.log", None);
        let mut report = Report::new(config);

        let initial_time = report.time_start;
        std::thread::sleep(std::time::Duration::from_millis(10));

        report.start();

        assert_eq!(
            report.time_start, initial_time,
            "time_start should not be updated when report=false"
        );
    }

    #[test]
    fn report_false_does_not_update_counters() {
        let config = test_config(false, "test_kind", "test.log", None);
        let mut report = Report::new(config);

        report.process(100);
        report.process(200);

        assert_eq!(
            report.sum_bytes, 0,
            "sum_bytes should not be updated when report=false"
        );
        assert_eq!(
            report.process_cnt, 0,
            "process_cnt should not be updated when report=false"
        );
        assert_eq!(
            report.min_bytes, 0,
            "min_bytes should not be updated when report=false"
        );
        assert_eq!(
            report.max_bytes, 0,
            "max_bytes should not be updated when report=false"
        );
    }

    /// Runs a complete report cycle (start/process/end) with the given byte
    /// values, writing to `report_dir`. Returns the report file path.
    fn run_report(report_dir: &std::path::Path, input: &str, bytes_list: &[usize]) -> PathBuf {
        let config = test_config(true, "test_kind", input, Some(report_dir.to_path_buf()));
        let mut report = Report::new(config);

        report.start();
        for &bytes in bytes_list {
            report.process(bytes);
        }
        report.end().expect("report end() should succeed");

        report_dir.join("test_kind.report")
    }

    #[test]
    fn report_true_creates_file() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_dir = temp_dir.path().join("reports");
        let report_file = run_report(&report_dir, "test.log", &[100, 200, 300]);
        assert!(
            report_file.exists(),
            "Report file should be created in report_dir when report=true"
        );
    }

    #[test]
    fn report_true_creates_missing_directory() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_dir = temp_dir.path().join("nested").join("reports");

        assert!(
            !report_dir.exists(),
            "report_dir should not exist before test"
        );

        let report_file = run_report(&report_dir, "test.log", &[100]);

        assert!(
            report_dir.is_dir(),
            "report_dir should be created automatically"
        );
        assert!(
            report_file.exists(),
            "Report file should exist in newly created directory"
        );
    }

    #[test]
    fn report_true_uses_existing_directory() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_dir = temp_dir.path().join("existing_reports");
        std::fs::create_dir_all(&report_dir).expect("failed to create report dir");

        let report_file = run_report(&report_dir, "test.log", &[100]);

        assert!(
            report_file.exists(),
            "Report file should be written into existing directory"
        );
    }

    #[test]
    fn report_true_file_contains_all_sections() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_dir = temp_dir.path().join("reports");
        let report_file = run_report(&report_dir, "test.log", &[100, 200, 300]);
        let content = std::fs::read_to_string(&report_file).expect("failed to read report file");

        assert!(content.contains("--------------------------------------------------"));
        assert!(content.contains("Time:"));
        assert!(content.contains("Input(LOG)"));
        assert!(content.contains("Output(Giganto):"));
        assert!(content.contains("Statistics (Min/Max/Avg):"));
        assert!(content.contains("Process Count:"));
        assert!(content.contains("Skip Count:"));
        assert!(content.contains("Elapsed Time:"));
        assert!(content.contains("Performance:"));
    }

    #[test]
    fn report_true_file_statistics_are_accurate() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_dir = temp_dir.path().join("reports");
        // process(50, 150, 100): min=50, max=150, avg=100.0
        // sum=300, cnt=3, processed_bytes=303 (Log: sum + cnt)
        let report_file = run_report(&report_dir, "test.log", &[50, 150, 100]);
        let content = std::fs::read_to_string(&report_file).expect("failed to read report file");

        assert!(
            content.contains("50/150/100.00"),
            "Statistics should show min=50, max=150, avg=100.00"
        );
        assert!(
            content.contains("3 (303 B)"),
            "Process Count should show 3 entries and 303 bytes \
             (300 data + 3 newlines)"
        );
    }

    #[test]
    fn report_handles_dir_input_type() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_dir = temp_dir.path().join("reports");

        // Use temp_dir itself as input -> InputType::Dir
        let report_file = run_report(
            &report_dir,
            temp_dir.path().to_str().expect("valid path"),
            &[100],
        );
        let content = std::fs::read_to_string(&report_file).expect("failed to read report file");

        assert!(
            !content.contains("Input(LOG)"),
            "Dir input should not show Input(LOG) header"
        );
        assert!(
            content.contains("(0 B)"),
            "Dir input should show 0 bytes for processed_bytes"
        );
    }

    #[test]
    fn report_appends_to_existing_file() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_dir = temp_dir.path().join("reports");
        std::fs::create_dir_all(&report_dir).expect("failed to create report dir");

        let report_file_path = report_dir.join("test_kind.report");
        let existing_content = "existing report content\n";
        std::fs::write(&report_file_path, existing_content).expect("failed to write existing file");

        let report_file = run_report(&report_dir, "test.log", &[100, 200]);
        let content = std::fs::read_to_string(&report_file).expect("failed to read report file");

        assert!(
            content.starts_with(existing_content),
            "Existing content should be preserved at the start of the file"
        );
        assert!(
            content.len() > existing_content.len(),
            "New report content should be appended after existing content"
        );
        assert!(
            content.contains("--------------------------------------------------"),
            "Appended content should contain the report separator"
        );
    }

    #[test]
    fn report_handles_elastic_input_type() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_dir = temp_dir.path().join("reports");

        // "elastic" string -> InputType::Elastic
        let report_file = run_report(&report_dir, "elastic", &[100]);
        let content = std::fs::read_to_string(&report_file).expect("failed to read report file");

        assert!(
            !content.contains("Input(LOG)"),
            "Elastic input should not show Input(LOG) header"
        );
        assert!(
            content.contains("(0 B)"),
            "Elastic input should show 0 bytes for processed_bytes"
        );
    }
}
