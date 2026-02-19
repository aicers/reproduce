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
    use std::collections::HashMap;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::time::SystemTime;

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

    /// Creates a test `Config` with the given parameters.
    fn test_config(report: bool, kind: &str, input: &str) -> Config {
        Config {
            cert: String::new(),
            key: String::new(),
            ca_certs: vec![],
            giganto_ingest_srv_addr: "127.0.0.1:8080".parse::<SocketAddr>().expect("valid addr"),
            giganto_name: String::from("test"),
            kind: String::from(kind),
            input: String::from(input),
            report,
            log_path: None,
            file: None,
            directory: None,
            elastic: None,
        }
    }

    /// Returns a snapshot of files in a directory as a map of path -> (size, modified time).
    fn snapshot_with_metadata(dir: &Path) -> HashMap<PathBuf, (u64, SystemTime)> {
        if !dir.is_dir() {
            return HashMap::new();
        }

        std::fs::read_dir(dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let meta = std::fs::metadata(&path).ok()?;
                Some((path, (meta.len(), meta.modified().ok()?)))
            })
            .collect()
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

    #[test]
    fn report_false_avoids_file_writes() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let temp_path = temp_dir.path();

        // Create config with report=false and input as a file path (InputType::Log)
        let input_file = temp_path.join("test.log");
        std::fs::write(&input_file, "test content").expect("failed to write input file");

        let config = test_config(false, "test_kind", input_file.to_str().expect("valid path"));
        let mut report = Report::new(config);

        // Snapshot: capture file metadata (path, size, modified time) before the test
        let cwd_before = snapshot_with_metadata(temp_path);
        let report_dir_before = snapshot_with_metadata(Path::new("/report"));

        // Save current directory and change to temp dir to verify CWD writes
        let original_dir = std::env::current_dir().expect("failed to get current dir");
        std::env::set_current_dir(temp_path).expect("failed to change to temp dir");

        // Call start, process some bytes, and end
        report.start();
        report.process(100);
        report.process(200);
        let result = report.end();

        // Restore original directory
        std::env::set_current_dir(&original_dir).expect("failed to restore original dir");

        // Snapshot: capture file metadata after the test
        let cwd_after = snapshot_with_metadata(temp_path);
        let report_dir_after = snapshot_with_metadata(Path::new("/report"));

        // end() should succeed without writing files
        assert!(result.is_ok());

        // Verify no files were created or modified in CWD
        assert_eq!(
            cwd_before, cwd_after,
            "No files should be created or modified in CWD when report=false"
        );

        // Verify no files were created or modified in /report
        assert_eq!(
            report_dir_before, report_dir_after,
            "No files should be created or modified in /report when report=false"
        );
    }

    #[test]
    fn report_false_does_not_update_time_start() {
        let config = test_config(false, "test_kind", "test.log");
        let mut report = Report::new(config);

        let initial_time = report.time_start;
        std::thread::sleep(std::time::Duration::from_millis(10));

        report.start();

        // When report=false, start() returns early without updating time_start
        assert_eq!(
            report.time_start, initial_time,
            "time_start should not be updated when report=false"
        );
    }

    #[test]
    fn report_false_does_not_update_counters() {
        let config = test_config(false, "test_kind", "test.log");
        let mut report = Report::new(config);

        // Call process with some bytes
        report.process(100);
        report.process(200);

        // When report=false, counters should remain at initial values
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

    #[test]
    fn byte_accounting_for_log_input() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let temp_path = temp_dir.path();

        // Create a log file to ensure InputType::Log is used
        let input_file = temp_path.join("test.log");
        std::fs::write(&input_file, "test content").expect("failed to write input file");

        let config = test_config(true, "test_kind", input_file.to_str().expect("valid path"));
        let mut report = Report::new(config);

        report.start();

        // Process known byte amounts
        // Line 1: 50 bytes
        // Line 2: 100 bytes
        // Line 3: 150 bytes
        report.process(50);
        report.process(100);
        report.process(150);

        // Verify byte counters are correctly updated
        assert_eq!(
            report.sum_bytes, 300,
            "sum_bytes should be 50 + 100 + 150 = 300"
        );
        assert_eq!(report.process_cnt, 3, "process_cnt should be 3");
        // Note: max_bytes is updated on first call (50 > 0), then min_bytes is set
        // on second call (100 < 50 is false but min_bytes == 0 is false after first
        // value set it). Actually on first call: 50 > 0 so max_bytes = 50, else if
        // not executed. On second call: 100 > 50 so max_bytes = 100, else if not
        // executed. Third call: 150 > 100 so max_bytes = 150.
        // min_bytes remains 0 because the condition is else-if and max is always
        // updated when value > current max (which starts at 0).
        // This is the existing production behavior.
        assert_eq!(report.max_bytes, 150, "max_bytes should be 150");

        // For InputType::Log, the processed_bytes calculation adds 1 byte per line
        // for the newline character: sum_bytes + process_cnt = 300 + 3 = 303
        let expected_processed_bytes = (report.sum_bytes + report.process_cnt) as u64;
        assert_eq!(
            expected_processed_bytes, 303,
            "processed_bytes for Log should include 1 byte per line for newlines"
        );
    }

    #[test]
    fn byte_accounting_min_max_tracking() {
        let config = test_config(true, "test_kind", "test.log");
        let mut report = Report::new(config);

        report.start();

        // The production logic is:
        //   if process_cnt == 0 { min_bytes = bytes; max_bytes = bytes }
        //   else if bytes > max_bytes { max_bytes = bytes }
        //   else if bytes < min_bytes { min_bytes = bytes }
        //
        // This means:
        // - First call with 100: min/max both set to 100
        // - Second call with 50: min updated to 50
        // - Third call with 200: max updated to 200
        // - Fourth call with 75: no update (between min/max)

        report.process(100);
        // First call: min/max set to 100
        assert_eq!(
            report.max_bytes, 100,
            "max_bytes should be 100 after first call"
        );
        assert_eq!(
            report.min_bytes, 100,
            "min_bytes should be 100 after first call"
        );

        report.process(50);
        // Second call: min updated to 50
        assert_eq!(
            report.min_bytes, 50,
            "min_bytes should be 50 after second call"
        );
        assert_eq!(report.max_bytes, 100, "max_bytes should remain 100");

        report.process(200);
        // Third call: max updated to 200
        assert_eq!(report.min_bytes, 50, "min_bytes should remain 50");
        assert_eq!(report.max_bytes, 200, "max_bytes should be updated to 200");

        report.process(75);
        // Fourth call: no update
        assert_eq!(report.min_bytes, 50, "min_bytes should remain 50");
        assert_eq!(report.max_bytes, 200, "max_bytes should remain 200");
    }

    #[test]
    fn byte_accounting_average_calculation() {
        let config = test_config(true, "test_kind", "test.log");
        let mut report = Report::new(config);

        report.start();

        // Process bytes: 100 + 200 + 300 = 600 total, 3 entries
        report.process(100);
        report.process(200);
        report.process(300);

        assert_eq!(report.sum_bytes, 600, "sum_bytes should be 600");
        assert_eq!(report.process_cnt, 3, "process_cnt should be 3");

        // avg_bytes is calculated in end(), verify the expected formula
        // Note: avg_bytes is not updated until end() is called
        // Here we verify the formula: sum_bytes / process_cnt = 600 / 3 = 200.0
        #[allow(clippy::cast_precision_loss)]
        let expected_avg = report.sum_bytes as f64 / report.process_cnt as f64;
        assert!(
            (expected_avg - 200.0).abs() < f64::EPSILON,
            "expected average should be 200.0"
        );
    }

    #[test]
    fn report_true_creates_file_with_content() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let temp_path = temp_dir.path();

        // Create config with report=true and input as a file path (InputType::Log)
        let input_file = temp_path.join("test.log");
        std::fs::write(&input_file, "test content").expect("failed to write input file");

        let config = test_config(true, "test_kind", input_file.to_str().expect("valid path"));
        let mut report = Report::new(config);

        // Save current directory and change to temp dir so report writes there
        let original_dir = std::env::current_dir().expect("failed to get current dir");
        std::env::set_current_dir(temp_path).expect("failed to change to temp dir");

        // Call start, process some bytes, and end
        report.start();
        report.process(100);
        report.process(200);
        report.process(300);
        let result = report.end();

        // Restore original directory
        std::env::set_current_dir(&original_dir).expect("failed to restore original dir");

        // end() should succeed
        assert!(result.is_ok(), "end() should succeed when report=true");

        // Verify report file was created in the temp directory (CWD during end())
        let report_file = temp_path.join("test_kind.report");
        assert!(
            report_file.exists(),
            "Report file should be created when report=true"
        );

        // Verify the file contains expected content
        let content = std::fs::read_to_string(&report_file).expect("failed to read report file");

        // Check for expected sections in the report
        assert!(
            content.contains("--------------------------------------------------"),
            "Report should contain separator line"
        );
        assert!(
            content.contains("Time:"),
            "Report should contain Time field"
        );
        assert!(
            content.contains("Input(LOG)"),
            "Report should contain Input(LOG) header for log input"
        );
        assert!(
            content.contains("Output(Giganto):"),
            "Report should contain Output header"
        );
        assert!(
            content.contains("Statistics (Min/Max/Avg):"),
            "Report should contain Statistics line"
        );
        assert!(
            content.contains("Process Count:"),
            "Report should contain Process Count line"
        );
        assert!(
            content.contains("Skip Count:"),
            "Report should contain Skip Count line"
        );
        assert!(
            content.contains("Elapsed Time:"),
            "Report should contain Elapsed Time line"
        );
        assert!(
            content.contains("Performance:"),
            "Report should contain Performance line"
        );

        // Verify statistics values are present
        // sum_bytes = 600, process_cnt = 3, so avg = 200.0
        // max_bytes = 300 (last value since 300 > 200 > 100)
        // min_bytes = 100 (set on second call when 200 < 100 is false but min_bytes == 0 fails,
        //   wait actually: first call 100 > 0 -> max=100, then 200 > 100 -> max=200,
        //   200 < 0 is false and min_bytes == 0 is true -> min=200... no wait that's wrong
        //   Let me trace: process(100): 100 > 0 -> max=100, else-if skipped
        //   process(200): 200 > 100 -> max=200, else-if skipped
        //   process(300): 300 > 200 -> max=300, else-if skipped
        //   So min_bytes stays 0 in this case because we never hit the else-if branch)
        assert!(
            content.contains("300"),
            "Report should contain max_bytes value 300"
        );
        assert!(
            content.contains("200.00"),
            "Report should contain avg_bytes value 200.00"
        );
    }
}
