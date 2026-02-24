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
    use std::net::SocketAddr;
    use std::time::SystemTime;

    use serial_test::serial;

    use super::*;

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
        let config = test_config(true, "test", "/path/to/file");
        let mut report = Report::new(config);

        report.process(10);

        assert_eq!(report.min_bytes, 10);
        assert_eq!(report.max_bytes, 10);
    }

    #[test]
    fn process_updates_min_and_max_correctly() {
        let config = test_config(true, "test", "/path/to/file");
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
        let config = test_config(true, "test", "/path/to/file");
        let mut report = Report::new(config);

        report.skip(100);
        assert_eq!(report.skip_bytes, 100);
        assert_eq!(report.skip_cnt, 1);

        report.skip(200);
        assert_eq!(report.skip_bytes, 300);
        assert_eq!(report.skip_cnt, 2);
    }

    #[test]
    #[serial]
    fn report_false_avoids_file_writes() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let temp_path = temp_dir.path();

        // Create config with report=false and input as a file path (InputType::Log)
        let config = test_config(false, "test_kind", "test.log");
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

    /// Runs a complete report cycle (start/process/end) with the given byte values,
    /// writing the output to `dir` as CWD. Returns the path of the generated report file.
    ///
    /// Note: When `/report` directory exists, `Report::end()` writes to `/report/test_kind.report`
    /// instead of the CWD. This function returns the actual path where the report was written.
    fn run_report_to_dir(dir: &Path, input: &str, bytes_list: &[usize]) -> PathBuf {
        let config = test_config(true, "test_kind", input);
        let mut report = Report::new(config);

        let original_dir = std::env::current_dir().expect("failed to get current dir");
        std::env::set_current_dir(dir).expect("failed to change dir");

        report.start();
        for &bytes in bytes_list {
            report.process(bytes);
        }
        report.end().expect("report end() should succeed");

        std::env::set_current_dir(original_dir).expect("failed to restore dir");

        // Return the actual path where the report was written
        let report_dir = Path::new("/report");
        if report_dir.is_dir() {
            report_dir.join("test_kind.report")
        } else {
            dir.join("test_kind.report")
        }
    }

    #[test]
    #[serial]
    fn report_true_writes_to_report_dir_when_exists() {
        let report_dir = Path::new("/report");
        if !report_dir.is_dir() {
            return; // /report does not exist in this environment; skip
        }

        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let input_file = temp_dir.path().join("test.log");
        std::fs::write(&input_file, "test content").expect("failed to write input file");

        let config = test_config(true, "test_kind", input_file.to_str().expect("valid path"));
        let mut report = Report::new(config);

        let before = snapshot_with_metadata(report_dir);

        report.start();
        report.process(100);
        let result = report.end();

        let after = snapshot_with_metadata(report_dir);

        assert!(result.is_ok(), "end() should succeed");
        assert_ne!(
            before, after,
            "Report file should be created or modified in /report"
        );
    }

    #[test]
    #[serial]
    fn report_true_creates_file() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_file = run_report_to_dir(temp_dir.path(), "test.log", &[100, 200, 300]);
        assert!(
            report_file.exists(),
            "Report file should be created when report=true"
        );
    }

    #[test]
    #[serial]
    fn report_true_file_contains_all_sections() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let report_file = run_report_to_dir(temp_dir.path(), "test.log", &[100, 200, 300]);
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
    #[serial]
    fn report_true_file_statistics_are_accurate() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        // process(50, 150, 100): min=50, max=150, avg=100.0
        // sum=300, cnt=3, processed_bytes=303 (Log: sum + cnt)
        let report_file = run_report_to_dir(temp_dir.path(), "test.log", &[50, 150, 100]);
        let content = std::fs::read_to_string(&report_file).expect("failed to read report file");

        assert!(
            content.contains("50/150/100.00"),
            "Statistics should show min=50, max=150, avg=100.00"
        );
        assert!(
            content.contains("3 (303 B)"),
            "Process Count should show 3 entries and 303 bytes (300 data + 3 newlines)"
        );
    }

    #[test]
    #[serial]
    fn report_handles_dir_input_type() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let temp_path = temp_dir.path();

        // Use temp_dir itself as input → InputType::Dir
        let report_file =
            run_report_to_dir(temp_path, temp_path.to_str().expect("valid path"), &[100]);
        let content = std::fs::read_to_string(&report_file).expect("failed to read report file");

        // Dir input uses empty header and processed_bytes=0
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
    #[serial]
    fn report_handles_elastic_input_type() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");

        // "elastic" string → InputType::Elastic
        let report_file = run_report_to_dir(temp_dir.path(), "elastic", &[100]);
        let content = std::fs::read_to_string(&report_file).expect("failed to read report file");

        // Elastic input uses empty header and processed_bytes=0
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
