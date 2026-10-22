//! Integration tests for tracing initialization defaults and the
//! journal-native output of the `reproduce` binary.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use tempfile::tempdir;

/// Emitted by `init_tracing` at INFO once stdout logging is configured.
const LOG_INIT_INFO_LOG: &str = "Initialized tracing logger";

fn write_tracing_startup_config() -> (tempfile::TempDir, PathBuf) {
    let temp_dir = tempdir().expect("tempdir");
    let config = r#"cert = "unused-cert.pem"
key = "unused-key.pem"
ca_certs = ["unused-root.pem"]
giganto_ingest_srv_addr = "127.0.0.1:1"
giganto_name = "localhost"
kind = "custom"
input = "unused.log"
report = false
"#;
    let config_path = temp_dir.path().join("config.toml");
    std::fs::write(&config_path, config).expect("write test config");
    (temp_dir, config_path)
}

/// Spawn `reproduce` with `RUST_LOG` unset and wait until an INFO startup
/// line appears on stdout.
#[test]
fn stdout_defaults_to_info_when_rust_log_unset() {
    let (_temp_dir, config_path) = write_tracing_startup_config();

    let bin = env!("CARGO_BIN_EXE_reproduce");
    let mut child = Command::new(bin)
        .arg(&config_path)
        .env_remove("RUST_LOG")
        .env_remove("JOURNAL_STREAM")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn reproduce binary");

    let stdout = child.stdout.take().expect("stdout pipe");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let found = BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .any(|line| line.contains(LOG_INIT_INFO_LOG));
        let _ = tx.send(found);
    });

    let saw_info = rx.recv_timeout(Duration::from_secs(10)).unwrap_or(false);

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        saw_info,
        "stdout logging should emit INFO by default when RUST_LOG is unset"
    );
}

/// Runs the `reproduce` binary with standard output and standard error in
/// temporary files and checks its journal-native output.
#[cfg(unix)]
mod journal {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use super::{LOG_INIT_INFO_LOG, write_tracing_startup_config};

    /// The local-mode form in the usage text.
    const LOCAL_FORM: &str = "reproduce <CONFIG>";

    /// The first line of the remote-mode form in the usage text.
    const REMOTE_FORM: &str = "reproduce --cert <CERT_PATH> --key <KEY_PATH> \
                               --ca-certs <CA_PATHS> --state-dir <DIR> <MANAGER>";

    struct Run {
        /// `None` when the process was stopped by the test.
        status: Option<ExitStatus>,
        /// The complete lines written to standard output.
        stdout: String,
        stderr: String,
    }

    impl Run {
        fn stdout_lines(&self) -> Vec<&str> {
            self.stdout.lines().collect()
        }

        fn assert_exit_1(&self) {
            assert_eq!(
                self.status.and_then(|status| status.code()),
                Some(1),
                "stdout: {}\nstderr: {}",
                self.stdout,
                self.stderr
            );
        }
    }

    /// Runs `reproduce` with `args` until it exits or, with `until`, until
    /// its standard output holds a complete line containing `until`; then
    /// stops it.
    ///
    /// `JOURNAL_STREAM` names the standard-output file when `journal` is
    /// set and is removed otherwise.
    fn run<S: AsRef<OsStr>>(args: &[S], journal: bool, until: Option<&str>) -> Run {
        let dir = tempfile::tempdir().expect("temporary directory");
        let stdout_path = dir.path().join("stdout");
        let stderr_path = dir.path().join("stderr");
        let stdout = File::create(&stdout_path).expect("stdout file");
        let stderr = File::create(&stderr_path).expect("stderr file");

        let mut command = Command::new(env!("CARGO_BIN_EXE_reproduce"));
        command.args(args).env_remove("RUST_LOG");
        if journal {
            let metadata = stdout.metadata().expect("metadata");
            command.env(
                "JOURNAL_STREAM",
                format!("{}:{}", metadata.dev(), metadata.ino()),
            );
        } else {
            command.env_remove("JOURNAL_STREAM");
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .expect("spawn reproduce binary");

        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait for reproduce") {
                break Some(status);
            }
            if until.is_some_and(|text| complete_lines(&stdout_path).contains(text)) {
                break None;
            }
            assert!(Instant::now() < deadline, "reproduce did not finish");
            std::thread::sleep(Duration::from_millis(20));
        };
        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }

        let stderr = std::fs::read(&stderr_path).expect("stderr is read");
        Run {
            status,
            stdout: complete_lines(&stdout_path),
            stderr: String::from_utf8(stderr).expect("UTF-8 stderr"),
        }
    }

    /// Reads the complete lines of a file, checking that it holds no ESC
    /// byte.
    fn complete_lines(path: &Path) -> String {
        let mut bytes = std::fs::read(path).expect("stdout is read");
        assert!(!bytes.contains(&0x1b), "ESC byte in {bytes:?}");
        let end = bytes
            .iter()
            .rposition(|&byte| byte == b'\n')
            .map_or(0, |i| i + 1);
        bytes.truncate(end);
        String::from_utf8(bytes).expect("UTF-8 stdout")
    }

    fn has_journal_prefix(line: &str) -> bool {
        ["<3>", "<4>", "<6>", "<7>"]
            .iter()
            .any(|prefix| line.starts_with(prefix))
    }

    fn remote_args(state_dir: &Path) -> Vec<&OsStr> {
        vec![
            OsStr::new("--cert"),
            OsStr::new("tests/cert.pem"),
            OsStr::new("--key"),
            OsStr::new("tests/key.pem"),
            OsStr::new("--ca-certs"),
            OsStr::new("tests/root.pem"),
            OsStr::new("--state-dir"),
            state_dir.as_os_str(),
            OsStr::new("localhost@127.0.0.1:1"),
        ]
    }

    /// Returns a state directory under a regular file, which cannot be
    /// created.
    fn state_dir_under_a_file(dir: &Path) -> std::path::PathBuf {
        let file = dir.join("file");
        std::fs::write(&file, "").expect("file is written");
        file.join("state")
    }

    #[test]
    fn local_startup_line_under_journal() {
        let (_temp_dir, config_path) = write_tracing_startup_config();
        let run = run(&[&config_path], true, Some(LOG_INIT_INFO_LOG));
        let lines = run.stdout_lines();
        let line = lines
            .iter()
            .find(|line| line.contains(LOG_INIT_INFO_LOG))
            .expect("startup line");
        assert!(line.starts_with("<6>"), "{line:?}");
    }

    #[test]
    fn local_startup_line_without_journal() {
        let (_temp_dir, config_path) = write_tracing_startup_config();
        let run = run(&[&config_path], false, Some(LOG_INIT_INFO_LOG));
        let lines = run.stdout_lines();
        let line = lines
            .iter()
            .find(|line| line.contains(LOG_INIT_INFO_LOG))
            .expect("startup line");
        assert!(!has_journal_prefix(line), "{line:?}");
        assert!(line.starts_with(|c: char| c.is_ascii_digit()), "{line:?}");
    }

    #[test]
    fn remote_startup_line_under_journal() {
        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let state_dir = temp_dir.path().join("state");
        let run = run(&remote_args(&state_dir), true, Some(LOG_INIT_INFO_LOG));
        let lines = run.stdout_lines();
        let first = lines.first().expect("a standard-output line");
        assert!(first.starts_with("<6>"), "{lines:?}");
        assert!(first.contains(LOG_INIT_INFO_LOG), "{lines:?}");
        assert!(
            lines.iter().all(|line| has_journal_prefix(line)),
            "{lines:?}"
        );
    }

    #[test]
    fn missing_config_under_journal() {
        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let config = temp_dir.path().join("missing.toml");
        let run = run(&[&config], true, None);
        run.assert_exit_1();
        let lines = run.stdout_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("<3>"), "{lines:?}");
        assert!(
            lines[0].contains(&config.display().to_string()),
            "{lines:?}"
        );
        assert_eq!(run.stderr, "");
    }

    #[test]
    fn missing_config_without_journal() {
        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let config = temp_dir.path().join("missing.toml");
        let run = run(&[&config], false, None);
        run.assert_exit_1();
        assert!(!run.stdout.contains("ERROR"), "{}", run.stdout);
        assert!(run.stderr.starts_with("Error: "), "{}", run.stderr);
        assert!(run.stderr.contains("missing.toml"), "{}", run.stderr);
    }

    #[test]
    fn state_dir_refusal_under_journal() {
        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let state_dir = state_dir_under_a_file(temp_dir.path());
        let run = run(&remote_args(&state_dir), true, None);
        run.assert_exit_1();
        let lines = run.stdout_lines();
        let errors = lines
            .iter()
            .filter(|line| line.starts_with("<3>"))
            .collect::<Vec<_>>();
        assert_eq!(errors.len(), 1, "{lines:?}");
        assert!(errors[0].contains("state directory"), "{lines:?}");
        assert!(
            lines.iter().all(|line| has_journal_prefix(line)),
            "{lines:?}"
        );
        assert_eq!(run.stderr, "");
    }

    #[test]
    fn state_dir_refusal_without_journal() {
        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let state_dir = state_dir_under_a_file(temp_dir.path());
        let run = run(&remote_args(&state_dir), false, None);
        run.assert_exit_1();
        assert!(!run.stdout.contains("ERROR"), "{}", run.stdout);
        assert!(run.stderr.starts_with("Error: "), "{}", run.stderr);
        assert!(run.stderr.contains("state directory"), "{}", run.stderr);
    }

    #[test]
    fn refused_arguments_under_journal() {
        let run = run(&["a", "b", "c"], true, None);
        run.assert_exit_1();
        let lines = run.stdout_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("<3>"), "{lines:?}");
        assert!(
            lines[0].contains(r"Error: too many arguments\n\nUSAGE:"),
            "{lines:?}"
        );
        assert!(lines[0].contains(LOCAL_FORM), "{lines:?}");
        assert!(lines[0].contains(REMOTE_FORM), "{lines:?}");
        assert_eq!(run.stderr, "");
    }

    #[test]
    fn refused_arguments_without_journal() {
        let run = run(&["a", "b", "c"], false, None);
        run.assert_exit_1();
        assert_eq!(run.stdout, "");
        assert!(
            run.stderr
                .starts_with("Error: too many arguments\n\nUSAGE:\n"),
            "{}",
            run.stderr
        );
        assert!(run.stderr.contains(REMOTE_FORM), "{}", run.stderr);
    }
}
