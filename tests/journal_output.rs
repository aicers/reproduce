//! Journal-native output of `reproduce::logging`.
//!
//! Logging is process-wide, so each case runs in a child process. Run without
//! `JOURNAL_OUTPUT_CASE`, this is the parent: for each case it re-runs itself
//! with the case named, standard output and standard error redirected to two
//! temporary files, and `JOURNAL_STREAM` set to the standard-output file,
//! set to another file, or removed, then checks the files. The child
//! initializes logging, emits the case's events, drops the logging so the
//! writer flushes, and exits 0.

fn main() {
    #[cfg(unix)]
    unix::main();
}

#[cfg(unix)]
mod unix {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};

    use reproduce::logging::init_tracing;
    use tracing::{debug, error, info, warn};

    /// Names the case a child runs.
    const CASE_VAR: &str = "JOURNAL_OUTPUT_CASE";

    /// The log file of the `log-file` case.
    const LOG_FILE_VAR: &str = "JOURNAL_OUTPUT_LOG_FILE";

    /// The panic message of the `panic` and `log-file` cases.
    const PANIC_MESSAGE: &str = "journal test panic";

    /// What `JOURNAL_STREAM` is set to in a child.
    #[derive(Clone, Copy)]
    enum Stream {
        /// `<dev>:<ino>` of the child's standard output.
        Matching,
        /// `<dev>:<ino>` of a file the child does not write to.
        Other,
        /// Removed.
        Unset,
    }

    struct Output {
        status: ExitStatus,
        stdout: String,
        stderr: String,
        log_file: Option<String>,
    }

    impl Output {
        fn stdout_lines(&self) -> Vec<&str> {
            self.stdout.lines().collect()
        }
    }

    pub(crate) fn main() {
        if let Ok(case) = std::env::var(CASE_VAR) {
            child(&case);
            return;
        }

        let cases: [(&str, fn()); 9] = [
            ("journal_prefixes_by_level", journal_prefixes_by_level),
            (
                "journal_escapes_line_feed_and_nul",
                journal_escapes_line_feed_and_nul,
            ),
            (
                "mismatched_journal_stream_is_not_journal",
                mismatched_journal_stream_is_not_journal,
            ),
            (
                "unset_journal_stream_is_not_journal",
                unset_journal_stream_is_not_journal,
            ),
            (
                "journal_panic_is_one_error_line",
                journal_panic_is_one_error_line,
            ),
            ("default_panic_hook_stays", default_panic_hook_stays),
            ("info_is_the_default_level", info_is_the_default_level),
            ("rust_log_overrides_the_level", rust_log_overrides_the_level),
            ("log_file_leaves_the_journal", log_file_leaves_the_journal),
        ];
        println!("\nrunning {} tests", cases.len());
        for (name, case) in cases {
            case();
            println!("test {name} ... ok");
        }
        println!("\ntest result: ok. {} passed; 0 failed\n", cases.len());
    }

    fn child(case: &str) {
        let mut logging = init_tracing().expect("logging is initialized");
        match case {
            "levels" => {
                error!("error event");
                warn!("warn event");
                info!("info event");
                debug!("debug event");
            }
            "escapes" => info!("one\ntwo\0three \\ four"),
            "panic" => panic_in_thread(),
            "log-file" => {
                let path = std::env::var_os(LOG_FILE_VAR).expect("log file is named");
                logging
                    .use_log_file(Path::new(&path))
                    .expect("log file is opened");
                info!("file event");
                panic_in_thread();
            }
            _ => panic!("unknown case {case}"),
        }
        drop(logging);
    }

    fn panic_in_thread() {
        let result = std::thread::Builder::new()
            .name("journal-test".to_string())
            .spawn(|| panic!("{PANIC_MESSAGE}"))
            .expect("thread is spawned")
            .join();
        assert!(result.is_err());
    }

    /// Returns `<dev>:<ino>` of `file`.
    fn journal_stream(file: &File) -> String {
        let metadata = file.metadata().expect("metadata");
        format!("{}:{}", metadata.dev(), metadata.ino())
    }

    fn run(case: &str, stream: Stream, rust_log: Option<&str>) -> Output {
        let dir = tempfile::tempdir().expect("temporary directory");
        let stdout_path = dir.path().join("stdout");
        let stderr_path = dir.path().join("stderr");
        let log_path = dir.path().join("reproduce.log");
        let stdout = File::create(&stdout_path).expect("stdout file");
        let stderr = File::create(&stderr_path).expect("stderr file");

        let mut command =
            Command::new(std::env::current_exe().expect("the path of this test binary"));
        command.env(CASE_VAR, case).env(LOG_FILE_VAR, &log_path);
        match stream {
            Stream::Matching => {
                command.env("JOURNAL_STREAM", journal_stream(&stdout));
            }
            Stream::Other => {
                let other = File::create(dir.path().join("other")).expect("other file");
                command.env("JOURNAL_STREAM", journal_stream(&other));
            }
            Stream::Unset => {
                command.env_remove("JOURNAL_STREAM");
            }
        }
        match rust_log {
            Some(rust_log) => command.env("RUST_LOG", rust_log),
            None => command.env_remove("RUST_LOG"),
        };
        let status = command
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .status()
            .expect("child runs");

        Output {
            status,
            stdout: read(&stdout_path),
            stderr: read(&stderr_path),
            log_file: log_path.exists().then(|| read(&log_path)),
        }
    }

    /// Reads a file, checking that it holds no ESC byte.
    fn read(path: &PathBuf) -> String {
        let bytes = std::fs::read(path).expect("output file is read");
        assert!(
            !bytes.contains(&0x1b),
            "{} contains an ESC byte",
            path.display()
        );
        String::from_utf8(bytes).expect("UTF-8 output")
    }

    /// Returns the priority of a journal line and the rest of the line.
    fn journal_prefix(line: &str) -> Option<(&str, &str)> {
        ["<3>", "<4>", "<6>", "<7>"]
            .into_iter()
            .find_map(|prefix| line.strip_prefix(prefix).map(|rest| (prefix, rest)))
    }

    fn starts_with_timestamp(line: &str) -> bool {
        line.starts_with(|c: char| c.is_ascii_digit())
    }

    /// Returns the one line containing `text`.
    fn line_with<'a>(lines: &[&'a str], text: &str) -> &'a str {
        let found = lines
            .iter()
            .filter(|line| line.contains(text))
            .collect::<Vec<_>>();
        assert_eq!(found.len(), 1, "one line with {text:?} in {lines:?}");
        found[0]
    }

    /// Checks that every line is a journal line without a timestamp.
    fn assert_journal_lines(lines: &[&str]) {
        for line in lines {
            let (_, rest) =
                journal_prefix(line).unwrap_or_else(|| panic!("no priority prefix: {line:?}"));
            assert!(!starts_with_timestamp(rest.trim_start()), "{line:?}");
        }
    }

    fn journal_prefixes_by_level() {
        let output = run("levels", Stream::Matching, Some("debug"));
        assert!(output.status.success());
        let lines = output.stdout_lines();
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_journal_lines(&lines);
        assert!(line_with(&lines, "error event").starts_with("<3>"));
        assert!(line_with(&lines, "warn event").starts_with("<4>"));
        assert!(line_with(&lines, "info event").starts_with("<6>"));
        assert!(line_with(&lines, "debug event").starts_with("<7>"));
        assert_eq!(output.stderr, "");
    }

    fn journal_escapes_line_feed_and_nul() {
        let output = run("escapes", Stream::Matching, None);
        assert!(output.status.success());
        let lines = output.stdout_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("<6>"), "{lines:?}");
        assert!(lines[0].ends_with(r"one\ntwo\0three \ four"), "{lines:?}");
        assert!(output.stdout.ends_with("four\n"), "{:?}", output.stdout);
    }

    fn assert_not_journal(output: &Output) {
        assert!(output.status.success());
        let lines = output.stdout_lines();
        assert_eq!(lines.len(), 4, "{lines:?}");
        for line in &lines {
            assert!(!line.starts_with('<'), "{line:?}");
            assert!(starts_with_timestamp(line), "{line:?}");
        }
        for event in ["error event", "warn event", "info event", "debug event"] {
            line_with(&lines, event);
        }
    }

    fn mismatched_journal_stream_is_not_journal() {
        assert_not_journal(&run("levels", Stream::Other, Some("debug")));
    }

    fn unset_journal_stream_is_not_journal() {
        assert_not_journal(&run("levels", Stream::Unset, Some("debug")));
    }

    fn journal_panic_is_one_error_line() {
        let output = run("panic", Stream::Matching, None);
        assert!(output.status.success());
        let lines = output.stdout_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("<3>"), "{lines:?}");
        assert!(
            lines[0].contains("thread 'journal-test' panicked at tests/journal_output.rs:"),
            "{lines:?}"
        );
        assert!(
            lines[0].ends_with(&format!(": {PANIC_MESSAGE}")),
            "{lines:?}"
        );
        assert_eq!(output.stderr, "");
    }

    fn default_panic_hook_stays() {
        let output = run("panic", Stream::Unset, None);
        assert!(output.status.success());
        assert_eq!(output.stdout, "");
        assert!(
            is_default_panic_message(&output.stderr),
            "{}",
            output.stderr
        );
    }

    /// Returns whether `stderr` holds the default hook's message for the
    /// panic of the `journal-test` thread, which may name the thread's id.
    fn is_default_panic_message(stderr: &str) -> bool {
        stderr.contains("thread 'journal-test'")
            && stderr.contains(" panicked at tests/journal_output.rs:")
            && stderr.contains(PANIC_MESSAGE)
    }

    fn info_is_the_default_level() {
        let output = run("levels", Stream::Matching, None);
        assert!(output.status.success());
        let lines = output.stdout_lines();
        assert_eq!(lines.len(), 3, "{lines:?}");
        line_with(&lines, "info event");
        assert!(!output.stdout.contains("debug event"));
    }

    fn rust_log_overrides_the_level() {
        let output = run("levels", Stream::Matching, Some("warn"));
        assert!(output.status.success());
        let lines = output.stdout_lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(line_with(&lines, "warn event").starts_with("<4>"));
        assert!(!output.stdout.contains("info event"));
    }

    fn log_file_leaves_the_journal() {
        let output = run("log-file", Stream::Matching, None);
        assert!(output.status.success());
        assert_eq!(output.stdout, "");
        let log_file = output.log_file.as_deref().expect("log file is written");
        let lines = log_file.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = line_with(&lines, "file event");
        assert!(starts_with_timestamp(line), "{line:?}");
        assert!(!line.contains("journal_output:"), "{line:?}");
        assert!(
            is_default_panic_message(&output.stderr),
            "{}",
            output.stderr
        );
    }
}
