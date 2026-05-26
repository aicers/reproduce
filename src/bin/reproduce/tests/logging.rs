use std::env;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusty_fork::rusty_fork_test;
use tempfile::tempdir;
use tracing_subscriber::{Layer, fmt, layer::SubscriberExt};

use crate::tracing_env_filter;

#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> fmt::MakeWriter<'a> for SharedWriter {
    type Writer = SharedWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedWriterGuard(Arc::clone(&self.0))
    }
}

struct SharedWriterGuard(Arc<Mutex<Vec<u8>>>);

impl io::Write for SharedWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("shared tracing writer lock")
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().expect("shared tracing writer lock").flush()
    }
}

fn emit_tracing_probe_events() {
    tracing::debug!("tracing filter probe debug");
    tracing::info!("tracing filter probe info");
    tracing::warn!("tracing filter probe warn");
}

fn capture_tracing_output_with_memory_writer() -> String {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = SharedWriter(Arc::clone(&buffer));
    let env_filter = tracing_env_filter();
    let subscriber = tracing_subscriber::Registry::default().with(
        fmt::Layer::default()
            .with_ansi(false)
            .with_target(false)
            .with_writer(writer)
            .with_filter(env_filter),
    );

    tracing::subscriber::with_default(subscriber, emit_tracing_probe_events);
    String::from_utf8(buffer.lock().expect("shared tracing writer lock").clone())
        .expect("captured tracing output should be valid UTF-8")
}

fn capture_file_tracing_output(log_path: &Path) -> String {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_path)
        .expect("tracing log file should be created");
    let (non_blocking, guard) = tracing_appender::non_blocking(file);
    let env_filter = tracing_env_filter();
    let subscriber = tracing_subscriber::Registry::default().with(
        fmt::Layer::default()
            .with_ansi(false)
            .with_target(false)
            .with_writer(non_blocking)
            .with_filter(env_filter),
    );

    tracing::subscriber::with_default(subscriber, emit_tracing_probe_events);
    drop(guard);
    std::fs::read_to_string(log_path).expect("tracing log file should be readable")
}

fn tracing_output_contains(output: &str, level: &str) -> bool {
    output.contains(&format!("tracing filter probe {level}"))
}

// Each test in this macro is run in its own subprocess.
// This isolates process-global environment mutations such as RUST_LOG.
rusty_fork_test! {
    #[test]
    fn rust_log_unset_stdout_defaults_to_info() {
        unsafe {
            env::remove_var("RUST_LOG");
        }
        let output = capture_tracing_output_with_memory_writer();
        assert!(
            tracing_output_contains(&output, "info"),
            "stdout logging should emit INFO by default: {output}"
        );
        assert!(
            !tracing_output_contains(&output, "debug"),
            "stdout logging should suppress DEBUG by default: {output}"
        );
    }

    #[test]
    fn rust_log_unset_file_defaults_to_info() {
        unsafe {
            env::remove_var("RUST_LOG");
        }
        let temp_dir = tempdir().expect("temporary directory should be created");
        let log_path = temp_dir.path().join("reproduce.log");
        let output = capture_file_tracing_output(&log_path);
        assert!(
            tracing_output_contains(&output, "info"),
            "file logging should emit INFO by default: {output}"
        );
        assert!(
            !tracing_output_contains(&output, "debug"),
            "file logging should suppress DEBUG by default: {output}"
        );
    }

    #[test]
    fn rust_log_set_stdout_respects_override() {
        unsafe {
            env::set_var("RUST_LOG", "warn");
        }
        let output = capture_tracing_output_with_memory_writer();
        assert!(
            tracing_output_contains(&output, "warn"),
            "stdout logging should honor RUST_LOG=warn: {output}"
        );
        assert!(
            !tracing_output_contains(&output, "info"),
            "stdout logging should suppress INFO when RUST_LOG=warn: {output}"
        );
    }

    #[test]
    fn rust_log_set_file_respects_override() {
        unsafe {
            env::set_var("RUST_LOG", "warn");
        }
        let temp_dir = tempdir().expect("temporary directory should be created");
        let log_path = temp_dir.path().join("reproduce.log");
        let output = capture_file_tracing_output(&log_path);
        assert!(
            tracing_output_contains(&output, "warn"),
            "file logging should honor RUST_LOG=warn: {output}"
        );
        assert!(
            !tracing_output_contains(&output, "info"),
            "file logging should suppress INFO when RUST_LOG=warn: {output}"
        );
    }
}
