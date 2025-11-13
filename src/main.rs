mod bincode_utils;
#[cfg(test)]
mod chrono_regression_tests;
mod config;
mod controller;
mod migration;
mod netflow;
mod operation_log;
mod producer;
mod report;
mod security_log;
mod syslog;
mod zeek;

use std::{
    env,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{Context, Result};
use config::{Config, InputType};
use controller::Controller;
use producer::Producer;
use report::Report;
use tokio::task;
use tracing::{error, info, level_filters::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

const USAGE: &str = "\
USAGE:
    REproduce [CONFIG]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARG:
    <CONFIG>    A TOML config file
";

#[tokio::main]
async fn main() -> Result<()> {
    let config_filename = parse();
    let config = Config::new(config_filename.as_ref())?;
    let _guard = init_tracing(config.log_path.as_deref())?;
    let controller = Controller::new(config);
    info!("Data Broker started");
    let _handle = task::spawn(async move {
        if let Err(e) = controller.run().await {
            error!("Terminated with error: {e}");
            std::process::exit(1);
        }
    })
    .await;
    info!("Data Broker completed");
    Ok(())
}

/// Parses the command line arguments and returns the first argument.
fn parse() -> PathBuf {
    let args = env::args().collect::<Vec<_>>();
    if args.len() <= 1 {
        eprintln!("Error: insufficient arguments");
        exit(1);
    }
    if args.len() > 2 {
        eprintln!("Error: too many arguments");
        exit(1);
    }

    if args[1] == "--help" || args[1] == "-h" {
        println!("{}", version());
        println!();
        print!("{USAGE}");
        exit(0);
    }
    if args[1] == "--version" || args[1] == "-V" {
        println!("{}", version());
        exit(0);
    }
    PathBuf::from(&args[1])
}

fn version() -> String {
    format!("REproduce {}", env!("CARGO_PKG_VERSION"))
}
/// Initializes the tracing subscriber and returns a `WorkerGuard`.
///
/// Logs will be written to the file specified by `log_path` if provided.
/// If `log_path` is `None`, logs will be printed to stdout.
fn init_tracing(log_path: Option<&Path>) -> Result<WorkerGuard> {
    let (layer, guard) = if let Some(log_path) = log_path {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("Failed to open the log file: {}", log_path.display()))?;
        let (non_blocking, file_guard) = tracing_appender::non_blocking(file);
        (
            fmt::Layer::default()
                .with_ansi(false)
                .with_target(false)
                .with_writer(non_blocking)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
            file_guard,
        )
    } else {
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        (
            fmt::Layer::default()
                .with_ansi(true)
                .with_writer(stdout_writer)
                .with_filter(EnvFilter::from_default_env()),
            stdout_guard,
        )
    };

    tracing_subscriber::Registry::default().with(layer).init();
    info!("Initialized tracing logger");
    Ok(guard)
}
