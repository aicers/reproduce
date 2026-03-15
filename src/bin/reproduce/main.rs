use std::{
    env,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::exit,
};

mod controller;
mod report;

use anyhow::{Context, Result};
use controller::Controller;
use reproduce::config::Config;
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
    let Some(arg) = args.get(1).map(String::as_str) else {
        eprintln!("Error: insufficient arguments");
        exit(1);
    };
    if args.get(2).is_some() {
        eprintln!("Error: too many arguments");
        exit(1);
    }

    if arg == "--help" || arg == "-h" {
        println!("{}", version());
        println!();
        print!("{USAGE}");
        exit(0);
    }
    if arg == "--version" || arg == "-V" {
        println!("{}", version());
        exit(0);
    }
    PathBuf::from(arg)
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
