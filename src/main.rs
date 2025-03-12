use std::{
    env,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{Context, Result};
use reproduce::{Config, Controller};
use tokio::task;
use tracing::{error, info, level_filters::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

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
    let _guards = init_tracing(config.common.log_dir.as_deref())?;
    let controller = Controller::new(config);
    info!("reproduce start");
    let _handle = task::spawn(async move {
        if let Err(e) = controller.run().await {
            error!("ERROR: {e}");
            std::process::exit(1);
        }
    })
    .await;
    info!("reproduce end");
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

/// Initializes the tracing subscriber and returns a vector of `WorkerGuard` that flushes the log
/// when dropped.
///
/// If `log_dir` is `None`, logs will be printed to stdout.
///
/// If the runtime is in debug mode, logs will be printed to stdout in addition to the specified
/// `log_dir`.
fn init_tracing(log_dir: Option<&Path>) -> Result<Vec<WorkerGuard>> {
    let mut guards = vec![];

    let file_layer = if let Some(log_dir) = log_dir {
        let file_path = log_dir.join(env!("LOG_FILENAME"));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .with_context(|| format!("Failed to open the log file: {}", file_path.display()))?;
        let (non_blocking, file_guard) = tracing_appender::non_blocking(file);
        guards.push(file_guard);
        Some(
            fmt::Layer::default()
                .with_ansi(false)
                .with_target(false)
                .with_writer(non_blocking)
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
    } else {
        None
    };

    let stdout_layer = if file_layer.is_none() || cfg!(debug_assertions) {
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        guards.push(stdout_guard);
        Some(
            fmt::Layer::default()
                .with_ansi(true)
                .with_writer(stdout_writer)
                .with_filter(EnvFilter::from_default_env()),
        )
    } else {
        None
    };

    tracing_subscriber::Registry::default()
        .with(stdout_layer)
        .with(file_layer)
        .init();
    info!("Initialized tracing logger");
    Ok(guards)
}
