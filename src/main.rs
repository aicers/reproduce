use std::{env, path::PathBuf, process::exit};

use anyhow::Result;
use reproduce::{Config, Controller};
use tokio::task;
use tracing::{error, info};

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
    tracing_subscriber::fmt::init();
    let config_filename = parse();
    let config = Config::new(config_filename.as_ref())?;
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
