use clap::{value_parser, Arg, Command};
use reproduce::{Config, Controller};
use std::num::NonZeroU64;
use tokio::task;
use tracing::{error, info};

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt::init();
    let config = parse();
    let mut controller = Controller::new(config);
    info!("reproduce start");
    let _handle = task::spawn(async move {
        if let Err(e) = controller.run().await {
            error!("ERROR: {e}");
            std::process::exit(1);
        }
    })
    .await;
    info!("reproduce end");
}

/// # Panics
///
/// Panics if argument parse fail.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn parse() -> Config {
    let m = Command::new("reproduce")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::new("count")
                .short('c')
                .value_parser(value_parser!(usize))
                .default_value("0")
                .help("Send count"),
        )
        .arg(
            Arg::new("eval")
                .short('e')
                .help("Evaluation mode. Outputs statistics of transmission."),
        )
        .arg(
            Arg::new("continuous")
                .short('g')
                .action(clap::ArgAction::SetTrue)
                .help("If option exists, continues to read from a growing input file"),
        )
        .arg(
            Arg::new("input")
                .short('i')
                .default_value("")
                .help("Input [LOGFILE/DIR/elastic]."),
        )
        .arg(
            Arg::new("prefix")
                .short('n')
                .default_value("")
                .help("Prefix of file names to send multiple files or a directory"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .default_value("giganto")
                .help("Output type [TEXTFILE/none/giganto]."),
        )
        .arg(Arg::new("offset").short('r').default_value("").help(
            "Record (prefix of offset file). Using this option will start the conversation \
                   after the previous conversation. The offset file name is managed by \
                   <input_file>_<prefix>.",
        ))
        .arg(
            Arg::new("skip")
                .short('s')
                .value_parser(value_parser!(usize))
                .default_value("0")
                .help("Skip count"),
        )
        .arg(
            Arg::new("polling")
                .short('v')
                .help("Polls the input directory"),
        )
        .arg(
            Arg::new("giganto")
                .short('G')
                .default_value("127.0.0.1:38370")
                .help("Giganto server address"),
        )
        .arg(
            Arg::new("name")
                .short('N')
                .default_value("localhost")
                .help("Giganto server hostname."),
        )
        .arg(
            Arg::new("config")
                .short('C')
                .default_value("config.toml")
                .help("config.toml file with cert paths, elastic search configures."),
        )
        .arg(
            Arg::new("kind")
                .short('k')
                .default_value("")
                .help("Giganto log kind."),
        )
        .arg(
            Arg::new("from")
                .short('f')
                .value_parser(value_parser!(NonZeroU64))
                .default_value("1")
                .help("log from line number(at least 1)"),
        )
        .arg(
            Arg::new("migration")
                .short('m')
                .action(clap::ArgAction::SetTrue)
                .help("if option exists, migration with giganto export file"),
        )
        .arg(
            Arg::new("elastic")
                .short('E')
                .default_value("")
                .help("if input is elastic, [ID:PASSWORD]"),
        )
        .get_matches();

    let count_sent = *m.get_one::<usize>("count").expect("has `default_value`");
    let mode_eval = m.contains_id("eval");
    let mode_grow = m.get_flag("continuous");
    let input = m.get_one::<String>("input").expect("has `default_value`");
    let file_prefix = m.get_one::<String>("prefix").expect("has `default_value`");
    let output = m.get_one::<String>("output").expect("has `default_value`");
    let offset_prefix = m.get_one::<String>("offset").expect("has `default_value`");
    let count_skip = *m.get_one::<usize>("skip").expect("has `default_value`");
    let config_toml = m.get_one::<String>("config").expect("has `default_value`");
    let giganto_name = m.get_one::<String>("name").expect("has `default_value`");
    let giganto_addr = m.get_one::<String>("giganto").expect("has `default_name`");
    let giganto_kind = m.get_one::<String>("kind").expect("has `default_value`");
    let elastic_auth = m.get_one::<String>("elastic").expect("has `default_value`");
    let send_from = m
        .get_one::<NonZeroU64>("from")
        .expect("has `default_value`")
        .get();
    let migration = m.get_flag("migration");
    let mode_polling_dir = m.contains_id("polling");
    if input.is_empty() {
        error!("input (-i) required.");
        std::process::exit(1);
    }
    if input == "elastic" && elastic_auth.is_empty() {
        error!("if input is elastic, auth (-E [ID:PASSWORD]) required.");
        std::process::exit(1);
    }

    Config {
        mode_eval,
        mode_grow,
        mode_polling_dir,
        count_skip,
        input: input.to_string(),
        output: output.to_string(),
        offset_prefix: offset_prefix.to_string(),
        file_prefix: file_prefix.to_string(),
        count_sent,
        config_toml: config_toml.to_string(),
        giganto_name: giganto_name.to_string(),
        giganto_addr: giganto_addr.to_string(),
        giganto_kind: giganto_kind.to_string(),
        send_from,
        migration,
        elastic_auth: elastic_auth.to_string(),
        ..Config::default()
    }
}
