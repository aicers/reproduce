use clap::{value_parser, Arg, Command};
use reproduce::{Config, Controller};
use std::num::NonZeroU64;
use tokio::task;
use tracing::{error, info};

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt::init();
    let config = parse();
    info!("{config}");
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
        .arg(Arg::new("input").short('i').default_value("").help(
            "Input [LOGFILE/DIR] \
	    	   If not given, internal sample data will be used.",
        ))
        .arg(
            Arg::new("prefix")
                .short('n')
                .default_value("")
                .help("Prefix of file names to send multiple files or a directory"),
        )
        .arg(Arg::new("output").short('o').default_value("").help(
            "Output type [TEXTFILE/none/giganto]. \
                   If not given, the output is sent to Kafka.",
        ))
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
            Arg::new("certs")
                .short('C')
                .default_value("config.toml")
                .help("config.toml file with cert, key, roots path."),
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
                .help("zeek log from line number(at least 1)"),
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
    let certs_toml = m.get_one::<String>("certs").expect("has `default_value`");
    let giganto_name = m.get_one::<String>("name").expect("has `default_value`");
    let giganto_addr = m.get_one::<String>("giganto").expect("has `default_name`");
    let giganto_kind = m.get_one::<String>("kind").expect("has `default_value`");
    let send_from = m
        .get_one::<NonZeroU64>("from")
        .expect("has `default_value`")
        .get();
    let mode_polling_dir = m.contains_id("polling");
    // if output.is_empty() && kafka_broker.is_empty() {
    //     error!("Kafka broker (-b) required");
    //     std::process::exit(1);
    // }
    // if output.is_empty() && kafka_topic.is_empty() {
    //     error!("Kafka topic (-t) required");
    //     std::process::exit(1);
    // }
    if input.is_empty() && output == "none" {
        error!("input (-i) required if output (-o) is \"none\"");
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
        certs_toml: certs_toml.to_string(),
        giganto_name: giganto_name.to_string(),
        giganto_addr: giganto_addr.to_string(),
        giganto_kind: giganto_kind.to_string(),
        send_from,
        ..Config::default()
    }
}
