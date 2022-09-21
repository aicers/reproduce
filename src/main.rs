use clap::{value_parser, Arg, Command};
use reproduce::{Config, Controller};
use std::num::{NonZeroI64, NonZeroU8};
use tokio::task;

#[tokio::main]
pub async fn main() {
    let config = parse();
    println!("{}", config);
    let mut controller = Controller::new(config);
    println!("reproduce start");
    let _handle = task::spawn(async move {
        if let Err(e) = controller.run().await {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
    })
    .await;
    println!("reproduce end");
}

#[allow(clippy::too_many_lines)]
#[must_use]
pub fn parse() -> Config {
    let m = Command::new("reproduce")
    .version(env!("CARGO_PKG_VERSION"))
    .arg(
        Arg::new("broker")
            .short('b')
            .default_value("")
	        .value_name("host1:port1,host2:port2,..")
            .help("Kafka broker list"),
    )
    .arg(
        Arg::new("count")
            .short('c')
            .value_parser(value_parser!(usize))
            .default_value("0")
            .help("Send count"),
    )
    .arg(
        Arg::new("source")
            .short('d')
            .value_parser(value_parser!(NonZeroU8))
            .default_value("1")
            .help("Data source ID (1-255)"),
    )
    .arg(
        Arg::new("eval")
            .short('e')
            .help("Evaluation mode. Outputs statistics of transmission.")
    )
    .arg(
        Arg::new("continuous")
            .short('g')
            .help("Continues to read from a growing input file")
    )
    .arg(
        Arg::new("input")
            .short('i')
            .default_value("")
            .help("Input [LOGFILE/DIR] \
	    	   If not given, internal sample data will be used.")
    )
    .arg(
        Arg::new("seq")
            .short('j')
            .value_parser(value_parser!(usize))
            .default_value("0")
            .help("Sets the initial sequence number (0-16777215).")
    )
    .arg(
        Arg::new("pattern")
            .short('m')
            .default_value("")
            .value_name("FILE")
            .help("Pattern filename")
    )
    .arg(
        Arg::new("prefix")
            .short('n')
            .default_value("")
            .help("Prefix of file names to send multiple files or a directory")
    )
    .arg(
        Arg::new("output")
            .short('o')
            .default_value("")
            .help("Output type [TEXTFILE/none]. \
                   If not given, the output is sent to Kafka.")
    )
    .arg(
        Arg::new("period")
            .short('p')
            .value_parser(value_parser!(NonZeroI64))
            .default_value("3")
            .help("Sepcifies how long data may be kept in the queue.")
    )
    .arg(
        Arg::new("size")
            .short('q')
            .value_parser(value_parser!(usize))
            .default_value("900000")
            .help("Specifies the maximum number of bytes to be sent to Kafka in a single message.")
    )
    .arg(
        Arg::new("offset")
            .short('r')
            .default_value("")
            .help("Record (prefix of offset file). Using this option will start the conversation \
                   after the previous conversation. The offset file name is managed by \
                   <input_file>_<prefix>.")
    )
    .arg(
        Arg::new("skip")
            .short('s')
            .value_parser(value_parser!(usize))
            .default_value("0")
            .help("Skip count")
    )
    .arg(
        Arg::new("topic")
            .short('t')
            .default_value("")
            .help("Kafka topic name. The topic should be available on the broker.")
    )
    .arg(
        Arg::new("polling")
            .short('v')
            .help("Polls the input directory")
    )
    .arg(
        Arg::new("giganto")
            .short('G')
            .default_value("127.0.0.1:38370")
            .help("Giganto server address")
    )
    .arg(
        Arg::new("name")
            .short('N')
            .default_value("localhost")
            .help("Giganto server hostname.")
    )
    .arg(
        Arg::new("certs")
            .short('C')
            .default_value("config.toml")
            .help("config.toml file with cert, key, roots path.")
    )
    .arg(
        Arg::new("kind")
            .short('k')
            .default_value("")
            .help("Giganto log kind.")
    )
    .get_matches();

    let kafka_broker = m.get_one::<String>("broker").expect("has `default_value`");
    let count_sent = *m.get_one::<usize>("count").expect("has `default_value`");
    let datasource_id = m
        .get_one::<NonZeroU8>("source")
        .expect("has `default_value`")
        .get();
    let mode_eval = m.contains_id("eval");
    let mode_grow = m.contains_id("continuous");
    let input = m.get_one::<String>("input").expect("has `default_value`");
    let initial_seq_no = *m.get_one::<usize>("seq").expect("has `default_value`");
    let pattern_file = m.get_one::<String>("pattern").expect("has `default_value`");
    let file_prefix = m.get_one::<String>("prefix").expect("has `default_value`");
    let output = m.get_one::<String>("output").expect("has `default_value`");
    let queue_period = m
        .get_one::<NonZeroI64>("period")
        .expect("has `default_value`")
        .get();
    let queue_size = *m.get_one::<usize>("size").expect("has `default_value`");
    if queue_size > 900_000 {
        eprintln!("ERROR: queue size is too large (should be no larger than 900,000");
        std::process::exit(1);
    }
    let offset_prefix = m.get_one::<String>("offset").expect("has `default_value`");
    let count_skip = *m.get_one::<usize>("skip").expect("has `default_value`");
    let kafka_topic = m.get_one::<String>("topic").expect("has `default_value`");
    let certs_toml = m.get_one::<String>("certs").expect("has `default_value`");
    let giganto_name = m.get_one::<String>("name").expect("has `default_value`");
    let giganto_addr = m.get_one::<String>("giganto").expect("has `default_name`");
    let giganto_kind = m.get_one::<String>("kind").expect("has `default_value`");
    let mode_polling_dir = m.contains_id("polling");
    if output.is_empty() && kafka_broker.is_empty() {
        eprintln!("ERROR: Kafka broker (-b) required");
        std::process::exit(1);
    }
    if output.is_empty() && kafka_topic.is_empty() {
        eprintln!("ERROR: Kafka topic (-t) required");
        std::process::exit(1);
    }
    if input.is_empty() && output == "none" {
        eprintln!("ERROR: input (-i) required if output (-o) is \"none\"");
        std::process::exit(1);
    }
    Config {
        mode_eval,
        mode_grow,
        mode_polling_dir,
        count_skip,
        queue_size,
        queue_period,
        input: input.to_string(),
        output: output.to_string(),
        offset_prefix: offset_prefix.to_string(),
        kafka_broker: kafka_broker.to_string(),
        kafka_topic: kafka_topic.to_string(),
        pattern_file: pattern_file.to_string(),
        file_prefix: file_prefix.to_string(),
        datasource_id,
        initial_seq_no,
        count_sent,
        certs_toml: certs_toml.to_string(),
        giganto_name: giganto_name.to_string(),
        giganto_addr: giganto_addr.to_string(),
        giganto_kind: giganto_kind.to_string(),
        ..Config::default()
    }
}
