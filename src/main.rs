use clap::{Arg, Command};
use reproduce::{Config, Controller};
use std::num::{NonZeroI64, NonZeroU8};

pub fn main() {
    let config = parse();
    println!("{}", config);

    let mut controller = Controller::new(config);
    println!("reproduce start");
    if let Err(e) = controller.run() {
        eprintln!("ERROR: {}", e);
        std::process::exit(1);
    }
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
            .takes_value(true)
	    .value_name("host1:port1,host2:port2,..")
            .help("Kafka broker list"),
    )
    .arg(
        Arg::new("count")
            .short('c')
            .takes_value(true)
            .help("Send count"),
    )
    .arg(
        Arg::new("source")
            .short('d')
            .takes_value(true)
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
            .takes_value(true)
            .help("Input [LOGFILE/DIR] \
	    	   If not given, internal sample data will be used.")
    )
    .arg(
        Arg::new("seq")
            .short('j')
            .takes_value(true)
            .help("Sets the initial sequence number (0-16777215).")
    )
    .arg(
        Arg::new("pattern")
            .short('m')
            .takes_value(true)
            .value_name("FILE")
            .help("Pattern filename")
    )
    .arg(
        Arg::new("prefix")
            .short('n')
            .takes_value(true)
            .help("Prefix of file names to send multiple files or a directory")
    )
    .arg(
        Arg::new("output")
            .short('o')
            .takes_value(true)
            .help("Output type [TEXTFILE/none]. \
                   If not given, the output is sent to Kafka.")
    )
    .arg(
        Arg::new("period")
            .short('p')
            .takes_value(true)
            .default_value("3")
            .help("Sepcifies how long data may be kept in the queue.")
    )
    .arg(
        Arg::new("size")
            .short('q')
            .takes_value(true)
            .default_value("900000")
            .help("Specifies the maximum number of bytes to be sent to Kafka in a single message.")
    )
    .arg(
        Arg::new("offset")
            .short('r')
            .takes_value(true)
            .help("Record (prefix of offset file). Using this option will start the conversation \
                   after the previous conversation. The offset file name is managed by \
                   <input_file>_<prefix>.")
    )
    .arg(
        Arg::new("skip")
            .short('s')
            .takes_value(true)
            .help("Skip count")
    )
    .arg(
        Arg::new("topic")
            .short('t')
            .takes_value(true)
            .help("Kafka topic name. The topic should be available on the broker.")
    )
    .arg(
        Arg::new("polling")
            .short('v')
            .help("Polls the input directory")
    )
    .get_matches();

    let kafka_broker = m.value_of("broker").unwrap_or_default();
    let count_sent = m
        .value_of("count")
        .map(|v| {
            let result = v.parse::<usize>();
            match result {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: invalid count: {}", v);
                    eprintln!("\t{}", e);
                    std::process::exit(1);
                }
            }
        })
        .unwrap_or_default();
    let datasource_id = m.value_of("source").map_or(1, |v| {
        let result = v.parse::<NonZeroU8>();
        match result {
            Ok(v) => v.get(),
            Err(e) => {
                eprintln!("ERROR: invalid data source ID: {}", v);
                eprintln!("\t{}", e);
                std::process::exit(1);
            }
        }
    });
    let mode_eval = m.is_present("eval");
    let mode_grow = m.is_present("continuous");
    let input = m.value_of("input").unwrap_or_default();
    let initial_seq_no = m
        .value_of("seq")
        .map(|v| {
            let result = v.parse::<usize>();
            match result {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: invalid sequence number: {}", v);
                    eprintln!("\t{}", e);
                    std::process::exit(1);
                }
            }
        })
        .unwrap_or_default();
    let pattern_file = m.value_of("pattern").unwrap_or_default();
    let file_prefix = m.value_of("prefix").unwrap_or_default();
    let output = m.value_of("output").unwrap_or_default();
    let queue_period = m.value_of("period").map_or(3, |v| {
        let result = v.parse::<NonZeroI64>();
        match result {
            Ok(v) => v.get(),
            Err(e) => {
                eprintln!("ERROR: invalid queue period: {}", v);
                eprintln!("\t{}", e);
                std::process::exit(1);
            }
        }
    });
    let queue_size = m.value_of("size").map_or(900_000, |v| {
        let result = v.parse::<usize>();
        match result {
            Ok(v) => {
                if v > 900_000 {
                    eprintln!("ERROR: queue size is too large (should be no larger than 900,000");
                    std::process::exit(1);
                }
                v
            }
            Err(e) => {
                eprintln!("ERROR: invalid queue size: {}", v);
                eprintln!("\t{}", e);
                std::process::exit(1);
            }
        }
    });
    let offset_prefix = m.value_of("offset").unwrap_or_default();
    let count_skip = m
        .value_of("skip")
        .map(|v| {
            let result = v.parse::<usize>();
            match result {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: invalid queue size: {}", v);
                    eprintln!("\t{}", e);
                    std::process::exit(1);
                }
            }
        })
        .unwrap_or_default();
    let kafka_topic = m.value_of("topic").unwrap_or_default();
    let mode_polling_dir = m.is_present("polling");
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
        ..Config::default()
    }
}
