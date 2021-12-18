use clap::{App, Arg};
use reproduce::{Config, Controller, OperationMode};
use std::num::{NonZeroI64, NonZeroU8};
use tracing::{error, info};

pub fn main() {
    tracing_subscriber::fmt::init();
    info!("Version {}", env!("CARGO_PKG_VERSION"));

    let config = parse();
    info!("config:\n{}", config);

    create_pid_file();

    let mut controller = Controller::new(config);
    info!("reproduce start");
    if let Err(e) = controller.run() {
        error!("ERROR: {}", e);
        std::process::exit(1);
    }
    info!("reproduce end");
}

fn create_pid_file() {
    let pid_dir = if env!("HOME").trim().is_empty() {
        "/tmp/.aice".to_string()
    } else {
        format!("{}/.aice", env!("HOME"))
    };
    if std::fs::create_dir_all(&pid_dir).is_ok() {
        let pid = format!("{}/{}.pid", pid_dir, env!("CARGO_PKG_NAME"));
        if let Err(e) = std::fs::write(&pid, &format!("{}\n", std::process::id())) {
            info!("failed to create pid file {}. {}", pid, e);
        }
    }
}

#[allow(clippy::too_many_lines)]
#[must_use]
pub fn parse() -> Config {
    let m = App::new("reproduce")
    .version(env!("CARGO_PKG_VERSION"))
    .arg(
        Arg::with_name("broker")
            .short("b")
            .takes_value(true)
	        .value_name("host1:port1,host2:port2,..")
            .help("Kafka broker list"),
    )
    .arg(
        Arg::with_name("count")
            .short("c")
            .takes_value(true)
            .help("Send count"),
    )
    .arg(
        Arg::with_name("source")
            .short("d")
            .takes_value(true)
            .default_value("1")
            .help("Data source ID (1-255)"),
    )
    .arg(
        Arg::with_name("eval")
            .short("e")
            .help("Evaluation mode. Outputs statistics of transmission.")
    )
    .arg(
        Arg::with_name("continuous")
            .short("g")
            .help("Continues to read from a growing input file")
    )
    .arg(
        Arg::with_name("input")
            .short("i")
            .takes_value(true)
            .help("Input [LOGFILE/DIR] \
	    	   If not given, internal sample data will be used.")
    )
    .arg(
        Arg::with_name("seq")
            .short("j")
            .takes_value(true)
            .help("Sets the initial sequence number (0-16777215).")
    )
    .arg(
        Arg::with_name("pattern")
            .short("m")
            .takes_value(true)
            .value_name("FILE")
            .help("Pattern filename")
    )
    .arg(
        Arg::with_name("prefix")
            .short("n")
            .takes_value(true)
            .help("Prefix of file names to send multiple files or a directory")
    )
    .arg(
        Arg::with_name("output")
            .short("o")
            .takes_value(true)
            .help("Output type [TEXTFILE/none]. \
                   If not given, the output is sent to Kafka.")
    )
    .arg(
        Arg::with_name("period")
            .short("p")
            .takes_value(true)
            .default_value("3")
            .help("Sepcifies how long data may be kept in the queue.")
    )
    .arg(
        Arg::with_name("size")
            .short("q")
            .takes_value(true)
            .default_value("900000")
            .help("Specifies the maximum number of bytes to be sent to Kafka in a single message.")
    )
    .arg(
        Arg::with_name("offset")
            .short("r")
            .takes_value(true)
            .help("Record (prefix of offset file). Using this option will start the conversation \
                   after the previous conversation. The offset file name is managed by \
                   <input_file>_<prefix>.")
    )
    .arg(
        Arg::with_name("skip")
            .short("s")
            .takes_value(true)
            .help("Skip count")
    )
    .arg(
        Arg::with_name("topic")
            .short("t")
            .takes_value(true)
            .help("Kafka topic name. The topic should be available on the broker.")
    )
    .arg(
        Arg::with_name("polling")
            .short("v")
            .help("Polls the input directory")
    )
    .arg(
        Arg::with_name("zeek")
            .short("z")
            .takes_value(false)
            .help("Convert zeek log")
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
                    error!("ERROR: invalid count: {}", v);
                    error!("\t{}", e);
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
                error!("ERROR: invalid data source ID: {}", v);
                error!("\t{}", e);
                std::process::exit(1);
            }
        }
    });
    let mode_eval = OperationMode::Reporting(m.is_present("eval"));
    let mode_grow = OperationMode::Continuous(m.is_present("continuous"));
    let input = m.value_of("input").unwrap_or_default();
    let initial_seq_no = m
        .value_of("seq")
        .map(|v| {
            let result = v.parse::<usize>();
            match result {
                Ok(v) => v,
                Err(e) => {
                    error!("ERROR: invalid sequence number: {}", v);
                    error!("\t{}", e);
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
                error!("ERROR: invalid queue period: {}", v);
                error!("\t{}", e);
                std::process::exit(1);
            }
        }
    });
    let queue_size = m.value_of("size").map_or(900_000, |v| {
        let result = v.parse::<usize>();
        match result {
            Ok(v) => {
                if v > 900_000 {
                    error!("ERROR: queue size is too large (should be no larger than 900,000");
                    std::process::exit(1);
                }
                v
            }
            Err(e) => {
                error!("ERROR: invalid queue size: {}", v);
                error!("\t{}", e);
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
                    error!("ERROR: invalid queue size: {}", v);
                    error!("\t{}", e);
                    std::process::exit(1);
                }
            }
        })
        .unwrap_or_default();
    let kafka_topic = m.value_of("topic").unwrap_or_default();
    let mode_polling_dir = OperationMode::Polling(m.is_present("polling"));
    if output.is_empty() && kafka_broker.is_empty() {
        error!("ERROR: Kafka broker (-b) required");
        std::process::exit(1);
    }
    if output.is_empty() && kafka_topic.is_empty() {
        error!("ERROR: Kafka topic (-t) required");
        std::process::exit(1);
    }
    if input.is_empty() && output == "none" {
        error!("ERROR: input (-i) required if output (-o) is \"none\"");
        std::process::exit(1);
    }
    let zeek_flag = OperationMode::ZeekConverting(m.is_present("zeek"));

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
        zeek_flag,
        datasource_id,
        initial_seq_no,
        count_sent,
        ..Config::default()
    }
}
