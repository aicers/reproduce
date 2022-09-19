use std::fmt;

#[derive(Clone)]
pub struct Config {
    // user
    pub mode_eval: bool,        // report statistics
    pub mode_grow: bool,        // convert while tracking the growing file
    pub mode_polling_dir: bool, // polling the input directory
    pub count_skip: usize,      // count to skip
    pub queue_size: usize,      // how many bytes sent at once
    pub queue_period: i64,      // how much time queued data is kept for
    pub input: String,          // input: packet/log/none
    pub output: String,         // output: kafka/file/none
    pub offset_prefix: String,  // prefix of offset file to read from and write to
    pub kafka_broker: String,
    pub kafka_topic: String,
    pub pattern_file: String,
    pub file_prefix: String, // file name prefix when sending multiple files or a directory
    pub certs_toml: String,
    pub giganto_name: String,
    pub giganto_addr: String,

    pub datasource_id: u8,
    pub initial_seq_no: usize,

    // internal
    pub count_sent: usize,
    pub input_type: InputType,
    pub output_type: OutputType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputType {
    Log,
    Dir,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputType {
    None,
    Kafka,
    File,
    Giganto,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode_eval: false,
            mode_grow: false,
            mode_polling_dir: false,
            count_skip: 0,
            queue_size: 900_000,
            queue_period: 3,
            input: String::new(),
            output: String::new(),
            offset_prefix: String::new(),
            kafka_broker: String::new(),
            kafka_topic: String::new(),
            pattern_file: String::new(),
            file_prefix: String::new(),
            datasource_id: 1,
            initial_seq_no: 0,
            count_sent: 0,
            input_type: InputType::Log,
            output_type: OutputType::None,
            certs_toml: String::new(),
            giganto_name: String::new(),
            giganto_addr: String::new(),
        }
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "mode_eval={}", self.mode_eval)?;
        writeln!(f, "mode_grow={}", self.mode_grow)?;
        writeln!(f, "count_sent={}", self.count_sent)?;
        writeln!(f, "count_skip={}", self.count_skip)?;
        writeln!(f, "queue_size={}", self.queue_size)?;
        writeln!(f, "input={}", self.input)?;
        writeln!(f, "output={}", self.output)?;
        writeln!(f, "offset_prefix={}", self.offset_prefix)?;
        writeln!(f, "kafka_broker={}", self.kafka_broker)?;
        writeln!(f, "kafka_topic={}", self.kafka_topic)?;
        writeln!(f, "file_prefix={}", self.file_prefix.clone())?;
        writeln!(f, "datasource_id={}", self.datasource_id)?;
        writeln!(f, "certs_toml={}", self.certs_toml)?;
        writeln!(f, "giganto_name={}", self.giganto_name)?;
        writeln!(f, "giganto_addr={}", self.giganto_addr)
    }
}
