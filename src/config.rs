use std::fmt;

#[derive(Clone)]
pub struct Config {
    // user
    pub mode_eval: OperationMode,        // report statistics
    pub mode_grow: OperationMode,        // convert while tracking the growing file
    pub mode_polling_dir: OperationMode, // polling the input directory
    pub count_skip: usize,               // count to skip
    pub queue_size: usize,               // how many bytes sent at once
    pub queue_period: i64,               // how much time queued data is kept for
    pub input: String,                   // input: packet/log/none
    pub output: String,                  // output: kafka/file/none
    pub offset_prefix: String,           // prefix of offset file to read from and write to
    pub kafka_broker: String,
    pub kafka_topic: String,
    pub pattern_file: String,
    pub file_prefix: String, // file name prefix when sending multiple files or a directory
    pub zeek_flag: OperationMode, // zeek log parsing mode: replace ',' -> ';' and '\t' -> ','

    pub datasource_id: u8,
    pub initial_seq_no: usize,

    // internal
    pub count_sent: usize,
    pub input_type: InputType,
    pub output_type: OutputType,
}

#[derive(Clone)]
pub enum OperationMode {
    Reporting(bool),
    Continuous(bool),
    Polling(bool),
    ZeekConverting(bool),
}

impl std::fmt::Display for OperationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.is_set())
    }
}

impl OperationMode {
    #[must_use]
    pub fn is_set(&self) -> bool {
        match self {
            OperationMode::Reporting(x)
            | OperationMode::Continuous(x)
            | OperationMode::Polling(x)
            | OperationMode::ZeekConverting(x) => *x,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InputType {
    Log,
    Dir,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OutputType {
    None,
    Kafka,
    File,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode_eval: OperationMode::Reporting(false),
            mode_grow: OperationMode::Continuous(false),
            mode_polling_dir: OperationMode::Polling(false),
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
            zeek_flag: OperationMode::ZeekConverting(false),
            datasource_id: 1,
            initial_seq_no: 0,
            count_sent: 0,
            input_type: InputType::Log,
            output_type: OutputType::None,
        }
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.mode_eval.is_set() {
            writeln!(f, "mode_eval={}", self.mode_eval)?;
        }
        if self.mode_grow.is_set() {
            writeln!(f, "mode_grow={}", self.mode_grow)?;
        }
        if self.count_sent > 0 {
            writeln!(f, "count_sent={}", self.count_sent)?;
        }
        if self.count_skip > 0 {
            writeln!(f, "count_skip={}", self.count_skip)?;
        }
        writeln!(f, "queue_size={}", self.queue_size)?;
        writeln!(f, "input={}", self.input)?;
        if !self.output.is_empty() {
            writeln!(f, "output={}", self.output)?;
        }
        if !self.offset_prefix.is_empty() {
            writeln!(f, "offset_prefix={}", self.offset_prefix)?;
        }
        writeln!(f, "kafka_broker={}", self.kafka_broker)?;
        writeln!(f, "kafka_topic={}", self.kafka_topic)?;
        if !self.file_prefix.is_empty() {
            writeln!(f, "file_prefix={}", self.file_prefix)?;
        }
        write!(f, "datasource_id={}", self.datasource_id)
    }
}
