use std::fmt;

#[derive(Clone)]
pub struct Config {
    // user
    pub mode_eval: bool,        // report statistics
    pub mode_grow: bool,        // convert while tracking the growing file
    pub mode_polling_dir: bool, // polling the input directory
    pub count_skip: usize,      // count to skip
    pub input: String,          // input: packet/log/none
    pub output: String,         // output: giganto/file/none
    pub offset_prefix: String,  // prefix of offset file to read from and write to
    pub file_prefix: String,    // file name prefix when sending multiple files or a directory
    pub certs_toml: String,
    pub giganto_name: String,
    pub giganto_addr: String,
    pub giganto_kind: String,
    pub send_from: u64,

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
            input: String::new(),
            output: String::new(),
            offset_prefix: String::new(),
            file_prefix: String::new(),
            count_sent: 0,
            input_type: InputType::Log,
            output_type: OutputType::None,
            certs_toml: String::new(),
            giganto_name: String::new(),
            giganto_addr: String::new(),
            giganto_kind: String::new(),
            send_from: 1,
        }
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "mode_eval={}", self.mode_eval)?;
        writeln!(f, "mode_grow={}", self.mode_grow)?;
        writeln!(f, "count_sent={}", self.count_sent)?;
        writeln!(f, "count_skip={}", self.count_skip)?;
        writeln!(f, "input={}", self.input)?;
        writeln!(f, "output={}", self.output)?;
        if !self.offset_prefix.is_empty() {
            writeln!(f, "offset_prefix={}", self.offset_prefix)?;
        }
        if !self.file_prefix.is_empty() {
            writeln!(f, "file_prefix={}", self.file_prefix.clone())?;
        }
        writeln!(f, "certs_toml={}", self.certs_toml)?;
        writeln!(f, "giganto_name={}", self.giganto_name)?;
        writeln!(f, "giganto_addr={}", self.giganto_addr)?;
        writeln!(f, "giganto_kind={}", self.giganto_kind)
    }
}
