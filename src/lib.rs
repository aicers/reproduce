mod config;
mod controller;
mod migration;
mod netflow;
mod operation_log;
mod producer;
mod report;
mod security_log;
mod syslog;
mod zeek;

use anyhow::Result;
pub use config::{Config, InputType};
pub use controller::Controller;
use csv::StringRecord;
pub use producer::Producer;
pub use report::Report;

pub trait TryFromCsvRecord: Sized {
    /// # Errors
    ///
    /// Returns an error if any data field parsing fails.
    fn try_from_csv_record(rec: &StringRecord) -> Result<(Self, i64)>;
}
