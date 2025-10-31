mod network;
#[cfg(test)]
mod tests;

use std::{fs::File, path::Path};

use anyhow::{anyhow, Context, Result};
use csv::{Reader, ReaderBuilder, StringRecord};
use jiff::Timestamp;

const PROTO_TCP: u8 = 0x06;
const PROTO_UDP: u8 = 0x11;
const PROTO_ICMP: u8 = 0x01;

pub(crate) trait TryFromZeekRecord: Sized {
    fn try_from_zeek_record(rec: &StringRecord) -> Result<(Self, i64)>;
}

pub(crate) fn parse_zeek_timestamp(timestamp: &str) -> Result<Timestamp> {
    let Some((sec_str, micro_str)) = timestamp.split_once('.') else {
        return Err(anyhow!("invalid timestamp: {timestamp}"));
    };

    let secs = sec_str
        .parse::<i64>()
        .context("invalid timestamp (seconds)")?;
    let micros = micro_str
        .parse::<i32>()
        .context("invalid timestamp (microseconds)")?;
    if micros >= 1_000_000 {
        return Err(anyhow!(
            "invalid microsecond precision (>= 1_000_000): {timestamp}"
        ));
    }

    let nanos = micros * 1_000;

    Timestamp::new(secs, nanos).context("failed to create Timestamp (secs+nanos)")
}

pub(crate) fn open_raw_event_log_file(path: &Path) -> Result<Reader<File>> {
    Ok(ReaderBuilder::new()
        .comment(Some(b'#'))
        .delimiter(b'\t')
        .has_headers(false)
        .flexible(true)
        .from_path(path)?)
}
