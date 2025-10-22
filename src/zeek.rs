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
    if let Some(i) = timestamp.find('.') {
        let secs = timestamp[..i].parse::<i64>().context("invalid timestamp")?;
        let micros = timestamp[i + 1..]
            .parse::<i64>()
            .context("invalid timestamp")?;
        let nanos = micros * 1000;
        let time = Timestamp::from_second(secs)
            .map_err(|e| anyhow!("failed to create Timestamp from timestamp: {e}"))?
            .checked_add(jiff::Span::new().nanoseconds(nanos))
            .map_err(|e| anyhow!("failed to add nanoseconds to timestamp: {e}"))?;
        Ok(time)
    } else {
        Err(anyhow!("invalid timestamp: {timestamp}"))
    }
}

pub(crate) fn open_raw_event_log_file(path: &Path) -> Result<Reader<File>> {
    Ok(ReaderBuilder::new()
        .comment(Some(b'#'))
        .delimiter(b'\t')
        .has_headers(false)
        .flexible(true)
        .from_path(path)?)
}
