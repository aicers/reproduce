mod network;
#[cfg(test)]
mod tests;

use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use csv::StringRecord;
use jiff::Timestamp;

pub(crate) trait TryFromGigantoRecord: Sized {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)>;
}

fn parse_giganto_timestamp(timestamp: &str) -> Result<Timestamp> {
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

fn parse_comma_separated<T: FromStr>(s: &str) -> std::result::Result<Vec<T>, T::Err> {
    let mut v = Vec::new();
    if s != "-" {
        for t in s.split(',') {
            v.push(t.parse()?);
        }
    }
    Ok(v)
}

fn parse_post_body(s: &str) -> Vec<u8> {
    if s != "-" && !s.is_empty() {
        s.as_bytes().to_vec()
    } else {
        Vec::new()
    }
}
