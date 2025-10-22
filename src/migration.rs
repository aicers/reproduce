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
    let Some((sec_str, nano_str)) = timestamp.split_once('.') else {
        return Err(anyhow!("invalid timestamp: {timestamp}"));
    };

    let secs = sec_str
        .parse::<i64>()
        .context("invalid timestamp (seconds)")?;
    let nanos = nano_str
        .parse::<i32>()
        .context("invalid timestamp (nanoseconds)")?;
    let ts = Timestamp::new(secs, nanos)
        .context("failed to create Timestamp from (seconds, nanoseconds)")?;

    Ok(ts)
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
