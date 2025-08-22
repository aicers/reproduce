mod network;
#[cfg(test)]
mod tests;

use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use csv::StringRecord;

pub(crate) trait TryFromGigantoRecord: Sized {
    fn try_from_giganto_record(rec: &StringRecord) -> Result<(Self, i64)>;
}

fn parse_giganto_timestamp(timestamp: &str) -> Result<DateTime<Utc>> {
    if let Some(i) = timestamp.find('.') {
        let secs = timestamp[..i].parse::<i64>().context("invalid timestamp")?;
        let micros = timestamp[i + 1..]
            .parse::<u32>()
            .context("invalid timestamp")?;
        let Some(time) = DateTime::from_timestamp(secs, micros) else {
            return Err(anyhow!("failed to create DateTime<Utc> from timestamp"));
        };
        Ok(time)
    } else {
        Err(anyhow!("invalid timestamp: {}", timestamp))
    }
}

fn parse_comma_separated<T: FromStr>(s: &str) -> std::result::Result<Vec<T>, T::Err> {
    let mut v = Vec::new();
    if s != "-" && !s.is_empty() {
        for t in s.split(',') {
            v.push(t.parse()?);
        }
    }
    Ok(v)
}
