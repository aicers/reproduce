use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::str::FromStr;

#[derive(Debug, Serialize)]
pub(crate) struct Oplog {
    agent_id: String,
    log_level: LogLevel,
    log: String,
    // log category, log id
}

#[derive(Debug, Serialize)]
pub(crate) enum LogLevel {
    Info,
    Warn,
    Error,
}

fn parse_oplog_timestamp(datetime: &str) -> Result<DateTime<Utc>> {
    DateTime::from_str(datetime).map_err(|e| anyhow!("{:?}", e))
}

fn parse_log_level(level: &str) -> Result<LogLevel> {
    match level {
        "INFO" => Ok(LogLevel::Info),
        "WARN" => Ok(LogLevel::Warn),
        "ERROR" => Ok(LogLevel::Error),
        _ => Err(anyhow!("invalid log level")),
    }
}

pub(crate) fn log_regex(line: &str, agent: &str) -> Result<(Oplog, i64)> {
    lazy_static! {
        static ref LOG_REGEX: Regex =
            Regex::new(r"(?P<datetime>\S{27})\s+(?P<level>INFO|WARN|ERROR)\s(?P<contents>.+)$")
                .expect("regex");
    }
    let caps = LOG_REGEX.captures(line).context("invalid log line")?;

    let log_level = match caps.name("level") {
        Some(l) => l.as_str(),
        None => bail!("invalid log level"),
    };
    let log_level = parse_log_level(log_level)?;

    let datetime = match caps.name("datetime") {
        Some(d) => d.as_str(),
        None => bail!("invalid datetime"),
    };
    let timestamp = parse_oplog_timestamp(datetime)?.timestamp_nanos();

    let log = match caps.name("contents") {
        Some(l) => l.as_str(),
        None => "-",
    };

    Ok((
        Oplog {
            agent_id: agent.to_string(),
            log_level,
            log: log.to_string(),
        },
        timestamp,
    ))
}
