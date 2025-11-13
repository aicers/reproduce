use std::sync::OnceLock;
#[cfg(test)]
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use giganto_client::ingest::log::SecuLog;
use regex::Regex;

use super::{ParseSecurityLog, SecurityLogInfo, Ubuntu, datetime_to_nanos};

fn get_ubuntu_regex() -> &'static Regex {
    static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

    LOG_REGEX
        .get_or_init(|| Regex::new(r"(?<datetime>\w{3} \d{1,2} \d{2}:\d{2}:\d{2})").expect("regex"))
}

#[cfg(test)]
static TEST_YEAR_OVERRIDE: AtomicI32 = AtomicI32::new(0);

fn parse_ubuntu_timestamp(datetime: &str) -> Result<DateTime<Utc>> {
    let year = current_year()?;
    DateTime::parse_from_str(&format!("{year} {datetime} +0900"), "%Y %b %d %H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| anyhow!("{e:?}"))
}

fn current_year() -> Result<i32> {
    #[cfg(test)]
    {
        let override_year = TEST_YEAR_OVERRIDE.load(Ordering::Relaxed);
        if override_year != 0 {
            return Ok(override_year);
        }
    }

    Utc::now()
        .format("%Y")
        .to_string()
        .parse::<i32>()
        .map_err(|e| anyhow!("failed to parse current year: {e}"))
}

#[cfg(test)]
pub(crate) fn set_test_year_override(year: Option<i32>) {
    TEST_YEAR_OVERRIDE.store(year.unwrap_or(0), Ordering::Relaxed);
}

impl ParseSecurityLog for Ubuntu {
    fn parse_security_log(
        line: &str,
        serial: i64,
        info: SecurityLogInfo,
    ) -> Result<(SecuLog, i64)> {
        let caps = get_ubuntu_regex()
            .captures(line)
            .context("invalid log line")?;

        let datetime = match caps.name("datetime") {
            Some(d) => d.as_str(),
            None => bail!("invalid datetime"),
        };

        let timestamp = datetime_to_nanos(parse_ubuntu_timestamp(datetime)?)? + serial;

        Ok((
            SecuLog {
                kind: info.kind,
                log_type: info.log_type,
                version: info.version,
                orig_addr: None,
                orig_port: None,
                resp_addr: None,
                resp_port: None,
                proto: None,
                contents: line.to_string(),
            },
            timestamp,
        ))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::{parse_ubuntu_timestamp, set_test_year_override};

    #[test]
    fn ubuntu_timestamp_uses_current_year() {
        set_test_year_override(Some(2024));
        let ts = parse_ubuntu_timestamp("Jan 02 03:04:05").unwrap();
        let expected =
            DateTime::parse_from_str("2024 Jan 02 03:04:05 +0900", "%Y %b %d %H:%M:%S %z")
                .expect("valid timestamp")
                .with_timezone(&Utc);
        assert_eq!(ts, expected);
        set_test_year_override(None);
    }

    #[test]
    fn ubuntu_timestamp_rejects_invalid_input() {
        set_test_year_override(Some(2024));
        assert!(parse_ubuntu_timestamp("not a date").is_err());
        set_test_year_override(None);
    }
}
