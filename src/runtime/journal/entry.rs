//! One line of journalctl's JSON output: its position, whether the
//! collector keeps it, and the `OpLog` it is sent as.
//!
//! Journal content is untrusted: an entry is selected by the fields journald
//! sets itself, plus `CONTAINER_NAME` only under `docker.service`.

use std::borrow::Cow;

use giganto_client::ingest::log::{OpLog, OpLogLevel};
use serde_json::{Map, Value};

use super::JournalPosition;

/// The longest `contents` sent, in bytes.
const MAX_CONTENTS: usize = 64 * 1024;

/// What ends a cut `contents`.
const TRUNCATED: &str = " \u{2026}[truncated]";

/// The units kept besides those matching `clumit-security-*.service`.
const UNITS: [&str; 4] = [
    "bootroot-registrar.service",
    "roxyd-selfupdate-boot.service",
    "roxyd-selfupdate-crash.service",
    "roxyd-selfupdate-deadline.service",
];

/// The prefixes of the container names kept.
const CONTAINERS: [&str; 2] = ["aice-web-next-", "clumit-security-"];

/// One parsed journal entry.
#[derive(Debug)]
pub(super) struct Entry {
    pub(super) position: JournalPosition,
    /// The serialized `OpLog` of a kept entry; `None` for a dropped one.
    pub(super) record: Option<Vec<u8>>,
}

/// Parses one line of journalctl's JSON output. Returns `None` if the line
/// is not a JSON object or has no `__CURSOR` string.
pub(super) fn parse(line: &[u8]) -> Option<Entry> {
    let object = serde_json::from_slice::<Map<String, Value>>(line).ok()?;
    let position = position(&object)?;
    let record = op_log(&object).and_then(|op_log| bincode::serialize(&op_log).ok());
    Some(Entry { position, record })
}

/// Returns the position of an entry, or `None` if it has no `__CURSOR`
/// string.
fn position(object: &Map<String, Value>) -> Option<JournalPosition> {
    let string = |name: &str| object.get(name).and_then(Value::as_str);
    Some(JournalPosition {
        cursor: string("__CURSOR")?.to_string(),
        seqnum_id: string("__SEQNUM_ID").map(str::to_string),
        seqnum: string("__SEQNUM").and_then(decimal),
        realtime_us: string("__REALTIME_TIMESTAMP").and_then(decimal),
    })
}

/// Parses a string of decimal digits.
fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The `OpLog` of an entry the collector keeps, or `None` if it drops the
/// entry.
fn op_log(object: &Map<String, Value>) -> Option<OpLog> {
    let field = |name: &str| object.get(name).and_then(text);
    let (systemd_unit, unit, container_name) = (
        field("_SYSTEMD_UNIT"),
        field("UNIT"),
        field("CONTAINER_NAME"),
    );
    let (source, name) = select(
        systemd_unit.as_deref(),
        field("_PID").as_deref(),
        unit.as_deref(),
        container_name.as_deref(),
    )?;
    Some(OpLog {
        sensor: String::new(),
        service_name: format!("clumit-security/{source}/{name}"),
        log_level: level(field("PRIORITY").as_deref()),
        contents: contents(field("MESSAGE").map(Cow::into_owned).unwrap_or_default()),
    })
}

/// Reads a field's value: a string; an array of integers 0 to 255, which is
/// binary data, as lossy UTF-8; or, for a field set more than once, the
/// first value by the same rules. Anything else is a missing field.
fn text(value: &Value) -> Option<Cow<'_, str>> {
    match value {
        Value::String(s) => Some(Cow::Borrowed(s)),
        Value::Array(items) => binary(items).or_else(|| match items.first()? {
            Value::String(s) => Some(Cow::Borrowed(s.as_str())),
            Value::Array(items) => binary(items),
            _ => None,
        }),
        _ => None,
    }
}

/// Decodes an array of integers 0 to 255 as lossy UTF-8.
fn binary(items: &[Value]) -> Option<Cow<'_, str>> {
    let bytes = items
        .iter()
        .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect::<Option<Vec<u8>>>()?;
    Some(Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()))
}

/// Returns the source type and the name of an entry the collector keeps.
fn select<'a>(
    systemd_unit: Option<&'a str>,
    pid: Option<&str>,
    unit: Option<&'a str>,
    container_name: Option<&'a str>,
) -> Option<(&'static str, &'a str)> {
    if let Some(systemd_unit) = systemd_unit.filter(|name| is_product_unit(name)) {
        return Some(("unit", systemd_unit));
    }
    if pid == Some("1")
        && let Some(unit) = unit.filter(|name| is_product_unit(name))
    {
        return Some(("systemd", unit));
    }
    if systemd_unit == Some("docker.service")
        && let Some(name) =
            container_name.filter(|name| CONTAINERS.iter().any(|prefix| name.starts_with(prefix)))
    {
        return Some(("container", name));
    }
    None
}

/// Tells whether `name` matches `clumit-security-*.service`, the `*`
/// standing for one or more characters from `[a-z0-9@-]`, or is one of
/// [`UNITS`].
fn is_product_unit(name: &str) -> bool {
    if UNITS.contains(&name) {
        return true;
    }
    name.strip_prefix("clumit-security-")
        .and_then(|rest| rest.strip_suffix(".service"))
        .is_some_and(|middle| {
            !middle.is_empty()
                && middle
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'@' || b == b'-')
        })
}

/// Maps a `PRIORITY`: `0` to `3` is an error and `4` a warning; anything
/// else, missing included, is information.
fn level(priority: Option<&str>) -> OpLogLevel {
    match priority {
        Some("0" | "1" | "2" | "3") => OpLogLevel::Error,
        Some("4") => OpLogLevel::Warn,
        _ => OpLogLevel::Info,
    }
}

/// Cuts a `MESSAGE` longer than [`MAX_CONTENTS`] bytes at a UTF-8 boundary
/// and marks it, so that the result is at most [`MAX_CONTENTS`] bytes long.
fn contents(mut message: String) -> String {
    if message.len() > MAX_CONTENTS {
        let mut cut = MAX_CONTENTS - TRUNCATED.len();
        while !message.is_char_boundary(cut) {
            cut -= 1;
        }
        message.truncate(cut);
        message.push_str(TRUNCATED);
    }
    message
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const CURSOR: &str = "s=0123456789abcdef0123456789abcdef;i=1;\
                          b=0123456789abcdef0123456789abcdef;m=2;t=3;x=4";

    fn object(value: &Value) -> Map<String, Value> {
        value.as_object().expect("an object").clone()
    }

    /// The `service_name` of an entry, or `None` if it is dropped.
    fn kept(value: &Value) -> Option<String> {
        op_log(&object(value)).map(|op_log| op_log.service_name)
    }

    #[test]
    fn the_unit_row_keeps_product_units() {
        for unit in [
            "clumit-security-roxyd.service",
            "clumit-security-a.service",
            "clumit-security-roxyd-supervisor-selftest@0f3a.service",
            "clumit-security-x@.service",
            "clumit-security-0-9.service",
            "bootroot-registrar.service",
            "roxyd-selfupdate-boot.service",
            "roxyd-selfupdate-crash.service",
            "roxyd-selfupdate-deadline.service",
        ] {
            assert_eq!(
                kept(&json!({ "_SYSTEMD_UNIT": unit })),
                Some(format!("clumit-security/unit/{unit}")),
                "{unit}"
            );
        }
    }

    #[test]
    fn the_wildcard_matches_only_its_characters() {
        for unit in [
            "clumit-security-.service",
            "clumit-security-A.service",
            "clumit-security-a.b.service",
            "clumit-security-a_b.service",
            "clumit-security-a.socket",
            "clumit-security-a.service.d",
            "Clumit-security-a.service",
            "clumit-security.service",
            "xclumit-security-a.service",
            "bootroot-registrar.socket",
            "roxyd-selfupdate-other.service",
            "user@1000.service",
            "",
        ] {
            assert_eq!(kept(&json!({ "_SYSTEMD_UNIT": unit })), None, "{unit:?}");
        }
    }

    #[test]
    fn the_systemd_row_needs_pid_1_and_a_product_unit() {
        let entry = json!({
            "_SYSTEMD_UNIT": "init.scope",
            "_PID": "1",
            "UNIT": "clumit-security-roxyd.service",
        });
        assert_eq!(
            kept(&entry),
            Some("clumit-security/systemd/clumit-security-roxyd.service".to_string())
        );
        // A trusted `_PID=1` with an allowed `UNIT` is kept without
        // `_SYSTEMD_UNIT`.
        let entry = json!({ "_PID": "1", "UNIT": "roxyd-selfupdate-boot.service" });
        assert_eq!(
            kept(&entry),
            Some("clumit-security/systemd/roxyd-selfupdate-boot.service".to_string())
        );

        for entry in [
            json!({ "_SYSTEMD_UNIT": "init.scope", "_PID": "1", "UNIT": "sshd.service" }),
            json!({ "_SYSTEMD_UNIT": "init.scope", "_PID": "2", "UNIT": "clumit-security-a.service" }),
            json!({ "_SYSTEMD_UNIT": "init.scope", "_PID": "01", "UNIT": "clumit-security-a.service" }),
            json!({ "_SYSTEMD_UNIT": "init.scope", "UNIT": "clumit-security-a.service" }),
            json!({ "_SYSTEMD_UNIT": "init.scope", "_PID": "1" }),
        ] {
            assert_eq!(kept(&entry), None, "{entry}");
        }
    }

    #[test]
    fn the_container_row_needs_docker() {
        for name in [
            "aice-web-next-app",
            "clumit-security-db",
            "clumit-security-",
        ] {
            assert_eq!(
                kept(&json!({ "_SYSTEMD_UNIT": "docker.service", "CONTAINER_NAME": name })),
                Some(format!("clumit-security/container/{name}")),
                "{name}"
            );
        }
        for entry in [
            // A forged `CONTAINER_NAME`.
            json!({ "_SYSTEMD_UNIT": "logger.service", "CONTAINER_NAME": "clumit-security-db" }),
            json!({ "CONTAINER_NAME": "clumit-security-db" }),
            // Other containers.
            json!({ "_SYSTEMD_UNIT": "docker.service", "CONTAINER_NAME": "postgres" }),
            json!({ "_SYSTEMD_UNIT": "docker.service", "CONTAINER_NAME": "aice-web-next" }),
            json!({ "_SYSTEMD_UNIT": "docker.service", "CONTAINER_NAME": "Clumit-security-db" }),
            json!({ "_SYSTEMD_UNIT": "docker.service" }),
        ] {
            assert_eq!(kept(&entry), None, "{entry}");
        }
    }

    #[test]
    fn untrusted_and_unlisted_entries_are_dropped() {
        for entry in [
            // A `logger` entry naming a product unit in its own fields.
            json!({
                "_SYSTEMD_UNIT": "session-3.scope",
                "SYSLOG_IDENTIFIER": "clumit-security-roxyd",
                "UNIT": "clumit-security-roxyd.service",
                "MESSAGE": "forged",
            }),
            // A user unit named like a product unit.
            json!({
                "_SYSTEMD_UNIT": "user@1000.service",
                "_SYSTEMD_USER_UNIT": "clumit-security-x.service",
            }),
            json!({ "_SYSTEMD_UNIT": "sshd.service" }),
            json!({ "MESSAGE": "no unit" }),
            json!({}),
        ] {
            assert_eq!(kept(&entry), None, "{entry}");
        }
    }

    #[test]
    fn selection_reads_binary_and_multi_valued_fields() {
        let binary = "clumit-security-a.service"
            .bytes()
            .map(Value::from)
            .collect::<Vec<_>>();
        assert_eq!(
            kept(&json!({ "_SYSTEMD_UNIT": binary })),
            Some("clumit-security/unit/clumit-security-a.service".to_string())
        );
        assert_eq!(
            kept(&json!({ "_SYSTEMD_UNIT": ["clumit-security-a.service", "sshd.service"] })),
            Some("clumit-security/unit/clumit-security-a.service".to_string())
        );
        assert_eq!(
            kept(&json!({ "_SYSTEMD_UNIT": ["sshd.service", "clumit-security-a.service"] })),
            None
        );
        assert_eq!(
            kept(&json!({
                "_SYSTEMD_UNIT": "docker.service",
                "CONTAINER_NAME": [binary_of("clumit-security-db"), "other"],
            })),
            Some("clumit-security/container/clumit-security-db".to_string())
        );
        assert_eq!(
            kept(&json!({ "_PID": ["1", "2"], "UNIT": "clumit-security-a.service" })),
            Some("clumit-security/systemd/clumit-security-a.service".to_string())
        );
        // Neither a string nor binary data.
        for value in [
            json!(null),
            json!(7),
            json!([256]),
            json!([{}]),
            json!(true),
        ] {
            assert_eq!(kept(&json!({ "_SYSTEMD_UNIT": value })), None, "{value}");
        }
    }

    fn binary_of(s: &str) -> Value {
        Value::from(s.bytes().map(Value::from).collect::<Vec<_>>())
    }

    fn mapped(fields: &Value) -> OpLog {
        let mut entry = object(fields);
        entry.insert(
            "_SYSTEMD_UNIT".to_string(),
            Value::from("clumit-security-a.service"),
        );
        op_log(&entry).expect("kept")
    }

    #[test]
    fn priorities_map_to_levels() {
        let level_of = |priority: Value| mapped(&json!({ "PRIORITY": priority })).log_level;
        for (priority, expected) in [
            ("0", OpLogLevel::Error),
            ("1", OpLogLevel::Error),
            ("2", OpLogLevel::Error),
            ("3", OpLogLevel::Error),
            ("4", OpLogLevel::Warn),
            ("5", OpLogLevel::Info),
            ("6", OpLogLevel::Info),
            ("7", OpLogLevel::Info),
            ("8", OpLogLevel::Info),
            ("-1", OpLogLevel::Info),
            ("x", OpLogLevel::Info),
            ("07", OpLogLevel::Info),
            ("3 ", OpLogLevel::Info),
            ("", OpLogLevel::Info),
        ] {
            assert_eq!(level_of(Value::from(priority)), expected, "{priority:?}");
        }
        assert_eq!(level_of(json!(3)), OpLogLevel::Info);
        assert_eq!(level_of(json!(null)), OpLogLevel::Info);
        // An array is read by its first value.
        assert_eq!(level_of(json!(["3", "6"])), OpLogLevel::Error);
        assert_eq!(level_of(json!([[52]])), OpLogLevel::Warn);
        let op_log = mapped(&json!({}));
        assert_eq!(op_log.log_level, OpLogLevel::Info);
    }

    #[test]
    fn messages_map_to_contents() {
        let contents_of = |message: Value| mapped(&json!({ "MESSAGE": message })).contents;
        assert_eq!(contents_of(json!("plain")), "plain");
        // Escapes a component wrote are sent as written.
        assert_eq!(contents_of(json!("a\\nb\\0c")), "a\\nb\\0c");
        assert_eq!(contents_of(json!([104, 105, 255, 0])), "hi\u{fffd}\0");
        assert_eq!(contents_of(json!(["first", "second"])), "first");
        assert_eq!(contents_of(json!([[111, 107], "second"])), "ok");
        assert_eq!(contents_of(json!(null)), "");
        assert_eq!(mapped(&json!({})).contents, "");
    }

    #[test]
    fn long_messages_are_cut_at_a_character_boundary() {
        let exact = "a".repeat(MAX_CONTENTS);
        assert_eq!(contents(exact.clone()), exact);

        let over = "a".repeat(MAX_CONTENTS + 1);
        let cut = contents(over);
        assert_eq!(cut.len(), MAX_CONTENTS);
        assert!(
            cut.ends_with(" \u{2026}[truncated]"),
            "{}",
            &cut[cut.len() - 20..]
        );
        assert_eq!(cut.len() - TRUNCATED.len(), 65_521);

        // A three-byte character across the cut is left out whole.
        let across = format!("{}\u{20ac}{}", "a".repeat(65_519), "b".repeat(100));
        let cut = contents(across);
        assert!(cut.len() <= MAX_CONTENTS);
        assert_eq!(cut, format!("{} \u{2026}[truncated]", "a".repeat(65_519)));
    }

    #[test]
    fn the_sensor_is_empty_and_names_follow_the_source() {
        let op_log = op_log(&object(&json!({
            "_SYSTEMD_UNIT": "docker.service",
            "CONTAINER_NAME": "aice-web-next-app",
            "MESSAGE": "m",
            "PRIORITY": "4",
        })))
        .expect("kept");
        assert_eq!(op_log.sensor, "");
        assert_eq!(
            op_log.service_name,
            "clumit-security/container/aice-web-next-app"
        );
        assert_eq!(op_log.log_level, OpLogLevel::Warn);
        assert_eq!(op_log.contents, "m");
    }

    #[test]
    fn lines_parse_to_positions() {
        let line = json!({
            "__CURSOR": CURSOR,
            "__REALTIME_TIMESTAMP": "1700000000000001",
            "__MONOTONIC_TIMESTAMP": "5",
            "__SEQNUM": "42",
            "__SEQNUM_ID": "0123456789abcdef0123456789abcdef",
            "_BOOT_ID": "x",
            "_SYSTEMD_UNIT": "clumit-security-a.service",
            "MESSAGE": "hello",
        })
        .to_string();
        let entry = parse(line.as_bytes()).expect("parsed");
        assert_eq!(
            entry.position,
            JournalPosition {
                cursor: CURSOR.to_string(),
                seqnum_id: Some("0123456789abcdef0123456789abcdef".to_string()),
                seqnum: Some(42),
                realtime_us: Some(1_700_000_000_000_001),
            }
        );
        let record = entry.record.expect("kept");
        let op_log: OpLog = bincode::deserialize(&record).expect("an OpLog");
        assert_eq!(op_log.contents, "hello");

        // A dropped entry still has a position.
        let line = json!({ "__CURSOR": CURSOR, "_SYSTEMD_UNIT": "sshd.service" }).to_string();
        let entry = parse(line.as_bytes()).expect("parsed");
        assert!(entry.record.is_none());
        assert_eq!(
            entry.position,
            JournalPosition {
                cursor: CURSOR.to_string(),
                seqnum_id: None,
                seqnum: None,
                realtime_us: None,
            }
        );
    }

    #[test]
    fn optional_position_fields_are_absent_when_they_do_not_parse() {
        for value in [
            json!("+5"),
            json!("-5"),
            json!("5 "),
            json!(""),
            json!("18446744073709551616"),
            json!(5),
            json!(null),
        ] {
            let line = json!({
                "__CURSOR": CURSOR,
                "__REALTIME_TIMESTAMP": value,
                "__SEQNUM": value,
                "__SEQNUM_ID": 7,
            })
            .to_string();
            let position = parse(line.as_bytes()).expect("parsed").position;
            assert_eq!(position.realtime_us, None, "{value}");
            assert_eq!(position.seqnum, None, "{value}");
            assert_eq!(position.seqnum_id, None, "{value}");
        }
        let line = json!({ "__CURSOR": CURSOR, "__SEQNUM": "18446744073709551615" }).to_string();
        assert_eq!(
            parse(line.as_bytes()).expect("parsed").position.seqnum,
            Some(u64::MAX)
        );
    }

    #[test]
    fn lines_without_an_object_or_a_cursor_do_not_parse() {
        for line in [
            &b""[..],
            b"not json",
            b"[1, 2]",
            b"\"__CURSOR\"",
            b"{\"__CURSOR\": 5}",
            b"{\"__CURSOR\": [115]}",
            b"{\"MESSAGE\": \"x\"}",
            b"{\"__CURSOR\": \"s=1\"",
        ] {
            assert!(parse(line).is_none(), "{}", String::from_utf8_lossy(line));
        }
    }
}
