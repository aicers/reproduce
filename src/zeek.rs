mod conn;
mod dce_rpc;
mod dns;
mod http;
mod kerberos;
mod ntlm;
mod rdp;
mod smtp;
mod ssh;

pub(crate) use self::{
    conn::ZeekConn, dce_rpc::ZeekDceRpc, dns::ZeekDns, http::ZeekHttp, kerberos::ZeekKerberos,
    ntlm::ZeekNtlm, rdp::ZeekRdp, smtp::ZeekSmtp, ssh::ZeekSsh,
};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use csv::{Reader, ReaderBuilder, StringRecord};
use std::str;
use std::{fs::File, path::Path};

const PROTO_TCP: u8 = 0x06;
const PROTO_UDP: u8 = 0x11;
const PROTO_ICMP: u8 = 0x01;

pub trait TryFromZeekRecord: Sized {
    fn try_from_zeek_record(rec: &StringRecord) -> Result<(Self, i64)>;
}

fn parse_zeek_timestamp(timestamp: &str) -> Result<DateTime<Utc>> {
    if let Some(i) = timestamp.find('.') {
        let secs = timestamp[..i].parse::<i64>().context("invalid timestamp")?;
        let micros = timestamp[i + 1..]
            .parse::<u32>()
            .context("invalid timestamp")?;
        let Some(time) = NaiveDateTime::from_timestamp_opt(secs, micros * 1000) else {
            return Err(anyhow!("failed to create NaiveDateTime from timestamp"));
        };
        Ok(DateTime::<Utc>::from_utc(time, Utc))
    } else {
        Err(anyhow!("invalid timestamp: {}", timestamp))
    }
}

pub fn open_log_file(path: &Path) -> Result<Reader<File>> {
    let file = File::open(path)?;
    Ok(ReaderBuilder::new()
        .comment(Some(b'#'))
        .delimiter(b'\t')
        .from_reader(file))
}
