#![allow(clippy::module_name_repetitions)]

mod aiwaf;
mod axgate;
mod fgt;
mod mf2;
mod nginx;
mod shadow_wall;
mod sniper_ips;
mod sonic_wall;
mod srx;
mod tg;
mod ubuntu;
mod vforce;
mod wapples;

use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use giganto_client::ingest::log::SecuLog;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const PROTO_TCP: u8 = 0x06;
const PROTO_UDP: u8 = 0x11;
const PROTO_ICMP: u8 = 0x01;
const DEFAULT_PORT: u16 = 0;
const DEFAULT_IPADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

#[derive(Debug, Clone)]
pub(crate) struct SecurityLogInfo {
    kind: String,
    log_type: String,
    version: String,
}

#[derive(Debug, Error)]
pub(crate) enum SecurityLogInfoError {
    #[error("security log kind must contain at least three '_' separated segments: {kind}")]
    InvalidKind { kind: String },
}

impl SecurityLogInfo {
    /// Creates a new `SecurityLogInfo` by splitting a kind string on `_`.
    ///
    /// # Errors
    ///
    /// Returns an error if the kind string does not contain at least three
    /// `_`-separated segments.
    pub(crate) fn try_new(
        giganto_kind: &str,
    ) -> std::result::Result<SecurityLogInfo, SecurityLogInfoError> {
        let mut parts = giganto_kind.splitn(3, '_');
        let Some(kind) = parts.next() else {
            return Err(SecurityLogInfoError::InvalidKind {
                kind: giganto_kind.to_string(),
            });
        };
        let Some(log_type) = parts.next() else {
            return Err(SecurityLogInfoError::InvalidKind {
                kind: giganto_kind.to_string(),
            });
        };
        let Some(version) = parts.next() else {
            return Err(SecurityLogInfoError::InvalidKind {
                kind: giganto_kind.to_string(),
            });
        };

        Ok(SecurityLogInfo {
            kind: kind.to_string(),
            log_type: log_type.to_string(),
            version: version.to_string(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Wapples;

#[derive(Debug, Serialize, Deserialize)]
pub struct Mf2;

#[derive(Debug, Serialize, Deserialize)]
pub struct SniperIps;

#[derive(Debug, Serialize, Deserialize)]
pub struct Aiwaf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Tg;

#[derive(Debug, Serialize, Deserialize)]
pub struct Vforce;

#[derive(Debug, Serialize, Deserialize)]
pub struct Srx;

#[derive(Debug, Serialize, Deserialize)]
pub struct SonicWall;

#[derive(Debug, Serialize, Deserialize)]
pub struct Fgt;

#[derive(Debug, Serialize, Deserialize)]
pub struct ShadowWall;

#[derive(Debug, Serialize, Deserialize)]
pub struct Axgate;

#[derive(Debug, Serialize, Deserialize)]
pub struct Ubuntu;

#[derive(Debug, Serialize, Deserialize)]
pub struct Nginx;

pub(crate) trait ParseSecurityLog {
    /// Parses a security log line into a `SecuLog` record with a timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if the log line cannot be parsed.
    fn parse_security_log(line: &str, serial: i64, info: SecurityLogInfo)
    -> Result<(SecuLog, i64)>;
}

fn proto_to_u8(proto: &str) -> u8 {
    match proto {
        "TCP" | "tcp" => PROTO_TCP,
        "UDP" | "udp" => PROTO_UDP,
        "ICMP" | "icmp" => PROTO_ICMP,
        _ => 0,
    }
}
