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

const PROTO_TCP: u8 = 0x06;
const PROTO_UDP: u8 = 0x11;
const PROTO_ICMP: u8 = 0x01;
const DEFAULT_PORT: u16 = 0;
const DEFAULT_IPADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

#[derive(Debug, Clone)]
pub struct SecurityLogInfo {
    kind: String,
    log_type: String,
    version: String,
}

impl SecurityLogInfo {
    /// Creates a new `SecurityLogInfo` by splitting a kind string on `_`.
    ///
    /// # Panics
    ///
    /// Panics if the kind string does not contain at least three `_`-separated segments.
    #[must_use]
    pub fn new(giganto_kind: &str) -> SecurityLogInfo {
        let info: Vec<&str> = giganto_kind.split('_').collect();
        let msg =
            "verified by `match` expression in the `Producer::send_seculog_to_giganto` method.";
        SecurityLogInfo {
            kind: (*info.first().expect(msg)).to_string(),
            log_type: (*info.get(1).expect(msg)).to_string(),
            version: (*info.get(2).expect(msg)).to_string(),
        }
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

pub trait ParseSecurityLog {
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
