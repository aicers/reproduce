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
pub(crate) struct SecurityLogInfo {
    kind: String,
    log_type: String,
    version: String,
}

impl SecurityLogInfo {
    pub(crate) fn new(giganto_kind: &str) -> SecurityLogInfo {
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
pub(crate) struct Wapples;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Mf2;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SniperIps;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Aiwaf;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Tg;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Vforce;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Srx;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SonicWall;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Fgt;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ShadowWall;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Axgate;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Ubuntu;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Nginx;

pub(crate) trait ParseSecurityLog {
    fn parse_security_log(line: &str, serial: i64, info: SecurityLogInfo)
    -> Result<(SecuLog, i64)>; // agent: &str
}

fn proto_to_u8(proto: &str) -> u8 {
    match proto {
        "TCP" | "tcp" => PROTO_TCP,
        "UDP" | "udp" => PROTO_UDP,
        "ICMP" | "icmp" => PROTO_ICMP,
        _ => 0,
    }
}
