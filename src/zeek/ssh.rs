use super::{parse_zeek_timestamp, TryFromZeekRecord};
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Serialize)]
pub(crate) struct ZeekSsh {
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: u16,
    dst_port: u16,
    version: i64,
    auth_success: String,
    auth_attempts: i64,
    direction: String,
    client: String,
    server: String,
    cipher_alg: String,
    mac_alg: String,
    compression_alg: String,
    kex_alg: String,
    host_key_alg: String,
    host_key: String,
}

#[allow(clippy::too_many_lines)]
impl TryFromZeekRecord for ZeekSsh {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let src_addr = if let Some(src_addr) = rec.get(2) {
            src_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let src_port = if let Some(src_port) = rec.get(3) {
            src_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let dst_addr = if let Some(dst_addr) = rec.get(4) {
            dst_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let dst_port = if let Some(dst_port) = rec.get(5) {
            dst_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let version = if let Some(version) = rec.get(6) {
            if version.eq("-") {
                0
            } else {
                version.parse::<i64>().context("invalid version")?
            }
        } else {
            return Err(anyhow!("missing version"));
        };
        let auth_success = if let Some(auth_success) = rec.get(7) {
            auth_success.to_string()
        } else {
            return Err(anyhow!("missing auth_success"));
        };
        let auth_attempts = if let Some(auth_attempts) = rec.get(8) {
            if auth_attempts.eq("-") {
                0
            } else {
                auth_attempts
                    .parse::<i64>()
                    .context("invalid auth_attempts")?
            }
        } else {
            return Err(anyhow!("missing auth_attempts"));
        };
        let direction = if let Some(direction) = rec.get(9) {
            direction.to_string()
        } else {
            return Err(anyhow!("missing direction"));
        };
        let client = if let Some(client) = rec.get(10) {
            client.to_string()
        } else {
            return Err(anyhow!("missing client"));
        };
        let server = if let Some(server) = rec.get(11) {
            server.to_string()
        } else {
            return Err(anyhow!("missing server"));
        };
        let cipher_alg = if let Some(cipher_alg) = rec.get(12) {
            cipher_alg.to_string()
        } else {
            return Err(anyhow!("missing cipher_alg"));
        };
        let mac_alg = if let Some(mac_alg) = rec.get(13) {
            mac_alg.to_string()
        } else {
            return Err(anyhow!("missing mac_alg"));
        };
        let compression_alg = if let Some(compression_alg) = rec.get(14) {
            compression_alg.to_string()
        } else {
            return Err(anyhow!("missing compression_alg"));
        };
        let kex_alg = if let Some(kex_alg) = rec.get(15) {
            kex_alg.to_string()
        } else {
            return Err(anyhow!("missing kex_alg"));
        };
        let host_key_alg = if let Some(host_key_alg) = rec.get(16) {
            host_key_alg.to_string()
        } else {
            return Err(anyhow!("missing host_key_alg"));
        };
        let host_key = if let Some(host_key) = rec.get(17) {
            host_key.to_string()
        } else {
            return Err(anyhow!("missing host_key"));
        };

        Ok((
            Self {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                version,
                auth_success,
                auth_attempts,
                direction,
                client,
                server,
                cipher_alg,
                mac_alg,
                compression_alg,
                kex_alg,
                host_key_alg,
                host_key,
            },
            time,
        ))
    }
}
