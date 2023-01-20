use super::{parse_zeek_timestamp, TryFromZeekRecord};
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Serialize)]
pub(crate) struct ZeekKerberos {
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
    proto: u8,
    duration: i64,
    request_type: String,
    client: String,
    service: String,
    success: String,
    error_msg: String,
    from: i64,
    till: i64,
    cipher: String,
    forwardable: String,
    renewable: String,
    client_cert_subject: String,
    server_cert_subject: String,
}

#[allow(clippy::too_many_lines)]
impl TryFromZeekRecord for ZeekKerberos {
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
        let request_type = if let Some(request_type) = rec.get(6) {
            request_type.to_string()
        } else {
            return Err(anyhow!("missing request_type"));
        };
        let client = if let Some(client) = rec.get(7) {
            client.to_string()
        } else {
            return Err(anyhow!("missing client"));
        };
        let service = if let Some(service) = rec.get(8) {
            service.to_string()
        } else {
            return Err(anyhow!("missing service"));
        };
        let success = if let Some(success) = rec.get(9) {
            success.to_string()
        } else {
            return Err(anyhow!("missing success"));
        };
        let error_msg = if let Some(error_msg) = rec.get(10) {
            error_msg.to_string()
        } else {
            return Err(anyhow!("missing error_msg"));
        };
        let from = if let Some(from) = rec.get(11) {
            if from.eq("-") {
                0
            } else {
                parse_zeek_timestamp(from)?.timestamp_nanos()
            }
        } else {
            return Err(anyhow!("missing from"));
        };
        let till = if let Some(till) = rec.get(12) {
            if till.eq("-") {
                0
            } else {
                parse_zeek_timestamp(till)?.timestamp_nanos()
            }
        } else {
            return Err(anyhow!("missing till"));
        };
        let cipher = if let Some(cipher) = rec.get(13) {
            cipher.to_string()
        } else {
            return Err(anyhow!("missing cipher"));
        };
        let forwardable = if let Some(forwardable) = rec.get(14) {
            forwardable.to_string()
        } else {
            return Err(anyhow!("missing forwardable"));
        };
        let renewable = if let Some(renewable) = rec.get(15) {
            renewable.to_string()
        } else {
            return Err(anyhow!("missing renewable"));
        };
        let client_cert_subject = if let Some(client_cert_subject) = rec.get(16) {
            client_cert_subject.to_string()
        } else {
            return Err(anyhow!("missing client_cert_subject"));
        };
        let server_cert_subject = if let Some(server_cert_subject) = rec.get(18) {
            server_cert_subject.to_string()
        } else {
            return Err(anyhow!("missing server_cert_subject"));
        };

        Ok((
            Self {
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                proto: 0,
                duration: 0,
                request_type,
                client,
                service,
                success,
                error_msg,
                from,
                till,
                cipher,
                forwardable,
                renewable,
                client_cert_subject,
                server_cert_subject,
            },
            time,
        ))
    }
}
