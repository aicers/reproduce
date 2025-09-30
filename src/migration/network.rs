use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::network::{
    Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, FtpCommand, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Radius,
    Rdp, Smb, Smtp, Ssh, Tls,
};

use super::{
    parse_comma_separated, parse_giganto_timestamp, parse_post_body, TryFromGigantoRecord,
};

impl TryFromGigantoRecord for Conn {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let conn_state = if let Some(conn_state) = rec.get(7) {
            conn_state.to_string()
        } else {
            return Err(anyhow!("missing conn state"));
        };
        let start_time = if let Some(start_time) = rec.get(8) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(9) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(10) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let service = if let Some(service) = rec.get(11) {
            service.to_string()
        } else {
            return Err(anyhow!("missing service"));
        };
        let orig_bytes = if let Some(orig_bytes) = rec.get(12) {
            orig_bytes.parse::<u64>().context("invalid source bytes")?
        } else {
            return Err(anyhow!("missing source bytes"));
        };
        let resp_bytes = if let Some(resp_bytes) = rec.get(13) {
            resp_bytes
                .parse::<u64>()
                .context("invalid destination bytes")?
        } else {
            return Err(anyhow!("missing destination bytes"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(14) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(15) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(16) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(17) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                conn_state,
                start_time,
                end_time,
                duration,
                service,
                orig_bytes,
                resp_bytes,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Dns {
    #[allow(
        clippy::similar_names,
        clippy::cast_possible_truncation,
        clippy::too_many_lines
    )]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let query = if let Some(query) = rec.get(14) {
            query.to_string()
        } else {
            return Err(anyhow!("missing query"));
        };
        let answer = if let Some(answer) = rec.get(15) {
            answer
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing answer"));
        };
        let trans_id = if let Some(trans_id) = rec.get(16) {
            trans_id.parse::<u16>().context("invalid trans_id")?
        } else {
            return Err(anyhow!("missing trans_id"));
        };
        let rtt = if let Some(rtt) = rec.get(17) {
            rtt.parse::<i64>().context("invalid rtt")?
        } else {
            return Err(anyhow!("missing rtt"));
        };
        let qclass = if let Some(qclass) = rec.get(18) {
            match qclass {
                "C_INTERNET" => 1,
                _ => 0,
            }
        } else {
            return Err(anyhow!("missing qclass"));
        };
        let qtype = if let Some(qtype) = rec.get(19) {
            parse_qtype(qtype)
        } else {
            return Err(anyhow!("missing qtype"));
        };
        let rcode = if let Some(rcode) = rec.get(20) {
            rcode.parse::<u16>().context("rcode")?
        } else {
            return Err(anyhow!("missing rcode"));
        };
        let aa_flag = if let Some(aa) = rec.get(21) {
            if aa.eq("true") {
                true
            } else if aa.eq("false") {
                false
            } else {
                return Err(anyhow!("invalid aa_flag"));
            }
        } else {
            return Err(anyhow!("missing aa_flag"));
        };
        let tc_flag = if let Some(tc) = rec.get(22) {
            if tc.eq("true") {
                true
            } else if tc.eq("false") {
                false
            } else {
                return Err(anyhow!("invalid tc_flag"));
            }
        } else {
            return Err(anyhow!("missing tc_flag"));
        };
        let rd_flag = if let Some(rd) = rec.get(23) {
            if rd.eq("true") {
                true
            } else if rd.eq("false") {
                false
            } else {
                return Err(anyhow!("invalid rd_flag"));
            }
        } else {
            return Err(anyhow!("missing rd_flag"));
        };
        let ra_flag = if let Some(ra) = rec.get(24) {
            if ra.eq("true") {
                true
            } else if ra.eq("false") {
                false
            } else {
                return Err(anyhow!("invalid ra_flag"));
            }
        } else {
            return Err(anyhow!("missing ra_flag"));
        };

        let mut ttl = Vec::new();
        let ttl_str = rec.get(25).context("missing ttl")?;
        if ttl_str != "-" {
            for t in ttl_str.split(',') {
                ttl.push(t.parse::<i32>()?);
            }
        }

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                query,
                answer,
                trans_id,
                rtt,
                qclass,
                qtype,
                rcode,
                aa_flag,
                tc_flag,
                rd_flag,
                ra_flag,
                ttl,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Http {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let method = if let Some(method) = rec.get(14) {
            method.to_string()
        } else {
            return Err(anyhow!("missing method"));
        };
        let host = if let Some(host) = rec.get(15) {
            host.to_string()
        } else {
            return Err(anyhow!("missing host"));
        };
        let uri = if let Some(uri) = rec.get(16) {
            uri.to_string()
        } else {
            return Err(anyhow!("missing uri"));
        };
        let referer = if let Some(referer) = rec.get(17) {
            referer.to_string()
        } else {
            return Err(anyhow!("missing referer"));
        };
        let version = if let Some(version) = rec.get(18) {
            version.to_string()
        } else {
            return Err(anyhow!("missing version"));
        };
        let user_agent = if let Some(user_agent) = rec.get(19) {
            user_agent.to_string()
        } else {
            return Err(anyhow!("missing user_agent"));
        };
        let request_len = if let Some(request_len) = rec.get(20) {
            request_len
                .parse::<usize>()
                .context("invalid request_len")?
        } else {
            return Err(anyhow!("missing request_len"));
        };
        let response_len = if let Some(response_len) = rec.get(21) {
            response_len
                .parse::<usize>()
                .context("invalid response_len")?
        } else {
            return Err(anyhow!("missing response_len"));
        };
        let status_code = if let Some(status_code) = rec.get(22) {
            status_code.parse::<u16>().context("invalid status code")?
        } else {
            return Err(anyhow!("missing status code"));
        };
        let status_msg = if let Some(status_msg) = rec.get(23) {
            status_msg.to_string()
        } else {
            return Err(anyhow!("missing status_msg"));
        };
        let username = if let Some(username) = rec.get(24) {
            username.to_string()
        } else {
            return Err(anyhow!("missing username"));
        };
        let password = if let Some(password) = rec.get(25) {
            password.to_string()
        } else {
            return Err(anyhow!("missing password"));
        };
        let cookie = if let Some(cookie) = rec.get(26) {
            cookie.to_string()
        } else {
            return Err(anyhow!("missing cookie"));
        };
        let content_encoding = if let Some(content_encoding) = rec.get(27) {
            content_encoding.to_string()
        } else {
            return Err(anyhow!("missing content_encoding"));
        };
        let content_type = if let Some(content_type) = rec.get(28) {
            content_type.to_string()
        } else {
            return Err(anyhow!("missing content_type"));
        };
        let cache_control = if let Some(cache_control) = rec.get(29) {
            cache_control.to_string()
        } else {
            return Err(anyhow!("missing cache_control"));
        };
        let filenames = if let Some(filenames) = rec.get(30) {
            filenames
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing filenames"));
        };
        let mime_types = if let Some(mime_types) = rec.get(31) {
            mime_types
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing mime_types"));
        };
        let body = parse_post_body(rec.get(32).context("missing body")?);
        let state = if let Some(state) = rec.get(33) {
            state.to_string()
        } else {
            return Err(anyhow!("missing state"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                method,
                host,
                uri,
                referer,
                version,
                user_agent,
                request_len,
                response_len,
                status_code,
                status_msg,
                username,
                password,
                cookie,
                content_encoding,
                content_type,
                cache_control,
                filenames,
                mime_types,
                body,
                state,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Rdp {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };

        let cookie = if let Some(cookie) = rec.get(14) {
            cookie.to_string()
        } else {
            return Err(anyhow!("missing cookie"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                cookie,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Smtp {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let mailfrom = if let Some(mailfrom) = rec.get(14) {
            mailfrom.to_string()
        } else {
            return Err(anyhow!("missing mailfrom"));
        };
        let date = if let Some(date) = rec.get(15) {
            date.to_string()
        } else {
            return Err(anyhow!("missing date"));
        };
        let from = if let Some(from) = rec.get(16) {
            from.to_string()
        } else {
            return Err(anyhow!("missing from"));
        };
        let to = if let Some(to) = rec.get(17) {
            to.to_string()
        } else {
            return Err(anyhow!("missing to"));
        };
        let subject = if let Some(subject) = rec.get(18) {
            subject.to_string()
        } else {
            return Err(anyhow!("missing subject"));
        };
        let agent = if let Some(agent) = rec.get(19) {
            agent.to_string()
        } else {
            return Err(anyhow!("missing agent"));
        };
        let state = if let Some(state) = rec.get(20) {
            state.to_string()
        } else {
            return Err(anyhow!("missing state"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                mailfrom,
                date,
                from,
                to,
                subject,
                agent,
                state,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Ntlm {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let protocol = if let Some(protocol) = rec.get(14) {
            protocol.to_string()
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let username = if let Some(username) = rec.get(15) {
            username.to_string()
        } else {
            return Err(anyhow!("missing username"));
        };
        let hostname = if let Some(hostname) = rec.get(16) {
            hostname.to_string()
        } else {
            return Err(anyhow!("missing hostname"));
        };
        let domainname = if let Some(domainname) = rec.get(17) {
            domainname.to_string()
        } else {
            return Err(anyhow!("missing domainname"));
        };
        let success = if let Some(success) = rec.get(18) {
            success.to_string()
        } else {
            return Err(anyhow!("missing success"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                protocol,
                username,
                hostname,
                domainname,
                success,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines, clippy::similar_names)]
impl TryFromGigantoRecord for Kerberos {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let client_time = if let Some(client_time) = rec.get(14) {
            parse_giganto_timestamp(client_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing client_time"));
        };
        let server_time = if let Some(server_time) = rec.get(15) {
            parse_giganto_timestamp(server_time)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing server_time"));
        };
        let error_code = if let Some(error_code) = rec.get(16) {
            error_code.parse::<u32>().context("invalid error_code")?
        } else {
            return Err(anyhow!("missing error_code"));
        };
        let client_realm = if let Some(client_realm) = rec.get(17) {
            client_realm.to_string()
        } else {
            return Err(anyhow!("missing client_realm"));
        };
        let cname_type = if let Some(cname_type) = rec.get(18) {
            cname_type.parse::<u8>().context("invalid cname_type")?
        } else {
            return Err(anyhow!("missing cname_type"));
        };
        let client_name = if let Some(client_name) = rec.get(19) {
            client_name
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing client_name"));
        };
        let realm = if let Some(realm) = rec.get(20) {
            realm.to_string()
        } else {
            return Err(anyhow!("missing realm"));
        };
        let sname_type = if let Some(sname_type) = rec.get(21) {
            sname_type.parse::<u8>().context("invalid sname_type")?
        } else {
            return Err(anyhow!("missing sname_type"));
        };
        let service_name = if let Some(service_name) = rec.get(22) {
            service_name
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing service_name"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                client_time,
                server_time,
                error_code,
                client_realm,
                cname_type,
                client_name,
                realm,
                sname_type,
                service_name,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Ssh {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let client = if let Some(client) = rec.get(14) {
            client.to_string()
        } else {
            return Err(anyhow!("missing client"));
        };
        let server = if let Some(server) = rec.get(15) {
            server.to_string()
        } else {
            return Err(anyhow!("missing server"));
        };
        let cipher_alg = if let Some(cipher_alg) = rec.get(16) {
            cipher_alg.to_string()
        } else {
            return Err(anyhow!("missing cipher_alg"));
        };
        let mac_alg = if let Some(mac_alg) = rec.get(17) {
            mac_alg.to_string()
        } else {
            return Err(anyhow!("missing mac_alg"));
        };
        let compression_alg = if let Some(compression_alg) = rec.get(18) {
            compression_alg.to_string()
        } else {
            return Err(anyhow!("missing compression_alg"));
        };
        let kex_alg = if let Some(kex_alg) = rec.get(19) {
            kex_alg.to_string()
        } else {
            return Err(anyhow!("missing kex_alg"));
        };
        let host_key_alg = if let Some(host_key_alg) = rec.get(20) {
            host_key_alg.to_string()
        } else {
            return Err(anyhow!("missing host_key_alg"));
        };
        let hassh_algorithms = if let Some(hassh_algorithms) = rec.get(21) {
            hassh_algorithms.to_string()
        } else {
            return Err(anyhow!("missing hassh_algorithms"));
        };
        let hassh = if let Some(hassh) = rec.get(22) {
            hassh.to_string()
        } else {
            return Err(anyhow!("missing hassh"));
        };
        let hassh_server_algorithms = if let Some(hassh_server_algorithms) = rec.get(23) {
            hassh_server_algorithms.to_string()
        } else {
            return Err(anyhow!("missing hassh_server_algorithms"));
        };
        let hassh_server = if let Some(hassh_server) = rec.get(24) {
            hassh_server.to_string()
        } else {
            return Err(anyhow!("missing hassh_server"));
        };
        let client_shka = if let Some(client_shka) = rec.get(25) {
            client_shka.to_string()
        } else {
            return Err(anyhow!("missing client_shka"));
        };
        let server_shka = if let Some(server_shka) = rec.get(26) {
            server_shka.to_string()
        } else {
            return Err(anyhow!("missing server_shka"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                client,
                server,
                cipher_alg,
                mac_alg,
                compression_alg,
                kex_alg,
                host_key_alg,
                hassh_algorithms,
                hassh,
                hassh_server_algorithms,
                hassh_server,
                client_shka,
                server_shka,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for DceRpc {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let rtt = if let Some(rtt) = rec.get(14) {
            rtt.parse::<i64>().context("invalid rtt")?
        } else {
            return Err(anyhow!("missing rtt"));
        };
        let named_pipe = if let Some(named_pipe) = rec.get(15) {
            named_pipe.to_string()
        } else {
            return Err(anyhow!("missing named_pipe"));
        };
        let endpoint = if let Some(endpoint) = rec.get(16) {
            endpoint.to_string()
        } else {
            return Err(anyhow!("missing endpoint"));
        };
        let operation = if let Some(operation) = rec.get(17) {
            operation.to_string()
        } else {
            return Err(anyhow!("missing operation"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                rtt,
                named_pipe,
                endpoint,
                operation,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Ftp {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let user = if let Some(user) = rec.get(14) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let password = if let Some(password) = rec.get(15) {
            password.to_string()
        } else {
            return Err(anyhow!("missing password"));
        };

        let commands = if let Some(commands_str) = rec.get(16) {
            let tuple_parts: Vec<&str> = if commands_str.contains("),(") {
                commands_str.split("),(").collect()
            } else {
                vec![commands_str]
            };
            tuple_parts
                .into_iter()
                .map(|tuple_str| -> Result<FtpCommand> {
                    let tuple_content = tuple_str.trim_start_matches('(').trim_end_matches(')');

                    // Split first 2 fields (command, reply_code) from the front
                    let front_parts: Vec<&str> = tuple_content.splitn(3, ',').collect();
                    let command = (*front_parts
                        .first()
                        .ok_or_else(|| anyhow!("missing command"))?)
                    .to_string();
                    let reply_code = (*front_parts
                        .get(1)
                        .ok_or_else(|| anyhow!("missing reply code"))?)
                    .to_string();
                    let rest = front_parts
                        .get(2)
                        .ok_or_else(|| anyhow!("missing remaining fields"))?;

                    // Split last 7 fields from the back, leaving reply_msg in the middle
                    let back_parts: Vec<&str> = rest.rsplitn(8, ',').collect();

                    let reply_msg = (*back_parts
                        .get(7)
                        .ok_or_else(|| anyhow!("missing reply message"))?)
                    .to_string();
                    let data_passive = back_parts
                        .get(6)
                        .ok_or_else(|| anyhow!("missing data passive"))?
                        .parse::<bool>()
                        .context("invalid data passive")?;
                    let data_orig_addr = back_parts
                        .get(5)
                        .ok_or_else(|| anyhow!("missing data source address"))?
                        .parse::<IpAddr>()
                        .context("invalid data source address")?;
                    let data_resp_addr = back_parts
                        .get(4)
                        .ok_or_else(|| anyhow!("missing data response address"))?
                        .parse::<IpAddr>()
                        .context("invalid data response address")?;
                    let data_resp_port = back_parts
                        .get(3)
                        .ok_or_else(|| anyhow!("missing data response port"))?
                        .parse::<u16>()
                        .context("invalid data response port")?;
                    let file =
                        (*back_parts.get(2).ok_or_else(|| anyhow!("missing file"))?).to_string();
                    let file_size = back_parts
                        .get(1)
                        .ok_or_else(|| anyhow!("missing file size"))?
                        .parse::<u64>()
                        .context("invalid file size")?;
                    let file_id = (*back_parts
                        .first()
                        .ok_or_else(|| anyhow!("missing file ID"))?)
                    .to_string();

                    Ok(FtpCommand {
                        command,
                        reply_code,
                        reply_msg,
                        data_passive,
                        data_orig_addr,
                        data_resp_addr,
                        data_resp_port,
                        file,
                        file_size,
                        file_id,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            return Err(anyhow!("missing commands"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                user,
                password,
                commands,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Mqtt {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let protocol = if let Some(protocol) = rec.get(14) {
            protocol.to_string()
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let version = if let Some(version) = rec.get(15) {
            version.parse::<u8>().context("invalid version")?
        } else {
            return Err(anyhow!("missing version"));
        };
        let client_id = if let Some(client_id) = rec.get(16) {
            client_id.to_string()
        } else {
            return Err(anyhow!("missing client_id"));
        };
        let connack_reason = if let Some(connack_reason) = rec.get(17) {
            connack_reason
                .parse::<u8>()
                .context("invalid connack_reason")?
        } else {
            return Err(anyhow!("missing connack_reason"));
        };
        let subscribe = if let Some(subscribe) = rec.get(18) {
            subscribe
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing subscribe"));
        };
        let suback_reason = parse_comma_separated(rec.get(19).context("missing suback_reason")?)
            .context("invalid suback_reason")?;

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                protocol,
                version,
                client_id,
                connack_reason,
                subscribe,
                suback_reason,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Ldap {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let message_id = if let Some(message_id) = rec.get(14) {
            message_id.parse::<u32>().context("invalid message_id")?
        } else {
            return Err(anyhow!("missing message_id"));
        };
        let version = if let Some(version) = rec.get(15) {
            version.parse::<u8>().context("invalid version")?
        } else {
            return Err(anyhow!("missing version"));
        };
        let opcode = if let Some(opcode) = rec.get(16) {
            opcode
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing opcode"));
        };
        let result = if let Some(result) = rec.get(17) {
            result
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing result"));
        };
        let diagnostic_message = if let Some(diagnostic_message) = rec.get(18) {
            diagnostic_message
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing diagnostic_message"));
        };
        let object = if let Some(object) = rec.get(19) {
            object
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing object"));
        };
        let argument = if let Some(argument) = rec.get(20) {
            argument
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing argument"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                message_id,
                version,
                opcode,
                result,
                diagnostic_message,
                object,
                argument,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Tls {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let server_name = if let Some(server_name) = rec.get(14) {
            server_name.to_string()
        } else {
            return Err(anyhow!("missing server_name"));
        };
        let alpn_protocol = if let Some(alpn_protocol) = rec.get(15) {
            alpn_protocol.to_string()
        } else {
            return Err(anyhow!("missing alpn_protocol"));
        };
        let ja3 = if let Some(ja3) = rec.get(16) {
            ja3.to_string()
        } else {
            return Err(anyhow!("missing ja3"));
        };
        let version = if let Some(version) = rec.get(17) {
            version.to_string()
        } else {
            return Err(anyhow!("missing version"));
        };

        let client_cipher_suites =
            parse_comma_separated(rec.get(18).context("missing client_cipher_suites")?)
                .context("invalid client_cipher_suites")?;

        let client_extensions =
            parse_comma_separated(rec.get(19).context("missing client_extensions")?)
                .context("invalid client_extensions")?;

        let cipher = if let Some(cipher) = rec.get(20) {
            cipher.parse::<u16>().context("invalid cipher")?
        } else {
            return Err(anyhow!("missing cipher"));
        };

        let extensions = parse_comma_separated(rec.get(21).context("missing extensions")?)
            .context("invalid extensions")?;

        let ja3s = if let Some(ja3s) = rec.get(22) {
            ja3s.to_string()
        } else {
            return Err(anyhow!("missing ja3s"));
        };
        let serial = if let Some(serial) = rec.get(23) {
            serial.to_string()
        } else {
            return Err(anyhow!("missing serial"));
        };
        let subject_country = if let Some(subject_country) = rec.get(24) {
            subject_country.to_string()
        } else {
            return Err(anyhow!("missing subject_country"));
        };
        let subject_org_name = if let Some(subject_org_name) = rec.get(25) {
            subject_org_name.to_string()
        } else {
            return Err(anyhow!("missing subject_org_name"));
        };
        let subject_common_name = if let Some(subject_common_name) = rec.get(26) {
            subject_common_name.to_string()
        } else {
            return Err(anyhow!("missing subject_common_name"));
        };
        let validity_not_before = if let Some(validity_not_before) = rec.get(27) {
            validity_not_before
                .parse::<i64>()
                .context("invalid validity_not_before")?
        } else {
            return Err(anyhow!("missing validity_not_before"));
        };
        let validity_not_after = if let Some(validity_not_after) = rec.get(28) {
            validity_not_after
                .parse::<i64>()
                .context("invalid validity_not_after")?
        } else {
            return Err(anyhow!("missing validity_not_after"));
        };
        let subject_alt_name = if let Some(subject_alt_name) = rec.get(29) {
            subject_alt_name.to_string()
        } else {
            return Err(anyhow!("missing subject_alt_name"));
        };
        let issuer_country = if let Some(issuer_country) = rec.get(30) {
            issuer_country.to_string()
        } else {
            return Err(anyhow!("missing issuer_country"));
        };
        let issuer_org_name = if let Some(issuer_org_name) = rec.get(31) {
            issuer_org_name.to_string()
        } else {
            return Err(anyhow!("missing issuer_org_name"));
        };
        let issuer_org_unit_name = if let Some(issuer_org_unit_name) = rec.get(32) {
            issuer_org_unit_name.to_string()
        } else {
            return Err(anyhow!("missing issuer_org_unit_name"));
        };
        let issuer_common_name = if let Some(issuer_common_name) = rec.get(33) {
            issuer_common_name.to_string()
        } else {
            return Err(anyhow!("missing issuer_common_name"));
        };
        let last_alert = if let Some(last_alert) = rec.get(34) {
            last_alert.parse::<u8>().context("invalid last_alert")?
        } else {
            return Err(anyhow!("missing last_alert"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                server_name,
                alpn_protocol,
                ja3,
                version,
                client_cipher_suites,
                client_extensions,
                cipher,
                extensions,
                ja3s,
                serial,
                subject_country,
                subject_org_name,
                subject_common_name,
                validity_not_before,
                validity_not_after,
                subject_alt_name,
                issuer_country,
                issuer_org_name,
                issuer_org_unit_name,
                issuer_common_name,
                last_alert,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Smb {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let command = if let Some(command) = rec.get(14) {
            command.parse::<u8>().context("invalid command")?
        } else {
            return Err(anyhow!("missing command"));
        };
        let path = if let Some(path) = rec.get(15) {
            path.to_string()
        } else {
            return Err(anyhow!("missing path"));
        };
        let service = if let Some(service) = rec.get(16) {
            service.to_string()
        } else {
            return Err(anyhow!("missing service"));
        };
        let file_name = if let Some(file_name) = rec.get(17) {
            file_name.to_string()
        } else {
            return Err(anyhow!("missing file_name"));
        };
        let file_size = if let Some(file_size) = rec.get(18) {
            file_size.parse::<u64>().context("invalid file_size")?
        } else {
            return Err(anyhow!("missing file_size"));
        };
        let resource_type = if let Some(resource_type) = rec.get(19) {
            resource_type
                .parse::<u16>()
                .context("invalid resource_type")?
        } else {
            return Err(anyhow!("missing resource_type"));
        };
        let fid = if let Some(fid) = rec.get(20) {
            fid.parse::<u16>().context("invalid fid")?
        } else {
            return Err(anyhow!("missing fid"));
        };
        let create_time = if let Some(create_time) = rec.get(21) {
            create_time.parse::<i64>().context("invalid create_time")?
        } else {
            return Err(anyhow!("missing create_time"));
        };
        let access_time = if let Some(access_time) = rec.get(22) {
            access_time.parse::<i64>().context("invalid access_time")?
        } else {
            return Err(anyhow!("missing access_time"));
        };
        let write_time = if let Some(write_time) = rec.get(23) {
            write_time.parse::<i64>().context("invalid write_time")?
        } else {
            return Err(anyhow!("missing write_time"));
        };
        let change_time = if let Some(change_time) = rec.get(24) {
            change_time.parse::<i64>().context("invalid change_time")?
        } else {
            return Err(anyhow!("missing change_time"));
        };
        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                command,
                path,
                service,
                file_name,
                file_size,
                resource_type,
                fid,
                create_time,
                access_time,
                write_time,
                change_time,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Nfs {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let read_files = if let Some(read_files) = rec.get(14) {
            read_files
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing read_files"));
        };
        let write_files = if let Some(write_files) = rec.get(15) {
            write_files
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing write_files"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                read_files,
                write_files,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Bootp {
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let op = if let Some(op) = rec.get(14) {
            op.parse::<u8>().context("invalid op")?
        } else {
            return Err(anyhow!("missing op"));
        };
        let htype = if let Some(htype) = rec.get(15) {
            htype.parse::<u8>().context("invalid htype")?
        } else {
            return Err(anyhow!("missing htype"));
        };
        let hops = if let Some(hops) = rec.get(16) {
            hops.parse::<u8>().context("invalid hops")?
        } else {
            return Err(anyhow!("missing hops"));
        };
        let xid = if let Some(xid) = rec.get(17) {
            xid.parse::<u32>().context("invalid xid")?
        } else {
            return Err(anyhow!("missing xid"));
        };
        let ciaddr = if let Some(ciaddr) = rec.get(18) {
            ciaddr.parse::<IpAddr>().context("invalid ciaddr")?
        } else {
            return Err(anyhow!("missing ciaddr"));
        };
        let yiaddr = if let Some(yiaddr) = rec.get(19) {
            yiaddr.parse::<IpAddr>().context("invalid yiaddr")?
        } else {
            return Err(anyhow!("missing yiaddr"));
        };
        let siaddr = if let Some(siaddr) = rec.get(20) {
            siaddr.parse::<IpAddr>().context("invalid siaddr")?
        } else {
            return Err(anyhow!("missing siaddr"));
        };
        let giaddr = if let Some(giaddr) = rec.get(21) {
            giaddr.parse::<IpAddr>().context("invalid giaddr")?
        } else {
            return Err(anyhow!("missing giaddr"));
        };

        let chaddr = parse_comma_separated(rec.get(22).context("missing chaddr")?)
            .context("invalid chaddr")?;

        let sname = if let Some(sname) = rec.get(23) {
            sname.to_string()
        } else {
            return Err(anyhow!("missing sname"));
        };
        let file = if let Some(file) = rec.get(24) {
            file.to_string()
        } else {
            return Err(anyhow!("missing file"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                op,
                htype,
                hops,
                xid,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                chaddr,
                sname,
                file,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Dhcp {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let msg_type = if let Some(msg_type) = rec.get(14) {
            msg_type.parse::<u8>().context("invalid msg_type")?
        } else {
            return Err(anyhow!("missing msg_type"));
        };

        let ciaddr = if let Some(ciaddr) = rec.get(15) {
            ciaddr.parse::<IpAddr>().context("invalid ciaddr")?
        } else {
            return Err(anyhow!("missing ciaddr"));
        };
        let yiaddr = if let Some(yiaddr) = rec.get(16) {
            yiaddr.parse::<IpAddr>().context("invalid yiaddr")?
        } else {
            return Err(anyhow!("missing yiaddr"));
        };
        let siaddr = if let Some(siaddr) = rec.get(17) {
            siaddr.parse::<IpAddr>().context("invalid siaddr")?
        } else {
            return Err(anyhow!("missing siaddr"));
        };
        let giaddr = if let Some(giaddr) = rec.get(18) {
            giaddr.parse::<IpAddr>().context("invalid giaddr")?
        } else {
            return Err(anyhow!("missing giaddr"));
        };
        let subnet_mask = if let Some(subnet_mask) = rec.get(19) {
            subnet_mask
                .parse::<IpAddr>()
                .context("invalid subnet_mask")?
        } else {
            return Err(anyhow!("missing subnet_mask"));
        };

        let router = parse_comma_separated(rec.get(20).context("missing router")?)
            .context("invalid router")?;

        let domain_name_server =
            parse_comma_separated(rec.get(21).context("missing domain_name_server")?)
                .context("invalid domain_name_server")?;

        let req_ip_addr = if let Some(req_ip_addr) = rec.get(22) {
            req_ip_addr
                .parse::<IpAddr>()
                .context("invalid req_ip_addr")?
        } else {
            return Err(anyhow!("missing req_ip_addr"));
        };
        let lease_time = if let Some(lease_time) = rec.get(23) {
            lease_time.parse::<u32>().context("invalid lease_time")?
        } else {
            return Err(anyhow!("missing lease_time"));
        };
        let server_id = if let Some(server_id) = rec.get(24) {
            server_id.parse::<IpAddr>().context("invalid server_id")?
        } else {
            return Err(anyhow!("missing server_id"));
        };

        let param_req_list = parse_comma_separated(rec.get(25).context("missing param_req_list")?)
            .context("invalid param_req_list")?;

        let message = if let Some(message) = rec.get(26) {
            message.to_string()
        } else {
            return Err(anyhow!("missing message"));
        };
        let renewal_time = if let Some(renewal_time) = rec.get(27) {
            renewal_time
                .parse::<u32>()
                .context("invalid renewal_time")?
        } else {
            return Err(anyhow!("missing renewal_time"));
        };
        let rebinding_time = if let Some(rebinding_time) = rec.get(28) {
            rebinding_time
                .parse::<u32>()
                .context("invalid rebinding_time")?
        } else {
            return Err(anyhow!("missing rebinding_time"));
        };

        let class_id = parse_comma_separated(rec.get(29).context("missing class_id")?)
            .context("invalid class_id")?;

        let client_id_type = if let Some(client_id_type) = rec.get(30) {
            client_id_type
                .parse::<u8>()
                .context("invalid client_id_type")?
        } else {
            return Err(anyhow!("missing client_id_type"));
        };
        let client_id = parse_comma_separated(rec.get(31).context("missing client_id")?)
            .context("invalid client_id")?;

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                end_time,
                duration,
                msg_type,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                subnet_mask,
                router,
                domain_name_server,
                req_ip_addr,
                lease_time,
                server_id,
                param_req_list,
                message,
                renewal_time,
                rebinding_time,
                class_id,
                client_id_type,
                client_id,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}

fn parse_qtype(qtype: &str) -> u16 {
    match qtype {
        "A" => 1,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "WKS" => 11,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "NSAP" => 22,
        "NSAP-PTR" => 23,
        "SIG" => 24,
        "KEY" => 25,
        "PX" => 26,
        "GPOS" => 27,
        "AAAA" => 28,
        "LOC" => 29,
        "NXT" => 30,
        "EID" => 31,
        "NIMLOC" => 32,
        "SRV" => 33,
        "ATMA" => 34,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "A6" => 38,
        "DNAME" => 39,
        "SINK" => 40,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC50" => 50,
        "NSEC52PARAM" => 51,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "HIP" => 55,
        "NINFO" => 56,
        "RKEY" => 57,
        "TALINK" => 58,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        _ => 0,
    }
}

impl TryFromGigantoRecord for Radius {
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?
                .timestamp_nanos_opt()
                .context("to_timestamp_nanos")?
        } else {
            return Err(anyhow!("missing timestamp"));
        };
        let orig_addr = if let Some(orig_addr) = rec.get(2) {
            orig_addr
                .parse::<IpAddr>()
                .context("invalid source address")?
        } else {
            return Err(anyhow!("missing source address"));
        };
        let orig_port = if let Some(orig_port) = rec.get(3) {
            orig_port.parse::<u16>().context("invalid source port")?
        } else {
            return Err(anyhow!("missing source port"));
        };
        let resp_addr = if let Some(resp_addr) = rec.get(4) {
            resp_addr
                .parse::<IpAddr>()
                .context("invalid destination address")?
        } else {
            return Err(anyhow!("missing destination address"));
        };
        let resp_port = if let Some(resp_port) = rec.get(5) {
            resp_port
                .parse::<u16>()
                .context("invalid destination port")?
        } else {
            return Err(anyhow!("missing destination port"));
        };
        let proto = if let Some(proto) = rec.get(6) {
            proto.parse::<u8>().context("invalid proto")?
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let start_time = if let Some(start_time) = rec.get(7) {
            parse_giganto_timestamp(start_time)?
        } else {
            return Err(anyhow!("missing start_time"));
        };
        let end_time = if let Some(end_time) = rec.get(8) {
            parse_giganto_timestamp(end_time)?
        } else {
            return Err(anyhow!("missing end_time"));
        };
        let duration = if let Some(duration) = rec.get(9) {
            duration.parse::<i64>().context("invalid duration")?
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(10) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(11) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };
        let orig_l2_bytes = if let Some(orig_l2_bytes) = rec.get(12) {
            orig_l2_bytes
                .parse::<u64>()
                .context("invalid source l2 bytes")?
        } else {
            return Err(anyhow!("missing source l2 bytes"));
        };
        let resp_l2_bytes = if let Some(resp_l2_bytes) = rec.get(13) {
            resp_l2_bytes
                .parse::<u64>()
                .context("invalid destination l2 bytes")?
        } else {
            return Err(anyhow!("missing destination l2 bytes"));
        };
        let id = if let Some(id) = rec.get(14) {
            id.parse::<u8>().context("invalid id")?
        } else {
            return Err(anyhow!("missing id"));
        };
        let code = if let Some(code) = rec.get(15) {
            code.parse::<u8>().context("invalid code")?
        } else {
            return Err(anyhow!("missing code"));
        };
        let resp_code = if let Some(resp_code) = rec.get(16) {
            resp_code.parse::<u8>().context("invalid resp_code")?
        } else {
            return Err(anyhow!("missing resp_code"));
        };
        let auth = if let Some(auth) = rec.get(17) {
            auth.to_string()
        } else {
            return Err(anyhow!("missing auth"));
        };
        let resp_auth = if let Some(resp_auth) = rec.get(18) {
            resp_auth.to_string()
        } else {
            return Err(anyhow!("missing resp_auth"));
        };
        let user_name = parse_comma_separated(rec.get(19).context("missing user_name")?)
            .context("invalid user_name")?;
        let user_passwd = parse_comma_separated(rec.get(20).context("missing user_passwd")?)
            .context("invalid user_passwd")?;
        let chap_passwd = parse_comma_separated(rec.get(21).context("missing chap_passwd")?)
            .context("invalid chap_passwd")?;
        let nas_ip = if let Some(nas_ip) = rec.get(22) {
            nas_ip.parse::<IpAddr>().context("invalid nas_ip")?
        } else {
            return Err(anyhow!("missing nas_ip"));
        };
        let nas_port = if let Some(nas_port) = rec.get(23) {
            nas_port.parse::<u32>().context("invalid nas_port")?
        } else {
            return Err(anyhow!("missing nas_port"));
        };
        let state = parse_comma_separated(rec.get(24).context("missing state")?)
            .context("invalid state")?;
        let nas_id = parse_comma_separated(rec.get(25).context("missing nas_id")?)
            .context("invalid nas_id")?;
        let nas_port_type = if let Some(nas_port_type) = rec.get(26) {
            nas_port_type
                .parse::<u32>()
                .context("invalid nas_port_type")?
        } else {
            return Err(anyhow!("missing nas_port_type"));
        };
        let message = if let Some(message) = rec.get(27) {
            message.to_string()
        } else {
            return Err(anyhow!("missing message"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                end_time,
                start_time,
                duration,
                id,
                code,
                resp_code,
                auth,
                resp_auth,
                user_name,
                user_passwd,
                chap_passwd,
                nas_ip,
                nas_port,
                state,
                nas_id,
                nas_port_type,
                message,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
            },
            time,
        ))
    }
}
