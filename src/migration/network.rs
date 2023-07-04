use super::{parse_giganto_timestamp, TryFromGigantoRecord};
use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::network::{
    Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Nfs, Ntlm, Rdp, Smb, Smtp, Ssh, Tls,
};
use std::net::IpAddr;

impl TryFromGigantoRecord for Conn {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let duration = if let Some(duration) = rec.get(7) {
            parse_giganto_timestamp(duration)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing duration"));
        };

        let service = if let Some(service) = rec.get(8) {
            service.to_string()
        } else {
            return Err(anyhow!("missing service"));
        };
        let orig_bytes = if let Some(orig_bytes) = rec.get(9) {
            orig_bytes.parse::<u64>().context("invalid source bytes")?
        } else {
            return Err(anyhow!("missing source bytes"));
        };
        let resp_bytes = if let Some(resp_bytes) = rec.get(10) {
            resp_bytes
                .parse::<u64>()
                .context("invalid destination bytes")?
        } else {
            return Err(anyhow!("missing destination bytes"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(11) {
            orig_pkts.parse::<u64>().context("invalid source packets")?
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(12) {
            resp_pkts
                .parse::<u64>()
                .context("invalid destination packets")?
        } else {
            return Err(anyhow!("missing destination packets"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                duration,
                service,
                orig_bytes,
                resp_bytes,
                orig_pkts,
                resp_pkts,
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
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let query = if let Some(query) = rec.get(8) {
            query.to_string()
        } else {
            return Err(anyhow!("missing query"));
        };
        let answer = if let Some(answer) = rec.get(9) {
            answer
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing answer"));
        };
        let trans_id = if let Some(trans_id) = rec.get(10) {
            trans_id.parse::<u16>().context("invalid trans_id")?
        } else {
            return Err(anyhow!("missing trans_id"));
        };
        let rtt = if let Some(rtt) = rec.get(11) {
            rtt.parse::<i64>().context("invalid rtt")?
        } else {
            return Err(anyhow!("missing rtt"));
        };
        let qclass = if let Some(qclass) = rec.get(12) {
            match qclass {
                "C_INTERNET" => 1,
                _ => 0,
            }
        } else {
            return Err(anyhow!("missing qclass"));
        };
        let qtype = if let Some(qtype) = rec.get(13) {
            parse_qtype(qtype)
        } else {
            return Err(anyhow!("missing qtype"));
        };
        let rcode = if let Some(rcode) = rec.get(14) {
            rcode.parse::<u16>().context("rcode")?
        } else {
            return Err(anyhow!("missing rcode"));
        };
        let aa_flag = if let Some(aa) = rec.get(15) {
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
        let tc_flag = if let Some(tc) = rec.get(16) {
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
        let rd_flag = if let Some(rd) = rec.get(17) {
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
        let ra_flag = if let Some(ra) = rec.get(18) {
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
        let ttl = if let Some(ttl) = rec.get(19) {
            if ttl.eq("-") {
                vec![0]
            } else {
                ttl.split(',')
                    .map(|t| t.parse::<f32>().unwrap() as i32)
                    .collect()
            }
        } else {
            return Err(anyhow!("missing ttl"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                last_time,
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
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Http {
    #[allow(clippy::too_many_lines)]
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let method = if let Some(method) = rec.get(8) {
            method.to_string()
        } else {
            return Err(anyhow!("missing method"));
        };
        let host = if let Some(host) = rec.get(9) {
            host.to_string()
        } else {
            return Err(anyhow!("missing host"));
        };
        let uri = if let Some(uri) = rec.get(10) {
            uri.to_string()
        } else {
            return Err(anyhow!("missing uri"));
        };
        let referrer = if let Some(referrer) = rec.get(11) {
            referrer.to_string()
        } else {
            return Err(anyhow!("missing referrer"));
        };
        let version = if let Some(version) = rec.get(12) {
            version.to_string()
        } else {
            return Err(anyhow!("missing version"));
        };
        let user_agent = if let Some(user_agent) = rec.get(13) {
            user_agent.to_string()
        } else {
            return Err(anyhow!("missing user_agent"));
        };
        let request_len = if let Some(request_len) = rec.get(14) {
            request_len
                .parse::<usize>()
                .context("invalid request_len")?
        } else {
            return Err(anyhow!("missing request_len"));
        };
        let response_len = if let Some(response_len) = rec.get(15) {
            response_len
                .parse::<usize>()
                .context("invalid response_len")?
        } else {
            return Err(anyhow!("missing request_len"));
        };
        let status_code = if let Some(status_code) = rec.get(16) {
            status_code.parse::<u16>().context("invalid status code")?
        } else {
            return Err(anyhow!("missing status code"));
        };
        let status_msg = if let Some(status_msg) = rec.get(17) {
            status_msg.to_string()
        } else {
            return Err(anyhow!("missing status_msg"));
        };
        let username = if let Some(username) = rec.get(18) {
            username.to_string()
        } else {
            return Err(anyhow!("missing username"));
        };
        let password = if let Some(password) = rec.get(19) {
            password.to_string()
        } else {
            return Err(anyhow!("missing password"));
        };
        let cookie = if let Some(cookie) = rec.get(20) {
            cookie.to_string()
        } else {
            return Err(anyhow!("missing cookie"));
        };
        let content_encoding = if let Some(content_encoding) = rec.get(21) {
            content_encoding.to_string()
        } else {
            return Err(anyhow!("missing content_encoding"));
        };
        let content_type = if let Some(content_type) = rec.get(22) {
            content_type.to_string()
        } else {
            return Err(anyhow!("missing content_type"));
        };
        let cache_control = if let Some(cache_control) = rec.get(23) {
            cache_control.to_string()
        } else {
            return Err(anyhow!("missing cache_control"));
        };
        let orig_filenames = if let Some(orig_filenames) = rec.get(24) {
            orig_filenames
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing orig_filenames"));
        };
        let orig_mime_types = if let Some(orig_mime_types) = rec.get(25) {
            orig_mime_types
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing orig_mime_types"));
        };
        let resp_filenames = if let Some(resp_filenames) = rec.get(26) {
            resp_filenames
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing resp_filenames"));
        };
        let resp_mime_types = if let Some(resp_mime_types) = rec.get(27) {
            resp_mime_types
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing resp_mime_types"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                last_time,
                method,
                host,
                uri,
                referrer,
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
                orig_filenames,
                orig_mime_types,
                resp_filenames,
                resp_mime_types,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Rdp {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };

        let cookie = if let Some(cookie) = rec.get(8) {
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
                last_time,
                cookie,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Smtp {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let mailfrom = if let Some(mailfrom) = rec.get(8) {
            mailfrom.to_string()
        } else {
            return Err(anyhow!("missing mailfrom"));
        };
        let date = if let Some(date) = rec.get(9) {
            date.to_string()
        } else {
            return Err(anyhow!("missing date"));
        };
        let from = if let Some(from) = rec.get(10) {
            from.to_string()
        } else {
            return Err(anyhow!("missing from"));
        };
        let to = if let Some(to) = rec.get(11) {
            to.to_string()
        } else {
            return Err(anyhow!("missing to"));
        };
        let subject = if let Some(subject) = rec.get(12) {
            subject.to_string()
        } else {
            return Err(anyhow!("missing subject"));
        };
        let agent = if let Some(agent) = rec.get(13) {
            agent.to_string()
        } else {
            return Err(anyhow!("missing agent"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                last_time,
                mailfrom,
                date,
                from,
                to,
                subject,
                agent,
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Ntlm {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let username = if let Some(username) = rec.get(8) {
            username.to_string()
        } else {
            return Err(anyhow!("missing username"));
        };
        let hostname = if let Some(hostname) = rec.get(9) {
            hostname.to_string()
        } else {
            return Err(anyhow!("missing hostname"));
        };
        let domainname = if let Some(domainname) = rec.get(10) {
            domainname.to_string()
        } else {
            return Err(anyhow!("missing domainname"));
        };
        let server_nb_computer_name = if let Some(server_nb_computer_name) = rec.get(11) {
            server_nb_computer_name.to_string()
        } else {
            return Err(anyhow!("missing server_nb_computer_name"));
        };
        let server_dns_computer_name = if let Some(server_dns_computer_name) = rec.get(12) {
            server_dns_computer_name.to_string()
        } else {
            return Err(anyhow!("missing server_dns_computer_name"));
        };
        let server_tree_name = if let Some(server_tree_name) = rec.get(13) {
            server_tree_name.to_string()
        } else {
            return Err(anyhow!("missing server_tree_name"));
        };
        let success = if let Some(success) = rec.get(14) {
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
                last_time,
                username,
                hostname,
                domainname,
                server_nb_computer_name,
                server_dns_computer_name,
                server_tree_name,
                success,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Kerberos {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let request_type = if let Some(request_type) = rec.get(8) {
            request_type.to_string()
        } else {
            return Err(anyhow!("missing request_type"));
        };
        let client = if let Some(client) = rec.get(9) {
            client.to_string()
        } else {
            return Err(anyhow!("missing client"));
        };
        let service = if let Some(service) = rec.get(10) {
            service.to_string()
        } else {
            return Err(anyhow!("missing service"));
        };
        let success = if let Some(success) = rec.get(11) {
            success.to_string()
        } else {
            return Err(anyhow!("missing success"));
        };
        let error_msg = if let Some(error_msg) = rec.get(12) {
            error_msg.to_string()
        } else {
            return Err(anyhow!("missing error_msg"));
        };
        let from = if let Some(from) = rec.get(13) {
            from.parse::<i64>().context("invalid from")?
        } else {
            return Err(anyhow!("missing from"));
        };
        let till = if let Some(till) = rec.get(14) {
            till.parse::<i64>().context("invalid from")?
        } else {
            return Err(anyhow!("missing till"));
        };
        let cipher = if let Some(cipher) = rec.get(15) {
            cipher.to_string()
        } else {
            return Err(anyhow!("missing cipher"));
        };
        let forwardable = if let Some(forwardable) = rec.get(16) {
            forwardable.to_string()
        } else {
            return Err(anyhow!("missing forwardable"));
        };
        let renewable = if let Some(renewable) = rec.get(17) {
            renewable.to_string()
        } else {
            return Err(anyhow!("missing renewable"));
        };
        let client_cert_subject = if let Some(client_cert_subject) = rec.get(18) {
            client_cert_subject.to_string()
        } else {
            return Err(anyhow!("missing client_cert_subject"));
        };
        let server_cert_subject = if let Some(server_cert_subject) = rec.get(19) {
            server_cert_subject.to_string()
        } else {
            return Err(anyhow!("missing server_cert_subject"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                last_time,
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

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Ssh {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };

        let version = if let Some(version) = rec.get(8) {
            version.parse::<i64>().context("invalid version")?
        } else {
            return Err(anyhow!("missing version"));
        };
        let auth_success = if let Some(auth_success) = rec.get(9) {
            auth_success.to_string()
        } else {
            return Err(anyhow!("missing auth_success"));
        };
        let auth_attempts = if let Some(auth_attempts) = rec.get(10) {
            auth_attempts
                .parse::<i64>()
                .context("invalid auth_attempts")?
        } else {
            return Err(anyhow!("missing auth_attempts"));
        };
        let direction = if let Some(direction) = rec.get(11) {
            direction.to_string()
        } else {
            return Err(anyhow!("missing direction"));
        };
        let client = if let Some(client) = rec.get(12) {
            client.to_string()
        } else {
            return Err(anyhow!("missing client"));
        };
        let server = if let Some(server) = rec.get(13) {
            server.to_string()
        } else {
            return Err(anyhow!("missing server"));
        };
        let cipher_alg = if let Some(cipher_alg) = rec.get(14) {
            cipher_alg.to_string()
        } else {
            return Err(anyhow!("missing cipher_alg"));
        };
        let mac_alg = if let Some(mac_alg) = rec.get(15) {
            mac_alg.to_string()
        } else {
            return Err(anyhow!("missing mac_alg"));
        };
        let compression_alg = if let Some(compression_alg) = rec.get(16) {
            compression_alg.to_string()
        } else {
            return Err(anyhow!("missing compression_alg"));
        };
        let kex_alg = if let Some(kex_alg) = rec.get(17) {
            kex_alg.to_string()
        } else {
            return Err(anyhow!("missing kex_alg"));
        };
        let host_key_alg = if let Some(host_key_alg) = rec.get(18) {
            host_key_alg.to_string()
        } else {
            return Err(anyhow!("missing host_key_alg"));
        };
        let host_key = if let Some(host_key) = rec.get(19) {
            host_key.to_string()
        } else {
            return Err(anyhow!("missing host_key"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                last_time,
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

impl TryFromGigantoRecord for DceRpc {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let rtt = if let Some(rtt) = rec.get(8) {
            rtt.parse::<i64>().context("invalid rtt")?
        } else {
            return Err(anyhow!("missing rtt"));
        };
        let named_pipe = if let Some(named_pipe) = rec.get(9) {
            named_pipe.to_string()
        } else {
            return Err(anyhow!("missing named_pipe"));
        };
        let endpoint = if let Some(endpoint) = rec.get(10) {
            endpoint.to_string()
        } else {
            return Err(anyhow!("missing endpoint"));
        };
        let operation = if let Some(operation) = rec.get(11) {
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
                last_time,
                rtt,
                named_pipe,
                endpoint,
                operation,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Ftp {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let user = if let Some(user) = rec.get(8) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let password = if let Some(password) = rec.get(9) {
            password.to_string()
        } else {
            return Err(anyhow!("missing password"));
        };
        let command = if let Some(command) = rec.get(10) {
            command.to_string()
        } else {
            return Err(anyhow!("missing command"));
        };
        let reply_code = if let Some(reply_code) = rec.get(11) {
            reply_code.to_string()
        } else {
            return Err(anyhow!("missing reply_code"));
        };
        let reply_msg = if let Some(reply_msg) = rec.get(12) {
            reply_msg.to_string()
        } else {
            return Err(anyhow!("missing reply_msg"));
        };
        let data_passive = if let Some(data_passive) = rec.get(13) {
            if data_passive.eq("true") {
                true
            } else if data_passive.eq("false") {
                false
            } else {
                return Err(anyhow!("invalid data_passive"));
            }
        } else {
            return Err(anyhow!("missing data_passive"));
        };
        let data_orig_addr = if let Some(data_orig_addr) = rec.get(14) {
            data_orig_addr
                .parse::<IpAddr>()
                .context("invalid data source address")?
        } else {
            return Err(anyhow!("missing data source address"));
        };
        let data_resp_addr = if let Some(data_resp_addr) = rec.get(15) {
            data_resp_addr
                .parse::<IpAddr>()
                .context("invalid data destination address")?
        } else {
            return Err(anyhow!("missing data destination address"));
        };
        let data_resp_port = if let Some(data_resp_port) = rec.get(16) {
            data_resp_port
                .parse::<u16>()
                .context("invalid data destination port")?
        } else {
            return Err(anyhow!("missing data destination port"));
        };
        let file = if let Some(file) = rec.get(17) {
            file.to_string()
        } else {
            return Err(anyhow!("missing file"));
        };
        let file_size = if let Some(file_size) = rec.get(18) {
            file_size.parse::<u64>().context("invalid file_size")?
        } else {
            return Err(anyhow!("missing file_size"));
        };
        let file_id = if let Some(file_id) = rec.get(19) {
            file_id.to_string()
        } else {
            return Err(anyhow!("missing file_id"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                last_time,
                user,
                password,
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
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Ldap {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let message_id = if let Some(message_id) = rec.get(8) {
            message_id.parse::<u32>().context("invalid message_id")?
        } else {
            return Err(anyhow!("missing message_id"));
        };
        let version = if let Some(version) = rec.get(9) {
            version.parse::<u8>().context("invalid version")?
        } else {
            return Err(anyhow!("missing version"));
        };
        let opcode = if let Some(opcode) = rec.get(10) {
            opcode
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing opcode"));
        };
        let result = if let Some(result) = rec.get(11) {
            result
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing result"));
        };
        let diagnostic_message = if let Some(diagnostic_message) = rec.get(12) {
            diagnostic_message
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing diagnostic_message"));
        };
        let object = if let Some(object) = rec.get(13) {
            object
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing object"));
        };
        let argument = if let Some(argument) = rec.get(14) {
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
                last_time,
                message_id,
                version,
                opcode,
                result,
                diagnostic_message,
                object,
                argument,
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Tls {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let server_name = if let Some(server_name) = rec.get(8) {
            server_name.to_string()
        } else {
            return Err(anyhow!("missing server_name"));
        };
        let alpn_protocol = if let Some(alpn_protocol) = rec.get(9) {
            alpn_protocol.to_string()
        } else {
            return Err(anyhow!("missing alpn_protocol"));
        };
        let ja3 = if let Some(ja3) = rec.get(10) {
            ja3.to_string()
        } else {
            return Err(anyhow!("missing ja3"));
        };
        let version = if let Some(version) = rec.get(11) {
            version.to_string()
        } else {
            return Err(anyhow!("missing version"));
        };
        let cipher = if let Some(cipher) = rec.get(12) {
            cipher.parse::<u16>().context("invalid cipher")?
        } else {
            return Err(anyhow!("missing cipher"));
        };
        let ja3s = if let Some(ja3s) = rec.get(13) {
            ja3s.to_string()
        } else {
            return Err(anyhow!("missing ja3s"));
        };
        let serial = if let Some(serial) = rec.get(14) {
            serial.to_string()
        } else {
            return Err(anyhow!("missing serial"));
        };
        let subject_country = if let Some(subject_country) = rec.get(15) {
            subject_country.to_string()
        } else {
            return Err(anyhow!("missing subject_country"));
        };
        let subject_org_name = if let Some(subject_org_name) = rec.get(16) {
            subject_org_name.to_string()
        } else {
            return Err(anyhow!("missing subject_org_name"));
        };
        let subject_common_name = if let Some(subject_common_name) = rec.get(17) {
            subject_common_name.to_string()
        } else {
            return Err(anyhow!("missing subject_common_name"));
        };
        let validity_not_before = if let Some(validity_not_before) = rec.get(18) {
            validity_not_before
                .parse::<i64>()
                .context("invalid validity_not_before")?
        } else {
            return Err(anyhow!("missing validity_not_before"));
        };
        let validity_not_after = if let Some(validity_not_after) = rec.get(19) {
            validity_not_after
                .parse::<i64>()
                .context("invalid validity_not_after")?
        } else {
            return Err(anyhow!("missing validity_not_after"));
        };
        let subject_alt_name = if let Some(subject_alt_name) = rec.get(20) {
            subject_alt_name.to_string()
        } else {
            return Err(anyhow!("missing subject_alt_name"));
        };
        let issuer_country = if let Some(issuer_country) = rec.get(21) {
            issuer_country.to_string()
        } else {
            return Err(anyhow!("missing issuer_country"));
        };
        let issuer_org_name = if let Some(issuer_org_name) = rec.get(22) {
            issuer_org_name.to_string()
        } else {
            return Err(anyhow!("missing issuer_org_name"));
        };
        let issuer_org_unit_name = if let Some(issuer_org_unit_name) = rec.get(23) {
            issuer_org_unit_name.to_string()
        } else {
            return Err(anyhow!("missing issuer_org_unit_name"));
        };
        let issuer_common_name = if let Some(issuer_common_name) = rec.get(24) {
            issuer_common_name.to_string()
        } else {
            return Err(anyhow!("missing issuer_common_name"));
        };
        let last_alert = if let Some(last_alert) = rec.get(25) {
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
                last_time,
                server_name,
                alpn_protocol,
                ja3,
                version,
                cipher,
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
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromGigantoRecord for Smb {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let command = if let Some(command) = rec.get(8) {
            command.parse::<u8>().context("invalid command")?
        } else {
            return Err(anyhow!("missing command"));
        };
        let path = if let Some(path) = rec.get(9) {
            path.to_string()
        } else {
            return Err(anyhow!("missing path"));
        };
        let service = if let Some(service) = rec.get(10) {
            service.to_string()
        } else {
            return Err(anyhow!("missing service"));
        };
        let file_name = if let Some(file_name) = rec.get(11) {
            file_name.to_string()
        } else {
            return Err(anyhow!("missing file_name"));
        };
        let file_size = if let Some(file_size) = rec.get(12) {
            file_size.parse::<u64>().context("invalid file_size")?
        } else {
            return Err(anyhow!("missing file_size"));
        };
        let resource_type = if let Some(resource_type) = rec.get(13) {
            resource_type
                .parse::<u16>()
                .context("invalid resource_type")?
        } else {
            return Err(anyhow!("missing resource_type"));
        };
        let fid = if let Some(fid) = rec.get(14) {
            fid.parse::<u16>().context("invalid fid")?
        } else {
            return Err(anyhow!("missing fid"));
        };
        let create_time = if let Some(create_time) = rec.get(15) {
            create_time.parse::<i64>().context("invalid create_time")?
        } else {
            return Err(anyhow!("missing create_time"));
        };
        let access_time = if let Some(access_time) = rec.get(16) {
            access_time.parse::<i64>().context("invalid access_time")?
        } else {
            return Err(anyhow!("missing access_time"));
        };
        let write_time = if let Some(write_time) = rec.get(17) {
            write_time.parse::<i64>().context("invalid write_time")?
        } else {
            return Err(anyhow!("missing write_time"));
        };
        let change_time = if let Some(change_time) = rec.get(18) {
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
                last_time,
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
            },
            time,
        ))
    }
}

impl TryFromGigantoRecord for Nfs {
    fn try_from_giganto_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_giganto_timestamp(timestamp)?.timestamp_nanos()
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
        let last_time = if let Some(last_time) = rec.get(7) {
            parse_giganto_timestamp(last_time)?.timestamp_nanos()
        } else {
            return Err(anyhow!("missing last_time"));
        };
        let read_files = if let Some(read_files) = rec.get(8) {
            read_files
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing read_files"));
        };
        let write_files = if let Some(write_files) = rec.get(9) {
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
                last_time,
                read_files,
                write_files,
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
