use super::{parse_zeek_timestamp, TryFromZeekRecord, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::network::{Conn, DceRpc, Dns, Http, Kerberos, Ntlm, Rdp, Smtp, Ssh};
use num_traits::ToPrimitive;
use std::net::IpAddr;

impl TryFromZeekRecord for Conn {
    #[allow(clippy::too_many_lines)]
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
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
            match proto {
                "tcp" => PROTO_TCP,
                "udp" => PROTO_UDP,
                "icmp" => PROTO_ICMP,
                _ => 0,
            }
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let service = if let Some(service) = rec.get(7) {
            service.to_string()
        } else {
            return Err(anyhow!("missing service"));
        };
        let duration = if let Some(duration) = rec.get(8) {
            if duration.eq("-") {
                0
            } else {
                ((duration.parse::<f64>().context("invalid duration")? * 1_000_000_000.0).round())
                    .to_i64()
                    .expect("valid")
            }
        } else {
            return Err(anyhow!("missing duration"));
        };
        let orig_bytes = if let Some(orig_bytes) = rec.get(9) {
            if orig_bytes.eq("-") {
                0
            } else {
                orig_bytes.parse::<u64>().context("invalid source bytes")?
            }
        } else {
            return Err(anyhow!("missing source bytes"));
        };
        let resp_bytes = if let Some(resp_bytes) = rec.get(10) {
            if resp_bytes.eq("-") {
                0
            } else {
                resp_bytes
                    .parse::<u64>()
                    .context("invalid destination bytes")?
            }
        } else {
            return Err(anyhow!("missing destination bytes"));
        };
        let orig_pkts = if let Some(orig_pkts) = rec.get(16) {
            if orig_pkts.eq("-") {
                0
            } else {
                orig_pkts.parse::<u64>().context("invalid source packets")?
            }
        } else {
            return Err(anyhow!("missing source packets"));
        };
        let resp_pkts = if let Some(resp_pkts) = rec.get(18) {
            if resp_pkts.eq("-") {
                0
            } else {
                resp_pkts
                    .parse::<u64>()
                    .context("invalid destination packets")?
            }
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

impl TryFromZeekRecord for Dns {
    #[allow(
        clippy::similar_names,
        clippy::cast_possible_truncation,
        clippy::too_many_lines
    )]
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
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
            match proto {
                "tcp" => PROTO_TCP,
                "udp" => PROTO_UDP,
                "icmp" => PROTO_ICMP,
                _ => 0,
            }
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let query = if let Some(query) = rec.get(9) {
            query.to_string()
        } else {
            return Err(anyhow!("missing query"));
        };
        let answer = if let Some(answer) = rec.get(21) {
            answer
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing answer"));
        };
        let trans_id = if let Some(trans_id) = rec.get(7) {
            if trans_id.eq("-") {
                0
            } else {
                trans_id.parse::<u16>().context("invalid trans_id")?
            }
        } else {
            return Err(anyhow!("missing trans_id"));
        };
        let rtt = if let Some(rtt) = rec.get(8) {
            if rtt.eq("-") {
                0
            } else {
                parse_zeek_timestamp(rtt)?.timestamp_nanos()
            }
        } else {
            return Err(anyhow!("missing rtt"));
        };
        let qclass = if let Some(qclass) = rec.get(10) {
            if qclass.eq("-") {
                0
            } else {
                qclass.parse::<u16>().context("invalid qclass")?
            }
        } else {
            return Err(anyhow!("missing qclass"));
        };
        let qtype = if let Some(qtype) = rec.get(12) {
            if qtype.eq("-") {
                0
            } else {
                qtype.parse::<u16>().context("invalid qtype")?
            }
        } else {
            return Err(anyhow!("missing qtype"));
        };
        let rcode = if let Some(rcode) = rec.get(14) {
            if rcode.eq("-") {
                0
            } else {
                rcode.parse::<u16>().context("rcode")?
            }
        } else {
            return Err(anyhow!("missing rcode"));
        };
        let aa_flag = if let Some(aa) = rec.get(16) {
            if aa.eq("T") {
                true
            } else if aa.eq("F") {
                false
            } else {
                return Err(anyhow!("invalid aa_flag"));
            }
        } else {
            return Err(anyhow!("missing aa_flag"));
        };
        let tc_flag = if let Some(tc) = rec.get(17) {
            if tc.eq("T") {
                true
            } else if tc.eq("F") {
                false
            } else {
                return Err(anyhow!("invalid tc_flag"));
            }
        } else {
            return Err(anyhow!("missing tc_flag"));
        };
        let rd_flag = if let Some(rd) = rec.get(18) {
            if rd.eq("T") {
                true
            } else if rd.eq("F") {
                false
            } else {
                return Err(anyhow!("invalid rd_flag"));
            }
        } else {
            return Err(anyhow!("missing rd_flag"));
        };
        let ra_flag = if let Some(ra) = rec.get(19) {
            if ra.eq("T") {
                true
            } else if ra.eq("F") {
                false
            } else {
                return Err(anyhow!("invalid ra_flag"));
            }
        } else {
            return Err(anyhow!("missing ra_flag"));
        };
        let ttl = if let Some(ttl) = rec.get(22) {
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
                duration: rtt,
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

impl TryFromZeekRecord for Http {
    #[allow(clippy::too_many_lines)]
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
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
        let method = if let Some(method) = rec.get(7) {
            method.to_string()
        } else {
            return Err(anyhow!("missing method"));
        };
        let host = if let Some(host) = rec.get(8) {
            host.to_string()
        } else {
            return Err(anyhow!("missing host"));
        };
        let uri = if let Some(uri) = rec.get(9) {
            uri.to_string()
        } else {
            return Err(anyhow!("missing uri"));
        };
        let referrer = if let Some(referrer) = rec.get(10) {
            referrer.to_string()
        } else {
            return Err(anyhow!("missing referrer"));
        };
        let version = if let Some(version) = rec.get(11) {
            version.to_string()
        } else {
            return Err(anyhow!("missing version"));
        };
        let user_agent = if let Some(user_agent) = rec.get(12) {
            user_agent.to_string()
        } else {
            return Err(anyhow!("missing user_agent"));
        };
        let request_len = if let Some(request_len) = rec.get(14) {
            if request_len.eq("-") {
                0
            } else {
                request_len
                    .parse::<usize>()
                    .context("invalid request_len")?
            }
        } else {
            return Err(anyhow!("missing request_len"));
        };
        let response_len = if let Some(response_len) = rec.get(15) {
            if response_len.eq("-") {
                0
            } else {
                response_len
                    .parse::<usize>()
                    .context("invalid response_len")?
            }
        } else {
            return Err(anyhow!("missing request_len"));
        };
        let status_code = if let Some(status_code) = rec.get(16) {
            if status_code.eq("-") {
                0
            } else {
                status_code.parse::<u16>().context("invalid status code")?
            }
        } else {
            return Err(anyhow!("missing status code"));
        };
        let status_msg = if let Some(status_msg) = rec.get(17) {
            status_msg.to_string()
        } else {
            return Err(anyhow!("missing status_msg"));
        };
        let username = if let Some(username) = rec.get(21) {
            username.to_string()
        } else {
            return Err(anyhow!("missing username"));
        };
        let password = if let Some(password) = rec.get(22) {
            password.to_string()
        } else {
            return Err(anyhow!("missing password"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto: 0,
                duration: 0,
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
                cookie: String::from("-"),
                content_encoding: String::from("-"),
                content_type: String::from("-"),
                cache_control: String::from("-"),
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromZeekRecord for Kerberos {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
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
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
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

impl TryFromZeekRecord for Ntlm {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
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
        let username = if let Some(username) = rec.get(6) {
            username.to_string()
        } else {
            return Err(anyhow!("missing username"));
        };
        let hostname = if let Some(hostname) = rec.get(7) {
            hostname.to_string()
        } else {
            return Err(anyhow!("missing hostname"));
        };
        let domainname = if let Some(domainname) = rec.get(8) {
            domainname.to_string()
        } else {
            return Err(anyhow!("missing domainname"));
        };
        let server_nb_computer_name = if let Some(server_nb_computer_name) = rec.get(9) {
            server_nb_computer_name.to_string()
        } else {
            return Err(anyhow!("missing server_nb_computer_name"));
        };
        let server_dns_computer_name = if let Some(server_dns_computer_name) = rec.get(10) {
            server_dns_computer_name.to_string()
        } else {
            return Err(anyhow!("missing server_dns_computer_name"));
        };
        let server_tree_name = if let Some(server_tree_name) = rec.get(11) {
            server_tree_name.to_string()
        } else {
            return Err(anyhow!("missing server_tree_name"));
        };
        let success = if let Some(success) = rec.get(12) {
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
                proto: 0,
                duration: 0,
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

impl TryFromZeekRecord for Rdp {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
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
        let cookie = if let Some(cookie) = rec.get(6) {
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
                proto: 0,
                duration: 0,
                cookie,
            },
            time,
        ))
    }
}

impl TryFromZeekRecord for Smtp {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
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
        let mailfrom = if let Some(mailfrom) = rec.get(8) {
            mailfrom.to_string()
        } else {
            return Err(anyhow!("missing mailfrom"));
        };
        let date = if let Some(date) = rec.get(10) {
            date.to_string()
        } else {
            return Err(anyhow!("missing date"));
        };
        let from = if let Some(from) = rec.get(11) {
            from.to_string()
        } else {
            return Err(anyhow!("missing from"));
        };
        let to = if let Some(to) = rec.get(12) {
            to.to_string()
        } else {
            return Err(anyhow!("missing to"));
        };
        let subject = if let Some(subject) = rec.get(17) {
            subject.to_string()
        } else {
            return Err(anyhow!("missing subject"));
        };
        let agent = if let Some(agent) = rec.get(23) {
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
                proto: 0,
                duration: 0,
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

#[allow(clippy::too_many_lines)]
impl TryFromZeekRecord for Ssh {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
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
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto: 0,
                duration: 0,
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

impl TryFromZeekRecord for DceRpc {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?.timestamp_nanos()
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
        let rtt = if let Some(rtt) = rec.get(6) {
            if rtt.eq("-") {
                0
            } else {
                parse_zeek_timestamp(rtt)?.timestamp_nanos()
            }
        } else {
            return Err(anyhow!("missing rtt"));
        };
        let named_pipe = if let Some(named_pipe) = rec.get(7) {
            named_pipe.to_string()
        } else {
            return Err(anyhow!("missing named_pipe"));
        };
        let endpoint = if let Some(endpoint) = rec.get(8) {
            endpoint.to_string()
        } else {
            return Err(anyhow!("missing endpoint"));
        };
        let operation = if let Some(operation) = rec.get(9) {
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
                proto: 0,
                duration: 0,
                rtt,
                named_pipe,
                endpoint,
                operation,
            },
            time,
        ))
    }
}
