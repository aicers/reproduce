use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use giganto_client::ingest::network::{
    Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Ntlm, Rdp, Smtp, Ssh, Tls,
};
use num_traits::ToPrimitive;

use super::{parse_zeek_timestamp, TryFromZeekRecord, PROTO_ICMP, PROTO_TCP, PROTO_UDP};

impl TryFromZeekRecord for Conn {
    #[allow(clippy::too_many_lines)]
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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
        let conn_state = if let Some(conn_state) = rec.get(11) {
            conn_state.to_string()
        } else {
            return Err(anyhow!("missing conn_state"));
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
                conn_state,
                duration,
                service,
                orig_bytes,
                resp_bytes,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes: 0,
                resp_l2_bytes: 0,
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
            parse_zeek_timestamp(timestamp)?
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
                parse_zeek_timestamp(rtt)?
                    .timestamp_nanos_opt()
                    .context("to_timestamp_nanos")?
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
                Vec::new()
            } else {
                let mut ttl_vec = Vec::new();
                for t in ttl.split(',') {
                    ttl_vec.push(
                        t.parse::<f32>()?
                            .to_i32()
                            .context("failed to convert f32 to i32")?,
                    );
                }
                ttl_vec
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
                last_time: rtt,
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
            parse_zeek_timestamp(timestamp)?
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
        let orig_filenames = if let Some(orig_filenames) = rec.get(25) {
            orig_filenames
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing orig_filenames"));
        };
        let orig_mime_types = if let Some(orig_mime_types) = rec.get(26) {
            orig_mime_types
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing orig_mime_types"));
        };
        let resp_filenames = if let Some(resp_filenames) = rec.get(28) {
            resp_filenames
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing resp_filenames"));
        };
        let resp_mime_types = if let Some(resp_mime_types) = rec.get(29) {
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
                proto: PROTO_TCP,
                last_time: i64::MAX,
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
                cookie: String::new(),
                content_encoding: String::new(),
                content_type: String::new(),
                cache_control: String::new(),
                orig_filenames,
                orig_mime_types,
                resp_filenames,
                resp_mime_types,
                post_body: Vec::new(),
                state: String::new(),
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromZeekRecord for Kerberos {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto: PROTO_UDP,
                last_time: i64::MAX,
                client_time: 0,
                server_time: 0,
                error_code: 0,
                client_realm: String::new(),
                cname_type: 0,
                client_name: Vec::new(),
                realm: String::new(),
                sname_type: 0,
                service_name: Vec::new(),
            },
            time,
        ))
    }
}

impl TryFromZeekRecord for Ntlm {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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
                last_time: i64::MAX,
                protocol: String::new(),
                username,
                hostname,
                domainname,
                success,
            },
            time,
        ))
    }
}

impl TryFromZeekRecord for Rdp {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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
                proto: PROTO_TCP,
                last_time: i64::MAX,
                cookie,
            },
            time,
        ))
    }
}

impl TryFromZeekRecord for Smtp {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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
                proto: PROTO_TCP,
                last_time: i64::MAX,
                mailfrom,
                date,
                from,
                to,
                subject,
                agent,
                state: String::new(),
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromZeekRecord for Ssh {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto: PROTO_TCP,
                last_time: i64::MAX,
                client,
                server,
                cipher_alg,
                mac_alg,
                compression_alg,
                kex_alg,
                host_key_alg,
                hassh_algorithms: String::new(),
                hassh: String::new(),
                hassh_server_algorithms: String::new(),
                hassh_server: String::new(),
                client_shka: String::new(),
                server_shka: String::new(),
            },
            time,
        ))
    }
}

impl TryFromZeekRecord for DceRpc {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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
        let rtt = if let Some(rtt) = rec.get(6) {
            if rtt.eq("-") {
                0
            } else {
                parse_zeek_timestamp(rtt)?
                    .timestamp_nanos_opt()
                    .context("to_timestamp_nanos")?
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
                last_time: i64::MAX,
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
impl TryFromZeekRecord for Ftp {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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
        let user = if let Some(user) = rec.get(6) {
            user.to_string()
        } else {
            return Err(anyhow!("missing user"));
        };
        let password = if let Some(password) = rec.get(7) {
            password.to_string()
        } else {
            return Err(anyhow!("missing password"));
        };
        let command = if let Some(command) = rec.get(8) {
            command.to_string()
        } else {
            return Err(anyhow!("missing command"));
        };
        let reply_code = if let Some(reply_code) = rec.get(9) {
            reply_code.to_string()
        } else {
            return Err(anyhow!("missing reply_code"));
        };
        let reply_msg = if let Some(reply_msg) = rec.get(10) {
            reply_msg.to_string()
        } else {
            return Err(anyhow!("missing reply_msg"));
        };
        let data_passive = if let Some(data_passive) = rec.get(11) {
            if data_passive.eq("T") {
                true
            } else if data_passive.eq("F") {
                false
            } else {
                return Err(anyhow!("invalid data_passive"));
            }
        } else {
            return Err(anyhow!("missing data_passive"));
        };
        let data_orig_addr = if let Some(data_orig_addr) = rec.get(12) {
            data_orig_addr
                .parse::<IpAddr>()
                .context("invalid data source address")?
        } else {
            return Err(anyhow!("missing data source address"));
        };
        let data_resp_addr = if let Some(data_resp_addr) = rec.get(13) {
            data_resp_addr
                .parse::<IpAddr>()
                .context("invalid data destination address")?
        } else {
            return Err(anyhow!("missing data destination address"));
        };
        let data_resp_port = if let Some(data_resp_port) = rec.get(14) {
            data_resp_port
                .parse::<u16>()
                .context("invalid data destination port")?
        } else {
            return Err(anyhow!("missing data destination port"));
        };
        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto: PROTO_TCP,
                last_time: i64::MAX,
                user,
                password,
                command,
                reply_code,
                reply_msg,
                data_passive,
                data_orig_addr,
                data_resp_addr,
                data_resp_port,
                file: String::new(),
                file_size: 0,
                file_id: String::new(),
            },
            time,
        ))
    }
}

#[allow(clippy::too_many_lines)]
impl TryFromZeekRecord for Ldap {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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
            match proto {
                "tcp" => PROTO_TCP,
                "udp" => PROTO_UDP,
                "icmp" => PROTO_ICMP,
                _ => 0,
            }
        } else {
            return Err(anyhow!("missing protocol"));
        };
        let message_id = if let Some(message_id) = rec.get(7) {
            if message_id.eq("-") {
                0
            } else {
                message_id.parse::<u32>().context("invalid message_id")?
            }
        } else {
            return Err(anyhow!("missing message_id"));
        };
        let version = if let Some(version) = rec.get(8) {
            if version.eq("-") {
                0
            } else {
                version.parse::<u8>().context("invalid version")?
            }
        } else {
            return Err(anyhow!("missing version"));
        };
        let opcode = if let Some(opcode) = rec.get(9) {
            opcode
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing opcode"));
        };
        let result = if let Some(result) = rec.get(10) {
            result
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing result"));
        };
        let diagnostic_message = if let Some(diagnostic_message) = rec.get(11) {
            diagnostic_message
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing diagnostic_message"));
        };
        let object = if let Some(object) = rec.get(12) {
            object
                .split(',')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            return Err(anyhow!("missing object"));
        };
        let argument = if let Some(argument) = rec.get(13) {
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
                last_time: i64::MAX,
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

impl TryFromZeekRecord for Tls {
    fn try_from_zeek_record(rec: &csv::StringRecord) -> Result<(Self, i64)> {
        let time = if let Some(timestamp) = rec.get(0) {
            parse_zeek_timestamp(timestamp)?
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
        let version = if let Some(version) = rec.get(6) {
            version.to_string()
        } else {
            return Err(anyhow!("missing version"));
        };
        let server_name = if let Some(server_name) = rec.get(9) {
            server_name.to_string()
        } else {
            return Err(anyhow!("missing server_name"));
        };
        let last_alert = if let Some(last_alert) = rec.get(11) {
            if last_alert.eq("-") {
                0
            } else {
                last_alert.parse::<u8>().context("invalid last_alert")?
            }
        } else {
            return Err(anyhow!("missing last_alert"));
        };

        Ok((
            Self {
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto: PROTO_TCP,
                last_time: i64::MAX,
                server_name,
                alpn_protocol: String::new(),
                ja3: String::new(),
                version,
                client_cipher_suites: Vec::new(),
                client_extensions: Vec::new(),
                cipher: 0,
                extensions: Vec::new(),
                ja3s: String::new(),
                serial: String::new(),
                subject_country: String::new(),
                subject_org_name: String::new(),
                subject_common_name: String::new(),
                validity_not_before: 0,
                validity_not_after: 0,
                subject_alt_name: String::new(),
                issuer_country: String::new(),
                issuer_org_name: String::new(),
                issuer_org_unit_name: String::new(),
                issuer_common_name: String::new(),
                last_alert,
            },
            time,
        ))
    }
}
