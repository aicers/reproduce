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
    pub(crate) kind: String,
    pub(crate) log_type: String,
    pub(crate) version: String,
}

impl SecurityLogInfo {
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
    fn parse_security_log(line: &str, serial: i64, info: SecurityLogInfo)
        -> Result<(SecuLog, i64)>; // agent: &str
}

pub fn proto_to_u8(proto: &str) -> u8 {
    match proto {
        "TCP" | "tcp" => PROTO_TCP,
        "UDP" | "udp" => PROTO_UDP,
        "ICMP" | "icmp" => PROTO_ICMP,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Aiwaf, Axgate, Fgt, Mf2, ParseSecurityLog, SecurityLogInfo, ShadowWall, SniperIps,
        SonicWall, Srx, Tg, Vforce, Wapples,
    };
    use crate::security_log::{Nginx, Ubuntu, PROTO_TCP};

    #[test]
    fn parse_wapples() {
        let logs = [
            "<182>Jan 9 09:26:09 penta wplogd: WAPPLES INTRUSION WAPPLES DETECTION TIME : 2020-01-09 09:26:09 +0900 WAPPLES RULE NAME : Extension Filtering WAPPLES (client 119.75.88.90 WAPPLES) -> (server 210.99.177.16:1443)",
            "<182>Nov 2 18:27:04 penta wplogd: [WAPPLES] INTRUSION [WAPPLES] DETECTION TIME : 2020-11-02 18:27:04 +0900 [WAPPLES] RULE NAME : Extension Filtering [WAPPLES] (client 211.245.254.29 [WAPPLES]) -> (server 10.10.111.132:443)"
        ];

        let info = SecurityLogInfo {
            kind: "wapples".to_string(),
            log_type: "fw".to_string(),
            version: "5.0.12".to_string(),
        };

        for log in logs {
            let (seculog, _) = Wapples::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.proto, Some(PROTO_TCP));
            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_mf2() {
        let logs = [
            "<190>1 2020-07-13T00:33:28.957810Z [ips_ddos_detect] [211.217.5.120]2020-07-13 09:33:23,KOFIH,#21965(HTTP Sensitive file Access Attempt(index.jsp)),#0(IPS),192.168.20.79,56889,211.42.85.240,80,TCP,don't frag/last frag,AP,24:f5:aa:e1:fc:a0,1,541,detect,0",
        ];

        let info = SecurityLogInfo {
            kind: "mf2".to_string(),
            log_type: "ips".to_string(),
            version: "4.0".to_string(),
        };

        for log in logs {
            let (seculog, _) = Mf2::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_sniper() {
        let logs = [
            "<36>[SNIPER-0123] [Attack_Name=(0395)UDP Source-IP Flooding], [Time=2020/07/13 09:45:54], [Hacker=168.126.63.1], [Victim=192.168.253.13], [Protocol=udp/56157], [Risk=Low], [Handling=Alarm], [Information=], [SrcPort=53], [HackType=00001]",
        ];

        let info = SecurityLogInfo {
            kind: "sniper".to_string(),
            log_type: "ips".to_string(),
            version: "8.0".to_string(),
        };

        for log in logs {
            let (seculog, _) = SniperIps::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_aiwaf() {
        let logs = [
            "DETECT|2019-07-19 11:47:15|1.1.1.2|v4.1|192.168.70.254|52677|192.168.200.44|80|Personal Information Leakage|중간|탐지|POST /ekp/rss.do?cmd=getRSSFeed&rssType=getAllUnReadMailList&sysMenuMode=1&sessionFromServer=Y HTTP/1.1Accept: */*naonAjax: xmlX-Requested-With: XMLHttpRequestReferer: http://gw.charmzone.co.kr/ekp/main/home/homGwMainAccept-Language: ko-KRAccept-Encoding: gzip, deflateUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like GeckoHost: gw.charmzone.co.krContent-Length: 0Connection: Keep-AliveCache-Control: no-cacheCookie: JSESSIONID=374F619FA47872BB71D7672DD167DB46.groupware_server1; SCOUTER=x7o9hdtj2ta2pp; locale=ko; CEnterkey_3.5.1.23_gwNaoneditor1=M0ZDS0Nl",
            "DETECT|2019-07-19 11:54:03|1.1.1.2|v4.1|192.168.70.254|55425|192.168.200.44|80|Personal Information Flow|중간|탐지|GET /resources/common/js/jquery.rating.js?_=1563504839762 HTTP/1.1Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01X-Requested-With: XMLHttpRequestReferer: http://gw.charmzone.co.kr/ekp/main/home/homGwMainSubAccept-Language: ko-KRAccept-Encoding: gzip, deflateUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like GeckoHost: gw.charmzone.co.krConnection: Keep-AliveCookie: locale=ko; CEnterkey_3.5.1.23_gwNaoneditor1=M0ZDS0NlRFTDFPV0RVZXMkg4|39|개인 정보 유입 탐지|[: 156350#######]|http|gw.charmzone.co.kr|546",
            "DETECT|2019-07-19 11:53:54|1.1.1.2|v4.1|172.58.139.90|33652|192.168.200.13|80|Error Page Cloaking|중간|탐지|GET /favicon.ico HTTP/1.1Host: cos.charmzone.co.krAccept: */*Connection: keep-aliveCookie: PHPSESSID=e2t3bs5k2h0ct1q5m1042dh0v2; AUAZ3MM40898=1526269480301798032%7C3%7C1497813500777009514%7C1%7C149781350015902FPSWUser-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Mobile/15E148 Safari/604.1Accept-Language: ko-krReferer: http://cos.charmzone.co.kr/ko/index.phpAccept-Encoding: gzip, deflate|21|에러페이지 클로킹|[status code 404]|http|cos.charmzone.co.kr|484",
        ];

        let info = SecurityLogInfo {
            kind: "aiwaf".to_string(),
            log_type: "waf".to_string(),
            version: "4.1".to_string(),
        };

        for log in logs {
            let (seculog, _) = Aiwaf::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_tg() {
        let logs = [
            "3`0`2`1`6cfe35`1100`20200713`09:20:08`2`6`101.79.244.171`80`14.39.192.214`51548`3003``IPS`2009`eth0`0800`40:7C:7D:33:FD:42`840020401`-1`http_ms_adodb.stream-3``eth2```06848753127936347939`default`IDS_HTTP`1`0`",
        ];

        let info = SecurityLogInfo {
            kind: "tg".to_string(),
            log_type: "ips".to_string(),
            version: "2.7".to_string(),
        };

        for log in logs {
            let (seculog, _) = Tg::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_vforce() {
        let logs = [
            "<134>Jul 13 09:41:04 ips: Src:129.129.101.107, Dst:168.126.63.1, Proto:17, Spt_c:60491, Dpt_t:53, Policy:alert, Sid:2000014, Count:1, Severity:high, Group:ANOMALY, Class:TRAFFIC ANOMALY, Msg:DNS Cache Poisoning Attack Detection",
        ];

        let info = SecurityLogInfo {
            kind: "vforce".to_string(),
            log_type: "ips".to_string(),
            version: "4.6".to_string(),
        };

        for log in logs {
            let (seculog, _) = Vforce::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_srx() {
        let logs = [
            r#"<14>1 2019-05-10T17:31:09.856+09:00 Saeki_PNC_SRX340 RT_IDP - IDP_ATTACK_LOG_EVENT [junos@2636.1.1.1.2.135 epoch-time="1557477065" message-type="ANOMALY" source-address="211.192.8.240" source-port="8071" destination-address="13.124.252.139" destination-port="80" protocol-name="TCP" service-name="HTTP" application-name="HTTP" rule-name="1" rulebase-name="IPS" policy-name="UTM" export-id="1716" repeat-count="3" action="NONE" threat-severity="HIGH" attack-name="HTTP:OVERFLOW:URL-OVERFLOW" nat-source-address="0.0.0.0" nat-source-port="0" nat-destination-address="0.0.0.0" nat-destination-port="0" elapsed-time="0" inbound-bytes="0" outbound-bytes="0" inbound-packets="0" outbound-packets="0" source-zone-name="trust" source-interface-name="ge-0/0/1.0" destination-zone-name="untrust" destination-interface-name="ge-0/0/0.0" packet-log-id="0" alert="no" username="N/A" roles="N/A" message="-"]"#,
        ];

        let info = SecurityLogInfo {
            kind: "srx".to_string(),
            log_type: "ips".to_string(),
            version: "15.1".to_string(),
        };

        for log in logs {
            let (seculog, _) = Srx::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_sonic() {
        let logs = [
            r#"<185> id=firewall sn=C0EAE4F562EE time="2020-03-16 15:59:52 UTC" fw=220.83.254.2 pri=1 c=32 m=82 msg="Possible port scan detected" app=49201 appName='General TCP' n=42 src=139.199.19.227:50432:X1 dst=220.83.254.2:9200:X1 srcMac=a4:7b:2c:44:cf:62 dstMac=c0:ea:e4:f5:62:ef proto=tcp/9200 note="TCP scanned port list, 7002, 8080, 8088, 7001, 6380" fw_action="NA""#,
        ];

        let info = SecurityLogInfo {
            kind: "sonicwall".to_string(),
            log_type: "fw".to_string(),
            version: "6.5".to_string(),
        };

        for log in logs {
            let (seculog, _) = SonicWall::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_fgt() {
        let logs = [
            r#"<185>date=2020-07-13 time=09:37:44 devname="Chamhosp_201E" devid="FG201ETK19907629" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" eventtime=1594600665469973652 tz="+0900" severity="medium" srcip=10.10.40.132 srccountry="Reserved" dstip=10.10.40.245 srcintf="port13" srcintfrole="undefined" dstintf="port13" dstintfrole="undefined" sessionid=78411987 action="dropped" proto=6 service="NBSS" policyid=1 attack="MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure" srcport=62227 dstport=445 direction="outgoing" attackid=43799 profile="sniffer-profile" ref="http://www.fortinet.com/ids/VID43799" incidentserialno=1038270373 msg="applications3: MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure," crscore=10 craction=16384 crlevel="medium""#,
        ];

        let info = SecurityLogInfo {
            kind: "fgt".to_string(),
            log_type: "ips".to_string(),
            version: "5.2".to_string(),
        };

        for log in logs {
            let (seculog, _) = Fgt::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_shadow() {
        let logs = [
            "<142>Oct 31 13:45:51 ShadowWall sm[22143]: ipslog	111363	1698727507	387133	0	1	DURUAN	3	1	2012937	3	ET SCAN Internal Dummy Connection User-Agent Inbound	21	1	6	159.223.48.151	44814	112.175.234.93	80",
            "<142>Oct 31 07:54:37 ShadowWall sm[22143]: ipslog	111362	1698617916	481609	0	1	DURUAN	3	1	2020912	2	ET WEB_SERVER Possible IIS Integer Overflow DoS (CVE-2015-1635)	28	1	6	185.180.143.81	38354	112.175.234.93	80",
            "<142>Oct 31 04:23:24 ShadowWall sm[3220]: ipslog	111362	1698617916	481609	0	1	DURUAN	3	1	2020912	2	ET WEB_SERVER Possible IIS Integer Overflow DoS (CVE-2015-1635)	28	1	6	185.180.143.81	38354	112.175.234.93	80",
            "<142>Oct 31 03:42:21 ShadowWall sm[31944]: ipslog	111362	1698617916	481609	0	1	DURUAN	3	1	2020912	2	ET WEB_SERVER Possible IIS Integer Overflow DoS (CVE-2015-1635)	28	1	6	185.180.143.81	38354	112.175.234.93	80",
        ];

        let info = SecurityLogInfo {
            kind: "shadowwall".to_string(),
            log_type: "ips".to_string(),
            version: "5.0".to_string(),
        };

        for log in logs {
            let (seculog, _) = ShadowWall::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_axgate() {
        let logs = [
            "Aug 11 13:07:17 106.243.158.126 Aug 11 13:07:18 amnet kernel: ver:3,time:2021-08-11 13:07:18,src:192.168.0.234,nat_src:106.243.158.126,dst:208.91.112.52,nat_dst:0.0.0.0,priority:medium,sport:57879,nat_sport:57879,dport:53,nat_dport:0,proto:17,sid:1551,category:application,action:pass,count:1,sessid:63760071,npdump:0,id:404,prof_id:1,nat_type:s,snat_id:500,dnat_id:0,uid:-,stime:2021-08-11 13:02:35,etime:- -,s_pkts:54,s_bytes:4122,r_pkts:53,r_bytes:8953,rule_ver:4,f_zone:trust,t_zone:untrust,vd_id:0,rule_pri:25,rule_id:27,pdir:to-src,message:APPLICATION DNS Spoof query response with TTL of 1 min. and no authority",
            "Aug 11 12:46:00 106.243.158.126 Aug 11 12:46:01 amnet kernel: ver:3,time:2021-08-11 12:46:01,src:192.168.0.234,nat_src:106.243.158.126,dst:13.107.4.50,nat_dst:0.0.0.0,priority:low,sport:62899,nat_sport:62899,dport:80,nat_dport:0,proto:6,sid:1686,category:attack-response,action:pass,count:1,sessid:15897769,npdump:0,id:396,prof_id:1,nat_type:s,snat_id:500,dnat_id:0,uid:-,stime:2021-08-11 12:46:00,etime:- -,s_pkts:3,s_bytes:596,r_pkts:3,r_bytes:425,rule_ver:4,f_zone:trust,t_zone:untrust,vd_id:0,rule_pri:25,rule_id:27,pdir:to-src,message:ATTACK-RESPONSES 403 Forbidden",
        ];

        let info = SecurityLogInfo {
            kind: "axgate".to_string(),
            log_type: "fw".to_string(),
            version: "2.0".to_string(),
        };

        for log in logs {
            let (seculog, _) = Axgate::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_ubuntu() {
        let logs = [
            r"Oct 12 00:00:04 safe-web-red systemd[1]: logrotate.service: Succeeded.",
            r"Oct 12 00:00:04 safe-web-red systemd[1]: Finished Rotate log files.",
            r"Oct 12 00:00:04 safe-web-red systemd[1]: man-db.service: Succeeded.",
            r"Oct 12 00:00:04 safe-web-red systemd[1]: Finished Daily man-db regeneration.",
            r"Oct 12 00:17:01 safe-web-red CRON[1497802]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
            r"Oct 12 01:17:01 safe-web-red CRON[1509996]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
            r"Oct 12 01:47:20 safe-web-red systemd[1]: Starting Ubuntu Advantage Timer for running repeated jobs...",
            r"Oct 12 01:47:21 safe-web-red systemd[1]: ua-timer.service: Succeeded.",
            r"Oct 12 01:47:21 safe-web-red systemd[1]: Finished Ubuntu Advantage Timer for running repeated jobs.",
            r"Oct 12 02:17:01 safe-web-red CRON[1522215]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
            r"Oct 12 03:10:01 safe-web-red CRON[1532988]: (root) CMD (test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r)",
            r"Oct 12 03:17:01 safe-web-red CRON[1534414]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
            r"Oct 12 04:08:19 safe-web-red systemd[1]: Starting Message of the Day...",
            r"Oct 12 04:08:28 safe-web-red 50-motd-news[1544912]:  * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s",
            r"Oct 12 04:08:28 safe-web-red 50-motd-news[1544912]:    just raised the bar for easy, resilient and secure K8s cluster deployment.",
            r"Oct 12 04:08:28 safe-web-red 50-motd-news[1544912]:    https://ubuntu.com/engage/secure-kubernetes-at-the-edge",
        ];

        let info = SecurityLogInfo {
            kind: "ubuntu".to_string(),
            log_type: "syslog".to_string(),
            version: "20.04".to_string(),
        };

        for log in logs {
            let (seculog, _) = Ubuntu::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }

    #[test]
    fn parse_nginx() {
        let logs = [
            r#"172.30.1.150 - - [28/Jul/2023:00:00:24 +0900] "GET /favicon.ico HTTP/1.1" 404 1427 "http://www.moneta.co.kr/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183""#,
            r#"172.30.1.150 - - [28/Jul/2023:00:00:25 +0900] "GET /favicon.ico HTTP/1.1" 404 1747 "http://www.datanet.co.kr/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183""#,
            r#"172.30.1.150 - - [28/Jul/2023:00:00:27 +0900] "GET /favicon.ico HTTP/1.1" 404 1664 "http://www.brainbox.co.kr/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183""#,
            r#"172.30.1.150 - - [28/Jul/2023:00:00:29 +0900] "GET /favicon.ico HTTP/1.1" 404 1427 "http://warning.safenet.kt.co.kr/block_extraction.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183""#,
            r#"172.30.1.150 - - [28/Jul/2023:00:01:02 +0900] "GET /favicon.ico HTTP/1.1" 404 1427 "http://www.moneta.co.kr/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183""#,
            r#"172.30.1.150 - - [28/Jul/2023:00:01:04 +0900] "GET /favicon.ico HTTP/1.1" 404 1747 "http://www.datanet.co.kr/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183""#,
            r#"172.30.1.150 - - [28/Jul/2023:00:01:06 +0900] "GET /favicon.ico HTTP/1.1" 404 1664 "http://www.brainbox.co.kr/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183""#,
            r#"172.30.1.150 - - [28/Jul/2023:00:01:09 +0900] "GET /favicon.ico HTTP/1.1" 404 1427 "http://warning.safenet.kt.co.kr/block_extraction.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.183""#,
        ];

        let info = SecurityLogInfo {
            kind: "nginx".to_string(),
            log_type: "accesslog".to_string(),
            version: "1.25.2".to_string(),
        };

        for log in logs {
            let (seculog, _) = Nginx::parse_security_log(log, 1, info.clone()).unwrap();

            assert_eq!(seculog.contents, log);
        }
    }
}
