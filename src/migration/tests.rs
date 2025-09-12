use csv::ReaderBuilder;
use csv::StringRecord;
use giganto_client::ingest::network::{
    Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Kerberos, Ldap, Mqtt, Nfs, Ntlm, Rdp, Smb, Smtp,
    Ssh, Tls,
};

use super::TryFromGigantoRecord;

#[test]
fn giganto_conn() {
    let data =
        "1669735962.571151000	localhost	fe80::2267:7cff:fef0:cb09	133	ff02::2	134	1	sf	0.000000000	0.000000000	-	0	0	1	0	21515	27889";

    let rec = stringrecord(data);

    assert!(Conn::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_http() {
    let data = "1669773412.241856000	localhost	129.204.40.54	47697	218.144.35.150	80	0	0.000000000	0.000000000	GET	218.144.35.150	/root11.php	-	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36	0	286	302	Found	-	-	-	-	-	-	-	-	10,10,10	-";

    let rec = stringrecord(data);

    assert!(Http::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_rdp() {
    let data =
        "1669775611.098308000	localhost	112.160.137.136	61572	103.153.182.151	3389	0	0.000000000	0.000000000	hello";

    let rec = stringrecord(data);

    assert!(Rdp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_smtp() {
    let data = "1669136154.131718000	localhost	220.73.219.213	51280	67.195.204.72	25	0	0.000000000	0.000000000	hanjinyea@monami.com	-	-	-	-	-	-";

    let rec = stringrecord(data);

    assert!(Smtp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_dns() {
    let data = "1664549996.073650000	collect	59.18.121.131	28116	211.252.150.11	53	17	0.000000000	0.000000000	discoplexa4.pl	-	30565	0	C_INTERNET	TXT	0	false	false	true	false	0";

    let rec = stringrecord(data);

    assert!(Dns::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ntlm() {
    let data = "1614130258.669753000	localhost	10.200.90.100	59271	192.168.0.111	445	0	0.000000000	0.000000000	-	it	-	-	-";

    let rec = stringrecord(data);

    assert!(Ntlm::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_kerberos() {
    let data = "1562093132.125665000	localhost	89.248.167.131	24067	210.117.142.55	88	0	0.000000000	0.000000000	0.000000000	0.000000000	1	client_realm	1	client,name	realm	1	service,name";

    let rec = stringrecord(data);

    assert!(Kerberos::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ssh() {
    let data = "1562093121.802019000	localhost	114.249.237.38	41260	203.254.132.18	22	0	0.000000000	0.000000000	SSH-2.0-Go	SSH-1.99-Cisco-1.25	aes128-cbc	hmac-sha1	none	diffie-hellman-group1-sha1	ssh-rsa	-	-	-	-	-	-";

    let rec = stringrecord(data);

    assert!(Ssh::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_dce_rpc() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	0.000000000	547000	49670	netlogon	NetrLogonSamLogonEx";

    let rec = stringrecord(data);

    assert!(DceRpc::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ftp() {
    let data = r"1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	1614130373.991064000	1614130373.991064000	anonymous	ftp@example.com	(EPSV,229,Entering Extended Passive Mode,true,192.168.4.76,196.216.2.24,31746,ftp://192.168.0.7/pub/stats/afrinic/delegated-afrinic-extended-latest.md5,74,226)";

    let rec = stringrecord(data);

    assert!(Ftp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ftp_reply_230() {
    let data = r"1614130373.991064000	localhost	192.168.0.111	21	192.168.0.7	49670	6	1614130373.991064000	1614130373.991064000	csanders	echo	(USER,230,User logged in, proceed,false,192.168.0.111,192.168.0.7,20,ftp://192.168.0.7/,0,1614130373991064000)";

    let rec = stringrecord(data);

    assert!(Ftp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_mqtt() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	0.000000000	0.000000000	mqtt	3	my_client_id	10	topic1,topic2	10,10,10";

    let rec = stringrecord(data);

    assert!(Mqtt::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ldap() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	0.000000000	2	3	opcode	result	diagnostic_mgs	object	argument";

    let rec = stringrecord(data);

    assert!(Ldap::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_tls() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	0.000000000	server_name	alpn_protocol	ja3	version	771,769,770	0,1,2	10	0,1	ja3s	serial	sub_country	sub_org_name	sub_comm_name	1	2	sub_alt_name	issuer_country	issuer_org_name	issuer_org_unit_name	issuer_common_name	10";

    let rec = stringrecord(data);

    assert!(Tls::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_smb() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	0.000000000	0	path	service	file_name	10	20	30	10000000	20000000	10000000	20000000";

    let rec = stringrecord(data);

    assert!(Smb::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_nfs() {
    let data =
        "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	0.000000000	-	-";

    let rec = stringrecord(data);

    assert!(Nfs::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_bootp() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	0.000000000	0.000000000	0	1	2	3	192.168.4.1	192.168.4.2	192.168.4.3	192.168.4.4	0,1,2	sname	file";

    let rec = stringrecord(data);

    assert!(Bootp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_dhcp() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	0.000000000	0.000000000	0	192.168.4.1	192.168.4.2	192.168.4.3	192.168.4.4	192.168.4.5	192.168.4.11,192.168.4.22	192.168.4.33,192.168.4.44	192.168.4.6	1	192.168.4.7	0,1,2	message	1	1	0,1,2	1	0,1,2";

    let rec = stringrecord(data);

    assert!(Dhcp::try_from_giganto_record(&rec).is_ok());
}

fn stringrecord(data: &str) -> StringRecord {
    let rdr = ReaderBuilder::new()
        .delimiter(b'\t')
        .has_headers(false)
        .from_reader(data.as_bytes());

    rdr.into_records().next().unwrap().unwrap()
}
