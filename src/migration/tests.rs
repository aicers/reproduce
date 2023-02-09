use crate::migration::TryFromGigantoRecord;
use csv::ReaderBuilder;
use csv::StringRecord;
use giganto_client::ingest::network::{Conn, DceRpc, Dns, Http, Kerberos, Ntlm, Rdp, Smtp, Ssh};

#[test]
fn giganto_conn() {
    let data =
        "1669735962.571151000	localhost	fe80::2267:7cff:fef0:cb09	133	ff02::2	134	1	0.000000000	-	0	0	1	0";

    let rec = stringrecord(data);

    assert!(Conn::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_http() {
    let data = "1669773412.241856000	localhost	129.204.40.54	47697	218.144.35.150	80	0	0.000000000	GET	218.144.35.150	/root11.php	-	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36	0	286	302	Found	-	-	-	-	-	-";

    let rec = stringrecord(data);

    assert!(Http::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_rdp() {
    let data =
        "1669775611.098308000	localhost	112.160.137.136	61572	103.153.182.151	3389	0	0.000000000	hello";

    let rec = stringrecord(data);

    assert!(Rdp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_smtp() {
    let data = "1669136154.131718000	localhost	220.73.219.213	51280	67.195.204.72	25	0	0.000000000	hanjinyea@monami.com	-	-	-	-	-";

    let rec = stringrecord(data);

    assert!(Smtp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_dns() {
    let data = "1664549996.073650000	collect	59.18.121.131	28116	211.252.150.11	53	17	0.000000000	discoplexa4.pl	-	30565	0	C_INTERNET	TXT	0	false	false	true	false	0";

    let rec = stringrecord(data);

    assert!(Dns::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ntlm() {
    let data = "1614130258.669753000	localhost	10.200.90.100	59271	192.168.0.111	445	0	0.000000000	it	-	-	HYPER01	HYPER01.hansae.local	hansae.local	-";

    let rec = stringrecord(data);

    assert!(Ntlm::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_kerberos() {
    let data = "1562093132.125665000	localhost	89.248.167.131	24067	210.117.142.55	88	0	0.000000000	AS	/NM	krbtgt/NM	-	-	0	0	-	T	T	-	-";

    let rec = stringrecord(data);

    assert!(Kerberos::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ssh() {
    let data = "1562093121.802019000	localhost	114.249.237.38	41260	203.254.132.18	22	0	0.000000000	2	F	1	-	SSH-2.0-Go	SSH-1.99-Cisco-1.25	aes128-cbc	hmac-sha1	none	diffie-hellman-group1-sha1	ssh-rsa	e8:1a:0c:fe:e5:d9:0d:d7:2f:9f:a2:c4:4a:36:c5:24";

    let rec = stringrecord(data);

    assert!(Ssh::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_dce_rpc() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	547000	49670	netlogon	NetrLogonSamLogonEx";

    let rec = stringrecord(data);

    assert!(DceRpc::try_from_giganto_record(&rec).is_ok());
}

fn stringrecord(data: &str) -> StringRecord {
    let rdr = ReaderBuilder::new()
        .delimiter(b'\t')
        .has_headers(false)
        .from_reader(data.as_bytes());

    rdr.into_records().next().unwrap().unwrap()
}
