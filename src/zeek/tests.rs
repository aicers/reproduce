use super::{
    TryFromZeekRecord, ZeekConn, ZeekDceRpc, ZeekDns, ZeekHttp, ZeekKerberos, ZeekNtlm, ZeekRdp,
    ZeekSmtp, ZeekSsh,
};
use csv::ReaderBuilder;
use csv::StringRecord;

// data from zeek log
#[test]
fn zeek_conn() {
    let data = "1669773412.689790	ClEkJM2Vm5giqnMf4h	192.168.1.77	57655	209.197.168.151	1024	tcp	irc-dcc-data	2.256935	124	42208	SF	-	-	0	ShAdDaFf	28	1592	43	44452	-";

    let rec = stringrecord(data);

    assert!(ZeekConn::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_http() {
    let data = "1669773412.689790	CHhAvVGS1DHFjwGM9	127.0.0.1	42960	127.0.0.1	80	1	GET	-	/zeek.html	-	-	-	-	0	0	-	-	-	-	(empty)	-	-	-	-	-	-	-	-	-";

    let rec = stringrecord(data);

    assert!(ZeekHttp::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_rdp() {
    let data = "1669773412.689790	CHhAvVGS1DHFjwGM9	192.168.1.1	54990	192.168.1.2	3389	JOHN-PC  	Success	RDP	rdpdr,rdpsnd,cliprdr,drdynvc	English - United States	RDP 8.1	JOHN-PC-LAPTOP	3c571ed0-3415-474b-ae94-74e151b	1920	1080	16bit	X.509	2	F	Client compatible	128bit";

    let rec = stringrecord(data);

    assert!(ZeekRdp::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_smtp() {
    let data = r#"1669773412.689790	CHhAvVGS1DHFjwGM9	10.10.1.4	1470	74.53.140.153	25	1	GP	gurpartap@patriots.in	raj_deol2002in@yahoo.co.in	Mon, 5 Oct 2009 11:36:07 +0530	"Gurpartap Singh" <gurpartap@patriots.in>	<raj_deol2002in@yahoo.co.in>	-	-	<000301ca4581$ef9e57f0$cedb07d0$@in>	-	SMTP	-	-	-	250 OK id=1Mugho-0003Dg-Un	74.53.140.153,10.10.1.4	Microsoft Office Outlook 12.0	F	FmFp351N5nhsMmAfQg,Fqrb1K5DWEfgy4WU2,FEFYSd1s8Onn9LynKj"#;

    let rec = stringrecord(data);

    assert!(ZeekSmtp::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_dns() {
    let data = "1669773412.689790	CHhAvVGS1DHFjwGM9	192.168.153.129	50729	192.168.153.2	53	udp	39080	0.017821	upenn.edu	1	C_INTERNET	43	DS	0	NOERROR	F	F	T	T	2	DS 5 1,DS 5 2,RRSIG 43 edu	5.000000,5.000000,5.000000	F";

    let rec = stringrecord(data);

    assert!(ZeekDns::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_ntlm() {
    let data = "1669773412.689790	CFLRIC3zaTU1loLGxh	192.168.0.173	1073	192.168.0.2	1032	ALeonard	ALEONARD-XP	CNAMIS	SATURN	-	-	-";

    let rec = stringrecord(data);

    assert!(ZeekNtlm::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_kerberos() {
    let data = "1669773412.689790	CHhAvVGS1DHFjwGM9	192.168.1.31	64889	192.168.1.32	88	TGS	vladg/VLADG.NET	krbtgt/VLADG.NET	T	-	-	0.000000	aes256-cts-hmac-sha1-96	T	F	-	-	-	-";

    let rec = stringrecord(data);

    assert!(ZeekKerberos::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_ssh() {
    let data = "1669773412.689790	CUM0KZ3MLUfNB0cl11	192.168.2.1	55179	192.168.2.158	2200	2	T	1	-	SSH-2.0-OpenSSH_6.2	SSH-2.0-paramiko_1.15.2	aes128-ctr	hmac-md5	none	diffie-hellman-group-exchange-sha1	ssh-rsa	60:73:38:44:cb:51:86:65:7f:de:da:a2:2b:5a:57:d5";

    let rec = stringrecord(data);

    assert!(ZeekSsh::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_dce_rpc() {
    let data = "1669773412.689790	CmES5u32sYpV7JYN	192.168.0.173	1066	192.168.0.2	135	0.000375	135	epmapper	ept_map";

    let rec = stringrecord(data);

    assert!(ZeekDceRpc::try_from_zeek_record(&rec).is_ok());
}

fn stringrecord(data: &str) -> StringRecord {
    let rdr = ReaderBuilder::new()
        .delimiter(b'\t')
        .has_headers(false)
        .from_reader(data.as_bytes());

    rdr.into_records().next().unwrap().unwrap()
}
