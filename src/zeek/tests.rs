use csv::ReaderBuilder;
use csv::StringRecord;
use giganto_client::ingest::network::{
    Conn, DceRpc, Dns, Ftp, Http, Kerberos, Ldap, Ntlm, Rdp, Smtp, Ssh, Tls,
};

use crate::zeek::TryFromZeekRecord;

// data from zeek log
#[test]
fn zeek_conn() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
    let data = "1669773412.689790	ClEkJM2Vm5giqnMf4h	192.168.1.77	57655	209.197.168.151	1024	tcp	irc-dcc-data	2.256935	124	42208	SF	-	-	0	ShAdDaFf	28	1592	43	44452	-";

    let rec = stringrecord(data);

    assert!(Conn::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_http() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
    let data = "1669773412.689790	CHhAvVGS1DHFjwGM9	127.0.0.1	42960	127.0.0.1	80	1	GET	-	/zeek.html	-	-	-	-	0	0	-	-	-	-	(empty)	-	-	-	-	-	-	-	-	-";

    let rec = stringrecord(data);

    assert!(Http::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_rdp() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	cookie	result	security_protocol	client_channels	keyboard_layout	client_build	client_name	client_dig_product_id	desktop_width	desktop_height	requested_color_depth	cert_type	cert_count	cert_permanent	encryption_level	encryption_method
    let data = "1669773412.689790	CHhAvVGS1DHFjwGM9	192.168.1.1	54990	192.168.1.2	3389	JOHN-PC  	Success	RDP	rdpdr,rdpsnd,cliprdr,drdynvc	English - United States	RDP 8.1	JOHN-PC-LAPTOP	3c571ed0-3415-474b-ae94-74e151b	1920	1080	16bit	X.509	2	F	Client compatible	128bit";

    let rec = stringrecord(data);

    assert!(Rdp::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_smtp() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	helo	mailfrom	rcptto	date	from	to	cc	reply_to	msg_id	in_reply_to	subject	x_originating_ip	first_received	second_received	last_reply	path	user_agent	tls	fuids
    let data = r#"1669773412.689790	CHhAvVGS1DHFjwGM9	10.10.1.4	1470	74.53.140.153	25	1	GP	gurpartap@patriots.in	raj_deol2002in@yahoo.co.in	Mon, 5 Oct 2009 11:36:07 +0530	"Gurpartap Singh" <gurpartap@patriots.in>	<raj_deol2002in@yahoo.co.in>	-	-	<000301ca4581$ef9e57f0$cedb07d0$@in>	-	SMTP	-	-	-	250 OK id=1Mugho-0003Dg-Un	74.53.140.153,10.10.1.4	Microsoft Office Outlook 12.0	F	FmFp351N5nhsMmAfQg,Fqrb1K5DWEfgy4WU2,FEFYSd1s8Onn9LynKj"#;

    let rec = stringrecord(data);

    assert!(Smtp::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_dns() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
    let data = "1669773412.689790	CHhAvVGS1DHFjwGM9	192.168.153.129	50729	192.168.153.2	53	udp	39080	0.017821	upenn.edu	1	C_INTERNET	43	DS	0	NOERROR	F	F	T	T	2	DS 5 1,DS 5 2,RRSIG 43 edu	5.000000,5.000000,5.000000	F";

    let rec = stringrecord(data);

    assert!(Dns::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_ntlm() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	username	hostname	domainname	server_nb_computer_name	server_dns_computer_name	server_tree_name	success
    let data = "1669773412.689790	CFLRIC3zaTU1loLGxh	192.168.0.173	1073	192.168.0.2	1032	ALeonard	ALEONARD-XP	CNAMIS	SATURN	-	-	-";

    let rec = stringrecord(data);

    assert!(Ntlm::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_kerberos() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	request_type	client	service	success	error_msg	from	till	cipher	forwardable	renewable	client_cert_subject	client_cert_fuid	server_cert_subject	server_cert_fuid
    let data = "1669773412.689790	CHhAvVGS1DHFjwGM9	192.168.1.31	64889	192.168.1.32	88	TGS	vladg/VLADG.NET	krbtgt/VLADG.NET	T	-	-	0.000000	aes256-cts-hmac-sha1-96	T	F	-	-	-	-";

    let rec = stringrecord(data);

    assert!(Kerberos::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_ssh() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	auth_success	auth_attempts	direction	client	server	cipher_alg	mac_alg	compression_alg	kex_alg	host_key_alg	host_key
    let data = "1669773412.689790	CUM0KZ3MLUfNB0cl11	192.168.2.1	55179	192.168.2.158	2200	2	T	1	-	SSH-2.0-OpenSSH_6.2	SSH-2.0-paramiko_1.15.2	aes128-ctr	hmac-md5	none	diffie-hellman-group-exchange-sha1	ssh-rsa	60:73:38:44:cb:51:86:65:7f:de:da:a2:2b:5a:57:d5";

    let rec = stringrecord(data);

    assert!(Ssh::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_dce_rpc() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	rtt	named_pipe	endpoint	operation
    let data = "1669773412.689790	CmES5u32sYpV7JYN	192.168.0.173	1066	192.168.0.2	135	0.000375	135	epmapper	ept_map";

    let rec = stringrecord(data);

    assert!(DceRpc::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_ftp() {
    // ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	user    password    command reply_code  reply_mgs   data_channel.passive   data_channel.orig_h   data_channel.resp_h   data_channel.resp_p
    let data = "1669773412.689790	CmES5u32sYpV7JYN	192.168.4.76	53380	196.216.2.24	21	anonymous	ftp@example.com	EPSV	229	Entering Extended Passive Mode  (|||31746|)	T	192.168.4.76	196.216.2.24	31746";

    let rec = stringrecord(data);

    assert!(Ftp::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_ldap() {
    //ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	message_id	version	opcode	result	diagnostic_message	object	argument
    let data = "1686710041.192255	CHhAvVGS1DHFjwGM9	10.0.0.1	25936	10.0.0.2	3268	tcp	1	3	bind simple	success	-	xxxxxxxxxxx@xx.xxx.xxxxx.net	REDACTED";

    let rec = stringrecord(data);

    assert!(Ldap::try_from_zeek_record(&rec).is_ok());
}

#[test]
fn zeek_tls() {
    //fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	resumed	last_alert	next_protocol	established	ssl_history	cert_chain_fps	client_cert_chain_fps	sni_matches_cert
    let data = "1686710041.192255	CiGlb63Xpb58HD7LVf	172.30.1.206	43672	211.249.221.105	443	TLSv12	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	x25519	kakao.com	F	-	h2	T	CsxknGIi	597e3ba5bf295718aa5691d0a153493cb8f2f2691aa10c1f504c1413479bccb6,4bcc5e234fe81ede4eaf883aa19c31335b0b26e85e066b9945e4cb6153eb20c2,cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f	(empty)	T";

    let rec = stringrecord(data);

    assert!(Tls::try_from_zeek_record(&rec).is_ok());
}

fn stringrecord(data: &str) -> StringRecord {
    let rdr = ReaderBuilder::new()
        .delimiter(b'\t')
        .has_headers(false)
        .from_reader(data.as_bytes());

    rdr.into_records().next().unwrap().unwrap()
}
