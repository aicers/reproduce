use csv::ReaderBuilder;
use csv::StringRecord;
use giganto_client::ingest::{
    network::{
        Bootp, Conn, DceRpc, Dhcp, Dns, Ftp, Http, Icmp, Kerberos, Ldap, MalformedDns, Mqtt, Nfs,
        Ntlm, Radius, Rdp, Smb, Smtp, Ssh, Tls,
    },
    sysmon::{
        DnsEvent, FileCreate, FileCreateStreamHash, FileCreationTimeChanged, FileDelete,
        FileDeleteDetected, ImageLoaded, NetworkConnection, PipeEvent, ProcessCreate,
        ProcessTampering, ProcessTerminated, RegistryKeyValueRename, RegistryValueSet,
    },
};

use super::TryFromGigantoRecord;

#[test]
fn giganto_conn() {
    let data = "1669735962.571151000	localhost	fe80::2267:7cff:fef0:cb09	133	ff02::2	134	1	sf	0.000000000	0	-	0	0	1	0	21515	27889";

    let rec = stringrecord(data);

    assert!(Conn::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_conn_rfc3339_start_time() {
    const RFC3339_START_TIME: &str = "2026-06-12T05:06:10.522174019+00:00";
    let data = format!(
        "1669735962.571151000\tlocalhost\tfe80::2267:7cff:fef0:cb09\t133\t\
         ff02::2\t134\t1\tsf\t{RFC3339_START_TIME}\t0\t-\t0\t0\t1\t0\t21515\t27889"
    );
    let rec = stringrecord(&data);

    let (conn, record_time) = Conn::try_from_giganto_record(&rec).unwrap();
    assert_eq!(record_time, 1_669_735_962_571_151_000);
    let expected_start_time = i64::try_from(
        RFC3339_START_TIME
            .parse::<jiff::Timestamp>()
            .expect("valid RFC3339 sample")
            .as_nanosecond(),
    )
    .expect("nanoseconds fit in i64");
    assert_eq!(conn.start_time, expected_start_time);
}

#[test]
fn giganto_conn_legacy_epoch_decimal_start_time() {
    let data = "1669735962.571151000	localhost	fe80::2267:7cff:fef0:cb09	133\t\
                ff02::2\t134\t1\tsf\t1669735962.571151000\t0\t-\t0\t0\t1\t0\t21515\t27889";
    let rec = stringrecord(data);

    let (conn, _) = Conn::try_from_giganto_record(&rec).unwrap();
    assert_eq!(conn.start_time, 1_669_735_962_571_151_000);
}

#[test]
fn giganto_http() {
    let data = "1669773412.241856000	localhost	129.204.40.54	47697	218.144.35.150	80	0	0.000000000	0	1	0	21515	27889	GET	218.144.35.150	/root11.php	-	1.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36	0	286	302	Found	-	-	-	-	-	-	-	-	10,10,10	-";

    let rec = stringrecord(data);

    assert!(Http::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_rdp() {
    let data = "1669775611.098308000	localhost	112.160.137.136	61572	103.153.182.151	3389	0	0.000000000	0	1	0	21515	27889	hello";

    let rec = stringrecord(data);

    assert!(Rdp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_smtp() {
    let data = "1669136154.131718000	localhost	220.73.219.213	51280	67.195.204.72	25	0	0.000000000	0	1	0	21515	27889	hanjinyea@monami.com	-	-	-	-	-	-";

    let rec = stringrecord(data);

    assert!(Smtp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_dns() {
    let data = "1664549996.073650000	collect	59.18.121.131	28116	211.252.150.11	53	17	0.000000000	0	1	0	21515	27889	discoplexa4.pl	-	30565	0	C_INTERNET	TXT	0	false	false	true	false	0";

    let rec = stringrecord(data);

    assert!(Dns::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_malformed_dns() {
    let data = "1761194588.611804000	localhost	127.0.0.1	46378	31.3.245.133	80	17	1761194588.611826000	1	1	2	100	200	1	42	1	1	0	0	1	1	16	32	[[65, 78, 61, 6d, 70, 6c, 65, 2e, 63, 6f, 6d]]	[[c0, c]]";

    let rec = stringrecord(data);

    assert!(MalformedDns::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ntlm() {
    let data = "1614130258.669753000	localhost	10.200.90.100	59271	192.168.0.111	445	0	0.000000000	0	1	0	21515	27889	-	it	-	-	-";

    let rec = stringrecord(data);

    assert!(Ntlm::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_kerberos() {
    let data = "1562093132.125665000	localhost	89.248.167.131	24067	210.117.142.55	88	0	0.000000000	0	1	0	21515	27889	0.000000000	0.000000000	1	client_realm	1	cname1,cname2	realm	1	sname1,sname2";

    let rec = stringrecord(data);

    assert!(Kerberos::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_kerberos_rfc3339_datetimes() {
    const RFC3339_START_TIME: &str = "2026-06-12T05:06:10.522174019+00:00";
    const RFC3339_CLIENT_TIME: &str = "2026-06-12T05:06:11.000000000+00:00";
    const RFC3339_SERVER_TIME: &str = "2026-06-12T05:06:12.000000000+00:00";
    let data = format!(
        "1562093132.125665000\tlocalhost\t89.248.167.131\t24067\t210.117.142.55\t\
         88\t0\t{RFC3339_START_TIME}\t0\t1\t0\t21515\t27889\t{RFC3339_CLIENT_TIME}\t\
         {RFC3339_SERVER_TIME}\t1\tclient_realm\t1\tcname1,cname2\trealm\t1\tsname1,sname2"
    );
    let rec = stringrecord(&data);

    let (kerberos, record_time) = Kerberos::try_from_giganto_record(&rec).unwrap();
    assert_eq!(record_time, 1_562_093_132_125_665_000);
    assert_eq!(kerberos.start_time, rfc3339_to_nanos(RFC3339_START_TIME));
    assert_eq!(kerberos.client_time, rfc3339_to_nanos(RFC3339_CLIENT_TIME));
    assert_eq!(kerberos.server_time, rfc3339_to_nanos(RFC3339_SERVER_TIME));
}

#[test]
fn giganto_ssh() {
    let data = "1562093121.802019000	localhost	114.249.237.38	41260	203.254.132.18	22	0	0.000000000	0	1	0	21515	27889	SSH-2.0-Go	SSH-1.99-Cisco-1.25	aes128-cbc	hmac-sha1	none	diffie-hellman-group1-sha1	ssh-rsa	-	-	-	-	-	-";

    let rec = stringrecord(data);

    assert!(Ssh::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_dce_rpc() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	1614130373.991064000	0	1	0	21515	27889	(0,0883AFE11F5DC91191A408002B14A0FA,3,0,045D888AEB1CC9119FE808002B104860,2,0,0,0),(1,1234567890ABCDEF1234567890ABCDEF,1,2,FEDCBA0987654321FEDCBA0987654321,3,4,5,6)	0:0,1:7";

    let rec = stringrecord(data);

    assert!(DceRpc::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ftp() {
    let data = r"1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	1614130373.991064000	0	1	0	21515	27889	anonymous	ftp@example.com	(EPSV,229,Entering Extended Passive Mode,true,192.168.4.76,196.216.2.24,31746,ftp://192.168.0.7/pub/stats/afrinic/delegated-afrinic-extended-latest.md5,74,226)";

    let rec = stringrecord(data);

    assert!(Ftp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ftp_reply_230() {
    let data = r"1614130373.991064000	localhost	192.168.0.111	21	192.168.0.7	49670	6	1614130373.991064000	0	1	0	21515	27889	csanders	echo	(USER,230,User logged in, proceed,false,192.168.0.111,192.168.0.7,20,ftp://192.168.0.7/,0,1614130373991064000)";

    let rec = stringrecord(data);

    assert!(Ftp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_mqtt() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	0.000000000	0	1	0	21515	27889	mqtt	3	my_client_id	10	topic1,topic2	10,10,10";

    let rec = stringrecord(data);

    assert!(Mqtt::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_ldap() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	0	1	0	21515	27889	2	3	opcode	result	diagnostic_mgs	object	argument";

    let rec = stringrecord(data);

    assert!(Ldap::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_tls() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	0	1	0	21515	27889	server_name	alpn_protocol	ja3	version	771,769,770	0,1,2	10	0,1	ja3s	serial	sub_country	sub_org_name	sub_comm_name	1700000000.000000000	1800000000.000000000	sub_alt_name	issuer_country	issuer_org_name	issuer_org_unit_name	issuer_common_name	10";

    let rec = stringrecord(data);

    assert!(Tls::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_tls_rfc3339_datetimes() {
    const RFC3339_START_TIME: &str = "2026-06-12T05:06:10.522174019+00:00";
    const RFC3339_NOT_BEFORE: &str = "2025-01-01T00:00:00.000000000+00:00";
    const RFC3339_NOT_AFTER: &str = "2027-01-01T00:00:00.000000000+00:00";
    let data = format!(
        "1614130373.991064000\tlocalhost\t192.168.0.111\t58459\t192.168.0.7\t\
         49670\t0\t{RFC3339_START_TIME}\t0\t1\t0\t21515\t27889\tserver_name\t\
         alpn_protocol\tja3\tversion\t771,769,770\t0,1,2\t10\t0,1\tja3s\tserial\t\
         sub_country\tsub_org_name\tsub_comm_name\t{RFC3339_NOT_BEFORE}\t\
         {RFC3339_NOT_AFTER}\tsub_alt_name\tissuer_country\tissuer_org_name\t\
         issuer_org_unit_name\tissuer_common_name\t10"
    );
    let rec = stringrecord(&data);

    let (tls, record_time) = Tls::try_from_giganto_record(&rec).unwrap();
    assert_eq!(record_time, 1_614_130_373_991_064_000);
    assert_eq!(tls.start_time, rfc3339_to_nanos(RFC3339_START_TIME));
    assert_eq!(
        tls.validity_not_before,
        rfc3339_to_nanos(RFC3339_NOT_BEFORE)
    );
    assert_eq!(tls.validity_not_after, rfc3339_to_nanos(RFC3339_NOT_AFTER));
}

#[test]
fn giganto_tls_legacy_epoch_decimal_validity() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7\t\
                49670\t0\t0.000000000\t0\t1\t0\t21515\t27889\tserver_name\t\
                alpn_protocol\tja3\tversion\t771,769,770\t0,1,2\t10\t0,1\tja3s\t\
                serial\tsub_country\tsub_org_name\tsub_comm_name\t\
                1700000000.000000000\t1800000000.000000000\tsub_alt_name\t\
                issuer_country\tissuer_org_name\tissuer_org_unit_name\t\
                issuer_common_name\t10";
    let rec = stringrecord(data);

    let (tls, _) = Tls::try_from_giganto_record(&rec).unwrap();
    assert_eq!(tls.validity_not_before, 1_700_000_000_000_000_000);
    assert_eq!(tls.validity_not_after, 1_800_000_000_000_000_000);
}

#[test]
fn giganto_smb() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	0	1	0	21515	27889	0	path	service	file_name	10	20	30	10000000	20000000	10000000	20000000";

    let rec = stringrecord(data);

    assert!(Smb::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_nfs() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	0	0.000000000	0	1	0	21515	27889	-	-";

    let rec = stringrecord(data);

    assert!(Nfs::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_bootp() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	0.000000000	0	1	0	21515	27889	0	1	2	3	192.168.4.1	192.168.4.2	192.168.4.3	192.168.4.4	0,1,2	sname	file";

    let rec = stringrecord(data);

    assert!(Bootp::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_dhcp() {
    let data = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	0.000000000	0	1	0	21515	27889	0	192.168.4.1	192.168.4.2	192.168.4.3	192.168.4.4	192.168.4.5	192.168.4.11,192.168.4.22	192.168.4.33,192.168.4.44	192.168.4.6	1	192.168.4.7	0,1,2	message	1	1	0,1,2	1	0,1,2	53:05,51:00015180";

    let rec = stringrecord(data);

    let (dhcp, _) = Dhcp::try_from_giganto_record(&rec).unwrap();
    assert_eq!(
        dhcp.options,
        vec![(53, vec![0x05]), (51, vec![0x00, 0x01, 0x51, 0x80])]
    );

    // Empty options
    let data_empty = "1614130373.991064000	localhost	192.168.0.111	58459	192.168.0.7	49670	6	0.000000000	0	1	0	21515	27889	0	192.168.4.1	192.168.4.2	192.168.4.3	192.168.4.4	192.168.4.5	192.168.4.11,192.168.4.22	192.168.4.33,192.168.4.44	192.168.4.6	1	192.168.4.7	0,1,2	message	1	1	0,1,2	1	0,1,2	-";
    let rec_empty = stringrecord(data_empty);
    let (dhcp_empty, _) = Dhcp::try_from_giganto_record(&rec_empty).unwrap();
    assert!(dhcp_empty.options.is_empty());
}

#[test]
fn giganto_dhcp_invalid_options() {
    let base = "1614130373.991064000\tlocalhost\t192.168.0.111\t58459\t192.168.0.7\t49670\t6\t0.000000000\t0\t1\t0\t21515\t27889\t0\t192.168.4.1\t192.168.4.2\t192.168.4.3\t192.168.4.4\t192.168.4.5\t192.168.4.11,192.168.4.22\t192.168.4.33,192.168.4.44\t192.168.4.6\t1\t192.168.4.7\t0,1,2\tmessage\t1\t1\t0,1,2\t1\t0,1,2\t";

    // Missing colon separator
    let rec = stringrecord(&format!("{base}invalid"));
    assert!(Dhcp::try_from_giganto_record(&rec).is_err());

    // Tag not a valid u8
    let rec = stringrecord(&format!("{base}999:05"));
    assert!(Dhcp::try_from_giganto_record(&rec).is_err());

    // Odd-length hex value
    let rec = stringrecord(&format!("{base}53:0"));
    assert!(Dhcp::try_from_giganto_record(&rec).is_err());

    // Invalid hex characters
    let rec = stringrecord(&format!("{base}53:ZZZZ"));
    assert!(Dhcp::try_from_giganto_record(&rec).is_err());
}

#[test]
fn giganto_radius() {
    let data = "1756197618.963374000	localhost	127.0.0.1	53031	192.0.2.1	1812	17	1440447766.441298000	0	1	0	21515	27889	103	1	255	40b664dbf5d681b2adbd1769515118c8		115,116,101,118,101	219,198,196,183,88,190,20,240,5,179,135,124,158,47,182,1	-	192.168.0.28	123	-	-	0	";

    let rec = stringrecord(data);

    assert!(Radius::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn giganto_icmp() {
    let data = "1756197618.963374000	localhost	192.168.1.1	192.168.1.2	1	1000000000.000000000	0	1	1	100	100	8	0	1234	1	56	[8, 0, ff, ff]";

    let rec = stringrecord(data);

    assert!(Icmp::try_from_giganto_record(&rec).is_ok());
}

fn stringrecord(data: &str) -> StringRecord {
    let rdr = ReaderBuilder::new()
        .delimiter(b'\t')
        .has_headers(false)
        .from_reader(data.as_bytes());

    rdr.into_records().next().unwrap().unwrap()
}

fn rfc3339_to_nanos(value: &str) -> i64 {
    i64::try_from(
        value
            .parse::<jiff::Timestamp>()
            .expect("valid RFC3339 sample")
            .as_nanosecond(),
    )
    .expect("nanoseconds fit in i64")
}

#[test]
fn sysmon_process_create_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{11111111-2222-3333-4444-555555555555}	1234	C:\\Windows\\System32\\cmd.exe	10.0.0.1	Test description	Test product	Test company	cmd.exe	\"C:\\Windows\\System32\\cmd.exe\" /c dir	C:\\Windows\\System32\\	DOMAIN\\User	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	1001	2	High	SHA256=ABCDEF,MD5=123456	{99999999-8888-7777-6666-555555555555}	4321	C:\\Windows\\explorer.exe	explorer.exe /something	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(ProcessCreate::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_file_create_time_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{11111111-2222-3333-4444-555555555555}	1234	C:\\Windows\\System32\\cmd.exe	C:\\Temp\\file.txt	1691452700.000000000	1691452600.000000000	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(FileCreationTimeChanged::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_file_create_time_rfc3339_creation_utc_time() {
    const RFC3339_CREATION: &str = "2026-06-12T05:06:10.522174019+00:00";
    const RFC3339_PREVIOUS: &str = "2026-06-12T05:06:09.000000000+00:00";
    let data = format!(
        "1691452807.978000000\tsensor1\tagent-a\tagent-id-1\t\
         {{11111111-2222-3333-4444-555555555555}}\t1234\tC:\\Windows\\System32\\cmd.exe\t\
         C:\\Temp\\file.txt\t{RFC3339_CREATION}\t{RFC3339_PREVIOUS}\tDOMAIN\\User"
    );
    let rec = stringrecord(&data);

    let (event, record_time) = FileCreationTimeChanged::try_from_giganto_record(&rec).unwrap();
    assert_eq!(record_time, 1_691_452_807_978_000_000);
    assert_eq!(event.creation_utc_time, rfc3339_to_nanos(RFC3339_CREATION));
    assert_eq!(
        event.previous_creation_utc_time,
        rfc3339_to_nanos(RFC3339_PREVIOUS)
    );
}

#[test]
fn sysmon_network_connect_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	C:\\Windows\\System32\\svchost.exe	DOMAIN\\User	TCP	true	false	192.168.0.10	desktop	51515	-	false	10.0.0.1	server	443	https";
    let rec = stringrecord(data);
    assert!(NetworkConnection::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_process_terminate_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	C:\\Windows\\System32\\svchost.exe	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(ProcessTerminated::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_file_create_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	C:\\Windows\\System32\\svchost.exe	C:\\Temp\\created.txt	1691452700.000000000	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(FileCreate::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_file_create_stream_hash_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	C:\\Windows\\System32\\svchost.exe	C:\\Temp\\created.txt	1691452700.000000000	SHA256=ABCDEF,MD5=123456	contents	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(FileCreateStreamHash::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_dns_query_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	example.com	0	1.1.1.1;8.8.8.8	C:\\Windows\\System32\\svchost.exe	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(DnsEvent::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_file_delete_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	DOMAIN\\User	C:\\Windows\\System32\\svchost.exe	C:\\Temp\\deleted.txt	SHA256=ABCDEF,MD5=123456	true	false";
    let rec = stringrecord(data);
    assert!(FileDelete::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_process_tamper_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	C:\\Windows\\System32\\svchost.exe	OpenProcess	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(ProcessTampering::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_image_load_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	C:\\Windows\\System32\\svchost.exe	C:\\Windows\\System32\\kernel32.dll	10.0.0.0	Test description	Test product	Test company	kernel32.dll	SHA256=ABCDEF,MD5=123456	true	Microsoft	Valid	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(ImageLoaded::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_registry_value_set_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	RenameValue	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	C:\\Windows\\System32\\reg.exe	HKLM\\Software\\Test	DWORD (0x1)	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(RegistryValueSet::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_registry_key_rename_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	RenameValue	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	C:\\Windows\\System32\\reg.exe	HKLM\\Software\\Test	HKLM\\Software\\TestNew	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(RegistryKeyValueRename::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_pipe_event_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	CreatePipe	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	\\\\.\\pipe\\testpipe	C:\\Windows\\System32\\svchost.exe	DOMAIN\\User";
    let rec = stringrecord(data);
    assert!(PipeEvent::try_from_giganto_record(&rec).is_ok());
}

#[test]
fn sysmon_file_delete_detected_sample() {
    let data = "1691452807.978000000	sensor1	agent-a	agent-id-1	{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}	4321	DOMAIN\\User	C:\\Windows\\System32\\svchost.exe	C:\\Temp\\deleted.txt	SHA256=ABCDEF,MD5=123456	false";
    let rec = stringrecord(data);
    assert!(FileDeleteDetected::try_from_giganto_record(&rec).is_ok());
}
