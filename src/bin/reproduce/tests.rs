use std::fs::{self, File};
#[cfg(feature = "netflow")]
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use giganto_client::{
    RawEventKind,
    connection::server_handshake,
    frame::{RecvError, SendError, recv_raw},
    ingest::{log::Log as GigantoLog, receive_record_header},
};
use quinn::Endpoint;
use reproduce::config::GigantoConfig;
use reproduce::sender::{CHANNEL_CLOSE_TIMESTAMP, REQUIRED_GIGANTO_VERSION};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tempfile::tempdir;
use tokio::time::timeout;

use super::*;
use crate::config::Directory;

#[cfg(feature = "netflow")]
const ETHERNET_DATALINK: u32 = 1;
#[cfg(feature = "netflow")]
const PROTO_UDP: u8 = 17;
const TEST_ROOT_PEM: &str = "tests/root.pem";
const TEST_CERT_PEM: &str = "tests/cert.pem";
const TEST_KEY_PEM: &str = "tests/key.pem";
const TEST_SERVER_NAME: &str = "localhost";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const SYSMON_HEADER: &str = "agent_name\tagent_id\tevent_action\tutc_time\tprocess_guid\tprocess_id\timage\t\
     file_version\tdescription\tproduct\tcompany\toriginal_file_name\tcommand_line\t\
     current_directory\tuser\tlogon_guid\tlogon_id\tterminal_session_id\t\
     integrity_level\thashes\tparent_process_guid\tparent_process_id\t\
     parent_image\tparent_command_line\tparent_user";
const SYSMON_PC_1: &str = "sensor\tagent001\tProcess Create\t2023-01-15 14:30:45.123456\t{AAAA-0001}\t1234\tC:\\notepad.exe\t1.0\tdesc\tprod\tco\torig.exe\tnotepad.exe /f\tC:\\Windows\\\tSYSTEM\t{BBBB-0001}\t0x3e7\t0\tSystem\tSHA256=abc123\t{CCCC-0001}\t5678\tC:\\explorer.exe\texplorer.exe\tSYSTEM";
const ZEEK_CONN_1: &str = "1669773412.689790\tuid001aaa\t192.168.1.77\t57655\t209.197.168.151\t1024\ttcp\tirc-dcc-data\t2.256935\t124\t42208\tSF\t-\t-\t0\tShAdDaFf\t28\t1592\t43\t44452\t-";
const MIGR_CONN_1: &str = "1669773412.655728000\tsrc1\t192.168.1.77\t57655\t209.197.168.151\t1024\t6\tSF\t1669773412.655728000\t2256935000\tirc-dcc-data\t124\t42208\t28\t43\t1592\t44452";
const OPLOG_LINE: &str = "2023-01-02T07:36:17Z INFO msg1";
const WAPPLES_LINE: &str = "<182>Jan 9 09:26:09 host wplogd: WAPPLES INTRUSION WAPPLES \
    DETECTION TIME : 2020-01-09 09:26:09 +0900 WAPPLES RULE NAME : \
    SQL Injection WAPPLES (client 192.168.1.100 WAPPLES) -> \
    (server 10.0.0.1:80)";

struct MockSender {
    batch_sizes: Vec<usize>,
    ensured_protocols: Vec<RawEventKind>,
    finish_calls: usize,
    reconnect_calls: usize,
    reset_header_calls: usize,
    header_pending: bool,
}

impl Default for MockSender {
    fn default() -> Self {
        Self {
            batch_sizes: Vec::new(),
            ensured_protocols: Vec::new(),
            finish_calls: 0,
            reconnect_calls: 0,
            reset_header_calls: 0,
            header_pending: true,
        }
    }
}

#[async_trait]
impl PipelineSender for MockSender {
    async fn ensure_header_sent(
        &mut self,
        protocol: RawEventKind,
    ) -> std::result::Result<(), reproduce::sender::SenderError> {
        if self.header_pending {
            self.ensured_protocols.push(protocol);
            self.header_pending = false;
        }
        Ok(())
    }

    async fn send_batch(&mut self, events: &[(i64, Vec<u8>)]) -> Result<(), SendError> {
        self.batch_sizes.push(events.len());
        Ok(())
    }

    async fn reconnect(&mut self) -> std::result::Result<(), reproduce::sender::SenderError> {
        self.reconnect_calls += 1;
        Ok(())
    }
}

#[async_trait]
impl ControllerSender for MockSender {
    async fn finish(&mut self) -> Result<()> {
        self.finish_calls += 1;
        Ok(())
    }

    fn reset_header(&mut self) {
        self.reset_header_calls += 1;
        self.header_pending = true;
    }
}

fn file_config(
    transfer_skip_count: Option<u64>,
    last_transfer_line_suffix: Option<&str>,
) -> FileConfig {
    FileConfig {
        export_from_giganto: Some(false),
        polling_mode: false,
        transfer_count: None,
        transfer_skip_count,
        last_transfer_line_suffix: last_transfer_line_suffix.map(str::to_string),
    }
}

fn test_config(input: &Path, kind: &str) -> Config {
    Config {
        giganto: GigantoConfig {
            cert: String::new(),
            key: String::new(),
            ca_certs: Vec::new(),
            ingest_srv_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
            name: "giganto".to_string(),
        },
        kind: kind.to_string(),
        input: input.to_string_lossy().into_owned(),
        report: false,
        report_dir: None,
        log_path: None,
        file: Some(FileConfig {
            export_from_giganto: Some(false),
            polling_mode: false,
            transfer_count: None,
            transfer_skip_count: None,
            last_transfer_line_suffix: None,
        }),
        directory: None,
        elastic: None,
    }
}

fn controller_for_file(
    input: &Path,
    kind: &str,
    export_from_giganto: Option<bool>,
    last_transfer_line_suffix: Option<&str>,
) -> Controller {
    let mut config = test_config(input, kind);
    config.file = Some(FileConfig {
        export_from_giganto,
        polling_mode: false,
        transfer_count: None,
        transfer_skip_count: None,
        last_transfer_line_suffix: last_transfer_line_suffix.map(str::to_string),
    });
    Controller::new(config)
}

fn controller_for_directory(input: &Path, kind: &str, prefix: Option<&str>) -> Controller {
    let mut config = test_config(input, kind);
    config.directory = Some(Directory {
        file_prefix: prefix.map(str::to_string),
        polling_mode: false,
    });
    Controller::new(config)
}

fn write_text_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("test fixture should be written");
    path
}

#[cfg(feature = "netflow")]
fn hex_to_bytes(s: &str) -> Vec<u8> {
    let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    filtered
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("valid hex bytes"), 16)
                .expect("valid hex pair")
        })
        .collect()
}

#[cfg(feature = "netflow")]
fn write_pcap(path: &Path, packets: &[Vec<u8>]) {
    let mut file = File::create(path).expect("pcap fixture should be created");
    file.write_all(&0xa1b2_c3d4_u32.to_le_bytes())
        .expect("pcap header should be written");
    file.write_all(&2u16.to_le_bytes())
        .expect("pcap version major should be written");
    file.write_all(&4u16.to_le_bytes())
        .expect("pcap version minor should be written");
    file.write_all(&0i32.to_le_bytes())
        .expect("pcap timezone should be written");
    file.write_all(&0u32.to_le_bytes())
        .expect("pcap sigfigs should be written");
    file.write_all(&65_535u32.to_le_bytes())
        .expect("pcap snaplen should be written");
    file.write_all(&ETHERNET_DATALINK.to_le_bytes())
        .expect("pcap linktype should be written");

    for packet in packets {
        let packet_len = u32::try_from(packet.len()).unwrap_or_default();
        file.write_all(&0u32.to_le_bytes())
            .expect("packet seconds should be written");
        file.write_all(&0u32.to_le_bytes())
            .expect("packet micros should be written");
        file.write_all(&packet_len.to_le_bytes())
            .expect("captured length should be written");
        file.write_all(&packet_len.to_le_bytes())
            .expect("original length should be written");
        file.write_all(packet)
            .expect("packet payload should be written");
    }
}

#[cfg(feature = "netflow")]
fn build_ipv4_udp_packet(payload: &[u8], dst_port: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0u8; 6]);
    bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    bytes.extend_from_slice(&0x0800u16.to_be_bytes());

    let total_len = 20u16 + 8u16 + u16::try_from(payload.len()).unwrap_or_default();
    bytes.push(0x45);
    bytes.push(0);
    bytes.extend_from_slice(&total_len.to_be_bytes());
    bytes.extend_from_slice(&0x1234u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.push(64);
    bytes.push(PROTO_UDP);
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&[10, 0, 0, 1]);
    bytes.extend_from_slice(&[10, 0, 0, 2]);

    let udp_len = 8u16 + u16::try_from(payload.len()).unwrap_or_default();
    bytes.extend_from_slice(&1000u16.to_be_bytes());
    bytes.extend_from_slice(&dst_port.to_be_bytes());
    bytes.extend_from_slice(&udp_len.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(payload);

    bytes
}

#[cfg(feature = "netflow")]
fn v5_header_bytes(count: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&5u16.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&3u32.to_be_bytes());
    bytes.extend_from_slice(&4u32.to_be_bytes());
    bytes.push(5);
    bytes.push(6);
    bytes.extend_from_slice(&0x4001u16.to_be_bytes());
    bytes
}

#[cfg(feature = "netflow")]
fn build_v5_packet(record_count: u16) -> Vec<u8> {
    let record = hex_to_bytes(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/netflow/v5_record.hex"
    )));

    let mut payload = v5_header_bytes(record_count);
    for _ in 0..record_count {
        payload.extend_from_slice(&record);
    }

    build_ipv4_udp_packet(&payload, 2055)
}

fn default_run_options() -> CollectorRunOptions {
    let (_shutdown_tx, shutdown) = watch::channel(false);
    CollectorRunOptions {
        offset: 0,
        count_sent: 0,
        file_polling_mode: false,
        dir_polling_mode: false,
        shutdown,
    }
}

fn report_for(input: &Path, kind: &str) -> Report {
    Report::new(test_config(input, kind))
}

fn fixture_path(relative: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(relative)
        .to_string_lossy()
        .into_owned()
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let cert_pem = fs::read(path)
        .with_context(|| format!("test certificate should be readable: {}", path.display()))?;
    rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<Result<_, _>>()
        .context("test certificate PEM should parse")
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key_pem = fs::read(path)
        .with_context(|| format!("test key should be readable: {}", path.display()))?;
    rustls_pemfile::private_key(&mut &*key_pem)
        .context("test key PEM should parse")?
        .context("test key PEM should contain a private key")
}

fn build_server_endpoint() -> Result<(Endpoint, SocketAddr)> {
    let cert_chain = load_cert_chain(Path::new(&fixture_path(TEST_CERT_PEM)))?;
    let private_key = load_private_key(Path::new(&fixture_path(TEST_KEY_PEM)))?;
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("test server certificate configuration should be valid")?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("test server QUIC config should build")?,
    ));
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint =
        Endpoint::server(server_config, bind_addr).context("test server endpoint should bind")?;
    let addr = endpoint
        .local_addr()
        .context("test server endpoint should have a local address")?;
    Ok((endpoint, addr))
}

struct ServerCapture {
    record_header: u32,
    events: Vec<(i64, Vec<u8>)>,
}

async fn serve_single_connection(server_endpoint: Endpoint) -> Result<ServerCapture> {
    let incoming = timeout(TEST_TIMEOUT, server_endpoint.accept())
        .await
        .context("test server should accept a controller connection in time")?
        .context("test server endpoint should stay open while accepting")?;
    let connection = incoming
        .await
        .context("controller connection should complete QUIC setup")?;

    let _handshake = server_handshake(&connection, REQUIRED_GIGANTO_VERSION)
        .await
        .context("controller sender should complete the Giganto handshake")?;
    let (mut server_send, mut server_recv) = timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .context("test server should accept the data stream in time")?
        .context("test server should accept the data stream")?;

    let mut header = [0_u8; std::mem::size_of::<u32>()];
    receive_record_header(&mut server_recv, &mut header)
        .await
        .context("test server should receive the record header")?;

    let mut events = Vec::new();
    let mut batch_buf = Vec::new();
    loop {
        match timeout(TEST_TIMEOUT, recv_raw(&mut server_recv, &mut batch_buf)).await {
            Ok(Ok(())) => {
                let batch: Vec<(i64, Vec<u8>)> = bincode::deserialize(&batch_buf)
                    .context("server batch payload should deserialize")?;
                let mut saw_close = false;
                for (timestamp, payload) in batch {
                    if timestamp == CHANNEL_CLOSE_TIMESTAMP {
                        saw_close = true;
                    } else {
                        events.push((timestamp, payload));
                    }
                }
                if saw_close {
                    server_send
                        .write_all(&CHANNEL_CLOSE_TIMESTAMP.to_be_bytes())
                        .await
                        .context("test server should send the close ACK")?;
                    server_send
                        .finish()
                        .context("test server ACK stream should finish cleanly")?;
                    break;
                }
            }
            Ok(Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(_)))) => break,
            Ok(Err(err)) => bail!("unexpected server receive error: {err}"),
            Err(_) => bail!("timed out waiting for controller event data"),
        }
    }

    server_endpoint.wait_idle().await;
    Ok(ServerCapture {
        record_header: u32::from_le_bytes(header),
        events,
    })
}

fn giganto_config(input: &Path, kind: &str, server_addr: SocketAddr) -> Config {
    let mut config = test_config(input, kind);
    config.giganto.cert = fixture_path(TEST_CERT_PEM);
    config.giganto.key = fixture_path(TEST_KEY_PEM);
    config.giganto.ca_certs = vec![fixture_path(TEST_ROOT_PEM)];
    config.giganto.ingest_srv_addr = server_addr;
    config.giganto.name = TEST_SERVER_NAME.to_string();
    config
}

fn decode_logs(capture: &ServerCapture) -> Vec<GigantoLog> {
    capture
        .events
        .iter()
        .map(|(_, payload)| {
            bincode::deserialize(payload).expect("captured payload should deserialize as Log")
        })
        .collect()
}

#[test]
fn input_type_elastic() {
    // When input string is "elastic", it should return InputType::Elastic
    let result = input_type("elastic");
    assert_eq!(result, InputType::Elastic);
}

#[test]
fn input_type_directory() {
    // Create a temporary directory
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let dir_path = temp_dir.path().to_string_lossy().to_string();

    // When input is a directory path, it should return InputType::Dir
    let result = input_type(&dir_path);
    assert_eq!(result, InputType::Dir);
}

#[test]
fn input_type_file() {
    // Create a temporary directory and file
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("test_file.csv");
    File::create(&file_path).expect("Failed to create temp file");

    // When input is a file path, it should return InputType::Log
    let result = input_type(&file_path.to_string_lossy());
    assert_eq!(result, InputType::Log);
}

#[test]
fn input_type_nonexistent_path() {
    // Create a temporary directory, then construct a path to a non-existent file within it
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let nonexistent_path = temp_dir.path().join("does_not_exist.log");

    // When input is a non-existent path, it should return InputType::Log
    // (since Path::is_dir() returns false for non-existent paths)
    let result = input_type(&nonexistent_path.to_string_lossy());
    assert_eq!(result, InputType::Log);
}

#[test]
fn valid_agent_filenames() {
    let valid_filenames = [
        "manager.log",
        "data_store.txt",
        "sensor.csv",
        "semi_supervised.json",
        "time_series_generator.log.1",
        "unsupervised.dat",
        "ti_container.out",
    ];

    for filename in valid_filenames {
        let path = Path::new(filename);
        let result = operation_log_agent_name(path);
        assert!(result.is_ok(), "Expected valid agent filename: {filename}");
    }
}

#[test]
fn valid_agent_filenames_with_directory() {
    let valid_paths = [
        "/var/log/manager.txt",
        "/home/user/logs/data_store.csv",
        "relative/path/sensor.json",
        "./semi_supervised.dat",
        "../time_series_generator.out",
    ];

    for path_str in valid_paths {
        let path = Path::new(path_str);
        let result = operation_log_agent_name(path);
        assert!(
            result.is_ok(),
            "Expected valid agent filename with path: {path_str}"
        );
    }
}

#[test]
fn invalid_agent_name_returns_error() {
    let invalid_agent_filenames = [
        "unknown_agent.txt",
        "invalid.csv",
        "test.json",
        "other_service.dat",
        "agent.out",
    ];

    for filename in invalid_agent_filenames {
        let path = Path::new(filename);
        let result = operation_log_agent_name(path);
        assert!(
            result.is_err(),
            "Expected invalid agent name to return an error: {filename}"
        );
    }
}

#[test]
fn returns_error_on_filename_without_dot() {
    let path = Path::new("manager_no_extension");
    let err = operation_log_agent_name(path).expect_err("missing extension must be rejected");
    assert!(err.to_string().contains("must have an extension"));
}

#[test]
fn returns_error_on_empty_path() {
    let path = Path::new("/");
    let err =
        operation_log_agent_name(path).expect_err("path without a file name must be rejected");
    assert!(err.to_string().contains("missing file name"));
}

#[test]
fn valid_agent_with_different_extensions() {
    let valid_with_other_ext = [
        "manager.txt",
        "sensor.csv",
        "data_store.json",
        "unsupervised.log.1",
    ];

    for filename in valid_with_other_ext {
        let path = Path::new(filename);
        let result = operation_log_agent_name(path);
        assert!(
            result.is_ok(),
            "Expected valid agent name regardless of extension: {filename}"
        );
    }
}

#[test]
fn file_to_kind_maps_supported_sysmon_event_codes() {
    let kind = file_to_kind(Path::new("event1_log.csv"))
        .expect("known sysmon event file name should parse");
    assert_eq!(kind, "process_create");

    let kind = file_to_kind(Path::new("event26_log.csv"))
        .expect("known sysmon event file name should parse");
    assert_eq!(kind, "file_delete_detected");
}

#[test]
fn file_to_kind_returns_empty_for_unknown_event_code() {
    let kind = file_to_kind(Path::new("event999_log.csv"))
        .expect("unknown sysmon event file name should still parse");
    assert_eq!(kind, "");
}

#[test]
fn file_to_kind_returns_empty_for_non_matching_file_name() {
    let kind = file_to_kind(Path::new("conn.log")).expect("non-sysmon file name should not error");
    assert_eq!(kind, "");
}

#[test]
fn checkpoint_for_input_returns_none_without_suffix() {
    let checkpoint = checkpoint_for_input("/tmp/input.log", None);
    assert!(checkpoint.is_none());
}

#[test]
fn resolve_offset_prefers_transfer_skip_count_over_checkpoint() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let input_path = temp_dir.path().join("input.log");
    let input = input_path
        .to_str()
        .expect("temporary input path must be valid UTF-8");
    let file = file_config(Some(7), Some("offset"));
    let checkpoint = checkpoint_for_input(input, file.last_transfer_line_suffix.as_deref());
    checkpoint
        .as_ref()
        .expect("checkpoint should exist when a suffix is configured")
        .save(b"42")
        .expect("checkpoint fixture should be written");

    assert_eq!(resolve_offset(&file, checkpoint.as_ref()), 7);
}

#[test]
fn resolve_offset_falls_back_to_checkpoint_value() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let input_path = temp_dir.path().join("input.log");
    let input = input_path
        .to_str()
        .expect("temporary input path must be valid UTF-8");
    let file = file_config(None, Some("offset"));
    let checkpoint = checkpoint_for_input(input, file.last_transfer_line_suffix.as_deref());
    checkpoint
        .as_ref()
        .expect("checkpoint should exist when a suffix is configured")
        .save(b"42")
        .expect("checkpoint fixture should be written");

    assert_eq!(resolve_offset(&file, checkpoint.as_ref()), 42);
}

#[tokio::test]
async fn run_with_sender_processes_log_input_and_finishes() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "input.log", "line1\nline2\n");
    let controller = controller_for_file(&path, "custom", Some(false), None);
    let mut sender = MockSender::default();

    controller
        .run_with_sender(&mut sender)
        .await
        .expect("log input should be processed");

    assert_eq!(sender.batch_sizes, vec![1, 1]);
    assert_eq!(sender.ensured_protocols, vec![RawEventKind::Log]);
    assert_eq!(sender.finish_calls, 1);
}

#[tokio::test]
async fn run_with_sender_processes_directory_input_and_finishes() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    write_text_file(&temp_dir, "keep_b.log", "second\n");
    write_text_file(&temp_dir, "keep_a.log", "first\n");
    write_text_file(&temp_dir, "drop.log", "ignored\n");
    let controller = controller_for_directory(temp_dir.path(), "custom", Some("keep_"));
    let mut sender = MockSender::default();

    controller
        .run_with_sender(&mut sender)
        .await
        .expect("directory input should be processed");

    assert_eq!(sender.batch_sizes, vec![1, 1]);
    assert_eq!(sender.ensured_protocols, vec![RawEventKind::Log]);
    assert_eq!(sender.finish_calls, 1);
}

#[tokio::test]
async fn run_single_processes_operation_log_and_saves_checkpoint() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "manager.log", &format!("{OPLOG_LINE}\n"));
    let controller = controller_for_file(&path, OPERATION_LOG, Some(false), Some("offset"));
    let mut sender = MockSender::default();

    controller
        .run_single(&path, &mut sender, OPERATION_LOG, false)
        .await
        .expect("operation log input should be processed");

    let checkpoint = PathBuf::from(format!("{}_offset", path.to_string_lossy()));
    let checkpoint_contents =
        std::fs::read_to_string(&checkpoint).expect("checkpoint file should be written");
    assert_eq!(sender.batch_sizes, vec![1]);
    assert_eq!(sender.ensured_protocols, vec![RawEventKind::OpLog]);
    assert_eq!(checkpoint_contents, "1");
}

#[tokio::test]
async fn run_single_processes_sysmon_and_resets_header() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(
        &temp_dir,
        "event1_log.csv",
        &format!("{SYSMON_HEADER}\n{SYSMON_PC_1}\n"),
    );
    let controller = controller_for_file(&path, "process_create", Some(false), None);
    let mut sender = MockSender::default();

    controller
        .run_single(&path, &mut sender, "process_create", false)
        .await
        .expect("sysmon input should be processed");

    assert_eq!(sender.batch_sizes, vec![1]);
    assert_eq!(sender.ensured_protocols, vec![RawEventKind::ProcessCreate]);
    assert_eq!(sender.reset_header_calls, 1);
}

#[tokio::test]
async fn run_single_processes_zeek_input() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "conn.log", &format!("{ZEEK_CONN_1}\n"));
    let controller = controller_for_file(&path, "conn", Some(false), None);
    let mut sender = MockSender::default();

    controller
        .run_single(&path, &mut sender, "conn", false)
        .await
        .expect("zeek input should be processed");

    assert_eq!(sender.batch_sizes, vec![1]);
    assert_eq!(sender.ensured_protocols, vec![RawEventKind::Conn]);
}

#[tokio::test]
async fn run_single_processes_migration_input() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "conn.log", &format!("{MIGR_CONN_1}\n"));
    let controller = controller_for_file(&path, "conn", Some(true), None);
    let mut sender = MockSender::default();

    controller
        .run_single(&path, &mut sender, "conn", false)
        .await
        .expect("migration input should be processed");

    assert_eq!(sender.batch_sizes, vec![1]);
    assert_eq!(sender.ensured_protocols, vec![RawEventKind::Conn]);
}

#[tokio::test]
async fn run_single_processes_security_log_input() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "seculog.log", &format!("{WAPPLES_LINE}\n"));
    let controller = controller_for_file(&path, "wapples_fw_6.0", Some(false), None);
    let mut sender = MockSender::default();

    controller
        .run_single(&path, &mut sender, "wapples_fw_6.0", false)
        .await
        .expect("security log input should be processed");

    assert_eq!(sender.batch_sizes, vec![1]);
    assert_eq!(sender.ensured_protocols, vec![RawEventKind::SecuLog]);
}

#[cfg(feature = "netflow")]
#[tokio::test]
async fn run_single_processes_netflow_input() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = temp_dir.path().join("netflow5.pcap");
    write_pcap(&path, &[build_v5_packet(1)]);
    let controller = controller_for_file(&path, "netflow5", Some(false), None);
    let mut sender = MockSender::default();

    controller
        .run_single(&path, &mut sender, "netflow5", false)
        .await
        .expect("netflow input should be processed");

    assert_eq!(sender.batch_sizes, vec![1]);
    assert_eq!(sender.ensured_protocols, vec![RawEventKind::Netflow5]);
}

#[tokio::test]
async fn run_uses_real_sender_for_single_log_input() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "input.log", "alpha\nbeta\n");
    let (server_endpoint, server_addr) =
        build_server_endpoint().expect("test server endpoint should be created");
    let server_task = tokio::spawn(async move { serve_single_connection(server_endpoint).await });
    let controller = Controller::new(giganto_config(&path, "custom", server_addr));

    controller
        .run()
        .await
        .expect("controller should send single-file log input through GigantoSender");

    let capture = server_task
        .await
        .expect("server task should join cleanly")
        .expect("server should capture controller traffic");
    let logs = decode_logs(&capture);
    let first = logs
        .first()
        .expect("server must capture the first log record");
    let second = logs
        .get(1)
        .expect("server must capture the second log record");

    assert_eq!(capture.record_header, u32::from(RawEventKind::Log));
    assert_eq!(logs.len(), 2);
    assert_eq!(first.kind, "custom");
    assert_eq!(first.log, b"alpha".to_vec());
    assert_eq!(second.kind, "custom");
    assert_eq!(second.log, b"beta".to_vec());
}

#[tokio::test]
async fn run_uses_real_sender_for_directory_input() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    write_text_file(&temp_dir, "keep_b.log", "second\n");
    write_text_file(&temp_dir, "keep_a.log", "first\n");
    write_text_file(&temp_dir, "drop.log", "ignored\n");
    let (server_endpoint, server_addr) =
        build_server_endpoint().expect("test server endpoint should be created");
    let server_task = tokio::spawn(async move { serve_single_connection(server_endpoint).await });
    let mut config = giganto_config(temp_dir.path(), "custom", server_addr);
    config.directory = Some(Directory {
        file_prefix: Some("keep_".to_string()),
        polling_mode: false,
    });
    let controller = Controller::new(config);

    controller
        .run()
        .await
        .expect("controller should send directory input through GigantoSender");

    let capture = server_task
        .await
        .expect("server task should join cleanly")
        .expect("server should capture controller traffic");
    let logs = decode_logs(&capture);
    let first = logs
        .first()
        .expect("server must capture the first directory log");
    let second = logs
        .get(1)
        .expect("server must capture the second directory log");

    assert_eq!(capture.record_header, u32::from(RawEventKind::Log));
    assert_eq!(logs.len(), 2);
    assert_eq!(first.log, b"first".to_vec());
    assert_eq!(second.log, b"second".to_vec());
}

#[tokio::test]
async fn run_zeek_kind_dispatches_all_supported_kinds_without_records() {
    let temp_dir = tempdir().expect("temporary directory should be created");

    for kind in ZeekKind::ALL {
        if kind.requires_migration() {
            continue;
        }
        let kind_name = kind.as_str();
        let path = write_text_file(&temp_dir, &format!("{kind_name}.log"), "");
        let mut sender = MockSender::default();

        let pos = run_zeek_kind(
            &path,
            kind_name,
            false,
            default_run_options(),
            &mut sender,
            report_for(&path, kind_name),
        )
        .await
        .expect("supported zeek kind should dispatch even when there are no records");

        assert_eq!(
            pos,
            b"0".to_vec(),
            "empty zeek input should preserve zero-progress checkpoint",
        );
        assert!(
            sender.batch_sizes.is_empty(),
            "empty zeek input should not send any batches",
        );
        assert!(
            sender.ensured_protocols.is_empty(),
            "empty zeek input should not send a record header",
        );
    }

    for kind in ZeekKind::ALL {
        if !kind.requires_migration() {
            continue;
        }
        let kind_name = kind.as_str();
        let path = write_text_file(&temp_dir, &format!("{kind_name}.log"), "");
        let mut sender = MockSender::default();

        let pos = run_zeek_kind(
            &path,
            kind_name,
            true,
            default_run_options(),
            &mut sender,
            report_for(&path, kind_name),
        )
        .await
        .expect("migration-only kind should dispatch in export mode");

        assert_eq!(
            pos,
            b"0".to_vec(),
            "empty migration input should preserve zero-progress checkpoint",
        );
        assert!(
            sender.batch_sizes.is_empty(),
            "empty migration input should not send any batches",
        );
    }
}

#[tokio::test]
async fn run_zeek_migration_only_kind_errors_without_migration_flag() {
    let temp_dir = tempdir().expect("temporary directory should be created");

    for kind in ZeekKind::ALL {
        if !kind.requires_migration() {
            continue;
        }
        let kind_name = kind.as_str();
        let path = write_text_file(&temp_dir, &format!("{kind_name}.log"), "");
        let mut sender = MockSender::default();

        let result = run_zeek_kind(
            &path,
            kind_name,
            false,
            default_run_options(),
            &mut sender,
            report_for(&path, kind_name),
        )
        .await;

        assert!(
            result.is_err(),
            "migration-only kind {kind_name} should error when migration=false",
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("is not supported"),
            "error for {kind_name} should mention unsupported: {err_msg}",
        );
    }
}

#[tokio::test]
async fn run_sysmon_kind_dispatches_all_supported_kinds_without_records() {
    let temp_dir = tempdir().expect("temporary directory should be created");

    for kind in SysmonKind::ALL {
        let kind_name = kind.as_str();
        let path = write_text_file(&temp_dir, &format!("{kind_name}.csv"), "header\n");
        let mut sender = MockSender::default();

        let pos = run_sysmon_kind(
            &path,
            kind_name,
            true,
            default_run_options(),
            &mut sender,
            report_for(&path, kind_name),
        )
        .await
        .expect("supported sysmon kind should dispatch even when there are no records");

        assert_eq!(
            pos,
            b"0".to_vec(),
            "header-only sysmon input should preserve zero-progress checkpoint",
        );
        assert!(
            sender.batch_sizes.is_empty(),
            "header-only sysmon input should not send any batches",
        );
        assert!(
            sender.ensured_protocols.is_empty(),
            "header-only sysmon input should not send a record header",
        );
    }
}

#[tokio::test]
async fn run_security_kind_dispatches_all_supported_kinds() {
    let temp_dir = tempdir().expect("temporary directory should be created");

    for kind in SecurityKind::ALL {
        let kind_name = kind.as_str();
        let path = write_text_file(
            &temp_dir,
            &format!("{kind_name}.log"),
            "not-a-security-log\n",
        );
        let mut sender = MockSender::default();

        let pos = run_security_kind(
            &path,
            kind_name,
            default_run_options(),
            &mut sender,
            report_for(&path, kind_name),
        )
        .await
        .expect("supported security kind should dispatch even if parsing fails");

        assert_eq!(
            pos,
            b"1".to_vec(),
            "invalid security records should still advance the checkpoint"
        );
        assert!(
            sender.batch_sizes.is_empty(),
            "invalid security logs should not send any batches",
        );
    }
}

#[cfg(feature = "netflow")]
#[tokio::test]
async fn run_netflow_kind_dispatches_all_supported_kinds_without_packets() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = temp_dir.path().join("empty.pcap");
    write_pcap(&path, &[]);

    for kind in NetflowKind::ALL {
        let kind_name = kind.as_str();
        let mut sender = MockSender::default();

        let pos = run_netflow_kind(
            &path,
            kind_name,
            default_run_options(),
            &mut sender,
            report_for(&path, kind_name),
        )
        .await
        .expect("supported netflow kind should dispatch even with no packets");

        assert_eq!(
            pos,
            b"0".to_vec(),
            "empty pcap should keep the initial checkpoint"
        );
        assert!(
            sender.batch_sizes.is_empty(),
            "empty pcap should not send any batches",
        );
    }
}

#[tokio::test]
async fn run_zeek_kind_rejects_unknown_kind() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "unknown.log", "");
    let mut sender = MockSender::default();

    let err = run_zeek_kind(
        &path,
        "unknown",
        false,
        default_run_options(),
        &mut sender,
        report_for(&path, "unknown"),
    )
    .await
    .expect_err("unknown zeek kind must be rejected");
    assert!(err.to_string().contains("unknown zeek/migration kind"));
}

#[tokio::test]
async fn run_sysmon_kind_rejects_unknown_kind() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "unknown.csv", "header\n");
    let mut sender = MockSender::default();

    let err = run_sysmon_kind(
        &path,
        "unknown",
        false,
        default_run_options(),
        &mut sender,
        report_for(&path, "unknown"),
    )
    .await
    .expect_err("unknown sysmon kind must be rejected");
    assert!(err.to_string().contains("unknown sysmon kind"));
}

#[tokio::test]
async fn run_security_kind_rejects_unknown_kind() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "unknown.log", "invalid\n");
    let mut sender = MockSender::default();

    let err = run_security_kind(
        &path,
        "unknown",
        default_run_options(),
        &mut sender,
        report_for(&path, "unknown"),
    )
    .await
    .expect_err("unknown security kind must be rejected");
    assert!(err.to_string().contains("unknown security log kind"));
}

#[cfg(feature = "netflow")]
#[tokio::test]
async fn run_netflow_kind_rejects_unknown_kind() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = temp_dir.path().join("empty.pcap");
    write_pcap(&path, &[]);
    let mut sender = MockSender::default();

    let err = run_netflow_kind(
        &path,
        "unknown",
        default_run_options(),
        &mut sender,
        report_for(&path, "unknown"),
    )
    .await
    .expect_err("unknown netflow kind must be rejected");
    assert!(err.to_string().contains("unknown netflow kind"));
}

#[tokio::test]
async fn run_single_requires_export_flag_for_zeek_kinds() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "conn.log", &format!("{ZEEK_CONN_1}\n"));
    let controller = controller_for_file(&path, "conn", None, None);
    let mut sender = MockSender::default();

    let err = controller
        .run_single(&path, &mut sender, "conn", false)
        .await
        .expect_err("missing export flag must be rejected");
    assert!(
        err.to_string()
            .contains("export_from_giganto parameter is required")
    );
}

#[tokio::test]
async fn run_single_rejects_directory_input() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let controller = controller_for_file(temp_dir.path(), "custom", Some(false), None);
    let mut sender = MockSender::default();

    let err = controller
        .run_single(temp_dir.path(), &mut sender, "custom", false)
        .await
        .expect_err("directory input must be rejected");
    assert!(err.to_string().contains("invalid input type"));
}

#[tokio::test]
async fn run_with_sender_rejects_elastic_input() {
    let mut config = test_config(Path::new("elastic"), "process_create");
    config.input = "elastic".to_string();
    let controller = Controller::new(config);
    let mut sender = MockSender::default();

    let err = controller
        .run_with_sender(&mut sender)
        .await
        .expect_err("elastic inputs require the elastic-specific path");
    assert!(
        err.to_string()
            .contains("elastic input requires a concrete sender factory")
    );
}

#[tokio::test]
async fn run_split_requires_directory_configuration() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let controller = Controller::new(test_config(temp_dir.path(), "custom"));
    let mut sender = MockSender::default();

    let err = controller
        .run_split(&mut sender)
        .await
        .expect_err("directory mode needs directory-specific options");
    assert!(
        err.to_string()
            .contains("directory's parameters is required")
    );
}

#[tokio::test]
async fn run_split_returns_ok_for_empty_directory_without_polling() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let controller = controller_for_directory(temp_dir.path(), "custom", None);
    let mut sender = MockSender::default();

    controller
        .run_split(&mut sender)
        .await
        .expect("empty non-polling directories should be ignored cleanly");

    assert!(sender.batch_sizes.is_empty());
    assert_eq!(sender.finish_calls, 0);
}

#[tokio::test]
async fn run_requires_elastic_configuration_for_elastic_input() {
    let mut config = test_config(Path::new("elastic"), "process_create");
    config.input = "elastic".to_string();
    let controller = Controller::new(config);

    let err = controller
        .run()
        .await
        .expect_err("elastic input without elastic config must fail");
    assert!(err.to_string().contains("elastic parameters is required"));
}

#[tokio::test]
async fn run_single_rejects_elastic_pseudo_input() {
    let controller = controller_for_file(Path::new("elastic"), "custom", Some(false), None);
    let mut sender = MockSender::default();

    let err = controller
        .run_single(Path::new("elastic"), &mut sender, "custom", false)
        .await
        .expect_err("elastic pseudo-input must be rejected by run_single");
    assert!(err.to_string().contains("invalid input type: Elastic"));
}

#[tokio::test]
async fn run_single_requires_file_configuration() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "input.log", "line1\n");
    let mut config = test_config(&path, "custom");
    config.file = None;
    let controller = Controller::new(config);
    let mut sender = MockSender::default();

    let err = controller
        .run_single(&path, &mut sender, "custom", false)
        .await
        .expect_err("run_single requires file-specific configuration");
    assert!(err.to_string().contains("file's parameters is required"));
}

#[tokio::test]
async fn run_single_ignores_checkpoint_write_failures() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let path = write_text_file(&temp_dir, "input.log", "line1\n");
    let checkpoint_dir = PathBuf::from(format!("{}_offset", path.to_string_lossy()));
    std::fs::create_dir(&checkpoint_dir)
        .expect("checkpoint target directory should be created to force save failure");
    let controller = controller_for_file(&path, "custom", Some(false), Some("offset"));
    let mut sender = MockSender::default();

    controller
        .run_single(&path, &mut sender, "custom", false)
        .await
        .expect("checkpoint save failures should only be logged");

    assert_eq!(sender.batch_sizes, vec![1]);
    assert!(checkpoint_dir.is_dir());
}

#[test]
fn migration_enabled_requires_export_setting() {
    let missing = FileConfig {
        export_from_giganto: None,
        polling_mode: false,
        transfer_count: None,
        transfer_skip_count: None,
        last_transfer_line_suffix: None,
    };
    let enabled = FileConfig {
        export_from_giganto: Some(true),
        polling_mode: false,
        transfer_count: None,
        transfer_skip_count: None,
        last_transfer_line_suffix: None,
    };

    let err = migration_enabled(missing.export_from_giganto)
        .expect_err("missing export_from_giganto must be rejected");
    assert!(
        err.to_string()
            .contains("export_from_giganto parameter is required")
    );
    assert!(
        migration_enabled(enabled.export_from_giganto)
            .expect("configured export flag should be returned")
    );
}

#[test]
fn resolve_offset_defaults_to_zero_without_skip_count_or_checkpoint() {
    let file = file_config(None, None);
    assert_eq!(resolve_offset(&file, None), 0);
}

#[tokio::test]
async fn dir_polling_creates_per_file_checkpoints() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    write_text_file(&temp_dir, "a.log", "line_a\n");
    write_text_file(&temp_dir, "b.log", "line_b\n");
    let mut config = test_config(temp_dir.path(), "custom");
    config.file = Some(FileConfig {
        export_from_giganto: Some(false),
        polling_mode: false,
        transfer_count: None,
        transfer_skip_count: None,
        last_transfer_line_suffix: Some("offset".to_string()),
    });
    config.directory = Some(Directory {
        file_prefix: None,
        polling_mode: false,
    });
    let controller = Controller::new(config);
    let mut sender = MockSender::default();

    controller
        .run_split(&mut sender)
        .await
        .expect("directory processing should succeed");

    // Each file should have its own checkpoint, not a single directory one.
    let cp_a = Checkpoint::from_input_and_suffix(
        &temp_dir.path().join("a.log").to_string_lossy(),
        "offset",
    );
    let cp_b = Checkpoint::from_input_and_suffix(
        &temp_dir.path().join("b.log").to_string_lossy(),
        "offset",
    );
    assert!(
        cp_a.load()
            .expect("checkpoint a should be readable")
            .is_some(),
        "per-file checkpoint for a.log should exist"
    );
    assert!(
        cp_b.load()
            .expect("checkpoint b should be readable")
            .is_some(),
        "per-file checkpoint for b.log should exist"
    );

    // The old directory-level checkpoint should NOT be created.
    let cp_dir = Checkpoint::from_input_and_suffix(&temp_dir.path().to_string_lossy(), "offset");
    assert!(
        cp_dir
            .load()
            .expect("directory checkpoint should be readable")
            .is_none(),
        "directory-level checkpoint should not be created"
    );
}

#[test]
fn resolve_offset_with_fallback_uses_per_file_checkpoint() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let file_path = temp_dir.path().join("data.log");
    let file_input = file_path
        .to_str()
        .expect("temporary path must be valid UTF-8");
    let file = file_config(None, Some("offset"));
    let checkpoint = checkpoint_for_input(file_input, file.last_transfer_line_suffix.as_deref());
    checkpoint
        .as_ref()
        .expect("checkpoint should exist")
        .save(b"50")
        .expect("per-file checkpoint should be written");

    let offset = resolve_offset_with_fallback(
        &file,
        checkpoint.as_ref(),
        &temp_dir.path().to_string_lossy(),
    );
    assert_eq!(offset, 50);
}

#[test]
fn resolve_offset_with_fallback_falls_back_to_directory_checkpoint() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let file_path = temp_dir.path().join("data.log");
    let file_input = file_path
        .to_str()
        .expect("temporary path must be valid UTF-8");
    let file = file_config(None, Some("offset"));

    // Create directory-level checkpoint (old format).
    let dir_checkpoint = checkpoint_for_input(
        &temp_dir.path().to_string_lossy(),
        file.last_transfer_line_suffix.as_deref(),
    );
    dir_checkpoint
        .as_ref()
        .expect("dir checkpoint should exist")
        .save(b"100")
        .expect("directory checkpoint should be written");

    // Per-file checkpoint does not exist yet.
    let checkpoint = checkpoint_for_input(file_input, file.last_transfer_line_suffix.as_deref());

    let offset = resolve_offset_with_fallback(
        &file,
        checkpoint.as_ref(),
        &temp_dir.path().to_string_lossy(),
    );
    assert_eq!(
        offset, 100,
        "should fall back to directory-level checkpoint"
    );
}

#[test]
fn resolve_offset_with_fallback_prefers_skip_count() {
    let temp_dir = tempdir().expect("temporary directory should be created");
    let file_path = temp_dir.path().join("data.log");
    let file_input = file_path
        .to_str()
        .expect("temporary path must be valid UTF-8");
    let file = file_config(Some(5), Some("offset"));
    let checkpoint = checkpoint_for_input(file_input, file.last_transfer_line_suffix.as_deref());
    checkpoint
        .as_ref()
        .expect("checkpoint should exist")
        .save(b"99")
        .expect("checkpoint should be written");

    let offset = resolve_offset_with_fallback(
        &file,
        checkpoint.as_ref(),
        &temp_dir.path().to_string_lossy(),
    );
    assert_eq!(offset, 5, "transfer_skip_count should take precedence");
}
