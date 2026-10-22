//! Tests of the Central Manager client against a mock review-protocol server.
//!
//! The mock serves `get_config` from a stored configuration, answers "config
//! unavailable" while none is stored, can delay its answer, sends
//! `update_config`, and records every handshake with the client certificate
//! it was made with.

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use reproduce::config::remote::RemoteConfig;
use reproduce::manager::{Client, ConfigRuntime, Manager, TlsError, TlsFiles, TlsMaterial};
use reproduce::reload::ReloadSignal;
use review_protocol::types::{HostNetworkGroup, Status};
#[cfg(unix)]
use support::send_signal;
use support::{Files, Logs, Mock, Pki, SERVER_NAME, VERSION_REQ, WAIT, wait_until};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

const RETRY_INTERVAL: Duration = Duration::from_millis(100);
/// How long a test waits to show that something does not happen.
const SETTLE: Duration = Duration::from_millis(1500);

const CONFIG: &str = r#"
giganto_ingest_srv_addr = "10.0.0.5:38370"
giganto_name = "giganto"

[[collectors]]
type = "log"
kind = "nginx_access"
path = "/var/log/nginx/access.log"
"#;

const OTHER_CONFIG: &str = r#"
giganto_ingest_srv_addr = "10.0.0.5:38370"
giganto_name = "giganto"

[[collectors]]
type = "log"
kind = "nginx_access"
path = "/var/log/nginx/access.log"

[[collectors]]
type = "log"
kind = "nginx_error"
path = "/var/log/nginx/error.log"
"#;

/// Records every configuration handed off.
struct Recording(Arc<Mutex<Vec<RemoteConfig>>>);

#[async_trait]
impl ConfigRuntime for Recording {
    async fn apply(&mut self, config: RemoteConfig) {
        self.0.lock().expect("lock").push(config);
    }
}

/// A running client.
struct Running {
    signal: ReloadSignal,
    shutdown: watch::Sender<bool>,
    handoffs: Arc<Mutex<Vec<RemoteConfig>>>,
    task: JoinHandle<()>,
}

impl Running {
    fn start(addr: SocketAddr, files: &TlsFiles) -> Result<Self> {
        let signal = ReloadSignal::new();
        let tls_reload = signal.subscribe();
        let wake = signal.subscribe();
        let material = TlsMaterial::read(files)?;
        let manager = Manager {
            server_name: SERVER_NAME.to_string(),
            addr,
        };
        let client = Client::new(manager, files.clone(), material, tls_reload, wake)
            .with_retry_interval(RETRY_INTERVAL);
        let (shutdown, receiver) = watch::channel(false);
        let handoffs = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = Recording(handoffs.clone());
        let task = tokio::spawn(async move { client.run(&mut runtime, receiver).await });
        Ok(Self {
            signal,
            shutdown,
            handoffs,
            task,
        })
    }

    fn handoffs(&self) -> Vec<RemoteConfig> {
        self.handoffs.lock().expect("lock").clone()
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        timeout(WAIT, self.task)
            .await
            .expect("the client ends on shutdown")
            .expect("the client does not panic");
    }
}

fn parsed(config: &str) -> RemoteConfig {
    reproduce::config::remote::parse(config).expect("a valid configuration")
}

/// Starts a mock with `config` stored and a client, and waits until the
/// client has applied it and reconnected with `Ready`.
async fn start_applied(config: &str) -> Result<(Pki, Mock, Files, Running)> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    mock.set_config(Some(config));
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until(
        "the configuration is handed off after the reconnect",
        || client.handoffs().len() == 2,
    )
    .await;
    assert_eq!(mock.statuses(), [Status::Idle, Status::Ready]);
    Ok((pki, mock, files, client))
}

#[tokio::test]
async fn idle_without_configuration() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;

    wait_until("the configuration is fetched", || mock.get_configs() == 1).await;
    sleep(SETTLE).await;
    assert!(!client.task.is_finished(), "the client keeps running");
    assert_eq!(mock.handshakes(), 1, "the connection is kept");
    assert_eq!(mock.get_configs(), 1);
    assert_eq!(client.handoffs().len(), 0, "nothing is handed off");

    {
        let handshakes = mock.state.handshakes.lock().expect("lock");
        let info = &handshakes[0].info;
        assert_eq!(info.agent_name, "reproduce");
        assert_eq!(info.agent_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.protocol_version, review_protocol::PROTOCOL_VERSION);
        assert_eq!(info.status, Status::Idle);
        assert_eq!(info.capabilities.len(), 0, "no capabilities are advertised");
    }

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn update_config_applies_and_reconnects_ready() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until("the configuration is fetched", || mock.get_configs() == 1).await;

    mock.set_config(Some(CONFIG));
    mock.send_update().await?;
    wait_until(
        "the configuration is handed off after the reconnect",
        || client.handoffs().len() == 2,
    )
    .await;
    assert_eq!(client.handoffs(), [parsed(CONFIG), parsed(CONFIG)]);
    assert_eq!(mock.statuses(), [Status::Idle, Status::Ready]);
    assert_eq!(mock.get_configs(), 3);

    // A new configuration is applied without a further reconnect.
    mock.set_config(Some(OTHER_CONFIG));
    mock.send_update().await?;
    wait_until("the new configuration is handed off", || {
        client.handoffs().len() == 3
    })
    .await;
    assert_eq!(client.handoffs()[2], parsed(OTHER_CONFIG));
    assert_eq!(mock.handshakes(), 2);

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn configuration_stored_while_disconnected_is_applied_after_reconnect() -> Result<()> {
    let pki = Pki::new()?;
    let mut mock = Mock::start(&pki)?;
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until("the configuration is fetched", || mock.get_configs() == 1).await;

    mock.stop().await;
    mock.set_config(Some(CONFIG));
    sleep(RETRY_INTERVAL * 3).await;
    mock.restart()?;

    wait_until(
        "the configuration is handed off after the reconnect",
        || client.handoffs().len() == 2,
    )
    .await;
    assert_eq!(mock.statuses(), [Status::Idle, Status::Idle, Status::Ready]);

    // Losing the connection keeps the applied configuration: the reconnect
    // reports `Ready`.
    mock.drop_connection();
    wait_until("the client reconnects", || mock.handshakes() == 4).await;
    assert_eq!(mock.statuses()[3], Status::Ready);

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn protocol_version_refusal_is_retried() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    mock.set_version_req(">=0.50.0");
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;

    wait_until("the refused connect is retried", || mock.attempts() >= 3).await;
    assert_eq!(mock.handshakes(), 0);
    assert!(
        !client.task.is_finished(),
        "a refusal does not end the client"
    );

    mock.set_version_req(VERSION_REQ);
    wait_until("the client connects", || mock.handshakes() == 1).await;

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn tls_refusal_is_retried() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    // A certificate the mock does not trust.
    let untrusted = Pki::new()?;
    let files = Files::new(&pki, &untrusted.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;

    sleep(RETRY_INTERVAL * 5).await;
    assert_eq!(mock.handshakes(), 0);
    assert!(
        !client.task.is_finished(),
        "a refusal does not end the client"
    );

    // The next connects re-read the files after `SIGHUP`.
    files.write_identity(&pki.client()?)?;
    client.signal.request();
    wait_until("the client connects", || mock.handshakes() == 1).await;

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn other_requests_are_not_supported() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until("the client connects", || mock.handshakes() == 1).await;

    let error = mock
        .connection()
        .send_allowlist(&HostNetworkGroup::default())
        .await
        .expect_err("allowlist is not supported");
    assert!(error.to_string().contains("not supported"), "{error}");

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn invalid_configuration_keeps_the_applied_one() -> Result<()> {
    let (logs, _guard) = Logs::capture();
    let (_pki, mock, _files, client) = start_applied(CONFIG).await?;
    let fetched = mock.get_configs();

    let invalid = "giganto_name = \"giganto\"\nsecret_marker = 1\n";
    mock.set_config(Some(invalid));
    mock.send_update().await?;
    wait_until("the configuration is fetched", || {
        mock.get_configs() == fetched + 1
    })
    .await;
    wait_until("the refusal is logged", || {
        logs.text().contains("Invalid configuration")
    })
    .await;
    assert_eq!(client.handoffs().len(), 2, "nothing is handed off");

    let text = logs.text();
    let line = text
        .lines()
        .find(|line| line.contains("Invalid configuration"))
        .expect("a refusal line");
    assert!(line.contains("ERROR"), "{line}");
    assert!(line.contains("keeping the applied configuration"), "{line}");
    assert!(text.contains("secret_marker"), "the error names the key");
    assert!(
        !text.contains("giganto_name = \"giganto\""),
        "the configuration is not logged as a whole"
    );

    // The applied configuration stays in force, so a reconnect reports
    // `Ready` and a valid configuration is applied again.
    mock.set_config(Some(OTHER_CONFIG));
    mock.drop_connection();
    wait_until("the configuration is handed off", || {
        client.handoffs().len() == 3
    })
    .await;
    assert_eq!(mock.statuses().last(), Some(&Status::Ready));
    assert_eq!(client.handoffs()[2], parsed(OTHER_CONFIG));

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn invalid_configuration_while_idle_stays_idle() -> Result<()> {
    let (logs, _guard) = Logs::capture();
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    mock.set_config(Some("collectors = []"));
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;

    wait_until("the refusal is logged", || {
        logs.text().contains("Invalid configuration")
    })
    .await;
    assert!(logs.text().contains("staying idle"));
    sleep(SETTLE).await;
    assert_eq!(client.handoffs().len(), 0, "nothing is handed off");
    assert_eq!(mock.statuses(), [Status::Idle]);

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn updates_during_an_apply_lead_to_one_more_fetch() -> Result<()> {
    let (_pki, mock, _files, client) = start_applied(CONFIG).await?;
    let fetched = mock.get_configs();

    let delay = Duration::from_secs(1);
    mock.set_delay(delay);
    mock.send_update().await?;
    wait_until("the fetch starts", || mock.get_configs() == fetched + 1).await;

    // Both are answered at once, while the fetch is still in progress.
    for _ in 0..2 {
        let started = Instant::now();
        mock.send_update().await?;
        assert!(
            started.elapsed() < delay / 2,
            "update_config is answered at once"
        );
    }

    wait_until("both fetches are handed off", || {
        client.handoffs().len() == 4
    })
    .await;
    sleep(delay + SETTLE).await;
    assert_eq!(mock.get_configs(), fetched + 2, "exactly one more fetch");
    assert_eq!(client.handoffs().len(), 4);

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn update_and_sighup_during_an_idle_fetch_lead_to_one_more_fetch() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    let delay = Duration::from_secs(1);
    mock.set_delay(delay);
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until("the fetch starts", || mock.get_configs() == 1).await;

    mock.send_update().await?;
    client.signal.request();
    mock.send_update().await?;
    client.signal.request();

    wait_until("one more fetch starts", || mock.get_configs() == 2).await;
    sleep(delay + SETTLE).await;
    assert_eq!(mock.get_configs(), 2, "exactly one more fetch");
    assert_eq!(client.handoffs().len(), 0, "nothing is handed off");

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn sighup_while_idle_fetches() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until("the configuration is fetched", || mock.get_configs() == 1).await;

    client.signal.request();
    wait_until("SIGHUP schedules a fetch", || mock.get_configs() == 2).await;
    sleep(SETTLE).await;
    assert_eq!(mock.get_configs(), 2, "one fetch per SIGHUP");
    assert_eq!(mock.handshakes(), 1, "SIGHUP does not drop the connection");

    mock.set_config(Some(CONFIG));
    client.signal.request();
    wait_until(
        "the configuration is handed off after the reconnect",
        || client.handoffs().len() == 2,
    )
    .await;
    let fetched = mock.get_configs();

    // Once a configuration is applied, SIGHUP does not fetch.
    client.signal.request();
    sleep(SETTLE).await;
    assert_eq!(mock.get_configs(), fetched);

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn shutdown_ends_a_connect_attempt() -> Result<()> {
    let pki = Pki::new()?;
    let files = Files::new(&pki, &pki.client()?)?;
    // A port that never answers, so the connect waits for the idle timeout.
    let silent = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let client = Running::start(silent.local_addr()?, &files.files)?;

    sleep(Duration::from_millis(300)).await;
    assert!(!client.task.is_finished());
    let started = Instant::now();
    client.stop().await;
    assert!(started.elapsed() < Duration::from_secs(1));
    Ok(())
}

#[tokio::test]
async fn shutdown_ends_an_apply_and_drops_the_connection() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    mock.set_delay(Duration::from_secs(30));
    let files = Files::new(&pki, &pki.client()?)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until("the fetch starts", || mock.get_configs() == 1).await;
    let connection = mock.quinn_connection();

    let started = Instant::now();
    client.stop().await;
    assert!(started.elapsed() < Duration::from_secs(1));
    timeout(WAIT, connection.closed())
        .await
        .expect("the client drops the connection");
    Ok(())
}

#[tokio::test]
async fn sighup_with_valid_files_clears_the_reload() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    let first = pki.client()?;
    let files = Files::new(&pki, &first)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until("the client connects", || mock.handshakes() == 1).await;
    assert_eq!(mock.cert(0), first.der());

    // SIGHUP keeps the connection; the next connect uses the new files.
    let second = pki.client()?;
    files.write_identity(&second)?;
    client.signal.request();
    sleep(SETTLE).await;
    assert_eq!(mock.handshakes(), 1, "SIGHUP does not drop the connection");
    mock.drop_connection();
    wait_until("the client reconnects", || mock.handshakes() == 2).await;
    assert_eq!(mock.cert(1), second.der());

    // The reload is cleared, so a later reconnect does not re-read.
    files.write_identity(&pki.client()?)?;
    mock.drop_connection();
    wait_until("the client reconnects", || mock.handshakes() == 3).await;
    assert_eq!(mock.cert(2), second.der());

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn sighup_with_unreadable_files_falls_back() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    let first = pki.client()?;
    let files = Files::new(&pki, &first)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until("the client connects", || mock.handshakes() == 1).await;

    std::fs::remove_file(&files.files.cert)?;
    client.signal.request();
    mock.drop_connection();
    wait_until("the client reconnects", || mock.handshakes() == 2).await;
    assert_eq!(mock.cert(1), first.der(), "the last-known-good material");

    // The reload stays pending, so the next connect re-reads the files.
    let second = pki.client()?;
    files.write_identity(&second)?;
    mock.drop_connection();
    wait_until("the client reconnects", || mock.handshakes() == 3).await;
    assert_eq!(mock.cert(2), second.der());

    client.stop().await;
    Ok(())
}

#[tokio::test]
async fn sighup_with_failing_files_falls_back() -> Result<()> {
    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    let first = pki.client()?;
    let files = Files::new(&pki, &first)?;
    let client = Running::start(mock.addr, &files.files)?;
    wait_until("the client connects", || mock.handshakes() == 1).await;

    // Valid files, but the CA does not sign the mock's certificate.
    let second = pki.client()?;
    files.write_identity(&second)?;
    std::fs::write(&files.files.ca_certs[0], Pki::new()?.ca)?;
    client.signal.request();
    mock.drop_connection();
    wait_until("the client reconnects", || mock.handshakes() == 2).await;
    assert_eq!(mock.cert(1), first.der(), "the last-known-good material");

    // The reload stays pending, so the next connect re-reads the files.
    std::fs::write(&files.files.ca_certs[0], &pki.ca)?;
    mock.drop_connection();
    wait_until("the client reconnects", || mock.handshakes() == 3).await;
    assert_eq!(mock.cert(2), second.der());

    client.stop().await;
    Ok(())
}

fn assert_refused(files: &TlsFiles, path: &Path, reason: &str) {
    let error = TlsMaterial::read(files).expect_err("the material is refused");
    let message = error.to_string();
    assert!(message.contains(&path.display().to_string()), "{message}");
    assert!(message.contains(reason), "{message}");
    match error {
        TlsError::Read { path: p, .. } | TlsError::Invalid { path: p, .. } => assert_eq!(p, path),
    }
}

#[test]
fn tls_material_errors_name_the_file() -> Result<()> {
    let pki = Pki::new()?;
    let identity = pki.client()?;
    let files = Files::new(&pki, &identity)?;
    TlsMaterial::read(&files.files)?;

    let mut missing = files.files.clone();
    missing.cert.set_file_name("missing.pem");
    assert_refused(&missing, &missing.cert, "cannot read the certificate file");

    let mut missing = files.files.clone();
    missing.key.set_file_name("missing.pem");
    assert_refused(&missing, &missing.key, "cannot read the private key file");

    let mut missing = files.files.clone();
    missing
        .ca_certs
        .push(missing.ca_certs[0].with_file_name("missing.pem"));
    assert_refused(
        &missing,
        &missing.ca_certs[1],
        "cannot read the CA certificate file",
    );

    // A key where the certificate belongs, and the other way round.
    let swapped = TlsFiles {
        cert: files.files.key.clone(),
        key: files.files.cert.clone(),
        ca_certs: files.files.ca_certs.clone(),
    };
    assert_refused(&swapped, &swapped.cert, "no certificate");
    let no_key = TlsFiles {
        key: files.files.cert.clone(),
        ..files.files.clone()
    };
    assert_refused(&no_key, &no_key.key, "no private key");
    let no_ca = TlsFiles {
        ca_certs: vec![files.files.ca_certs[0].clone(), files.files.key.clone()],
        ..files.files.clone()
    };
    assert_refused(&no_ca, &no_ca.ca_certs[1], "no certificate");
    Ok(())
}

/// Runs the binary in remote mode against the mock: `SIGHUP` while idle
/// fetches, `update_config` applies and reconnects with `Ready`, and
/// `SIGTERM` exits 0.
#[cfg(unix)]
#[tokio::test]
async fn binary_follows_the_manager() -> Result<()> {
    use std::io::BufRead;

    let pki = Pki::new()?;
    let mock = Mock::start(&pki)?;
    let files = Files::new(&pki, &pki.client()?)?;
    let state_dir = tempfile::tempdir()?;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_reproduce"))
        .arg("--cert")
        .arg(&files.files.cert)
        .arg("--key")
        .arg(&files.files.key)
        .arg("--ca-certs")
        .arg(&files.files.ca_certs[0])
        .arg("--state-dir")
        .arg(state_dir.path())
        .arg(format!("{SERVER_NAME}@{}", mock.addr))
        .env_remove("RUST_LOG")
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let stdout = Arc::new(Mutex::new(String::new()));
    let reader = child.stdout.take().context("piped stdout")?;
    let output = stdout.clone();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(reader)
            .lines()
            .map_while(Result::ok)
        {
            let mut output = output.lock().expect("lock");
            output.push_str(&line);
            output.push('\n');
        }
    });
    let output = || stdout.lock().expect("lock").clone();

    wait_until("the configuration is fetched", || mock.get_configs() == 1).await;
    send_signal(&child, libc::SIGHUP);
    wait_until("SIGHUP schedules a fetch", || mock.get_configs() == 2).await;
    assert_eq!(mock.handshakes(), 1, "SIGHUP does not drop the connection");

    mock.set_config(Some(CONFIG));
    mock.send_update().await?;
    wait_until("the configuration is applied", || {
        output()
            .matches("Applied a configuration with 1 collectors: 1 started, 0 stopped")
            .count()
            == 1
    })
    .await;
    wait_until("the configuration is fetched after the reconnect", || {
        mock.get_configs() == 4
    })
    .await;
    assert_eq!(mock.statuses(), [Status::Idle, Status::Ready]);
    assert!(output().contains("with status Ready"), "{}", output());

    send_signal(&child, libc::SIGTERM);
    let deadline = Instant::now() + WAIT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            child.kill()?;
            panic!("no exit after SIGTERM; output:\n{}", output());
        }
        sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(status.code(), Some(0), "{}", output());
    Ok(())
}
