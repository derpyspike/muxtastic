//! Start-up behaviour that does not need a working physical node.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use meshtastic::protobufs::{self as pb, to_radio};
use meshtastic::Message;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind an ephemeral port");
    listener
        .local_addr()
        .expect("read the local address")
        .port()
}

/// A config whose physical node (`node_port`) is a TCP endpoint on loopback.
fn config_path(label: &str, server_port: u16, node_port: u16, mqtt: bool) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "muxtastic-startup-{label}-{}-{unique}.toml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        format!(
            r#"
[node]
type = "tcp"
tcp_host = "127.0.0.1"
tcp_port = {node_port}

[server]
host = "127.0.0.1"
port = {server_port}

[discovery]
enabled = false

[web]
enabled = false

[logging]
console = false
file = ""

[mqtt_bridge]
enabled = {mqtt}
broker = "127.0.0.1"
port = 1
tls = false
"#
        ),
    )
    .expect("write a test config");
    path
}

fn wait_for_server(port: u16, within: Duration) -> TcpStream {
    let deadline = Instant::now() + within;
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => return stream,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("daemon did not listen within {within:?}: {error}"),
        }
    }
}

#[test]
fn a_bind_failure_exits_non_zero() {
    // Keep the mux port occupied so the daemon cannot bind it.
    let occupied = TcpListener::bind(("127.0.0.1", 0)).expect("occupy a port");
    let server_port = occupied.local_addr().expect("local addr").port();
    let path = config_path("bind", server_port, free_port(), false);

    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_muxtastic"))
            .arg("--mock")
            .arg("--config")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the daemon"),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("poll the daemon") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon kept running without its mux port"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = std::fs::remove_file(path);

    assert!(!status.success(), "a bind failure must not exit with 0");
}

#[test]
fn an_unreachable_node_neither_delays_the_listener_nor_gets_a_fake_replay() {
    // Nothing listens on the node port, and the MQTT bridge is enabled: the
    // bridge used to hold the listener back for 15 s while it waited for the
    // node number.
    let server_port = free_port();
    let path = config_path("unsynced", server_port, free_port(), true);

    let _guard = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_muxtastic"))
            .arg("--config")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the daemon"),
    );

    let mut stream = wait_for_server(server_port, Duration::from_secs(5));
    let _ = std::fs::remove_file(path);

    let want_config = pb::ToRadio {
        payload_variant: Some(to_radio::PayloadVariant::WantConfigId(42)),
    }
    .encode_to_vec();
    let mut frame = vec![0x94, 0xC3];
    frame.extend_from_slice(&(want_config.len() as u16).to_be_bytes());
    frame.extend_from_slice(&want_config);
    stream.write_all(&frame).expect("send want_config");

    // With no synced node there is nothing truthful to replay, so the daemon
    // must stay silent instead of inventing a node.
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set a read timeout");
    let mut buffer = [0u8; 64];
    match stream.read(&mut buffer) {
        Ok(0) => panic!("the daemon closed the connection"),
        Ok(n) => panic!("the daemon answered with {n} bytes before the node synced"),
        Err(error) => assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "unexpected read error: {error}"
        ),
    }
}
