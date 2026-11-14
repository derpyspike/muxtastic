use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

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

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

fn http_get(port: u16, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    std::io::Write::write_all(
        &mut stream,
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default())
}

fn wait_for_nodes(port: u16) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(body) = http_get(port, "/api/stats") {
            if let Ok(value) = serde_json::from_str::<Value>(&body) {
                let nodes = value["status"]["nodes"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                if nodes.len() == 2
                    && nodes
                        .iter()
                        .all(|node| node["node"]["long_name"].as_str() == Some("Mock Node"))
                {
                    return value;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("multi-node web stats did not become ready");
}

#[test]
fn mock_daemon_serves_two_physical_nodes() {
    let alpha_port = free_port();
    let beta_port = free_port();
    let web_port = free_port();
    let suffix = unique_suffix();
    let directory = std::env::temp_dir();
    let database = directory.join(format!("muxtastic-multi-{suffix}.db"));
    let config = directory.join(format!("muxtastic-multi-{suffix}.toml"));

    std::fs::write(
        &config,
        format!(
            r#"
[discovery]
enabled = false

[web]
enabled = true
host = "127.0.0.1"
port = {web_port}
database = "{}"

[logging]
level = "error"
console = false
file = ""

[[nodes]]
name = "alpha"
[nodes.server]
host = "127.0.0.1"
port = {alpha_port}

[[nodes]]
name = "beta"
[nodes.server]
host = "127.0.0.1"
port = {beta_port}
"#,
            database.display()
        ),
    )
    .expect("write the test config");

    let child = Command::new(env!("CARGO_BIN_EXE_muxtastic"))
        .arg("--mock")
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the daemon");
    let _guard = ChildGuard(child);

    let stats = wait_for_nodes(web_port);
    assert_eq!(stats["status"]["physical_connected"], true);

    let nodes = stats["status"]["nodes"].as_array().expect("nodes array");
    assert_eq!(nodes[0]["name"], "alpha");
    assert_eq!(nodes[1]["name"], "beta");
    assert_eq!(nodes[0]["port"], alpha_port);
    assert_eq!(nodes[1]["port"], beta_port);
    assert_eq!(nodes[0]["connected"], true);
    assert_eq!(nodes[1]["connected"], true);
    assert_eq!(nodes[0]["node"]["color"], "#345678");
    assert_eq!(nodes[1]["node"]["color"], "#345679");

    let sources = stats["status"]["sources"]
        .as_array()
        .expect("sources array");
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0]["name"], "alpha");
    assert_eq!(sources[1]["name"], "beta");
    assert!(sources.iter().all(|source| source["kind"] == "physical"));
    assert!(sources.iter().all(|source| source["connected"] == true));
    assert_eq!(
        sources[0]["virtual_endpoint"],
        format!("127.0.0.1:{alpha_port}")
    );
    assert_eq!(
        sources[1]["virtual_endpoint"],
        format!("127.0.0.1:{beta_port}")
    );
    assert!(sources
        .iter()
        .all(|source| source["node"]["long_name"] == "Mock Node"));

    assert!(TcpStream::connect(("127.0.0.1", alpha_port)).is_ok());
    assert!(TcpStream::connect(("127.0.0.1", beta_port)).is_ok());

    let _ = std::fs::remove_file(&config);
    for path in [
        database.clone(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ] {
        let _ = std::fs::remove_file(path);
    }
}
