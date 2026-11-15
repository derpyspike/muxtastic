use std::io::{Read, Write};
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

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x94, 0xC3];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn http_get(port: u16, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default())
}

fn wait_for_stats(port: u16) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(body) = http_get(port, "/api/stats") {
            if let Ok(value) = serde_json::from_str::<Value>(&body) {
                let totals = &value["stats"]["totals"];
                if totals["messages"].as_i64().unwrap_or(0) >= 1
                    && totals["jencore_frames"].as_i64().unwrap_or(0) >= 1
                    && totals["nodes"].as_i64().unwrap_or(0) >= 1
                {
                    return value;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("web stats did not become ready");
}

#[test]
fn mock_daemon_exposes_web_history() {
    let server_port = free_port();
    let web_port = free_port();
    let suffix = unique_suffix();
    let directory = std::env::temp_dir();
    let database = directory.join(format!("muxtastic-web-{suffix}.db"));
    let config = directory.join(format!("muxtastic-web-{suffix}.toml"));

    std::fs::write(
        &config,
        format!(
            r#"
[server]
host = "127.0.0.1"
port = {server_port}

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

    let stats = wait_for_stats(web_port);
    assert_eq!(stats["status"]["physical_connected"], true);
    assert_eq!(stats["status"]["mqtt_enabled"], false);
    assert!(stats["status"]["database"]
        .as_str()
        .unwrap_or_default()
        .ends_with(".db"));
    assert_eq!(stats["status"]["nodes"][0]["connected"], true);
    assert_eq!(
        stats["status"]["nodes"][0]["node"]["long_name"],
        "Mock Node"
    );
    assert_eq!(stats["status"]["nodes"][0]["node"]["short_name"], "MOCK");
    assert_eq!(
        stats["status"]["nodes"][0]["node"]["firmware_version"],
        "2.7.0.mock"
    );
    assert_eq!(stats["status"]["nodes"][0]["node"]["pio_env"], "heltec-v3");
    assert_eq!(stats["status"]["nodes"][0]["node"]["hw_model"], "HELTEC_V3");
    assert_eq!(stats["status"]["nodes"][0]["node"]["color"], "#345678");
    assert_eq!(
        stats["status"]["nodes"][0]["node"]["lora"]["summary"],
        "SF7/62.5/CR5/869.619"
    );
    assert_eq!(
        stats["status"]["nodes"][0]["node"]["lora"]["region"],
        "EU_868"
    );
    let sources = stats["status"]["sources"]
        .as_array()
        .expect("sources array");
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0]["name"], "default");
    assert_eq!(sources[0]["kind"], "physical");
    assert_eq!(sources[0]["endpoint"], "mock");
    assert_eq!(sources[0]["connected"], true);
    assert_eq!(sources[0]["node"]["long_name"], "Mock Node");
    assert_eq!(sources[0]["receiver"], "!12345678");
    assert_eq!(
        sources[0]["virtual_endpoint"],
        format!("127.0.0.1:{server_port}")
    );
    assert!(sources[0]["clients"]
        .as_array()
        .expect("source clients")
        .is_empty());

    let mut client = TcpStream::connect(("127.0.0.1", server_port)).expect("connect mux client");
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set client timeout");
    client
        .write_all(&frame(&[0x18, 0xD2, 0x09]))
        .expect("send want_config");
    let mut replay = [0u8; 4096];
    let _ = client.read(&mut replay);
    client
        .write_all(&frame(&[0x3A, 0x00]))
        .expect("send heartbeat");
    std::thread::sleep(Duration::from_millis(200));

    let with_client: Value =
        serde_json::from_str(&http_get(web_port, "/api/stats").expect("client stats request"))
            .expect("client stats json");
    let sources = with_client["status"]["sources"]
        .as_array()
        .expect("sources with client");
    let clients = sources[0]["clients"].as_array().expect("client list");
    assert!(!clients.is_empty());
    assert!(clients[0]["peer"]
        .as_str()
        .unwrap_or_default()
        .starts_with("127.0.0.1:"));
    assert!(clients[0]["rx_frames"].as_u64().unwrap_or(0) >= 2);
    assert!(clients[0]["tx_frames"].as_u64().unwrap_or(0) >= 1);
    drop(client);

    let direct: Value = serde_json::from_str(
        &http_get(web_port, "/api/direct-nodes?receiver=%2112345678")
            .expect("direct nodes request"),
    )
    .expect("direct nodes json");
    let direct = direct.as_array().expect("direct nodes array");
    assert!(direct
        .iter()
        .any(|node| node["long_name"].as_str() == Some("Mock Peer")));

    let messages: Value =
        serde_json::from_str(&http_get(web_port, "/api/messages").expect("messages request"))
            .expect("messages json");
    let messages = messages.as_array().expect("messages array");
    assert!(!messages.is_empty());
    assert!(!messages[0]["text"].as_str().unwrap_or_default().is_empty());
    assert_eq!(messages[0]["source"], "physical");
    assert_eq!(messages[0]["relay_node"], 0xABCD_0004i64);
    assert_eq!(messages[0]["rx_frequency_error"], -123.0);
    assert_eq!(messages[0]["rx_coding_rate"], 3);
    assert_eq!(messages[0]["reception_count"], 1);
    assert_eq!(messages[0]["gateway_count"], 1);
    assert_eq!(stats["stats"]["totals"]["mqtt_source"], 0);
    assert!(stats["stats"]["totals"]["receptions"].as_i64().unwrap_or(0) >= 1);
    assert_eq!(stats["stats"]["totals"]["multi_heard"], 0);
    assert!(stats["stats"]["totals"]["bytes"].as_i64().unwrap_or(0) > 0);
    assert!(stats["stats"]["packets_per_hour"].as_f64().unwrap_or(0.0) > 0.0);
    assert!(stats["stats"]["bytes_per_hour"].as_f64().unwrap_or(0.0) > 0.0);
    assert!(
        stats["stats"]["totals"]["meshtastic_frames"]
            .as_i64()
            .unwrap_or(0)
            > 0
    );
    let channel_stats = stats["stats"]["channels"]
        .as_array()
        .expect("channel stats");
    assert!(!channel_stats.is_empty());
    assert!(channel_stats[0]["bytes"].as_i64().unwrap_or(0) > 0);
    assert!(!channel_stats[0]["nodes"]
        .as_array()
        .expect("channel nodes")
        .is_empty());

    let node_names: Value =
        serde_json::from_str(&http_get(web_port, "/api/node-names").expect("node names request"))
            .expect("node names json");
    assert!(node_names
        .as_array()
        .expect("node names array")
        .iter()
        .any(|node| node["long_name"].as_str() == Some("Mock Node")));

    let nodes: Value =
        serde_json::from_str(&http_get(web_port, "/api/nodes").expect("nodes request"))
            .expect("nodes json");
    let nodes = nodes.as_array().expect("nodes array");
    assert!(nodes
        .iter()
        .any(|node| node["long_name"].as_str() == Some("Mock Node")));
    let mock_node = nodes
        .iter()
        .find(|node| node["long_name"].as_str() == Some("Mock Node"))
        .expect("mock node");
    assert_eq!(mock_node["hardware"], "HELTEC_V3");

    let node_detail: Value = serde_json::from_str(
        &http_get(web_port, &format!("/api/nodes/{}", mock_node["num"]))
            .expect("node detail request"),
    )
    .expect("node detail json");
    assert_eq!(node_detail["node"]["hardware"], "HELTEC_V3");
    assert!(node_detail["packets"].is_array());

    let receptions_path = format!(
        "/api/receptions?from_num={}&packet_id={}",
        messages[0]["from_num"], messages[0]["packet_id"]
    );
    let receptions: Value =
        serde_json::from_str(&http_get(web_port, &receptions_path).expect("receptions request"))
            .expect("receptions json");
    let receptions = receptions.as_array().expect("receptions array");
    assert_eq!(receptions.len(), 1);
    assert!(receptions[0]["receiver"]
        .as_str()
        .unwrap_or_default()
        .starts_with('!'));
    assert_eq!(receptions[0]["relay_node"], 0xABCD_0004i64);
    assert_eq!(receptions[0]["rx_frequency_error"], -123.0);
    assert_eq!(receptions[0]["rx_coding_rate"], 3);

    let recent: Value = serde_json::from_str(
        &http_get(web_port, "/api/receptions?limit=10").expect("recent receptions request"),
    )
    .expect("recent receptions json");
    assert!(!recent
        .as_array()
        .expect("recent receptions array")
        .is_empty());

    let node_receptions: Value = serde_json::from_str(
        &http_get(
            web_port,
            &format!(
                "/api/receptions?from_num={}&limit=10",
                messages[0]["from_num"]
            ),
        )
        .expect("node receptions request"),
    )
    .expect("node receptions json");
    assert!(!node_receptions
        .as_array()
        .expect("node receptions array")
        .is_empty());

    let relay_stats: Value = serde_json::from_str(
        &http_get(web_port, "/api/relay-stats?receiver=%2112345678&limit=10")
            .expect("relay stats request"),
    )
    .expect("relay stats json");
    let relay_stats = relay_stats.as_array().expect("relay stats array");
    assert!(!relay_stats.is_empty());
    assert_eq!(relay_stats[0]["relay_node"], 4);
    assert!(relay_stats[0]["rssi"]["avg"].as_f64().is_some());

    let relay_series: Value = serde_json::from_str(
        &http_get(web_port, "/api/relay-series?receiver=%2112345678&limit=100")
            .expect("relay series request"),
    )
    .expect("relay series json");
    assert!(!relay_series
        .as_array()
        .expect("relay series array")
        .is_empty());

    let node_page =
        http_get(web_port, &format!("/node/{}", mock_node["num"])).expect("node page request");
    assert!(node_page.contains("Muxtastic"));
    assert!(node_page.contains("static/app.js"));

    let traces: Value =
        serde_json::from_str(&http_get(web_port, "/api/traceroutes").expect("traces request"))
            .expect("traces json");
    let traces = traces.as_array().expect("traces array");
    assert!(!traces.is_empty());
    assert!(!traces[0]["route"]
        .as_array()
        .expect("direct route")
        .is_empty());
    assert!(!traces[0]["route_back"]
        .as_array()
        .expect("back route")
        .is_empty());

    let channels: Value =
        serde_json::from_str(&http_get(web_port, "/api/channels").expect("channels request"))
            .expect("channels json");
    let channels = channels.as_array().expect("channels array");
    assert!(channels
        .iter()
        .any(|channel| channel["name"].as_str() == Some("LongFast")));

    let packets: Value = serde_json::from_str(
        &http_get(web_port, "/api/packets?limit=10").expect("packets request"),
    )
    .expect("packets json");
    let packets = packets.as_array().expect("packets array");
    assert!(!packets.is_empty());
    assert!(packets[0]["portnum_name"].is_string());
    assert!(packets[0]["gateways"].is_string());
    let filtered_packets: Value = serde_json::from_str(
        &http_get(web_port, "/api/packets?source=physical&limit=10").expect("filtered packets"),
    )
    .expect("filtered packets json");
    assert!(!filtered_packets
        .as_array()
        .expect("filtered packets array")
        .is_empty());
    let packet_filters: Value = serde_json::from_str(
        &http_get(web_port, "/api/packet-filters").expect("packet filters request"),
    )
    .expect("packet filters json");
    assert!(!packet_filters["portnums"]
        .as_array()
        .expect("portnum filters")
        .is_empty());
    assert!(!packet_filters["gateways"]
        .as_array()
        .expect("gateway filters")
        .is_empty());

    let jraw_nodes: Value = serde_json::from_str(
        &http_get(web_port, "/api/jraw-nodes?kind=1").expect("jraw nodes request"),
    )
    .expect("jraw nodes json");
    let jraw_nodes = jraw_nodes.as_array().expect("jraw nodes array");
    assert!(!jraw_nodes.is_empty());
    assert_eq!(jraw_nodes[0]["kind_name"], "MeshCore");

    let raw: Value =
        serde_json::from_str(&http_get(web_port, "/api/raw?kind=1").expect("raw request"))
            .expect("raw json");
    let raw = raw.as_array().expect("raw array");
    assert!(!raw.is_empty());
    assert_eq!(raw[0]["kind_name"], "jencore");
    assert_eq!(raw[0]["source"], "physical");
    assert_eq!(raw[0]["payload_name"], "TXT_MSG");
    assert_eq!(raw[0]["payload_text"], "mock");
    assert_eq!(raw[0]["path_hash_size"], 1);
    assert_eq!(raw[0]["frame_hex"], "0900abcd6d6f636b");
    assert_eq!(raw[0]["frequency_error"], -42.0);
    assert_eq!(raw[0]["coding_rate"], 4);

    let page = http_get(web_port, "/").expect("index request");
    assert!(page.contains("Muxtastic"));
    assert!(page.contains("Mesh Stats"));
    assert!(page.contains("Packets"));
    assert!(page.contains("packets-body"));
    assert!(page.contains("node-family"));
    assert!(page.contains("Channels"));
    assert!(page.contains("Sources"));
    assert!(page.contains("Traces"));
    assert!(page.contains("channel-pie"));
    assert!(page.contains("node-strip"));
    let script = http_get(web_port, "/static/app.js").expect("script request");
    assert!(script.contains("refreshActive"));
    assert!(script.contains("renderNodeStrips"));
    let style = http_get(web_port, "/static/style.css").expect("style request");
    assert!(style.contains("--bg"));

    let _ = std::fs::remove_file(&config);
    for path in [
        database.clone(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ] {
        let _ = std::fs::remove_file(path);
    }
}
