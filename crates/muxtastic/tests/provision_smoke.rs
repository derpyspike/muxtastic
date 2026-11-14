use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use meshtastic::protobufs::{self as pb, admin_message, from_radio, module_config, to_radio};
use meshtastic::Message;
use muxtastic_core::protocol::{encode_frame, FrameDecoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioListener, TcpStream};

const NODE_NUM: u32 = 0x1122_3344;

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

fn config_path(physical_port: u16, server_port: u16) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "muxtastic-provision-{}-{unique}.toml",
        std::process::id()
    ));
    let mut file = std::fs::File::create(&path).expect("create the test config");
    write!(
        file,
        r#"
[node]
type = "tcp"
tcp_host = "127.0.0.1"
tcp_port = {physical_port}
tcp_idle_timeout_secs = 300

[server]
host = "127.0.0.1"
port = {server_port}

[discovery]
enabled = false

[web]
enabled = false

[logging]
level = "error"
console = false
file = ""

[mqtt_bridge]
enabled = true
broker = "127.0.0.1"
port = 1
tls = false
uplink_enabled = false
downlink_enabled = false
ignore_ok_to_mqtt = true
root_topic = "msh"
raw_root_topic = "raw"
raw_uplink = false
raw_scope = "uncovered"
standard_mirror = "off"
keepalive = 30
"#
    )
    .expect("write the test config");
    path
}

struct Outcome {
    saw_begin: bool,
    saw_set: bool,
    saw_commit: bool,
    verified: bool,
    mqtt: module_config::MqttConfig,
}

async fn send_frame(socket: &mut TcpStream, frame: &pb::FromRadio) -> std::io::Result<()> {
    let payload = frame.encode_to_vec();
    let encoded = encode_frame(&payload).expect("frame the message");
    socket.write_all(&encoded).await
}

async fn fake_physical_node(socket: &mut TcpStream) -> Outcome {
    let mut mqtt = module_config::MqttConfig {
        enabled: false,
        proxy_to_client_enabled: false,
        address: "fake-broker".into(),
        username: "fake-user".into(),
        password: "fake-pass".into(),
        ..Default::default()
    };

    let mut saw_begin = false;
    let mut saw_set = false;
    let mut saw_commit = false;
    let mut decoder = FrameDecoder::new();
    let mut buffer = [0u8; 4096];

    loop {
        let read = tokio::time::timeout(Duration::from_secs(1), socket.read(&mut buffer)).await;
        let n = match read {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(error)) => panic!("fake node read error: {error}"),
            Err(_) => continue,
        };
        decoder.push(&buffer[..n]);

        while let Some(payload) = decoder.next_frame() {
            let Ok(to_radio) = pb::ToRadio::decode(payload.as_slice()) else {
                continue;
            };

            match to_radio.payload_variant {
                Some(to_radio::PayloadVariant::WantConfigId(id)) => {
                    let my_info = pb::FromRadio {
                        id: 1,
                        payload_variant: Some(from_radio::PayloadVariant::MyInfo(pb::MyNodeInfo {
                            my_node_num: NODE_NUM,
                            ..Default::default()
                        })),
                    };
                    let metadata = pb::FromRadio {
                        id: 2,
                        payload_variant: Some(from_radio::PayloadVariant::Metadata(
                            pb::DeviceMetadata {
                                firmware_version: "fake-1.0".into(),
                                has_wifi: false,
                                has_ethernet: false,
                                ..Default::default()
                            },
                        )),
                    };
                    let complete = pb::FromRadio {
                        id: 3,
                        payload_variant: Some(from_radio::PayloadVariant::ConfigCompleteId(id)),
                    };
                    send_frame(socket, &my_info).await.expect("send my_info");
                    send_frame(socket, &metadata).await.expect("send metadata");
                    send_frame(socket, &complete)
                        .await
                        .expect("send config complete");
                }
                Some(to_radio::PayloadVariant::Packet(packet)) => {
                    let Some(pb::mesh_packet::PayloadVariant::Decoded(data)) =
                        &packet.payload_variant
                    else {
                        continue;
                    };
                    if data.portnum != pb::PortNum::AdminApp as i32 {
                        continue;
                    }
                    let Ok(admin) = pb::AdminMessage::decode(data.payload.as_slice()) else {
                        continue;
                    };

                    match admin.payload_variant {
                        Some(admin_message::PayloadVariant::GetModuleConfigRequest(_)) => {
                            let response = pb::FromRadio {
                                id: 4,
                                payload_variant: Some(from_radio::PayloadVariant::ModuleConfig(
                                    pb::ModuleConfig {
                                        payload_variant: Some(module_config::PayloadVariant::Mqtt(
                                            mqtt.clone(),
                                        )),
                                    },
                                )),
                            };
                            send_frame(socket, &response)
                                .await
                                .expect("send module config");

                            if saw_commit && mqtt.enabled && mqtt.proxy_to_client_enabled {
                                return Outcome {
                                    saw_begin,
                                    saw_set,
                                    saw_commit,
                                    verified: true,
                                    mqtt,
                                };
                            }
                        }
                        Some(admin_message::PayloadVariant::BeginEditSettings(_)) => {
                            saw_begin = true;
                        }
                        Some(admin_message::PayloadVariant::SetModuleConfig(module)) => {
                            if let Some(module_config::PayloadVariant::Mqtt(updated)) =
                                module.payload_variant
                            {
                                assert_eq!(updated.address, "fake-broker");
                                assert_eq!(updated.username, "fake-user");
                                assert!(updated.enabled);
                                assert!(updated.proxy_to_client_enabled);
                                mqtt = updated;
                                saw_set = true;
                            }
                        }
                        Some(admin_message::PayloadVariant::CommitEditSettings(_)) => {
                            saw_commit = true;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    Outcome {
        saw_begin,
        saw_set,
        saw_commit,
        verified: false,
        mqtt,
    }
}

#[tokio::test]
async fn provisions_mqtt_flags_on_the_physical_node() {
    let physical = TokioListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind the fake physical node");
    let physical_port = physical.local_addr().expect("local addr").port();
    let server_port = free_port();
    let path = config_path(physical_port, server_port);

    let child = Command::new(env!("CARGO_BIN_EXE_muxtastic"))
        .arg("--config")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the daemon");
    let _guard = ChildGuard(child);

    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), physical.accept())
        .await
        .expect("the daemon did not connect to the fake node")
        .expect("accept the daemon connection");

    let outcome = tokio::time::timeout(Duration::from_secs(15), fake_physical_node(&mut socket))
        .await
        .expect("provisioning timed out");

    let _ = std::fs::remove_file(path);

    assert!(outcome.saw_begin, "begin_edit_settings was not sent");
    assert!(outcome.saw_set, "set_module_config was not sent");
    assert!(outcome.saw_commit, "commit_edit_settings was not sent");
    assert!(outcome.verified, "the read-back did not verify");
    assert!(outcome.mqtt.enabled);
    assert!(outcome.mqtt.proxy_to_client_enabled);
    assert_eq!(outcome.mqtt.address, "fake-broker");
}
