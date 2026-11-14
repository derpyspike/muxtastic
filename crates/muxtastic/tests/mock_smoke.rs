use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use meshtastic::protobufs::{self as pb, from_radio, to_radio};
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

fn config_path(port: u16) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "muxtastic-test-{}-{unique}.toml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        format!(
            r#"
[server]
host = "127.0.0.1"
port = {port}

[discovery]
enabled = false

[web]
enabled = false

[logging]
console = false
file = ""
"#
        ),
    )
    .expect("write a test config");
    path
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x94, 0xC3];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn read_varint(buf: &[u8], mut i: usize) -> (u64, usize) {
    let mut shift = 0;
    let mut value = 0;
    loop {
        let byte = buf[i];
        i += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return (value, i);
        }
        shift += 7;
    }
}

fn field_numbers(payload: &[u8]) -> Vec<u64> {
    let mut fields = Vec::new();
    let mut i = 0;
    while i < payload.len() {
        let (key, next) = read_varint(payload, i);
        i = next;
        let field = key >> 3;
        let wire = key & 7;
        fields.push(field);
        match wire {
            0 => {
                let (_, next) = read_varint(payload, i);
                i = next;
            }
            1 => i += 8,
            2 => {
                let (length, next) = read_varint(payload, i);
                i = next + length as usize;
            }
            5 => i += 4,
            _ => break,
        }
    }
    fields
}

fn wait_for_server(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => return stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("daemon did not start: {error}"),
        }
    }
}

fn collect_fields(mut stream: TcpStream) -> Vec<u64> {
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set a read timeout");

    // ToRadio.want_config_id = field 3 (varint).
    stream
        .write_all(&frame(&[0x18, 0xD2, 0x09]))
        .expect("send want_config");
    // ToRadio.heartbeat = field 7, empty message.
    stream
        .write_all(&frame(&[0x3A, 0x00]))
        .expect("send heartbeat");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buffer = Vec::new();
    let mut fields = Vec::new();
    let mut chunk = [0u8; 4096];

    while Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                while buffer.len() >= 4 {
                    if buffer[0] != 0x94 || buffer[1] != 0xC3 {
                        buffer.remove(0);
                        continue;
                    }
                    let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
                    if buffer.len() < 4 + length {
                        break;
                    }
                    fields.extend(field_numbers(&buffer[4..4 + length]));
                    buffer.drain(..4 + length);
                }
            }
            Err(_) => {}
        }
    }

    fields
}

fn read_frames(stream: &mut TcpStream, duration: Duration) -> Vec<pb::FromRadio> {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set a read timeout");

    let deadline = Instant::now() + duration;
    let mut buffer = Vec::new();
    let mut frames = Vec::new();
    let mut chunk = [0u8; 4096];

    while Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(_) => continue,
        }

        while buffer.len() >= 4 {
            if buffer[0] != 0x94 || buffer[1] != 0xC3 {
                buffer.remove(0);
                continue;
            }
            let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
            if buffer.len() < 4 + length {
                break;
            }
            let payload: Vec<u8> = buffer.drain(..4 + length).skip(4).collect();
            if let Ok(frame) = pb::FromRadio::decode(payload.as_slice()) {
                frames.push(frame);
            }
        }
    }

    frames
}

fn wait_for_config(stream: &mut TcpStream) {
    // ToRadio.want_config_id = field 3 (varint).
    stream
        .write_all(&frame(&[0x18, 0xD2, 0x09]))
        .expect("send want_config");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if read_frames(stream, Duration::from_millis(200))
            .iter()
            .any(|frame| {
                matches!(
                    frame.payload_variant,
                    Some(from_radio::PayloadVariant::ConfigCompleteId(_))
                )
            })
        {
            return;
        }
    }
    panic!("config replay did not complete");
}

fn traceroute_request(id: u32) -> pb::ToRadio {
    let data = pb::Data {
        portnum: pb::PortNum::TracerouteApp as i32,
        want_response: true,
        dest: u32::MAX,
        ..Default::default()
    };
    let packet = pb::MeshPacket {
        id,
        to: u32::MAX,
        hop_start: 0,
        hop_limit: 0,
        payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
        ..Default::default()
    };
    pb::ToRadio {
        payload_variant: Some(to_radio::PayloadVariant::Packet(packet)),
    }
}

fn packet_ids(frames: &[pb::FromRadio]) -> Vec<u32> {
    frames
        .iter()
        .filter_map(|frame| match &frame.payload_variant {
            Some(from_radio::PayloadVariant::Packet(packet)) => Some(packet.id),
            _ => None,
        })
        .collect()
}

#[test]
fn local_echo_skips_the_sending_client() {
    let port = free_port();
    let path = config_path(port);
    let child = Command::new(env!("CARGO_BIN_EXE_muxtastic"))
        .arg("--mock")
        .arg("--config")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the daemon");
    let _guard = ChildGuard(child);

    let mut sender = wait_for_server(port);
    let mut observer = wait_for_server(port);
    wait_for_config(&mut sender);
    wait_for_config(&mut observer);

    let id = 0x5EED_0001;
    sender
        .write_all(&frame(&traceroute_request(id).encode_to_vec()))
        .expect("send a client packet");

    let sender_ids = packet_ids(&read_frames(&mut sender, Duration::from_millis(600)));
    let observer_ids = packet_ids(&read_frames(&mut observer, Duration::from_millis(600)));
    let _ = std::fs::remove_file(path);

    assert!(
        !sender_ids.contains(&id),
        "sender received its own echo: {sender_ids:?}"
    );
    assert!(
        observer_ids.contains(&id),
        "other client did not receive the echo: {observer_ids:?}"
    );
}

#[test]
fn mock_daemon_replays_config_and_answers_heartbeats() {
    let port = free_port();
    let path = config_path(port);
    let child = Command::new(env!("CARGO_BIN_EXE_muxtastic"))
        .arg("--mock")
        .arg("--config")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the daemon");
    let _guard = ChildGuard(child);

    let stream = wait_for_server(port);
    let fields = collect_fields(stream);
    let _ = std::fs::remove_file(path);

    assert!(fields.contains(&3), "expected my_info, got {fields:?}");
    assert!(fields.contains(&10), "expected channels, got {fields:?}");
    assert!(fields.contains(&13), "expected metadata, got {fields:?}");
    assert!(fields.contains(&5), "expected config, got {fields:?}");
    assert!(
        fields.contains(&7),
        "expected config_complete, got {fields:?}"
    );
    assert!(
        fields.contains(&11),
        "expected queue_status, got {fields:?}"
    );
}
