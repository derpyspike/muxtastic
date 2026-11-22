use std::sync::Arc;
use std::time::{Duration, Instant};

use meshtastic::protobufs::{self as pb, admin_message, from_radio, module_config};
use meshtastic::Message;
use muxtastic_core::mqtt::NodeMqttSnapshot;
use muxtastic_core::provision::{self as core, mqtt_from_module_config, wants_proxy};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::app::AppState;
use crate::mqtt::MqttBridge;

const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
const STEP_DELAY: Duration = Duration::from_millis(500);
const METADATA_WAIT: Duration = Duration::from_secs(5);
/// Attempts when the node does not answer the first config query at all.
const CHECK_ATTEMPTS: u32 = 3;
const CHECK_RETRY_DELAY: Duration = Duration::from_secs(10);

struct ProvisionResult {
    checked: bool,
    changed: bool,
    verified: bool,
    reason: &'static str,
    profile: &'static str,
    snapshot: Option<NodeMqttSnapshot>,
}

/// Once per boot: make sure the local node has MQTT enabled for the bridge.
pub async fn run(state: Arc<AppState>, bridge: Arc<MqttBridge>) {
    let node_num = state.node_num();
    if node_num == 0 {
        warn!("node MQTT provisioning skipped: node id is not known");
        return;
    }

    let has_net = wait_for_metadata(&state, METADATA_WAIT).await;
    let mut result = ensure_mqtt_proxy(&state, node_num, has_net).await;
    for attempt in 1..CHECK_ATTEMPTS {
        if result.checked {
            break;
        }
        warn!(
            attempt,
            reason = result.reason,
            "node MQTT provisioning got no answer; retrying"
        );
        sleep(CHECK_RETRY_DELAY).await;
        result = ensure_mqtt_proxy(&state, node_num, has_net).await;
    }
    info!(
        checked = result.checked,
        changed = result.changed,
        verified = result.verified,
        reason = result.reason,
        profile = result.profile,
        "node MQTT provisioning finished"
    );

    bridge.set_node_mqtt_snapshot(result.snapshot);
    if result.changed {
        let _ = state.resync.try_send(());
    }
}

async fn wait_for_metadata(state: &Arc<AppState>, wait: Duration) -> Option<bool> {
    let deadline = Instant::now() + wait;
    loop {
        let metadata = state
            .cache
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .metadata
            .clone();
        if let Some(metadata) = metadata {
            return Some(metadata.has_wifi || metadata.has_ethernet);
        }
        if Instant::now() >= deadline {
            return None;
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn ensure_mqtt_proxy(
    state: &Arc<AppState>,
    node_num: u32,
    has_net: Option<bool>,
) -> ProvisionResult {
    let want_proxy = wants_proxy(has_net);
    let profile = if want_proxy { "full" } else { "mqtt-only" };

    let Some(current) = query_mqtt_config(state, node_num).await else {
        return ProvisionResult {
            checked: false,
            changed: false,
            verified: false,
            reason: "no moduleConfig response from node",
            profile,
            snapshot: None,
        };
    };

    let snapshot = core::snapshot(&current, has_net);
    if core::sufficient(&current, want_proxy) {
        info!(profile, "node MQTT is already sufficient");
        return ProvisionResult {
            checked: true,
            changed: false,
            verified: true,
            reason: "already enabled",
            profile,
            snapshot: Some(snapshot),
        };
    }

    info!(
        profile,
        enabled = current.enabled,
        proxy = current.proxy_to_client_enabled,
        "enabling node MQTT"
    );

    if !send_admin(state, core::begin_edit(node_num, packet_id())).await {
        return failed("could not send begin_edit_settings", profile, snapshot);
    }
    sleep(STEP_DELAY).await;

    let Some(set) = core::set_mqtt(node_num, packet_id(), &current, want_proxy) else {
        return ProvisionResult {
            checked: true,
            changed: false,
            verified: true,
            reason: "already enabled",
            profile,
            snapshot: Some(snapshot),
        };
    };
    if !send_admin(state, set).await {
        return failed("could not send set_module_config", profile, snapshot);
    }
    sleep(STEP_DELAY).await;

    if !send_admin(state, core::commit_edit(node_num, packet_id())).await {
        return failed("could not send commit_edit_settings", profile, snapshot);
    }
    sleep(STEP_DELAY).await;

    // The node may briefly stall while saving, so retry the read-back.
    for attempt in 0..3 {
        if let Some(recheck) = query_mqtt_config(state, node_num).await {
            if core::sufficient(&recheck, want_proxy) {
                info!("node MQTT enabled and verified");
                return ProvisionResult {
                    checked: true,
                    changed: true,
                    verified: true,
                    reason: "ok",
                    profile,
                    snapshot: Some(core::snapshot(&recheck, has_net)),
                };
            }
        }
        if attempt < 2 {
            sleep(STEP_DELAY).await;
        }
    }

    ProvisionResult {
        checked: true,
        changed: true,
        verified: false,
        reason: "verify read-back mismatch",
        profile,
        snapshot: Some(snapshot),
    }
}

fn failed(
    reason: &'static str,
    profile: &'static str,
    snapshot: NodeMqttSnapshot,
) -> ProvisionResult {
    ProvisionResult {
        checked: true,
        changed: false,
        verified: false,
        reason,
        profile,
        snapshot: Some(snapshot),
    }
}

async fn query_mqtt_config(
    state: &Arc<AppState>,
    node_num: u32,
) -> Option<module_config::MqttConfig> {
    // Subscribe before sending so a fast reply cannot race us.
    let mut frames = state.physical_frames.subscribe();
    let request = core::get_mqtt_config(node_num, packet_id());
    debug!("querying the node MQTT module config");
    if !state.queue_to_node(request.encode_to_vec()) {
        warn!("could not queue the MQTT config query");
        return None;
    }

    let wait = async {
        loop {
            match frames.recv().await {
                Ok(frame) => {
                    let Ok(from_radio) = pb::FromRadio::decode(frame.as_ref()) else {
                        continue;
                    };
                    if let Some(mqtt) = mqtt_config_reply(&from_radio) {
                        return Some(mqtt);
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    debug!(skipped, "provisioning frame receiver lagged");
                }
                Err(RecvError::Closed) => return None,
            }
        }
    };

    match timeout(QUERY_TIMEOUT, wait).await {
        Ok(result) => result,
        Err(_) => {
            warn!("timed out waiting for the node MQTT module config");
            None
        }
    }
}

/// Extract the MQTT module config from either reply form.
///
/// Firmware answers `get_module_config_request` with an `ADMIN_APP` packet
/// carrying `get_module_config_response`; a config dump carries the same data
/// as a bare `FromRadio.moduleConfig` frame. Accept both.
fn mqtt_config_reply(from_radio: &pb::FromRadio) -> Option<module_config::MqttConfig> {
    match from_radio.payload_variant.as_ref()? {
        from_radio::PayloadVariant::ModuleConfig(module) => {
            mqtt_from_module_config(module).cloned()
        }
        from_radio::PayloadVariant::Packet(packet) => {
            let pb::mesh_packet::PayloadVariant::Decoded(data) = packet.payload_variant.as_ref()?
            else {
                return None;
            };
            if data.portnum != pb::PortNum::AdminApp as i32 {
                return None;
            }
            let admin = pb::AdminMessage::decode(data.payload.as_slice()).ok()?;
            match admin.payload_variant? {
                admin_message::PayloadVariant::GetModuleConfigResponse(module) => {
                    mqtt_from_module_config(&module).cloned()
                }
                _ => None,
            }
        }
        _ => None,
    }
}

async fn send_admin(state: &Arc<AppState>, to_radio: pb::ToRadio) -> bool {
    state.queue_to_node(to_radio.encode_to_vec())
}

fn packet_id() -> u32 {
    rand::random::<u32>().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mqtt_module() -> pb::ModuleConfig {
        pb::ModuleConfig {
            payload_variant: Some(module_config::PayloadVariant::Mqtt(
                module_config::MqttConfig {
                    enabled: true,
                    address: "broker".into(),
                    ..Default::default()
                },
            )),
        }
    }

    fn admin_packet(admin: pb::AdminMessage, portnum: pb::PortNum) -> pb::FromRadio {
        pb::FromRadio {
            id: 1,
            payload_variant: Some(from_radio::PayloadVariant::Packet(pb::MeshPacket {
                payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(pb::Data {
                    portnum: portnum as i32,
                    payload: admin.encode_to_vec(),
                    ..Default::default()
                })),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn accepts_a_bare_module_config_frame() {
        let frame = pb::FromRadio {
            id: 1,
            payload_variant: Some(from_radio::PayloadVariant::ModuleConfig(mqtt_module())),
        };
        assert_eq!(
            mqtt_config_reply(&frame).expect("mqtt config").address,
            "broker"
        );
    }

    #[test]
    fn accepts_an_admin_response_packet() {
        let admin = pb::AdminMessage {
            payload_variant: Some(admin_message::PayloadVariant::GetModuleConfigResponse(
                mqtt_module(),
            )),
            ..Default::default()
        };
        let reply = mqtt_config_reply(&admin_packet(admin.clone(), pb::PortNum::AdminApp));
        assert!(reply.expect("mqtt config").enabled);
        // The same bytes on another port are not an admin reply.
        assert!(mqtt_config_reply(&admin_packet(admin, pb::PortNum::TextMessageApp)).is_none());
    }

    #[test]
    fn ignores_other_module_configs_and_admin_messages() {
        let frame = pb::FromRadio {
            id: 1,
            payload_variant: Some(from_radio::PayloadVariant::ModuleConfig(pb::ModuleConfig {
                payload_variant: Some(module_config::PayloadVariant::Serial(Default::default())),
            })),
        };
        assert!(mqtt_config_reply(&frame).is_none());

        let admin = pb::AdminMessage {
            payload_variant: Some(admin_message::PayloadVariant::GetModuleConfigRequest(0)),
            ..Default::default()
        };
        assert!(mqtt_config_reply(&admin_packet(admin, pb::PortNum::AdminApp)).is_none());
    }
}
