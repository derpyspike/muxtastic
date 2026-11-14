use std::sync::Arc;
use std::time::{Duration, Instant};

use meshtastic::protobufs::{self as pb, from_radio, module_config};
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
    let result = ensure_mqtt_proxy(&state, node_num, has_net).await;
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
                    let Some(from_radio::PayloadVariant::ModuleConfig(module)) =
                        from_radio.payload_variant
                    else {
                        continue;
                    };
                    if let Some(mqtt) = mqtt_from_module_config(&module) {
                        return Some(mqtt.clone());
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

async fn send_admin(state: &Arc<AppState>, to_radio: pb::ToRadio) -> bool {
    state.queue_to_node(to_radio.encode_to_vec())
}

fn packet_id() -> u32 {
    rand::random::<u32>().max(1)
}
