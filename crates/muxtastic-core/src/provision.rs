//! Node MQTT provisioning message builders.
//!
//! The bridge only ever flips `moduleConfig.mqtt.enabled` and
//! `proxy_to_client_enabled` from false to true. Address, credentials, root
//! topic and channels are copied verbatim and never modified.

use meshtastic::protobufs::{self as pb, admin_message, module_config};
use meshtastic::Message;

use crate::mqtt::NodeMqttSnapshot;

/// Network-capable nodes report directly, so we leave the proxy flag alone.
pub fn wants_proxy(has_net: Option<bool>) -> bool {
    has_net != Some(true)
}

/// Wrap an `AdminMessage` in a local-node `ToRadio` packet.
pub fn build_admin_toradio(admin: pb::AdminMessage, node_num: u32, packet_id: u32) -> pb::ToRadio {
    let data = pb::Data {
        portnum: pb::PortNum::AdminApp as i32,
        payload: admin.encode_to_vec(),
        want_response: true,
        ..Default::default()
    };
    let packet = pb::MeshPacket {
        id: packet_id,
        from: node_num,
        to: node_num,
        want_ack: true,
        payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
        ..Default::default()
    };

    pb::ToRadio {
        payload_variant: Some(pb::to_radio::PayloadVariant::Packet(packet)),
    }
}

pub fn get_mqtt_config(node_num: u32, packet_id: u32) -> pb::ToRadio {
    let admin = pb::AdminMessage {
        payload_variant: Some(admin_message::PayloadVariant::GetModuleConfigRequest(
            admin_message::ModuleConfigType::MqttConfig as i32,
        )),
        ..Default::default()
    };
    build_admin_toradio(admin, node_num, packet_id)
}

pub fn begin_edit(node_num: u32, packet_id: u32) -> pb::ToRadio {
    let admin = pb::AdminMessage {
        payload_variant: Some(admin_message::PayloadVariant::BeginEditSettings(true)),
        ..Default::default()
    };
    build_admin_toradio(admin, node_num, packet_id)
}

pub fn commit_edit(node_num: u32, packet_id: u32) -> pb::ToRadio {
    let admin = pb::AdminMessage {
        payload_variant: Some(admin_message::PayloadVariant::CommitEditSettings(true)),
        ..Default::default()
    };
    build_admin_toradio(admin, node_num, packet_id)
}

/// Build `set_module_config` flipping only the missing flags.
///
/// Returns `None` when the live config already has everything we need.
pub fn set_mqtt(
    node_num: u32,
    packet_id: u32,
    current: &module_config::MqttConfig,
    ensure_proxy: bool,
) -> Option<pb::ToRadio> {
    let need_mqtt = !current.enabled;
    let need_proxy = ensure_proxy && !current.proxy_to_client_enabled;
    if !need_mqtt && !need_proxy {
        return None;
    }

    let mut mqtt = current.clone();
    if need_mqtt {
        mqtt.enabled = true;
    }
    if need_proxy {
        mqtt.proxy_to_client_enabled = true;
    }

    let module = pb::ModuleConfig {
        payload_variant: Some(module_config::PayloadVariant::Mqtt(mqtt)),
    };
    let admin = pb::AdminMessage {
        payload_variant: Some(admin_message::PayloadVariant::SetModuleConfig(module)),
        ..Default::default()
    };
    Some(build_admin_toradio(admin, node_num, packet_id))
}

pub fn sufficient(mqtt: &module_config::MqttConfig, want_proxy: bool) -> bool {
    mqtt.enabled && (mqtt.proxy_to_client_enabled || !want_proxy)
}

pub fn snapshot(mqtt: &module_config::MqttConfig, has_net: Option<bool>) -> NodeMqttSnapshot {
    NodeMqttSnapshot {
        enabled: mqtt.enabled,
        proxy: mqtt.proxy_to_client_enabled,
        has_net,
        address: mqtt.address.clone(),
    }
}

/// Extract an MQTT module config from a `FromRadio.moduleConfig` frame.
pub fn mqtt_from_module_config(module: &pb::ModuleConfig) -> Option<&module_config::MqttConfig> {
    match module.payload_variant.as_ref()? {
        module_config::PayloadVariant::Mqtt(mqtt) => Some(mqtt),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_of(to_radio: &pb::ToRadio) -> pb::AdminMessage {
        let Some(pb::to_radio::PayloadVariant::Packet(packet)) = &to_radio.payload_variant else {
            panic!("expected a packet");
        };
        assert_eq!(packet.from, 0xAB);
        assert_eq!(packet.to, 0xAB);
        let Some(pb::mesh_packet::PayloadVariant::Decoded(data)) = &packet.payload_variant else {
            panic!("expected decoded data");
        };
        assert_eq!(data.portnum, pb::PortNum::AdminApp as i32);
        assert!(data.want_response);
        pb::AdminMessage::decode(data.payload.as_slice()).expect("decode admin message")
    }

    #[test]
    fn ask_for_the_mqtt_module_config() {
        let admin = admin_of(&get_mqtt_config(0xAB, 7));
        assert_eq!(
            admin.payload_variant,
            Some(admin_message::PayloadVariant::GetModuleConfigRequest(
                admin_message::ModuleConfigType::MqttConfig as i32
            ))
        );
    }

    #[test]
    fn flips_only_the_missing_flags() {
        let current = module_config::MqttConfig {
            enabled: false,
            proxy_to_client_enabled: false,
            address: "broker.example".into(),
            username: "user".into(),
            password: "secret".into(),
            ..Default::default()
        };
        let to_radio = set_mqtt(0xAB, 8, &current, true).expect("needs changes");
        let admin = admin_of(&to_radio);
        let Some(admin_message::PayloadVariant::SetModuleConfig(module)) = admin.payload_variant
        else {
            panic!("expected set_module_config");
        };
        let Some(module_config::PayloadVariant::Mqtt(mqtt)) = module.payload_variant else {
            panic!("expected mqtt config");
        };
        assert!(mqtt.enabled);
        assert!(mqtt.proxy_to_client_enabled);
        assert_eq!(mqtt.address, "broker.example");
        assert_eq!(mqtt.username, "user");
    }

    #[test]
    fn network_nodes_keep_the_proxy_flag_untouched() {
        let current = module_config::MqttConfig {
            enabled: false,
            proxy_to_client_enabled: false,
            ..Default::default()
        };
        let to_radio = set_mqtt(0xAB, 2, &current, false).expect("needs mqtt");
        let admin = admin_of(&to_radio);
        let Some(admin_message::PayloadVariant::SetModuleConfig(module)) = admin.payload_variant
        else {
            panic!("expected set_module_config");
        };
        let Some(module_config::PayloadVariant::Mqtt(mqtt)) = module.payload_variant else {
            panic!("expected mqtt config");
        };
        assert!(mqtt.enabled);
        assert!(!mqtt.proxy_to_client_enabled);
    }

    #[test]
    fn nothing_to_do_returns_none() {
        let enabled = module_config::MqttConfig {
            enabled: true,
            proxy_to_client_enabled: true,
            ..Default::default()
        };
        assert!(set_mqtt(1, 2, &enabled, true).is_none());
        assert!(sufficient(&enabled, true));

        let mqtt_only = module_config::MqttConfig {
            enabled: true,
            proxy_to_client_enabled: false,
            ..Default::default()
        };
        assert!(sufficient(&mqtt_only, false));
        assert!(!sufficient(&mqtt_only, true));
    }

    #[test]
    fn snapshot_and_profile() {
        let mqtt = module_config::MqttConfig {
            enabled: true,
            proxy_to_client_enabled: true,
            address: "broker.local".into(),
            ..Default::default()
        };
        let snapshot = snapshot(&mqtt, Some(false));
        assert!(snapshot.enabled);
        assert!(snapshot.proxy);
        assert_eq!(snapshot.address, "broker.local");
        assert!(wants_proxy(Some(false)));
        assert!(wants_proxy(None));
        assert!(!wants_proxy(Some(true)));
    }
}
