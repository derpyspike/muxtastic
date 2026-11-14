//! Small helpers for reading decoded `MeshPacket` payloads.
//!
//! The state cache and the SQLite history both need the same NodeInfo,
//! Position and hop semantics; keeping them here stops the two paths drifting.

use meshtastic::protobufs as pb;
use meshtastic::Message;

/// The decoded `Data` payload, if the packet carries one.
pub fn decoded(packet: &pb::MeshPacket) -> Option<&pb::Data> {
    match &packet.payload_variant {
        Some(pb::mesh_packet::PayloadVariant::Decoded(data)) => Some(data),
        _ => None,
    }
}

/// The decoded port number, if any.
pub fn portnum(packet: &pb::MeshPacket) -> Option<i32> {
    decoded(packet).map(|data| data.portnum)
}

/// A non-empty NodeInfo user announcement.
pub fn nodeinfo(packet: &pb::MeshPacket) -> Option<pb::User> {
    let data = decoded(packet)?;
    if data.portnum != pb::PortNum::NodeinfoApp as i32 {
        return None;
    }
    let user = pb::User::decode(data.payload.as_slice()).ok()?;
    (!user.id.is_empty()).then_some(user)
}

/// A Position payload with at least one non-zero coordinate.
pub fn position(packet: &pb::MeshPacket) -> Option<pb::Position> {
    let data = decoded(packet)?;
    if data.portnum != pb::PortNum::PositionApp as i32 {
        return None;
    }
    let position = pb::Position::decode(data.payload.as_slice()).ok()?;
    let latitude = position.latitude_i.unwrap_or(0);
    let longitude = position.longitude_i.unwrap_or(0);
    (latitude != 0 || longitude != 0).then_some(position)
}

/// Hops away from the local node using the firmware's 3-hop start value.
pub fn hops_away(packet: &pb::MeshPacket) -> u32 {
    3u32.saturating_sub(packet.hop_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(portnum: pb::PortNum, payload: Vec<u8>) -> pb::MeshPacket {
        pb::MeshPacket {
            hop_limit: 2,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(pb::Data {
                portnum: portnum as i32,
                payload,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[test]
    fn reads_nodeinfo_and_hops() {
        let user = pb::User {
            id: "!0000002a".into(),
            long_name: "Alice".into(),
            ..Default::default()
        };
        let packet = data(pb::PortNum::NodeinfoApp, user.encode_to_vec());
        assert_eq!(nodeinfo(&packet).unwrap().long_name, "Alice");
        assert_eq!(hops_away(&packet), 1);
        assert_eq!(portnum(&packet), Some(pb::PortNum::NodeinfoApp as i32));
    }

    #[test]
    fn rejects_empty_identities_and_zero_positions() {
        let packet = data(
            pb::PortNum::NodeinfoApp,
            pb::User::default().encode_to_vec(),
        );
        assert!(nodeinfo(&packet).is_none());

        let zero = pb::Position {
            latitude_i: Some(0),
            longitude_i: Some(0),
            ..Default::default()
        };
        assert!(position(&data(pb::PortNum::PositionApp, zero.encode_to_vec())).is_none());

        let real = pb::Position {
            latitude_i: Some(1),
            longitude_i: Some(2),
            ..Default::default()
        };
        assert!(position(&data(pb::PortNum::PositionApp, real.encode_to_vec())).is_some());
    }

    #[test]
    fn non_decoded_packets_have_no_helpers() {
        let packet = pb::MeshPacket {
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Encrypted(vec![1])),
            ..Default::default()
        };
        assert!(decoded(&packet).is_none());
        assert!(nodeinfo(&packet).is_none());
        assert!(position(&packet).is_none());
    }
}
