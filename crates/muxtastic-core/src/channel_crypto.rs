//! Extra channel keys for decrypting opaque Meshtastic packets.
//!
//! Meshtastic channels use AES-CTR with a 16- or 32-byte key. A one-byte PSK
//! is a shorthand for the public default key with its last byte offset. The
//! same channel hash XORs the name and the expanded key, so a named extra
//! channel only tries packets whose header hash matches it. A `*` channel is a
//! wildcard: it tries its key against any packet and is labelled with the PSK
//! byte, e.g. `*-0x01` for `AQ==`.

use aes::{Aes128, Aes256};
use base64::Engine;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use meshtastic::protobufs::{self as pb, mesh_packet};
use meshtastic::Message;

use crate::util::hex;

/// The public Meshtastic default channel key. A one-byte PSK expands from this.
const DEFAULT_PSK: [u8; 16] = [
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraChannel {
    pub name: String,
    pub wildcard: bool,
    expanded_key: Vec<u8>,
    raw_key: Vec<u8>,
    channel_hash: u8,
}

impl ExtraChannel {
    /// Parse one `name` plus base64 PSK entry.
    pub fn parse(name: &str, key: &str) -> Result<Self, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("channel name is empty".into());
        }
        let raw_key = decode_key(key)?;
        Self::from_raw(name, raw_key)
    }

    fn from_raw(name: &str, raw_key: Vec<u8>) -> Result<Self, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("channel name is empty".into());
        }
        let expanded_key = expand_key(&raw_key)?;
        let wildcard = name == "*";
        let channel_hash = channel_hash(name.as_bytes(), &expanded_key);
        Ok(Self {
            name: name.to_owned(),
            wildcard,
            expanded_key,
            raw_key,
            channel_hash,
        })
    }

    pub fn label(&self) -> String {
        if self.wildcard {
            wildcard_label(&self.raw_key)
        } else {
            self.name.clone()
        }
    }

    pub fn channel_hash(&self) -> u8 {
        self.channel_hash
    }

    fn should_try(&self, packet: &pb::MeshPacket, hint: Option<&str>) -> bool {
        self.wildcard
            || (packet.channel <= u32::from(u8::MAX) && packet.channel as u8 == self.channel_hash)
            || hint.is_some_and(|hint| hint == self.name)
    }

    fn decrypt(&self, packet: &pb::MeshPacket) -> Option<pb::Data> {
        let mesh_packet::PayloadVariant::Encrypted(encrypted) = packet.payload_variant.as_ref()?
        else {
            return None;
        };
        if packet.pki_encrypted || encrypted.is_empty() || encrypted.starts_with(b"JRAW") {
            return None;
        }

        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&u64::from(packet.id).to_le_bytes());
        nonce[8..12].copy_from_slice(&packet.from.to_le_bytes());
        let mut plaintext = encrypted.clone();
        apply_ctr(&self.expanded_key, &nonce, &mut plaintext)?;

        let data = pb::Data::decode(plaintext.as_slice()).ok()?;
        let portnum = pb::PortNum::try_from(data.portnum).ok()?;
        (portnum != pb::PortNum::UnknownApp).then_some(data)
    }
}

/// Append wildcard entries for every non-zero one-byte PSK (`0x01..=0xff`).
///
/// These are tried after the configured channels, in ascending key order.
pub fn append_all_one_byte_keys(channels: &mut Vec<ExtraChannel>) {
    for byte in 1..=u8::MAX {
        if let Ok(channel) = ExtraChannel::from_raw("*", vec![byte]) {
            channels.push(channel);
        }
    }
}

/// Try every configured extra channel in order. Returns the decoded payload and
/// the channel label to record (`name` or `*-0xNN`).
pub fn decrypt_packet(
    packet: &pb::MeshPacket,
    extra_channels: &[ExtraChannel],
    hint: Option<&str>,
) -> Option<(pb::Data, String)> {
    for channel in extra_channels {
        if channel.should_try(packet, hint) {
            if let Some(data) = channel.decrypt(packet) {
                return Some((data, channel.label()));
            }
        }
    }
    None
}

fn decode_key(key: &str) -> Result<Vec<u8>, String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("channel key is empty".into());
    }
    base64::engine::general_purpose::STANDARD
        .decode(key)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(key))
        .map_err(|_| "channel key is not valid base64".to_owned())
}

fn expand_key(raw: &[u8]) -> Result<Vec<u8>, String> {
    match raw.len() {
        0 => Err("channel key is empty".into()),
        1 if raw[0] == 0 => Err("channel key 0 disables encryption".into()),
        1 => {
            let mut key = DEFAULT_PSK.to_vec();
            key[15] = key[15].wrapping_add(raw[0]).wrapping_sub(1);
            Ok(key)
        }
        2..=15 => {
            let mut key = vec![0u8; 16];
            key[..raw.len()].copy_from_slice(raw);
            Ok(key)
        }
        16 => Ok(raw.to_vec()),
        17..=31 => {
            let mut key = vec![0u8; 32];
            key[..raw.len()].copy_from_slice(raw);
            Ok(key)
        }
        32 => Ok(raw.to_vec()),
        _ => Err("channel key is longer than 32 bytes".into()),
    }
}

fn channel_hash(name: &[u8], key: &[u8]) -> u8 {
    xor_hash(name) ^ xor_hash(key)
}

fn xor_hash(bytes: &[u8]) -> u8 {
    bytes.iter().copied().fold(0, |hash, byte| hash ^ byte)
}

fn wildcard_label(raw: &[u8]) -> String {
    if raw.len() == 1 {
        format!("*-0x{:02x}", raw[0])
    } else {
        let prefix = &raw[..raw.len().min(4)];
        format!("*-0x{}", hex(prefix))
    }
}

fn apply_ctr(key: &[u8], nonce: &[u8; 16], bytes: &mut [u8]) -> Option<()> {
    match key.len() {
        16 => Ctr128BE::<Aes128>::new_from_slices(key, nonce)
            .ok()?
            .apply_keystream(bytes),
        32 => Ctr128BE::<Aes256>::new_from_slices(key, nonce)
            .ok()?
            .apply_keystream(bytes),
        _ => return None,
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_packet(id: u32, from: u32, channel: u32, encrypted: &[u8]) -> pb::MeshPacket {
        pb::MeshPacket {
            id,
            from,
            channel,
            pki_encrypted: false,
            payload_variant: Some(mesh_packet::PayloadVariant::Encrypted(encrypted.to_vec())),
            ..Default::default()
        }
    }

    #[test]
    fn expands_one_byte_keys_and_hashes_names() {
        let madrid = ExtraChannel::parse("Madrid", "AQ==").expect("channel");
        assert_eq!(madrid.expanded_key, DEFAULT_PSK);
        assert_eq!(madrid.channel_hash(), 0x35);
        assert_eq!(
            ExtraChannel::parse("Toledo", "AQ==")
                .expect("channel")
                .channel_hash(),
            0x3b
        );
        assert_eq!(
            ExtraChannel::parse("*", "AQ==").expect("channel").label(),
            "*-0x01"
        );
    }

    #[test]
    fn appends_all_255_one_byte_keys() {
        let mut channels = vec![ExtraChannel::parse("Madrid", "AQ==").expect("channel")];
        append_all_one_byte_keys(&mut channels);
        assert_eq!(channels.len(), 256);
        assert_eq!(channels[1].label(), "*-0x01");
        assert_eq!(channels[255].label(), "*-0xff");
    }

    #[test]
    fn decrypts_a_known_aes_ctr_packet() {
        // openssl aes-128-ctr key=defaultpsk nonce=id/from, plaintext Data{TEXT, "hi"}.
        let channel = ExtraChannel::parse("*", "AQ==").expect("channel");
        let packet = encrypted_packet(
            0x0506_0708,
            0x1122_3344,
            0x99,
            &[0x4f, 0x19, 0xcd, 0xee, 0x8d, 0x6f],
        );
        let (data, label) = decrypt_packet(&packet, &[channel], None).expect("decrypt");
        assert_eq!(data.portnum, pb::PortNum::TextMessageApp as i32);
        assert_eq!(data.payload, b"hi");
        assert_eq!(label, "*-0x01");
    }

    #[test]
    fn named_channels_only_try_matching_hashes() {
        let channel = ExtraChannel::parse("Madrid", "AQ==").expect("channel");
        let packet = encrypted_packet(1, 2, 0x99, &[0; 4]);
        assert!(decrypt_packet(&packet, std::slice::from_ref(&channel), None).is_none());
    }
}
