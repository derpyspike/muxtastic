//! MeshCore group channels and region scopes.
//!
//! Group payloads (`GRP_TXT`, `GRP_DATA`) are `channel hash (1) | MAC (2) |
//! AES-128-ECB ciphertext`. The MAC is HMAC-SHA256 over the ciphertext, keyed
//! with the 32-byte channel secret (a 16-byte key is zero-padded) and cut to
//! two bytes. The channel hash is the first byte of SHA-256 over the key.
//!
//! Transport-routed frames carry a 16-bit scope code instead of a region name:
//! HMAC-SHA256 over `payload type | payload`, keyed with the region key. A
//! region can therefore only be named by trying the keys we know.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// The well-known key of MeshCore's default "Public" channel.
const PUBLIC_KEY: [u8; 16] = [
    0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72,
];
const MAC_SIZE: usize = 2;
const BLOCK: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshCoreChannel {
    pub name: String,
    /// 16- or 32-byte key, zero-padded to 32 bytes as the firmware stores it.
    secret: [u8; 32],
    pub hash: u8,
}

impl MeshCoreChannel {
    pub fn public() -> Self {
        Self::from_key("Public", &PUBLIC_KEY).expect("public key has a valid length")
    }

    /// A hashtag channel: its key is the first 16 bytes of SHA-256 over the
    /// name including the leading `#`.
    pub fn hashtag(name: &str) -> Self {
        let name = hashtag_name(name);
        let digest = Sha256::digest(name.as_bytes());
        Self::from_key(&name, &digest[..16]).expect("derived key has a valid length")
    }

    pub fn from_key(name: &str, key: &[u8]) -> Option<Self> {
        if key.len() != 16 && key.len() != 32 {
            return None;
        }
        let mut secret = [0u8; 32];
        secret[..key.len()].copy_from_slice(key);
        Some(Self {
            name: name.to_owned(),
            secret,
            hash: Sha256::digest(key)[0],
        })
    }

    /// Build a channel from configuration. Without a key, `Public` is the
    /// well-known public channel and `#name` a hashtag channel. A key may be
    /// base64 or hex and must be 16 or 32 bytes.
    pub fn from_config(name: &str, key: &str) -> Result<Self, String> {
        let name = name.trim();
        let key = key.trim();
        if name.is_empty() {
            return Err("MeshCore channel needs a name".to_owned());
        }
        if key.is_empty() {
            if name.eq_ignore_ascii_case("public") {
                return Ok(Self::public());
            }
            if name.starts_with('#') {
                return Ok(Self::hashtag(name));
            }
            return Err(format!(
                "MeshCore channel {name:?} needs a key (only Public and #hashtag channels have a known one)"
            ));
        }
        let bytes = decode_key(key)
            .ok_or_else(|| format!("MeshCore channel {name:?}: key is neither base64 nor hex"))?;
        Self::from_key(name, &bytes).ok_or_else(|| {
            format!(
                "MeshCore channel {name:?}: key must be 16 or 32 bytes, got {}",
                bytes.len()
            )
        })
    }

    /// Build a group payload (`hash | MAC | ciphertext`) the way the firmware
    /// does: zero-padded AES-128-ECB, then a two-byte HMAC-SHA256.
    pub fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let aes = <Aes128 as KeyInit>::new_from_slice(&self.secret[..16])
            .expect("AES-128 key is 16 bytes");
        let mut cipher = plain.to_vec();
        cipher.resize(plain.len().div_ceil(BLOCK) * BLOCK, 0);
        for block in cipher.chunks_exact_mut(BLOCK) {
            aes.encrypt_block(block.into());
        }
        let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret)
            .expect("HMAC accepts any key length");
        hmac.update(&cipher);
        let mut payload = vec![self.hash];
        payload.extend_from_slice(&hmac.finalize().into_bytes()[..MAC_SIZE]);
        payload.extend_from_slice(&cipher);
        payload
    }

    /// Check the MAC and decrypt `MAC | ciphertext`.
    fn open(&self, mac_and_data: &[u8]) -> Option<Vec<u8>> {
        let (mac, cipher) = mac_and_data.split_at_checked(MAC_SIZE)?;
        if cipher.is_empty() || cipher.len() % BLOCK != 0 {
            return None;
        }
        let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret).ok()?;
        hmac.update(cipher);
        if hmac.finalize().into_bytes()[..MAC_SIZE] != *mac {
            return None;
        }
        let aes = <Aes128 as KeyInit>::new_from_slice(&self.secret[..16]).ok()?;
        let mut plain = cipher.to_vec();
        for block in plain.chunks_exact_mut(BLOCK) {
            aes.decrypt_block(block.into());
        }
        Some(plain)
    }
}

/// A decrypted group payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMessage {
    pub channel: String,
    /// Sender's clock (Unix seconds); only present for text.
    pub timestamp: Option<u32>,
    /// `sender: text` for `GRP_TXT`, a short description for `GRP_DATA`.
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshCoreRegion {
    pub name: String,
    key: [u8; 16],
}

impl MeshCoreRegion {
    /// A public region: its key is the first 16 bytes of SHA-256 over
    /// `#name`. Private (`$name`) regions have keys we cannot derive.
    pub fn named(name: &str) -> Self {
        let name = hashtag_name(name);
        let digest = Sha256::digest(name.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        Self { name, key }
    }

    /// The scope code this region gives a packet.
    pub fn transport_code(&self, payload_type: u8, payload: &[u8]) -> u16 {
        let mut hmac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC accepts any key length");
        hmac.update(&[payload_type]);
        hmac.update(payload);
        let digest = hmac.finalize().into_bytes();
        // 0x0000 and 0xFFFF are reserved by the firmware.
        match u16::from_le_bytes([digest[0], digest[1]]) {
            0 => 1,
            0xFFFF => 0xFFFE,
            code => code,
        }
    }
}

/// Every MeshCore key this instance knows.
#[derive(Debug, Clone)]
pub struct MeshCoreKeys {
    channels: Vec<MeshCoreChannel>,
    regions: Vec<MeshCoreRegion>,
}

impl Default for MeshCoreKeys {
    fn default() -> Self {
        Self::new(Vec::new(), Vec::new())
    }
}

impl MeshCoreKeys {
    /// The Public channel is always included.
    pub fn new(mut channels: Vec<MeshCoreChannel>, regions: Vec<MeshCoreRegion>) -> Self {
        let public = MeshCoreChannel::public();
        if !channels.iter().any(|channel| channel.secret == public.secret) {
            channels.insert(0, public);
        }
        Self { channels, regions }
    }

    pub fn channels(&self) -> &[MeshCoreChannel] {
        &self.channels
    }

    pub fn regions(&self) -> &[MeshCoreRegion] {
        &self.regions
    }

    /// Names of the known channels with this hash. A one-byte hash is shared
    /// by many channels, so this is a hint until a MAC confirms it.
    pub fn channel_names(&self, hash: u8) -> Vec<String> {
        self.channels
            .iter()
            .filter(|channel| channel.hash == hash)
            .map(|channel| channel.name.clone())
            .collect()
    }

    /// Decrypt a `GRP_TXT` (5) or `GRP_DATA` (6) payload with a known key.
    pub fn decrypt_group(&self, payload_type: u8, payload: &[u8]) -> Option<GroupMessage> {
        let (&hash, mac_and_data) = payload.split_first()?;
        for channel in self.channels.iter().filter(|channel| channel.hash == hash) {
            let Some(plain) = channel.open(mac_and_data) else {
                continue;
            };
            let message = match payload_type {
                0x05 => group_text(&plain),
                0x06 => group_data(&plain),
                _ => None,
            };
            if let Some((timestamp, text)) = message {
                return Some(GroupMessage {
                    channel: channel.name.clone(),
                    timestamp,
                    text,
                });
            }
        }
        None
    }

    /// The known region whose key produces this scope code for the packet.
    pub fn region_for(&self, payload_type: u8, payload: &[u8], code: u16) -> Option<&str> {
        self.regions
            .iter()
            .find(|region| region.transport_code(payload_type, payload) == code)
            .map(|region| region.name.as_str())
    }
}

/// `timestamp (4) | type (1) | "sender: text" NUL padding`.
fn group_text(plain: &[u8]) -> Option<(Option<u32>, String)> {
    if plain.len() < 5 || plain[4] >> 2 != 0 {
        return None;
    }
    let timestamp = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]);
    let body = &plain[5..];
    let end = body.iter().position(|byte| *byte == 0).unwrap_or(body.len());
    // Text comes straight off the air: keep it on one line and drop control
    // characters before it reaches logs or the UI.
    let text: String = String::from_utf8_lossy(&body[..end])
        .chars()
        .map(|ch| if ch == '\n' || ch == '\t' { ' ' } else { ch })
        .filter(|ch| !ch.is_control())
        .collect();
    Some((Some(timestamp), text.trim().to_owned()))
}

/// `data type (2) | length (1) | data`.
fn group_data(plain: &[u8]) -> Option<(Option<u32>, String)> {
    if plain.len() < 3 {
        return None;
    }
    let data_type = u16::from_le_bytes([plain[0], plain[1]]);
    let length = usize::from(plain[2]);
    let data = plain.get(3..3 + length)?;
    Some((
        None,
        format!(
            "data type 0x{data_type:04x}, {length} B: {}",
            crate::util::hex(data)
        ),
    ))
}

fn hashtag_name(name: &str) -> String {
    let name = name.trim();
    if name.starts_with('#') {
        name.to_owned()
    } else {
        format!("#{name}")
    }
}

fn decode_key(key: &str) -> Option<Vec<u8>> {
    let is_hex = (key.len() == 32 || key.len() == 64) && key.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex {
        return (0..key.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&key[at..at + 2], 16).ok())
            .collect();
    }
    base64::engine::general_purpose::STANDARD.decode(key).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(channel: &MeshCoreChannel, plain: &[u8]) -> Vec<u8> {
        channel.seal(plain)
    }

    fn text_plain(timestamp: u32, text: &str) -> Vec<u8> {
        let mut plain = timestamp.to_le_bytes().to_vec();
        plain.push(0);
        plain.extend_from_slice(text.as_bytes());
        plain
    }

    #[test]
    fn well_known_channel_hashes() {
        // 0x11 is the hash Public traffic carries on air.
        assert_eq!(MeshCoreChannel::public().hash, 0x11);
        assert_eq!(MeshCoreChannel::hashtag("#test").hash, 0xd9);
        assert_eq!(MeshCoreChannel::hashtag("test").name, "#test");
    }

    #[test]
    fn decrypts_public_and_hashtag_text() {
        let keys = MeshCoreKeys::new(vec![MeshCoreChannel::hashtag("#test")], Vec::new());
        let public = seal(&MeshCoreChannel::public(), &text_plain(1_700_000_000, "Ana: hola"));
        let message = keys.decrypt_group(0x05, &public).expect("decrypt public");
        assert_eq!(message.channel, "Public");
        assert_eq!(message.timestamp, Some(1_700_000_000));
        assert_eq!(message.text, "Ana: hola");

        let tagged = seal(
            &MeshCoreChannel::hashtag("#test"),
            &text_plain(5, "Bo: a longer message that spans more than one block"),
        );
        let message = keys.decrypt_group(0x05, &tagged).expect("decrypt hashtag");
        assert_eq!(message.channel, "#test");
        assert_eq!(
            message.text,
            "Bo: a longer message that spans more than one block"
        );
    }

    #[test]
    fn rejects_unknown_keys_and_tampering() {
        let keys = MeshCoreKeys::default();
        let other = seal(&MeshCoreChannel::hashtag("#other"), &text_plain(1, "x: y"));
        assert!(keys.decrypt_group(0x05, &other).is_none());

        let mut tampered = seal(&MeshCoreChannel::public(), &text_plain(1, "x: y"));
        *tampered.last_mut().unwrap() ^= 1;
        assert!(keys.decrypt_group(0x05, &tampered).is_none());
        assert!(keys.decrypt_group(0x05, &[0x11, 0, 0]).is_none());
        assert!(keys.decrypt_group(0x05, &[]).is_none());
    }

    #[test]
    fn strips_control_characters_from_text() {
        let keys = MeshCoreKeys::default();
        let payload = seal(
            &MeshCoreChannel::public(),
            &text_plain(1, "x: a\nb\u{1b}[31m"),
        );
        assert_eq!(keys.decrypt_group(0x05, &payload).unwrap().text, "x: a b[31m");
    }

    #[test]
    fn describes_group_data() {
        let keys = MeshCoreKeys::default();
        let payload = seal(&MeshCoreChannel::public(), &[0x34, 0x12, 2, 0xab, 0xcd]);
        let message = keys.decrypt_group(0x06, &payload).unwrap();
        assert_eq!(message.text, "data type 0x1234, 2 B: abcd");
        assert_eq!(message.timestamp, None);
    }

    #[test]
    fn matches_region_codes() {
        let keys = MeshCoreKeys::new(
            Vec::new(),
            vec![MeshCoreRegion::named("madrid"), MeshCoreRegion::named("#es")],
        );
        let payload = b"some payload";
        let code = MeshCoreRegion::named("#es").transport_code(0x05, payload);
        assert_eq!(keys.region_for(0x05, payload, code), Some("#es"));
        // The payload type is part of the code.
        assert_ne!(
            MeshCoreRegion::named("#es").transport_code(0x04, payload),
            code
        );
        assert_eq!(MeshCoreKeys::default().region_for(0x05, payload, code), None);
        assert_eq!(MeshCoreRegion::named("madrid").name, "#madrid");
    }

    #[test]
    fn reads_keys_from_config() {
        assert_eq!(
            MeshCoreChannel::from_config("public", "").unwrap(),
            MeshCoreChannel::public()
        );
        assert_eq!(
            MeshCoreChannel::from_config("Mine", "izOH6cXN6mrJ5e26oRXNcg==")
                .unwrap()
                .hash,
            0x11
        );
        assert_eq!(
            MeshCoreChannel::from_config("Mine", "8b3387e9c5cdea6ac9e5edbaa115cd72")
                .unwrap()
                .hash,
            0x11
        );
        assert!(MeshCoreChannel::from_config("Private", "").is_err());
        assert!(MeshCoreChannel::from_config("Short", "AQ==").is_err());
        assert!(MeshCoreChannel::from_config("", "").is_err());
    }
}
