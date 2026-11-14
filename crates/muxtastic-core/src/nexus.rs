//! Nexus-only `MeshPacket` diagnostics.
//!
//! The Nexus firmware adds two fields that are not in the upstream protobuf
//! artifact:
//!
//! * tag 63 `rx_frequency_error` — fixed32 float, Hz
//! * tag 64 `rx_coding_rate` — varint 1..=7 (the displayed denominator is raw + 4)
//!
//! Prost drops unknown fields, so the values are gone after decoding the
//! generated types. This module scans the raw `FromRadio` bytes directly,
//! mirroring the Jentastic `FromRadioDiagnostics` parser. Malformed or absent
//! input yields `None` and never affects the normal receive path.

pub const FREQUENCY_ERROR_FIELD: u32 = 63;
pub const CODING_RATE_FIELD: u32 = 64;

const FROM_RADIO_PACKET_FIELD: u32 = 2;
const WIRE_VARINT: u8 = 0;
const WIRE_FIXED64: u8 = 1;
const WIRE_LENGTH_DELIMITED: u8 = 2;
const WIRE_FIXED32: u8 = 5;
const MAX_VARINT_BYTES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct NexusDiagnostics {
    pub frequency_error: Option<f32>,
    pub coding_rate: Option<u8>,
}

impl NexusDiagnostics {
    pub fn is_empty(&self) -> bool {
        self.frequency_error.is_none() && self.coding_rate.is_none()
    }

    /// Display denominator used by the firmware/app (`raw + 4`).
    pub fn coding_rate_display(&self) -> Option<u8> {
        self.coding_rate.map(|raw| raw + 4)
    }
}

/// Parse diagnostics from one unframed `FromRadio` payload.
pub fn parse_from_radio(bytes: &[u8]) -> Option<NexusDiagnostics> {
    let mut offset = 0;
    while offset < bytes.len() {
        let (key, after_key) = read_varint(bytes, offset, bytes.len())?;
        offset = after_key;

        match wire_type(key) {
            WIRE_VARINT => {
                let (_, after_value) = read_varint(bytes, offset, bytes.len())?;
                offset = after_value;
            }
            WIRE_FIXED64 => offset = offset.checked_add(8)?,
            WIRE_LENGTH_DELIMITED => {
                let (length, after_length) = read_varint(bytes, offset, bytes.len())?;
                let length = usize::try_from(length).ok()?;
                let end = after_length.checked_add(length)?;
                if end > bytes.len() {
                    return None;
                }
                if field_number(key) == FROM_RADIO_PACKET_FIELD {
                    return parse_mesh_packet(bytes, after_length, end);
                }
                offset = end;
            }
            WIRE_FIXED32 => offset = offset.checked_add(4)?,
            _ => return None,
        }

        if offset > bytes.len() {
            return None;
        }
    }
    None
}

fn parse_mesh_packet(bytes: &[u8], start: usize, end: usize) -> Option<NexusDiagnostics> {
    let mut offset = start;
    let mut frequency_error = None;
    let mut coding_rate = None;

    while offset < end {
        let (key, after_key) = read_varint(bytes, offset, end)?;
        offset = after_key;

        match wire_type(key) {
            WIRE_VARINT => {
                let (value, after_value) = read_varint(bytes, offset, end)?;
                offset = after_value;
                if field_number(key) == CODING_RATE_FIELD {
                    coding_rate = u8::try_from(value)
                        .ok()
                        .filter(|value| (1..=7).contains(value));
                }
            }
            WIRE_FIXED64 => offset = offset.checked_add(8)?,
            WIRE_LENGTH_DELIMITED => {
                let (length, after_length) = read_varint(bytes, offset, end)?;
                let length = usize::try_from(length).ok()?;
                offset = after_length.checked_add(length)?;
                if offset > end {
                    return None;
                }
            }
            WIRE_FIXED32 => {
                if field_number(key) == FREQUENCY_ERROR_FIELD {
                    if offset + 4 > end {
                        return None;
                    }
                    let bits = u32::from_le_bytes([
                        bytes[offset],
                        bytes[offset + 1],
                        bytes[offset + 2],
                        bytes[offset + 3],
                    ]);
                    frequency_error = Some(f32::from_bits(bits));
                }
                offset = offset.checked_add(4)?;
            }
            _ => return None,
        }

        if offset < start || offset > end {
            return None;
        }
    }

    let diagnostics = NexusDiagnostics {
        frequency_error,
        coding_rate,
    };
    (!diagnostics.is_empty()).then_some(diagnostics)
}

fn read_varint(bytes: &[u8], start: usize, end: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    let mut offset = start;

    for _ in 0..MAX_VARINT_BYTES {
        if offset >= end {
            return None;
        }
        let byte = bytes[offset];
        offset += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((value, offset));
        }
        shift += 7;
    }
    None
}

fn field_number(key: u64) -> u32 {
    (key >> 3) as u32
}

fn wire_type(key: u64) -> u8 {
    (key & 0x07) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn key(field: u32, wire: u8) -> Vec<u8> {
        varint((u64::from(field) << 3) | u64::from(wire))
    }

    fn fixed32(field: u32, value: f32) -> Vec<u8> {
        let mut out = key(field, WIRE_FIXED32);
        out.extend_from_slice(&value.to_bits().to_le_bytes());
        out
    }

    fn varint_field(field: u32, value: u64) -> Vec<u8> {
        let mut out = key(field, WIRE_VARINT);
        out.extend_from_slice(&varint(value));
        out
    }

    fn length_field(field: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = key(field, WIRE_LENGTH_DELIMITED);
        out.extend_from_slice(&varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_frequency_error_and_coding_rate() {
        let mut packet = fixed32(FREQUENCY_ERROR_FIELD, -123.0);
        packet.extend_from_slice(&varint_field(CODING_RATE_FIELD, 3));
        let from_radio = length_field(FROM_RADIO_PACKET_FIELD, &packet);

        let diagnostics = parse_from_radio(&from_radio).expect("diagnostics");
        assert_eq!(diagnostics.frequency_error, Some(-123.0));
        assert_eq!(diagnostics.coding_rate, Some(3));
        assert_eq!(diagnostics.coding_rate_display(), Some(7));
    }

    #[test]
    fn parses_individual_fields() {
        let from_radio = length_field(
            FROM_RADIO_PACKET_FIELD,
            &fixed32(FREQUENCY_ERROR_FIELD, 12.0),
        );
        let diagnostics = parse_from_radio(&from_radio).expect("frequency error");
        assert_eq!(diagnostics.frequency_error, Some(12.0));
        assert_eq!(diagnostics.coding_rate, None);

        let from_radio = length_field(FROM_RADIO_PACKET_FIELD, &varint_field(CODING_RATE_FIELD, 1));
        let diagnostics = parse_from_radio(&from_radio).expect("coding rate");
        assert_eq!(diagnostics.frequency_error, None);
        assert_eq!(diagnostics.coding_rate, Some(1));
    }

    #[test]
    fn rejects_out_of_range_and_malformed_values() {
        let from_radio = length_field(FROM_RADIO_PACKET_FIELD, &varint_field(CODING_RATE_FIELD, 8));
        assert!(parse_from_radio(&from_radio).is_none());
        assert!(parse_from_radio(&length_field(FROM_RADIO_PACKET_FIELD, &[])).is_none());
        assert!(parse_from_radio(&varint_field(1, 42)).is_none());
        assert!(parse_from_radio(&key(FROM_RADIO_PACKET_FIELD, 2)).is_none());
        assert!(parse_from_radio(&from_radio[..from_radio.len() - 1]).is_none());
        assert!(parse_from_radio(&[]).is_none());
    }
}
