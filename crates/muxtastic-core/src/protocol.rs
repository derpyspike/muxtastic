//! Meshtastic PhoneAPI framing.
//!
//! Wire format: `[0x94, 0xC3, len_hi, len_lo, payload...]` with a 2-byte
//! big-endian length and a 512-byte payload cap (firmware
//! `MAX_TO_FROM_RADIO_SIZE`).

pub const START1: u8 = 0x94;
pub const START2: u8 = 0xC3;
pub const MAX_PACKET_SIZE: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("payload is {0} bytes, maximum is {MAX_PACKET_SIZE}")]
    PayloadTooLarge(usize),
}

/// Wrap a protobuf payload in a PhoneAPI frame.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PACKET_SIZE {
        return Err(FrameError::PayloadTooLarge(payload.len()));
    }
    let len = payload.len() as u16;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.push(START1);
    out.push(START2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Incremental frame decoder.
///
/// Feed arbitrary chunks with [`FrameDecoder::push`] and drain complete
/// payloads with [`FrameDecoder::next_frame`]. It tolerates leading garbage,
/// frames split across reads, and headers with an oversized length. Such a
/// header is treated as a false sync: only the 4 header bytes are dropped and
/// the search restarts right after them, like the firmware's stream parser.
/// The result therefore never depends on how the bytes were split into reads.
#[derive(Debug, Default, Clone)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append bytes received from the link.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Number of bytes waiting for a complete frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Return the next complete payload, or `None` if more bytes are needed.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        loop {
            // The original decoder keeps incomplete buffers untouched.
            if self.buf.len() < 4 {
                return None;
            }

            let start = match find_sync(&self.buf) {
                Some(pos) => pos,
                None => {
                    self.drop_unsynced();
                    return None;
                }
            };
            if start > 0 {
                self.buf.drain(..start);
            }

            // After dropping garbage we may no longer have a full header.
            if self.buf.len() < 4 {
                return None;
            }

            let payload_len = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;

            if payload_len > MAX_PACKET_SIZE {
                // No peer sends more than 512 bytes, so this is corruption or
                // a false sync. Trusting the bogus length would swallow up to
                // 64 KiB of good frames; drop just the header and resync.
                self.buf.drain(..4);
                continue;
            }

            let frame_len = 4 + payload_len;
            if self.buf.len() < frame_len {
                return None;
            }

            let payload = self.buf[4..frame_len].to_vec();
            self.buf.drain(..frame_len);
            return Some(payload);
        }
    }
}

/// Find the first `0x94 0xC3` pair, keeping a trailing lone `0x94` in case it
/// is the first half of a split pair.
fn find_sync(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == [START1, START2])
}

impl FrameDecoder {
    /// Drop bytes that cannot start a frame. Called when [`find_sync`] fails.
    fn drop_unsynced(&mut self) {
        if self.buf.last() == Some(&START1) {
            let keep = self.buf.len() - 1;
            self.buf.drain(..keep);
        } else {
            self.buf.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_frame() {
        let payload = b"hello mesh";
        let frame = encode_frame(payload).unwrap();
        assert_eq!(&frame[..4], &[START1, START2, 0, 10]);

        let mut decoder = FrameDecoder::new();
        decoder.push(&frame);
        assert_eq!(decoder.next_frame().as_deref(), Some(payload.as_slice()));
        assert_eq!(decoder.next_frame(), None);
    }

    #[test]
    fn handles_a_frame_split_across_reads() {
        let frame = encode_frame(b"abcdef").unwrap();
        let mut decoder = FrameDecoder::new();

        for chunk in frame.chunks(3) {
            decoder.push(chunk);
        }
        assert_eq!(decoder.next_frame().as_deref(), Some(b"abcdef".as_slice()));
    }

    #[test]
    fn skips_leading_garbage() {
        let mut decoder = FrameDecoder::new();
        decoder.push(&[0x00, 0xFF, 0x11, START1, START2, 0, 1, 0x42]);
        assert_eq!(decoder.next_frame(), Some(vec![0x42]));
    }

    #[test]
    fn keeps_a_trailing_partial_sync_byte() {
        // Fewer than four bytes are kept untouched, matching the Python codec.
        let mut decoder = FrameDecoder::new();
        decoder.push(&[0x00, 0x11, 0x94]);
        assert_eq!(decoder.next_frame(), None);
        assert_eq!(decoder.buffered(), 3);

        // Once we have a full header's worth, garbage is dropped but a
        // trailing lone 0x94 survives as the first half of a split sync.
        let mut decoder = FrameDecoder::new();
        decoder.push(&[0x00, 0x11, 0x22, 0x94]);
        assert_eq!(decoder.next_frame(), None);
        assert_eq!(decoder.buffered(), 1);
    }

    #[test]
    fn skips_an_oversized_frame_and_finds_the_next() {
        let mut decoder = FrameDecoder::new();
        // A complete oversized frame followed by a valid one.
        decoder.push(&[START1, START2, 0x02, 0x01]);
        decoder.push(&vec![0xAA; 0x201]);
        decoder.push(&encode_frame(b"ok").unwrap());
        assert_eq!(decoder.next_frame().as_deref(), Some(b"ok".as_slice()));
    }

    #[test]
    fn oversized_resync_does_not_depend_on_read_chunking() {
        // A bogus oversized header directly followed by a good frame, then
        // filler and another good frame.
        let mut stream = vec![START1, START2, 0x02, 0x01];
        stream.extend_from_slice(&encode_frame(b"first").unwrap());
        stream.extend_from_slice(&[0x55; 600]);
        stream.extend_from_slice(&encode_frame(b"second").unwrap());

        let decode = |chunk: usize| {
            let mut decoder = FrameDecoder::new();
            let mut frames = Vec::new();
            for part in stream.chunks(chunk) {
                decoder.push(part);
                while let Some(frame) = decoder.next_frame() {
                    frames.push(frame);
                }
            }
            frames
        };

        let expected = vec![b"first".to_vec(), b"second".to_vec()];
        for chunk in [1, 2, 3, 5, 64, 517, stream.len()] {
            assert_eq!(decode(chunk), expected, "chunk size {chunk}");
        }
    }

    #[test]
    fn rejects_oversized_payloads() {
        assert_eq!(
            encode_frame(&vec![0u8; MAX_PACKET_SIZE + 1]),
            Err(FrameError::PayloadTooLarge(MAX_PACKET_SIZE + 1))
        );
    }
}
