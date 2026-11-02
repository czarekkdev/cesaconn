//! Clipboard sync v1: the message, its strict decoder, ordering per peer,
//! and the one-byte answer (daemon.md 12).
//!
//! The message travels inside the `d_key` data layer of an authenticated
//! connection ([`crate::tcp_networker::ActionType::ClipboardSync`]):
//!
//! ```text
//! version     (1)  = 0x01
//! kind        (1)  = 0x01 text/utf-8
//! epoch       (8)  random per sender daemon run
//! origin_seq  (8)  u64 LE, per epoch, strictly increasing
//! content_len (4)  u32 LE, 1..=CLIP_MAX_LEN, equal to the remaining length
//! content     (content_len)
//! ```
//!
//! The sending device is not in the message: the receiver knows the
//! authenticated peer.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::auth_snow::{DATA_LAYER_OVERHEAD, MAX_TRUSTED_PEERS};

/// message format version
const CLIP_VERSION: u8 = 0x01;
/// content kind: UTF-8 text
const CLIP_KIND_TEXT: u8 = 0x01;
/// version (1) + kind (1) + epoch (8) + seq (8) + content length (4)
pub const CLIP_HEADER_LEN: usize = 22;
/// Longest clipboard text that is synced (bytes of UTF-8, 1 MiB).
pub const CLIP_MAX_LEN: usize = 1024 * 1024;
/// Longest clipboard payload on the wire, `d_key` layer included; the
/// receiver checks the declared length against it before allocating.
pub const CLIP_MAX_WIRE_LEN: usize = CLIP_HEADER_LEN + CLIP_MAX_LEN + DATA_LAYER_OVERHEAD;
/// Shortest one: one byte of text.
pub const CLIP_MIN_WIRE_LEN: usize = CLIP_HEADER_LEN + 1 + DATA_LAYER_OVERHEAD;

/// What the receiver answers after a data packet (`Hello`, `ClipboardSync`),
/// one byte through Noise (not the `d_key` layer: the answer to a wrong
/// `d_key` must still be readable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataAck {
    /// Taken (clipboard applied, hello answered).
    Applied = 0x00,
    /// Fine, but not used: clipboard sync is off there, an older message,
    /// or no clipboard on that platform.
    Ignored = 0x01,
    /// The payload failed the `d_key` layer: the data passwords differ.
    DataKeyDiffers = 0x02,
}

impl DataAck {
    /// The answer byte; unknown values are `None`.
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Applied),
            0x01 => Some(Self::Ignored),
            0x02 => Some(Self::DataKeyDiffers),
            _ => None,
        }
    }
}

/// A clipboard update. No `Debug` / `Clone`: it holds clipboard content.
pub struct ClipMessage {
    /// Random per sender daemon run.
    pub epoch: [u8; 8],
    /// Strictly increasing within the epoch.
    pub seq: u64,
    /// The text, valid UTF-8, wiped on drop.
    pub text: Zeroizing<String>,
}

/// Encodes an update into one buffer sized up front (it holds clipboard
/// content and must not reallocate). `None` if `text` is empty or longer
/// than [`CLIP_MAX_LEN`].
pub fn encode(epoch: &[u8; 8], seq: u64, text: &str) -> Option<Zeroizing<Vec<u8>>> {
    if text.is_empty() || text.len() > CLIP_MAX_LEN {
        return None;
    }
    let content_len = u32::try_from(text.len()).ok()?;

    let mut out = Zeroizing::new(Vec::with_capacity(
        CLIP_HEADER_LEN.saturating_add(text.len()),
    ));
    out.push(CLIP_VERSION);
    out.push(CLIP_KIND_TEXT);
    out.extend_from_slice(epoch);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&content_len.to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    Some(out)
}

/// Strict decoder: known version and kind, a content length of
/// `1..=CLIP_MAX_LEN` that matches the rest exactly, valid UTF-8. `None`
/// on anything else.
pub fn decode(payload: &[u8]) -> Option<ClipMessage> {
    let (&version, rest) = payload.split_first()?;
    let (&kind, rest) = rest.split_first()?;
    if version != CLIP_VERSION || kind != CLIP_KIND_TEXT {
        return None;
    }
    let (epoch, rest) = rest.split_first_chunk::<8>()?;
    let (seq, rest) = rest.split_first_chunk::<8>()?;
    let (content_len, content) = rest.split_first_chunk::<4>()?;
    let content_len = usize::try_from(u32::from_le_bytes(*content_len)).ok()?;

    if content_len == 0 || content_len > CLIP_MAX_LEN || content_len != content.len() {
        return None;
    }
    let text = std::str::from_utf8(content).ok()?;

    // one copy, sized exactly, wiped on drop
    let mut owned = Zeroizing::new(String::with_capacity(text.len()));
    owned.push_str(text);

    Some(ClipMessage {
        epoch: *epoch,
        seq: u64::from_le_bytes(*seq),
        text: owned,
    })
}

/// The newest update taken from each peer, so a late connection can't put
/// an older text back. A new epoch (the sender restarted) starts over.
#[derive(Default)]
pub struct UpdateOrder {
    /// (peer static key, epoch, last seq), at most [`MAX_TRUSTED_PEERS`].
    last: Vec<([u8; 32], [u8; 8], u64)>,
}

impl UpdateOrder {
    /// Whether an update `(epoch, seq)` from `peer` is newer than the last
    /// one taken; if so it is recorded.
    pub fn accept(&mut self, peer: &[u8; 32], epoch: &[u8; 8], seq: u64) -> bool {
        let known = self
            .last
            .iter_mut()
            .find(|(key, _, _)| bool::from(key.ct_eq(peer)));

        match known {
            Some((_, last_epoch, last_seq)) => {
                if last_epoch == epoch && seq <= *last_seq {
                    return false;
                }
                *last_epoch = *epoch;
                *last_seq = seq;
                true
            }
            None => {
                if self.last.len() >= MAX_TRUSTED_PEERS && !self.last.is_empty() {
                    self.last.remove(0);
                }
                self.last.push((*peer, *epoch, seq));
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that an update survives a round trip
    #[test]
    fn test_roundtrip() {
        let bytes = encode(&[7; 8], 42, "zażółć gęślą jaźń").unwrap();
        assert_eq!(bytes.len(), CLIP_HEADER_LEN + "zażółć gęślą jaźń".len());
        let message = decode(&bytes).unwrap();
        assert_eq!(message.epoch, [7; 8]);
        assert_eq!(message.seq, 42);
        assert_eq!(message.text.as_str(), "zażółć gęślą jaźń");
    }

    /// Test that nothing empty or too long is encoded
    #[test]
    fn test_encode_bounds() {
        assert!(encode(&[0; 8], 1, "").is_none());
        assert!(encode(&[0; 8], 1, &"a".repeat(CLIP_MAX_LEN)).is_some());
        assert!(encode(&[0; 8], 1, &"a".repeat(CLIP_MAX_LEN + 1)).is_none());
    }

    /// Test that the decoder refuses everything that isn't exactly right
    #[test]
    fn test_decode_strict() {
        let good = encode(&[1; 8], 1, "hello").unwrap().to_vec();
        assert!(decode(&good).is_some());

        let mut version = good.clone();
        version[0] = 2;
        assert!(decode(&version).is_none());

        let mut kind = good.clone();
        kind[1] = 2;
        assert!(decode(&kind).is_none());

        // length says more / less than is there
        let mut long = good.clone();
        long.push(b'!');
        assert!(decode(&long).is_none());
        assert!(decode(&good[..good.len() - 1]).is_none());

        // zero length
        let mut empty = good[..CLIP_HEADER_LEN].to_vec();
        empty[18..22].copy_from_slice(&0u32.to_le_bytes());
        assert!(decode(&empty).is_none());

        // over the limit, even when it matches
        let mut huge = good[..CLIP_HEADER_LEN].to_vec();
        let over = u32::try_from(CLIP_MAX_LEN + 1).unwrap();
        huge[18..22].copy_from_slice(&over.to_le_bytes());
        huge.resize(CLIP_HEADER_LEN + CLIP_MAX_LEN + 1, b'a');
        assert!(decode(&huge).is_none());

        // not UTF-8
        let mut binary = good.clone();
        let last = binary.len() - 1;
        binary[last] = 0xff;
        assert!(decode(&binary).is_none());

        // too short for a header
        assert!(decode(&good[..10]).is_none());
        assert!(decode(&[]).is_none());
    }

    /// Test that the decoder never panics on random input
    #[test]
    fn test_decode_random() {
        let mut seed = 0x1234_5678_u64;
        for len in 0..200usize {
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (seed >> 56) as u8
                })
                .collect();
            let _ = decode(&bytes);
        }
    }

    /// Test that only newer updates from a peer are taken, and a new epoch
    /// starts over
    #[test]
    fn test_ordering() {
        let mut ordering = UpdateOrder::default();
        let (a, b) = ([1; 32], [2; 32]);

        assert!(ordering.accept(&a, &[1; 8], 5));
        assert!(!ordering.accept(&a, &[1; 8], 5));
        assert!(!ordering.accept(&a, &[1; 8], 4));
        assert!(ordering.accept(&a, &[1; 8], 6));
        // another peer has its own counter
        assert!(ordering.accept(&b, &[1; 8], 1));
        // the sender restarted: a new epoch, its counter starts low again
        assert!(ordering.accept(&a, &[9; 8], 1));
        assert!(!ordering.accept(&a, &[9; 8], 1));
    }

    /// Test that the ordering memory is bounded
    #[test]
    fn test_ordering_bounded() {
        let mut ordering = UpdateOrder::default();
        for i in 0..=MAX_TRUSTED_PEERS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&u64::try_from(i).unwrap().to_le_bytes());
            assert!(ordering.accept(&key, &[0; 8], 1));
        }
        assert_eq!(ordering.last.len(), MAX_TRUSTED_PEERS);
    }

    /// Test the answer byte both ways
    #[test]
    fn test_ack_bytes() {
        for ack in [DataAck::Applied, DataAck::Ignored, DataAck::DataKeyDiffers] {
            assert_eq!(DataAck::from_u8(ack as u8), Some(ack));
        }
        assert_eq!(DataAck::from_u8(0x03), None);
    }
}
