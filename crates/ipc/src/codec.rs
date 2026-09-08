//! Length-prefixed framing for the IPC stream.
//!
//! Four-byte big-endian length, then that many bytes of JSON. A stream socket
//! gives no message boundaries, so the decoder has to tolerate a frame arriving
//! in any number of reads, and several frames arriving in one.

use crate::IpcError;

/// The largest frame accepted, in bytes.
///
/// The endpoint is owner-only (PROJECT.md §15.7), so this is defence in depth
/// rather than the primary control — but a length prefix a peer chooses must
/// never turn into an allocation we did not budget for. The device caps CTAP
/// messages far below this; the headroom is for JSON and base64 overhead.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

const PREFIX_LEN: usize = 4;

/// Prefixes a payload with its length.
pub(crate) fn frame(payload: &[u8]) -> Result<Vec<u8>, IpcError> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(IpcError::FrameTooLong {
            len: payload.len(),
            max: MAX_FRAME_LEN,
        });
    }
    let mut out = Vec::with_capacity(PREFIX_LEN + payload.len());
    // The cast is safe: the length was just bounded by MAX_FRAME_LEN.
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Accumulates bytes from a stream and yields whole frames.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    /// A decoder with an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// How many bytes are buffered but not yet a complete frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Takes the next complete frame, if one has arrived.
    ///
    /// Returns `Ok(None)` when more bytes are needed. An
    /// [`IpcError::FrameTooLong`] is **not recoverable**: the length prefix is
    /// how we find the next boundary, so once one is untrustworthy the stream
    /// cannot be resynchronised. Close the connection.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, IpcError> {
        if self.buf.len() < PREFIX_LEN {
            return Ok(None);
        }
        let mut prefix = [0u8; PREFIX_LEN];
        prefix.copy_from_slice(&self.buf[..PREFIX_LEN]);
        let len = u32::from_be_bytes(prefix) as usize;

        if len > MAX_FRAME_LEN {
            return Err(IpcError::FrameTooLong {
                len,
                max: MAX_FRAME_LEN,
            });
        }
        if self.buf.len() < PREFIX_LEN + len {
            return Ok(None);
        }

        let payload = self.buf[PREFIX_LEN..PREFIX_LEN + len].to_vec();
        self.buf.drain(..PREFIX_LEN + len);
        Ok(Some(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_whole_frame_decodes() {
        let mut dec = FrameDecoder::new();
        dec.push(&frame(b"hello").unwrap());
        assert_eq!(dec.next_frame().unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(dec.next_frame().unwrap(), None);
        assert_eq!(dec.buffered(), 0);
    }

    #[test]
    fn an_empty_payload_is_a_valid_frame() {
        let mut dec = FrameDecoder::new();
        dec.push(&frame(b"").unwrap());
        assert_eq!(dec.next_frame().unwrap().as_deref(), Some(&b""[..]));
    }

    #[test]
    fn a_frame_split_across_reads_reassembles() {
        let bytes = frame(b"a longer payload").unwrap();
        for split in 1..bytes.len() {
            let mut dec = FrameDecoder::new();
            dec.push(&bytes[..split]);
            assert_eq!(dec.next_frame().unwrap(), None, "split at {split}");
            dec.push(&bytes[split..]);
            assert_eq!(
                dec.next_frame().unwrap().as_deref(),
                Some(&b"a longer payload"[..]),
                "split at {split}"
            );
        }
    }

    #[test]
    fn one_byte_at_a_time_still_works() {
        let bytes = frame(b"drip").unwrap();
        let mut dec = FrameDecoder::new();
        for byte in &bytes[..bytes.len() - 1] {
            dec.push(&[*byte]);
            assert_eq!(dec.next_frame().unwrap(), None);
        }
        dec.push(&[bytes[bytes.len() - 1]]);
        assert_eq!(dec.next_frame().unwrap().as_deref(), Some(&b"drip"[..]));
    }

    #[test]
    fn several_frames_in_one_read_all_come_out() {
        let mut dec = FrameDecoder::new();
        let mut stream = Vec::new();
        for payload in [&b"one"[..], b"two", b"three"] {
            stream.extend_from_slice(&frame(payload).unwrap());
        }
        dec.push(&stream);
        assert_eq!(dec.next_frame().unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(dec.next_frame().unwrap().as_deref(), Some(&b"two"[..]));
        assert_eq!(dec.next_frame().unwrap().as_deref(), Some(&b"three"[..]));
        assert_eq!(dec.next_frame().unwrap(), None);
    }

    #[test]
    fn an_oversized_length_prefix_is_rejected_without_allocating() {
        let mut dec = FrameDecoder::new();
        dec.push(&u32::MAX.to_be_bytes());
        match dec.next_frame() {
            Err(IpcError::FrameTooLong { len, max }) => {
                assert_eq!(len, u32::MAX as usize);
                assert_eq!(max, MAX_FRAME_LEN);
            }
            other => panic!("expected FrameTooLong, got {other:?}"),
        }
    }

    #[test]
    fn encoding_an_oversized_payload_fails_rather_than_truncating() {
        let big = vec![0u8; MAX_FRAME_LEN + 1];
        assert!(matches!(frame(&big), Err(IpcError::FrameTooLong { .. })));
    }

    #[test]
    fn a_frame_at_exactly_the_limit_is_accepted() {
        let payload = vec![0x41u8; MAX_FRAME_LEN];
        let bytes = frame(&payload).unwrap();
        let mut dec = FrameDecoder::new();
        dec.push(&bytes);
        assert_eq!(dec.next_frame().unwrap(), Some(payload));
    }
}
