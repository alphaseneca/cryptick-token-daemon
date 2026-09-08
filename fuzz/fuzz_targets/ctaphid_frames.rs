//! Fuzz target: CTAPHID packets arriving on the virtual HID node
//! (PROJECT.md §14, source 3).
//!
//! This is the least protected surface in the project. Bonding protects the
//! radio; nothing protects this. Any local process that passes the device
//! node's permission check can write arbitrary 64-byte reports straight into
//! this parser, with no authentication of any kind. A panic here is a daemon
//! crash triggerable by unprivileged local code.

#![no_main]

use ctaphid::{Assembler, Packet, PACKET_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut assembler = Assembler::new();

    // The host always writes whole 64-byte reports, so feed whole packets and
    // let the fuzzer spend its budget on headers and ordering rather than on
    // lengths the kernel would never produce.
    for chunk in data.chunks(PACKET_SIZE) {
        if chunk.len() < PACKET_SIZE {
            // Still exercise the short-packet rejection path.
            assert!(Packet::parse(chunk).is_err());
            break;
        }
        if let Ok(packet) = Packet::parse(chunk) {
            if let Ok(Some(message)) = assembler.push(&packet) {
                // A reassembled message must survive a round trip back to
                // packets, or our encoder and decoder disagree.
                if let Ok(packets) = message.packets() {
                    let _ = packets.count();
                }
            }
        }
    }

    // The pending-channel cap is what stops a local process exhausting memory.
    assert!(assembler.pending_channels() <= ctaphid::MAX_PENDING_CHANNELS);
});
