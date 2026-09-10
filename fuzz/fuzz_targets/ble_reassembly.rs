//! Fuzz target: fragments arriving from the device (PROJECT.md §14, sources 1
//! and 2).
//!
//! Bonding does not make this input trustworthy. A bonded device running a
//! half-flashed image or an interrupted OTA sends garbage that is perfectly
//! authenticated, and service discovery happens outside the bond entirely. A
//! panic here is a user who cannot log in, caused by our own device.

#![no_main]

use ble_framing::Reassembler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The firmware's CTAP_MAX_MESSAGE_SIZE.
    let mut rx = Reassembler::with_max_message_len(1200);
    let rest = data;

    // Split the remaining bytes into fragments on a length-prefix, so the
    // fuzzer controls fragment boundaries as well as content.
    let mut cursor = rest;
    while let Some((&len, tail)) = cursor.split_first() {
        let take = (len as usize).min(tail.len());
        let (fragment, remainder) = tail.split_at(take);
        let _ = rx.push(fragment);
        cursor = remainder;
    }
});
