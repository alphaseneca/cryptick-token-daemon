//! Fuzz target: fragments arriving from the device (PROJECT.md §14, sources 1
//! and 2).
//!
//! Bonding does not make this input trustworthy. A bonded device running a
//! half-flashed image or an interrupted OTA sends garbage that is perfectly
//! authenticated, and service discovery happens outside the bond entirely. A
//! panic here is a user who cannot log in, caused by our own device.

#![no_main]

use ble_framing::{FragmentSize, Reassembler};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First byte picks the fragment size, so the fuzzer explores the boundary
    // sizes rather than only the default.
    let Some((&size_selector, rest)) = data.split_first() else {
        return;
    };
    let size = FragmentSize::new(20 + (size_selector as u16 * 2) % 493)
        .expect("selector is constrained to 20..=512");

    // The firmware's CTAP_MAX_MESSAGE_SIZE.
    let mut rx = Reassembler::with_max_message_len(size, 1200);

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
