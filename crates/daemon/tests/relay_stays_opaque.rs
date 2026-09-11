//! PROJECT.md §8: the daemon relays payloads it does not interpret.
//!
//! `crates/piv` exists and does parse APDUs, because the provisioning tool has
//! to build them. That is a different process with a different job. This test
//! is what keeps the two apart: if the card edge ever becomes reachable from
//! the process that also owns the radio, it becomes a second place to misread
//! the spec inside the component with the most authority.

use std::fs;

#[test]
fn the_daemon_does_not_depend_on_the_card_edge() {
    let manifest = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("the daemon's own manifest is readable");

    let offending: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("piv"))
        .collect();

    assert!(
        offending.is_empty(),
        "daemon must not depend on `piv`: APDUs are opaque on the relay path \
         (PROJECT.md §8). Found: {offending:?}"
    );
}

#[test]
fn the_ctap_crate_the_daemon_does_use_still_parses_no_cbor() {
    // The same rule, in the direction it was originally written for. A CTAP
    // response is a status byte and an opaque body; the daemon reads the byte.
    let response = ctap::Response::decode(&[0x00, 0xA1, 0x01, 0x02]).unwrap();
    assert_eq!(response.status, ctap::StatusCode::OK);
    assert_eq!(response.data, vec![0xA1, 0x01, 0x02]);
}
