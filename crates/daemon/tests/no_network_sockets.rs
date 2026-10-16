//! PROJECT.md §15.6: the daemon must never bind a socket to anything but a
//! loopback or filesystem endpoint.
//!
//! Inspecting a running process's listening sockets needs privileges CI does not
//! have and differs on every OS. Checking that network listener types and wildcard
//! addresses are never named catches mistakes at the moment they are written.
//!
//! As anticipated in lines 8-9 and PROJECT.md §5 & §15.6, the sole exception is
//! `vpcd_relay.rs`, which connects as a client to `127.0.0.1:35963` (vpcd loopback).
//! Non-loopback addresses, wildcard binds (0.0.0.0), and listeners remain strictly
//! forbidden everywhere.

use std::{fs, path::Path};

/// Forbidden across every file in `crates/daemon/src/` with no exceptions.
const GLOBALLY_FORBIDDEN: &[&str] = &["TcpListener", "UdpSocket", "SocketAddrV6", "0.0.0.0"];

/// Forbidden in all daemon files except `vpcd_relay.rs` (the loopback TCP client).
const FORBIDDEN_OUTSIDE_VPCD: &[&str] = &["TcpStream", "SocketAddrV4"];

fn walk(dir: &Path, found: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("readable source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            walk(&path, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let is_vpcd_relay = path.file_name().is_some_and(|n| n == "vpcd_relay.rs");
            let text = fs::read_to_string(&path).expect("readable source file");
            for (n, line) in text.lines().enumerate() {
                // Skip comments explaining the rule.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("*") {
                    continue;
                }
                for needle in GLOBALLY_FORBIDDEN {
                    if line.contains(needle) {
                        found.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                    }
                }
                if !is_vpcd_relay {
                    for needle in FORBIDDEN_OUTSIDE_VPCD {
                        if line.contains(needle) {
                            found.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn the_daemon_names_no_unapproved_network_socket_types() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    walk(&src, &mut found);
    assert!(
        found.is_empty(),
        "unapproved network sockets or wildcard addresses in the daemon (PROJECT.md §5, §15.6):\n{}",
        found.join("\n")
    );
}

#[test]
fn vpcd_relay_strictly_requires_loopback() {
    let vpcd_relay_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("vpcd_relay.rs");
    assert!(
        vpcd_relay_path.exists(),
        "vpcd_relay.rs must exist in crates/daemon/src/"
    );

    let content = fs::read_to_string(&vpcd_relay_path).expect("vpcd_relay.rs is readable");

    // Must explicitly mention loopback and 127.0.0.1
    assert!(
        content.contains("127.0.0.1"),
        "vpcd_relay must use 127.0.0.1 loopback address"
    );
    assert!(
        content.contains("is_loopback"),
        "vpcd_relay must enforce is_loopback() validation"
    );

    // Must never contain wildcard or non-loopback
    assert!(
        !content.contains("0.0.0.0"),
        "vpcd_relay must never contain 0.0.0.0"
    );
}
