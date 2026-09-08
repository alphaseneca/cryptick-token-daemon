//! PROJECT.md §15.6: the daemon must never bind a socket to anything but a
//! loopback or filesystem endpoint — and in this design, never to a network
//! socket at all.
//!
//! Inspecting a running process's listening sockets needs privileges CI does not
//! have and differs on every OS. Checking that the network types are never even
//! named is cruder but catches the mistake at the moment it is written, which is
//! the point. If a future adapter genuinely needs `vpcd`'s loopback ports, this
//! test is where that exception gets made explicit rather than slipping in.

use std::{fs, path::Path};

const FORBIDDEN: &[&str] = &[
    "TcpListener",
    "TcpStream",
    "UdpSocket",
    "SocketAddrV4",
    "SocketAddrV6",
    "0.0.0.0",
];

fn walk(dir: &Path, found: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("readable source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            walk(&path, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = fs::read_to_string(&path).expect("readable source file");
            for (n, line) in text.lines().enumerate() {
                // Skip this file's own list, and comments explaining the rule.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("*") {
                    continue;
                }
                for needle in FORBIDDEN {
                    if line.contains(needle) {
                        found.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                    }
                }
            }
        }
    }
}

#[test]
fn the_daemon_names_no_network_socket_types() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    walk(&src, &mut found);
    assert!(
        found.is_empty(),
        "network sockets are forbidden in the daemon (PROJECT.md §5, §15.6):\n{}",
        found.join("\n")
    );
}
