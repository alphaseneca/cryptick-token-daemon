//! The Unix domain socket binding: permissions, ownership, and a real
//! round trip (PROJECT.md §13, §15.6, §15.7).
#![cfg(all(unix, feature = "fake-transport"))]

use ble_framing::FragmentSize;
use ctap::{Response, StatusCode};
use daemon::{
    fake::{FakeDevice, Reply},
    server::{serve_connection, unix::IpcListener},
    Bridge,
};
use ipc::{ClientMessage, DaemonMessage, Envelope, FrameDecoder};
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A short unique directory. `sun_path` is 104 bytes on macOS, so the usual
/// scratch directories are too long to hold a socket.
fn scratch() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir();
    let base = if base.as_os_str().len() > 40 {
        PathBuf::from("/tmp")
    } else {
        base
    };
    base.join(format!("ck-{}-{n}", std::process::id()))
}

#[tokio::test]
async fn the_socket_and_its_directory_are_owner_only() {
    let dir = scratch();
    let listener = IpcListener::bind(dir.join("daemon.sock")).expect("bind");

    let socket_mode = std::fs::metadata(listener.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        socket_mode, 0o600,
        "socket must not be group/world readable"
    );

    let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "the directory must be owner-only too");

    drop(listener);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_request_round_trips_over_a_real_socket() {
    let dir = scratch();
    let path = dir.join("daemon.sock");
    let listener = IpcListener::bind(&path).expect("bind");

    let expected = Response::new(StatusCode::OK, vec![0xa1, 0x02]);
    let bridge = Arc::new(Bridge::new(FakeDevice::always(
        FragmentSize::new(64).unwrap(),
        Reply::Ctap(expected.clone()),
    )));

    tokio::spawn(async move {
        // Our own uid, so the credential check must let this through.
        let stream = listener.accept().await.expect("accept").expect("own uid");
        serve_connection(stream, bridge).await;
    });

    let mut client = tokio::net::UnixStream::connect(&path)
        .await
        .expect("connect");
    let frame = ipc::encode(&Envelope::new(
        "sock",
        ClientMessage::CtapRequest {
            cbor: vec![ctap::Command::GET_INFO.as_u8()],
            timeout_ms: 10_000,
        },
    ))
    .unwrap();
    client.write_all(&frame).await.unwrap();

    let mut decoder = FrameDecoder::new();
    let mut buf = [0u8; 4096];
    let reply = loop {
        if let Some(frame) = decoder.next_frame().unwrap() {
            break ipc::decode_daemon(&frame).unwrap();
        }
        let n = client.read(&mut buf).await.unwrap();
        assert_ne!(n, 0, "connection closed before a reply");
        decoder.push(&buf[..n]);
    };

    assert_eq!(reply.id, "sock");
    match reply.body {
        DaemonMessage::CtapResponse { status, cbor } => {
            assert_eq!(status, 0);
            assert_eq!(cbor, expected.data);
        }
        other => panic!("expected a response, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_stale_socket_from_a_crashed_daemon_is_replaced() {
    let dir = scratch();
    let path = dir.join("daemon.sock");

    let first = IpcListener::bind(&path).expect("first bind");
    // Leak the file rather than letting Drop clean it up, which is what a
    // crashed daemon leaves behind.
    std::mem::forget(first);
    assert!(path.exists());

    let second = IpcListener::bind(&path).expect("a stale socket must not block startup");
    assert!(second.path().exists());

    drop(second);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_over_long_path_fails_with_a_clear_error() {
    // Otherwise this surfaces as an opaque EINVAL from bind(2).
    let long = PathBuf::from("/tmp")
        .join("x".repeat(120))
        .join("daemon.sock");
    let err = IpcListener::bind(&long).expect_err("path is over the sun_path limit");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("limit"), "{err}");
}

#[tokio::test]
async fn dropping_the_listener_removes_the_socket() {
    let dir = scratch();
    let path = dir.join("daemon.sock");
    let listener = IpcListener::bind(&path).expect("bind");
    assert!(path.exists());
    drop(listener);
    assert!(
        !path.exists(),
        "a dead daemon should not leave a socket behind"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
