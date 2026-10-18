//! The Windows named pipe binding: the DACL, the peer-identity check, and a
//! real round trip (PROJECT.md §13, §15.6, §15.7).
//!
//! The counterpart of `unix_socket.rs`, and deliberately shaped like it: that
//! file asserts the socket's mode is `0600` and that a round trip survives the
//! `peer_cred()` check, so this one asserts the pipe's DACL names only the
//! daemon's own user and that a round trip survives the SID check.
//!
//! **None of this has ever been executed.** It was written on macOS alongside
//! `server::windows` and verified only by cross-compiling to
//! `x86_64-pc-windows-msvc`; the sandbox it was authored in cannot run Windows
//! code. Treat a first green run of this file as new information, not as a
//! regression check.
//!
//! What it still cannot prove even when it does run: a *cross-user* rejection.
//! That needs a second local account driving the client, which a single-user
//! test process cannot fake — a test cannot acquire another user's token
//! without credentials. The negative half of §15.7 therefore stays a manual
//! check (PROJECT.md §14, "What CI cannot cover") and belongs in
//! `docs/manual-tests.md`.
#![cfg(all(windows, feature = "fake-transport"))]

use ble_framing::FragmentSize;
use ctap::{Response, StatusCode};
use daemon::{
    devices::DeviceStore,
    fake::{FakeDevice, Reply},
    server::{serve_connection, windows::IpcListener},
    Bridge,
};
use ipc::{ClientMessage, DaemonMessage, Envelope, FrameDecoder};
use std::{
    os::windows::io::AsRawHandle,
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL},
    Security::{
        Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_KERNEL_OBJECT,
        },
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    },
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A pipe name unique to this process and test, so the tests in this file can
/// run concurrently without `first_pipe_instance(true)` colliding.
fn scratch_pipe() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(r"\\.\pipe\ck-test-{}-{n}", std::process::id()))
}

/// Reads the DACL the kernel actually stored on the object behind `handle`,
/// rendered back as SDDL.
///
/// Going through the kernel rather than re-reading our own string is the whole
/// point: it is the difference between asserting what we asked for and
/// asserting what we got.
fn dacl_of(handle: HANDLE) -> String {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `handle` is a live handle to a kernel object held by the caller.
    // The SID/ACL out-params are optional and passed null; only the
    // self-relative descriptor is requested, and it is freed below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(
        status, ERROR_SUCCESS,
        "GetSecurityInfo failed; a pipe client handle carries READ_CONTROL \
         through FILE_GENERIC_READ, so this should succeed"
    );

    let mut raw = std::ptr::null_mut();
    // SAFETY: `descriptor` is the descriptor just returned above; `raw` is a
    // live out-param receiving a LocalAlloc'd string.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut raw,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(ok, 0, "could not render the descriptor as SDDL");

    // SAFETY: `raw` is a NUL-terminated UTF-16 string owned by us until the
    // `LocalFree` below, which is the documented deallocator for both buffers.
    let sddl = unsafe {
        let mut len = 0usize;
        while *raw.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(raw, len));
        LocalFree(raw as HLOCAL);
        LocalFree(descriptor as HLOCAL);
        s
    };
    sddl
}

#[tokio::test]
async fn a_request_round_trips_over_a_real_pipe() {
    let path = scratch_pipe();
    let mut listener = IpcListener::bind(&path).expect("bind");

    let expected = Response::new(StatusCode::OK, vec![0xa1, 0x02]);
    let bridge = Arc::new(Bridge::new(FakeDevice::always(
        FragmentSize::new(64).unwrap(),
        Reply::Ctap(expected.clone()),
    )));

    let devices = Arc::new(Mutex::new(DeviceStore::in_memory()));
    tokio::spawn(async move {
        // Our own SID, so the peer check must let this through.
        let stream = listener.accept().await.expect("accept").expect("own SID");
        serve_connection(stream, bridge, devices, None).await;
    });

    let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(&path)
        .expect("connect");

    let frame = ipc::encode(&Envelope::new(
        "pipe",
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

    assert_eq!(reply.id, "pipe");
    match reply.body {
        DaemonMessage::CtapResponse { status, cbor } => {
            assert_eq!(status, 0);
            assert_eq!(cbor, expected.data);
        }
        other => panic!("expected a response, got {other:?}"),
    }
}

#[tokio::test]
async fn the_pipe_grants_access_only_to_the_daemons_own_user() {
    let path = scratch_pipe();
    let listener = IpcListener::bind(&path).expect("bind");
    let owner = listener.owner_sid().to_owned();

    // A client handle is the only way to reach the pipe object's descriptor
    // from outside the listener, and GENERIC_READ maps to FILE_GENERIC_READ,
    // which carries READ_CONTROL — enough for GetSecurityInfo.
    let client = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(&path)
        .expect("connect");

    let sddl = dacl_of(client.as_raw_handle() as HANDLE);

    assert!(
        sddl.contains(&owner),
        "the daemon's own user must be granted access: {sddl}"
    );

    // The failure this whole change exists to prevent. Microsoft documents the
    // *default* named-pipe descriptor as granting read access to Everyone and
    // to the anonymous account (CreateNamedPipeW, lpSecurityAttributes); if
    // any of these show up, the descriptor never took effect.
    for wide_open in [";WD)", ";AU)", ";BU)", ";BA)", ";AN)", ";WD;", "S-1-1-0"] {
        assert!(
            !sddl.contains(wide_open),
            "DACL still grants {wide_open}: {sddl}"
        );
    }

    // Exactly one ACE. A second one is either an inherited entry the `P`
    // (SE_DACL_PROTECTED) flag was supposed to block, or a sign the default
    // descriptor was merged rather than replaced.
    assert_eq!(
        sddl.matches('(').count(),
        1,
        "expected a single access-allowed ACE: {sddl}"
    );

    drop(client);
    drop(listener);
}

#[tokio::test]
async fn a_second_instance_carries_the_same_restriction() {
    // The listener creates a fresh instance per accepted connection, and
    // Microsoft's documentation defines the DACL only for the case where "a
    // new named pipe is being created" — it is silent on instances two and up.
    // This asserts the property that matters either way: whatever the kernel
    // does with the descriptor on a later instance, Everyone is not on it.
    let path = scratch_pipe();
    let mut listener = IpcListener::bind(&path).expect("bind");
    let owner = listener.owner_sid().to_owned();

    let first = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(&path)
        .expect("connect");
    let accepted = listener.accept().await.expect("accept").expect("own SID");

    // Accepting queued a second instance; connect to it.
    let second = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(&path)
        .expect("connect to the second instance");

    let sddl = dacl_of(second.as_raw_handle() as HANDLE);
    assert!(sddl.contains(&owner), "{sddl}");
    for wide_open in [";WD)", ";AU)", ";BU)", ";BA)", ";AN)", "S-1-1-0"] {
        assert!(
            !sddl.contains(wide_open),
            "the second instance grants {wide_open}: {sddl}"
        );
    }

    drop(first);
    drop(second);
    drop(accepted);
}

#[tokio::test]
async fn binding_twice_fails_rather_than_sharing_the_name() {
    // `first_pipe_instance(true)`: the Windows equivalent of refusing to bind
    // over a live daemon. A second daemon silently sharing the name would let
    // it answer clients that believe they are talking to the first.
    let path = scratch_pipe();
    let _first = IpcListener::bind(&path).expect("first bind");
    let second = IpcListener::bind(&path);
    assert!(
        second.is_err(),
        "a second listener must not be able to claim a live pipe name"
    );
}
