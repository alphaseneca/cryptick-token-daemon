//! Hot-retargeting the live transport through `devices.select`
//! (PROJECT.md's multi-device work) — driven over the real IPC server
//! dispatch (PROJECT.md §13), following the pattern in `ipc_server.rs`.
//!
//! There is no second physical BLE device in this sandbox, so this exercises
//! the generic plumbing (`Bridge`/`server::serve_connection`'s `SelectDevice`
//! handling and the `LiveRetarget` seam) against a small fake that stands in
//! for `ReconnectingBleTransport`: one `FakeDevice` per simulated physical
//! device, switchable through `LiveRetarget`, with a `reachable` set a test
//! can shrink to simulate a device going out of BLE range. What this does
//! **not** prove is covered in `NOTES.md`: whether
//! `ReconnectingBleTransport::retarget` itself behaves the same way against
//! a real radio and two real tokens.
#![cfg(feature = "fake-transport")]

use ble_framing::FragmentSize;
use ctap::{Response, StatusCode};
use daemon::{
    devices::DeviceStore,
    fake::{FakeDevice, Reply},
    server::serve_connection,
    transport::{FragmentTransport, LiveRetarget, RetargetError},
    Bridge, LinkState, TransportError,
};
use ipc::{ClientMessage, DaemonMessage, Envelope, ErrorCode, FrameDecoder};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn size(n: u16) -> FragmentSize {
    FragmentSize::new(n).expect("legal size")
}

fn get_info_cbor() -> Vec<u8> {
    vec![ctap::Command::GET_INFO.as_u8()]
}

/// Stands in for `ReconnectingBleTransport` in these tests: several named
/// `FakeDevice`s sharing one "current" pointer, switchable through
/// `LiveRetarget`. `reachable` simulates which ids currently answer a BLE
/// scan — removing one is how a test simulates a device going out of range,
/// without needing a real radio.
#[derive(Clone)]
struct MultiDeviceFake {
    devices: Arc<HashMap<String, FakeDevice>>,
    reachable: Arc<Mutex<HashSet<String>>>,
    current: Arc<Mutex<String>>,
}

impl MultiDeviceFake {
    fn new(devices: HashMap<String, FakeDevice>, initial: &str) -> Self {
        assert!(
            devices.contains_key(initial),
            "the initial id must be one of the fakes"
        );
        let reachable = devices.keys().cloned().collect();
        Self {
            devices: Arc::new(devices),
            reachable: Arc::new(Mutex::new(reachable)),
            current: Arc::new(Mutex::new(initial.to_string())),
        }
    }

    /// Simulates `id` going (or already being) out of BLE range.
    fn set_unreachable(&self, id: &str) {
        self.reachable.lock().unwrap().remove(id);
    }

    fn current_device(&self) -> FakeDevice {
        let id = self.current.lock().unwrap().clone();
        self.devices
            .get(&id)
            .cloned()
            .expect("current id is always one of the fakes")
    }
}

#[async_trait::async_trait]
impl FragmentTransport for MultiDeviceFake {
    async fn fragment_size(&mut self) -> Result<FragmentSize, TransportError> {
        self.current_device().fragment_size().await
    }

    async fn write_fragment(&mut self, fragment: &[u8]) -> Result<(), TransportError> {
        self.current_device().write_fragment(fragment).await
    }

    async fn next_notification(&mut self) -> Result<Vec<u8>, TransportError> {
        self.current_device().next_notification().await
    }

    fn link(&self) -> LinkState {
        self.current_device().link()
    }
}

#[async_trait::async_trait]
impl LiveRetarget for MultiDeviceFake {
    async fn retarget(&self, target: &str) -> Result<(), RetargetError> {
        let known = self.devices.contains_key(target);
        let reachable = self.reachable.lock().unwrap().contains(target);
        if !known || !reachable {
            // Mirrors `ReconnectingBleTransport::handle_retarget_request`:
            // refuse without touching `current` at all, so whatever was
            // connected before is left exactly as it was.
            return Err(RetargetError::Unreachable(target.to_string()));
        }
        *self.current.lock().unwrap() = target.to_string();
        Ok(())
    }
}

struct Client {
    stream: DuplexStream,
    decoder: FrameDecoder,
}

impl Client {
    async fn send(&mut self, id: &str, body: ClientMessage) {
        let frame = ipc::encode(&Envelope::new(id, body)).expect("encode");
        self.stream.write_all(&frame).await.expect("write");
    }

    async fn recv(&mut self) -> Envelope<DaemonMessage> {
        let mut buf = [0u8; 8192];
        loop {
            if let Some(frame) = self.decoder.next_frame().expect("framing") {
                return ipc::decode_daemon(&frame).expect("decode");
            }
            let n = self.stream.read(&mut buf).await.expect("read");
            assert_ne!(n, 0, "server closed the connection unexpectedly");
            self.decoder.push(&buf[..n]);
        }
    }

    /// Reads replies until one correlated to `id` arrives.
    async fn recv_matching(&mut self, id: &str) -> DaemonMessage {
        loop {
            let reply = self.recv().await;
            if reply.id == id {
                return reply.body;
            }
        }
    }
}

/// `retarget_capable = false` simulates a transport with no `LiveRetarget`
/// implementation (today's `fake-transport` build, for real) — exactly the
/// pre-existing "bookkeeping only" behaviour `without_a_live_retarget_capability_*`
/// below checks is unchanged by this work.
fn start(transport: MultiDeviceFake, store: DeviceStore, retarget_capable: bool) -> Client {
    let (server_side, client_side) = tokio::io::duplex(64 * 1024);
    let bridge = Arc::new(Bridge::new(transport.clone()));
    let devices = Arc::new(Mutex::new(store));
    let retarget: Option<Arc<dyn LiveRetarget>> = if retarget_capable {
        Some(Arc::new(transport))
    } else {
        None
    };
    tokio::spawn(serve_connection(server_side, bridge, devices, retarget));
    Client {
        stream: client_side,
        decoder: FrameDecoder::new(),
    }
}

/// Two known devices, `device-a` reachable and active (recorded first, so it
/// becomes active automatically — `devices.rs`), `device-b` reachable but
/// not yet selected. Each answers `CtapRequest` with a distinct one-byte
/// marker so a test can tell which device actually answered.
fn two_device_fixture() -> (MultiDeviceFake, DeviceStore) {
    let mut devices = HashMap::new();
    devices.insert(
        "device-a".to_string(),
        FakeDevice::always(
            size(64),
            Reply::Ctap(Response::new(StatusCode::OK, vec![0xAA])),
        ),
    );
    devices.insert(
        "device-b".to_string(),
        FakeDevice::always(
            size(64),
            Reply::Ctap(Response::new(StatusCode::OK, vec![0xBB])),
        ),
    );
    let fake = MultiDeviceFake::new(devices, "device-a");

    let mut store = DeviceStore::in_memory();
    store.record_seen("device-a", Some("Device A"), "ble", false);
    store.record_seen("device-b", Some("Device B"), "ble", false);

    (fake, store)
}

#[tokio::test(start_paused = true)]
async fn selecting_a_different_reachable_device_changes_where_requests_go() {
    let (fake, store) = two_device_fixture();
    let mut client = start(fake, store, true);

    client
        .send(
            "sel",
            ClientMessage::SelectDevice {
                id: "device-b".into(),
            },
        )
        .await;
    assert!(matches!(
        client.recv_matching("sel").await,
        DaemonMessage::Ack
    ));

    client
        .send(
            "req",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 5_000,
            },
        )
        .await;
    match client.recv_matching("req").await {
        DaemonMessage::CtapResponse { cbor, .. } => {
            assert_eq!(cbor, vec![0xBB], "the request must now go to device-b");
        }
        other => panic!("expected a response, got {other:?}"),
    }

    // `ListDevices` must agree with what actually happened.
    client.send("list", ClientMessage::ListDevices).await;
    match client.recv_matching("list").await {
        DaemonMessage::DeviceList { devices } => {
            let active = devices.iter().find(|d| d.active).expect("one is active");
            assert_eq!(active.id, "device-b");
        }
        other => panic!("expected a device list, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn selecting_an_unreachable_device_fails_without_disrupting_the_active_connection() {
    let (fake, store) = two_device_fixture();
    fake.set_unreachable("device-b");
    let mut client = start(fake, store, true);

    client
        .send(
            "sel",
            ClientMessage::SelectDevice {
                id: "device-b".into(),
            },
        )
        .await;
    match client.recv_matching("sel").await {
        DaemonMessage::Error { code, .. } => assert_eq!(code, ErrorCode::NotConnected),
        other => panic!("expected an unreachable-device error, got {other:?}"),
    }

    // The previously-active device must still be the one serving requests —
    // no silent fallback, and no connection left dangling.
    client
        .send(
            "req",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 5_000,
            },
        )
        .await;
    match client.recv_matching("req").await {
        DaemonMessage::CtapResponse { cbor, .. } => assert_eq!(cbor, vec![0xAA]),
        other => panic!("expected device-a to still answer, got {other:?}"),
    }

    // Bookkeeping must not have moved either — it must never disagree with
    // the live connection about which device is actually in use.
    client.send("list", ClientMessage::ListDevices).await;
    match client.recv_matching("list").await {
        DaemonMessage::DeviceList { devices } => {
            let active = devices.iter().find(|d| d.active).expect("one is active");
            assert_eq!(active.id, "device-a");
        }
        other => panic!("expected a device list, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn selecting_the_already_active_device_is_a_safe_noop() {
    let (fake, store) = two_device_fixture();
    let mut client = start(fake, store, true);

    client
        .send(
            "sel",
            ClientMessage::SelectDevice {
                id: "device-a".into(),
            },
        )
        .await;
    assert!(matches!(
        client.recv_matching("sel").await,
        DaemonMessage::Ack
    ));

    client
        .send(
            "req",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 5_000,
            },
        )
        .await;
    match client.recv_matching("req").await {
        DaemonMessage::CtapResponse { cbor, .. } => assert_eq!(cbor, vec![0xAA]),
        other => panic!("expected device-a to still answer, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn selecting_an_unknown_id_is_a_bad_request() {
    let (fake, store) = two_device_fixture();
    let mut client = start(fake, store, true);

    client
        .send(
            "sel",
            ClientMessage::SelectDevice {
                id: "never-recorded".into(),
            },
        )
        .await;
    match client.recv_matching("sel").await {
        DaemonMessage::Error { code, .. } => assert_eq!(code, ErrorCode::BadRequest),
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn without_a_live_retarget_capability_select_device_is_bookkeeping_only() {
    // The pre-existing limitation this whole change exists to lift for
    // `ReconnectingBleTransport` — preserved for any transport that still
    // has no `LiveRetarget` implementation, today's `fake-transport` build
    // included.
    let (fake, store) = two_device_fixture();
    let mut client = start(fake, store, false);

    client
        .send(
            "sel",
            ClientMessage::SelectDevice {
                id: "device-b".into(),
            },
        )
        .await;
    assert!(matches!(
        client.recv_matching("sel").await,
        DaemonMessage::Ack
    ));

    client.send("list", ClientMessage::ListDevices).await;
    match client.recv_matching("list").await {
        DaemonMessage::DeviceList { devices } => {
            let active = devices.iter().find(|d| d.active).expect("one is active");
            assert_eq!(active.id, "device-b", "bookkeeping still updates");
        }
        other => panic!("expected a device list, got {other:?}"),
    }

    // But the live connection never moved — there was no retarget hook to
    // call at all, so a request still reaches device-a.
    client
        .send(
            "req",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 5_000,
            },
        )
        .await;
    match client.recv_matching("req").await {
        DaemonMessage::CtapResponse { cbor, .. } => {
            assert_eq!(
                cbor,
                vec![0xAA],
                "no live-retarget capability, no live effect"
            );
        }
        other => panic!("expected device-a to still answer, got {other:?}"),
    }
}
