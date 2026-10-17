//! The IPC server, driven over an in-memory stream (PROJECT.md §13).
#![cfg(feature = "fake-transport")]

use ble_framing::{FragmentSize, KeepAliveStatus};
use ctap::{Response, StatusCode};
use daemon::{
    devices::DeviceStore,
    fake::{FakeDevice, Reply},
    server::serve_connection,
    Bridge,
};
use ipc::{ClientMessage, DaemonMessage, Envelope, ErrorCode, FrameDecoder, KeepaliveReason};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn size(n: u16) -> FragmentSize {
    FragmentSize::new(n).expect("legal size")
}

fn get_info_cbor() -> Vec<u8> {
    vec![ctap::Command::GET_INFO.as_u8()]
}

struct Client {
    stream: DuplexStream,
    decoder: FrameDecoder,
}

impl Client {
    async fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("write");
    }

    async fn send(&mut self, id: &str, body: ClientMessage) {
        let frame = ipc::encode(&Envelope::new(id, body)).expect("encode");
        self.send_raw(&frame).await;
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

    async fn closed(&mut self) -> bool {
        let mut buf = [0u8; 1024];
        loop {
            match self.stream.read(&mut buf).await {
                Ok(0) | Err(_) => return true,
                Ok(n) => self.decoder.push(&buf[..n]),
            }
        }
    }
}

fn start(device: FakeDevice) -> Client {
    start_with_devices(device, DeviceStore::in_memory())
}

fn start_with_devices(device: FakeDevice, devices: DeviceStore) -> Client {
    let (server_side, client_side) = tokio::io::duplex(64 * 1024);
    let bridge = Arc::new(Bridge::new(device));
    let devices = Arc::new(Mutex::new(devices));
    tokio::spawn(serve_connection(server_side, bridge, devices, None));
    Client {
        stream: client_side,
        decoder: FrameDecoder::new(),
    }
}

#[tokio::test(start_paused = true)]
async fn a_request_gets_a_response_with_the_same_id() {
    let expected = Response::new(StatusCode::OK, vec![0xa1, 0x01]);
    let mut client = start(FakeDevice::always(size(64), Reply::Ctap(expected.clone())));

    client
        .send(
            "req-1",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 30_000,
            },
        )
        .await;

    let reply = client.recv().await;
    assert_eq!(reply.id, "req-1");
    assert_eq!(reply.v, ipc::PROTOCOL_VERSION);
    match reply.body {
        DaemonMessage::CtapResponse { status, cbor } => {
            assert_eq!(status, 0);
            assert_eq!(cbor, expected.data);
        }
        other => panic!("expected a response, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn keepalives_arrive_before_the_response() {
    // A prompt that arrives after the answer is no prompt at all.
    let mut client = start(FakeDevice::always(
        size(64),
        Reply::KeepalivesThen {
            count: 3,
            status: KeepAliveStatus::UpNeeded,
            then: Box::new(Reply::Ctap(Response::error(StatusCode::OK))),
        },
    ));

    client
        .send(
            "k",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 30_000,
            },
        )
        .await;

    for _ in 0..3 {
        match client.recv().await.body {
            DaemonMessage::CtapKeepalive { reason } => assert_eq!(reason, KeepaliveReason::Up),
            other => panic!("expected a keepalive first, got {other:?}"),
        }
    }
    assert!(matches!(
        client.recv().await.body,
        DaemonMessage::CtapResponse { .. }
    ));
}

#[tokio::test(start_paused = true)]
async fn a_second_request_while_one_is_in_flight_is_refused() {
    // PROJECT.md §13: never interleave.
    let mut client = start(FakeDevice::always(
        size(64),
        Reply::KeepaliveForever(KeepAliveStatus::UpNeeded),
    ));

    client
        .send(
            "first",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 60_000,
            },
        )
        .await;
    // Let the first transaction take the slot.
    match client.recv().await.body {
        DaemonMessage::CtapKeepalive { .. } => {}
        other => panic!("expected a keepalive, got {other:?}"),
    }

    client
        .send(
            "second",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 60_000,
            },
        )
        .await;

    loop {
        let reply = client.recv().await;
        if reply.id == "second" {
            match reply.body {
                DaemonMessage::Error { code, .. } => {
                    assert_eq!(code, ErrorCode::Busy);
                    return;
                }
                other => panic!("expected Busy, got {other:?}"),
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn device_status_is_answerable_mid_transaction() {
    let mut client = start(FakeDevice::always(
        size(64),
        Reply::KeepaliveForever(KeepAliveStatus::UpNeeded),
    ));

    client
        .send(
            "t",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 60_000,
            },
        )
        .await;
    assert!(matches!(
        client.recv().await.body,
        DaemonMessage::CtapKeepalive { .. }
    ));

    client.send("s", ClientMessage::DeviceStatus).await;
    loop {
        let reply = client.recv().await;
        if reply.id == "s" {
            match reply.body {
                DaemonMessage::DeviceRange { in_range, bonded } => {
                    assert!(in_range);
                    assert!(bonded);
                    return;
                }
                other => panic!("expected a range report, got {other:?}"),
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn an_unbonded_device_reports_bonded_false() {
    // A Just Works bond exists but has no MITM protection, so it is not usable.
    let device = FakeDevice::always(size(64), Reply::Silent).with_link(daemon::LinkState {
        connected: true,
        bonded: true,
        authenticated: false,
    });
    let mut client = start(device);

    client.send("s", ClientMessage::DeviceStatus).await;
    match client.recv().await.body {
        DaemonMessage::DeviceRange { in_range, bonded } => {
            assert!(in_range);
            assert!(!bonded, "a bond without MITM protection is not usable");
        }
        other => panic!("expected a range report, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn cancelling_ends_the_transaction() {
    let mut client = start(FakeDevice::always(
        size(64),
        Reply::KeepaliveForever(KeepAliveStatus::UpNeeded),
    ));

    client
        .send(
            "c",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 60_000,
            },
        )
        .await;
    assert!(matches!(
        client.recv().await.body,
        DaemonMessage::CtapKeepalive { .. }
    ));

    client.send("c", ClientMessage::CtapCancel).await;
    loop {
        match client.recv().await.body {
            DaemonMessage::CtapKeepalive { .. } => continue,
            DaemonMessage::Error { code, .. } => {
                assert_eq!(code, ErrorCode::Cancelled);
                return;
            }
            other => panic!("expected a cancellation, got {other:?}"),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn cancelling_nothing_is_a_bad_request() {
    let mut client = start(FakeDevice::always(size(64), Reply::Silent));
    client.send("x", ClientMessage::CtapCancel).await;
    match client.recv().await.body {
        DaemonMessage::Error { code, .. } => assert_eq!(code, ErrorCode::BadRequest),
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn an_empty_ctap_request_is_rejected() {
    let mut client = start(FakeDevice::always(size(64), Reply::Silent));
    client
        .send(
            "e",
            ClientMessage::CtapRequest {
                cbor: Vec::new(),
                timeout_ms: 1000,
            },
        )
        .await;
    match client.recv().await.body {
        DaemonMessage::Error { code, .. } => assert_eq!(code, ErrorCode::BadRequest),
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn an_old_client_gets_a_version_error_not_a_misparse() {
    // PROJECT.md §14, release gate 6.
    let mut client = start(FakeDevice::always(size(64), Reply::Silent));
    let json = br#"{"v":99,"id":"old","type":"ctap.cancel"}"#;
    let mut frame = (json.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(json);
    client.send_raw(&frame).await;

    match client.recv().await.body {
        DaemonMessage::Error { code, .. } => assert_eq!(code, ErrorCode::UnsupportedVersion),
        other => panic!("expected a version error, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_bogus_length_prefix_closes_the_connection() {
    // The prefix is how frame boundaries are found; once one is untrustworthy
    // the stream cannot be resynchronised.
    let mut client = start(FakeDevice::always(size(64), Reply::Silent));
    client.send_raw(&u32::MAX.to_be_bytes()).await;
    assert!(client.closed().await);
}

#[tokio::test(start_paused = true)]
async fn a_timeout_is_reported_and_the_device_is_cancelled() {
    let device = FakeDevice::always(size(64), Reply::Silent);
    let state = device.state();
    let mut client = start(device);

    client
        .send(
            "t",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 5_000,
            },
        )
        .await;

    match client.recv().await.body {
        DaemonMessage::Error { code, .. } => assert_eq!(code, ErrorCode::Timeout),
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert_eq!(
        state.lock().unwrap().received_commands(),
        vec![ble_framing::Command::Msg, ble_framing::Command::Cancel]
    );
}

#[tokio::test(start_paused = true)]
async fn an_absurd_client_timeout_is_clamped() {
    let mut client = start(FakeDevice::always(size(64), Reply::Silent));
    client
        .send(
            "t",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: u64::MAX,
            },
        )
        .await;

    // Without the clamp this would pin the device indefinitely.
    let start = tokio::time::Instant::now();
    match client.recv().await.body {
        DaemonMessage::Error { code, .. } => assert_eq!(code, ErrorCode::Timeout),
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert!(start.elapsed() <= daemon::server::MAX_TIMEOUT + std::time::Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn a_client_that_disappears_cancels_its_transaction() {
    // Nobody is left to satisfy a user-presence prompt.
    let device = FakeDevice::always(size(64), Reply::KeepaliveForever(KeepAliveStatus::UpNeeded));
    let state = device.state();
    let mut client = start(device);

    client
        .send(
            "gone",
            ClientMessage::CtapRequest {
                cbor: get_info_cbor(),
                timeout_ms: 600_000,
            },
        )
        .await;
    assert!(matches!(
        client.recv().await.body,
        DaemonMessage::CtapKeepalive { .. }
    ));

    drop(client);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    assert!(
        state
            .lock()
            .unwrap()
            .received_commands()
            .contains(&ble_framing::Command::Cancel),
        "the device must be released when the client goes away"
    );
}

#[tokio::test]
async fn list_devices_on_an_empty_store_is_an_empty_list() {
    let mut client = start(FakeDevice::always(
        size(64),
        Reply::Ctap(Response::new(StatusCode::OK, vec![])),
    ));
    client.send("x", ClientMessage::ListDevices).await;
    match client.recv().await.body {
        DaemonMessage::DeviceList { devices } => assert!(devices.is_empty()),
        other => panic!("expected DeviceList, got {other:?}"),
    }
}

#[tokio::test]
async fn select_device_on_an_unknown_id_is_refused() {
    let mut client = start(FakeDevice::always(
        size(64),
        Reply::Ctap(Response::new(StatusCode::OK, vec![])),
    ));
    client
        .send(
            "x",
            ClientMessage::SelectDevice {
                id: "never-seen".into(),
            },
        )
        .await;
    match client.recv().await.body {
        DaemonMessage::Error { code, .. } => assert_eq!(code, ErrorCode::BadRequest),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn list_devices_reports_a_pre_seeded_device_as_active() {
    let mut store = DeviceStore::in_memory();
    store.record_seen("AA:BB:CC", Some("My Token"), "ble");
    let mut client = start_with_devices(
        FakeDevice::always(size(64), Reply::Ctap(Response::new(StatusCode::OK, vec![]))),
        store,
    );

    client.send("x", ClientMessage::ListDevices).await;
    match client.recv().await.body {
        DaemonMessage::DeviceList { devices } => {
            assert_eq!(devices.len(), 1);
            assert_eq!(devices[0].id, "AA:BB:CC");
            assert_eq!(devices[0].name, "My Token");
            assert_eq!(devices[0].transport, "ble");
            assert!(devices[0].active);
        }
        other => panic!("expected DeviceList, got {other:?}"),
    }
}

#[tokio::test]
async fn select_device_then_list_devices_reflects_the_new_active_id() {
    let mut store = DeviceStore::in_memory();
    store.record_seen("first", Some("First"), "ble");
    store.record_seen("second", Some("Second"), "ble");
    let mut client = start_with_devices(
        FakeDevice::always(size(64), Reply::Ctap(Response::new(StatusCode::OK, vec![]))),
        store,
    );

    client
        .send(
            "sel",
            ClientMessage::SelectDevice {
                id: "second".into(),
            },
        )
        .await;
    assert!(matches!(client.recv().await.body, DaemonMessage::Ack));

    client.send("list", ClientMessage::ListDevices).await;
    match client.recv().await.body {
        DaemonMessage::DeviceList { devices } => {
            let first = devices.iter().find(|d| d.id == "first").unwrap();
            let second = devices.iter().find(|d| d.id == "second").unwrap();
            assert!(!first.active);
            assert!(second.active);
        }
        other => panic!("expected DeviceList, got {other:?}"),
    }
}
