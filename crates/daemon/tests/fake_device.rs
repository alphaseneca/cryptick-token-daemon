//! L2: the whole proxy against an in-process fake, no radio (PROJECT.md §14).
#![cfg(feature = "fake-transport")]

use ble_framing::{BleErrorCode, Command, FragmentSize, KeepAliveStatus};
use ctap::{Request, Response, StatusCode};
use daemon::{
    cancel_pair,
    fake::{FakeDevice, Reply},
    DaemonError, LinkState, Session,
};
use ipc::KeepaliveReason;
use std::time::Duration;
use tokio::sync::mpsc;

fn size(n: u16) -> FragmentSize {
    FragmentSize::new(n).expect("test uses a legal fragment size")
}

fn get_info() -> Request {
    Request::new(ctap::Command::GET_INFO, Vec::new())
}

/// A response body big enough to need many fragments.
fn big_response(len: usize) -> Response {
    Response::new(StatusCode::OK, (0..len).map(|i| i as u8).collect())
}

struct Harness {
    keepalives: mpsc::UnboundedReceiver<KeepaliveReason>,
    sink: mpsc::UnboundedSender<KeepaliveReason>,
}

impl Harness {
    fn new() -> Self {
        let (sink, keepalives) = mpsc::unbounded_channel();
        Self { keepalives, sink }
    }

    fn drain(&mut self) -> Vec<KeepaliveReason> {
        let mut out = Vec::new();
        while let Ok(r) = self.keepalives.try_recv() {
            out.push(r);
        }
        out
    }
}

#[tokio::test(start_paused = true)]
async fn a_request_and_response_round_trip() {
    let expected = Response::new(StatusCode::OK, vec![0xa1, 0x01, 0x18, 0x20]);
    let device = FakeDevice::always(size(20), Reply::Ctap(expected.clone()));
    let state = device.state();
    let mut session = Session::new(device);
    let mut h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let got = session
        .transact(&get_info(), Duration::from_secs(30), &h.sink, &mut cancel)
        .await
        .expect("the happy path must work");

    assert_eq!(got, expected);
    assert!(h.drain().is_empty());

    // The device must have received exactly the request we meant to send.
    let state = state.lock().unwrap();
    assert_eq!(state.received_commands(), vec![Command::Msg]);
    assert_eq!(state.received[0].payload, get_info().encode());
}

#[tokio::test(start_paused = true)]
async fn round_trips_at_every_legal_fragment_size() {
    for n in [20u16, 21, 23, 64, 128, 255, 511, 512] {
        let expected = big_response(700);
        let device = FakeDevice::always(size(n), Reply::Ctap(expected.clone()));
        let mut session = Session::new(device);
        let h = Harness::new();
        let (_handle, mut cancel) = cancel_pair();

        let got = session
            .transact(&get_info(), Duration::from_secs(30), &h.sink, &mut cancel)
            .await
            .unwrap_or_else(|e| panic!("size {n} failed: {e}"));
        assert_eq!(got, expected, "size {n}");
    }
}

#[tokio::test(start_paused = true)]
async fn tolerates_a_device_that_under_fills_its_fragments() {
    // Advertises 512 but fragments at 20. Legal — HLEN is authoritative.
    let expected = big_response(400);
    let device = FakeDevice::always(size(512), Reply::Ctap(expected.clone()))
        .with_response_fragment_size(size(20));
    let mut session = Session::new(device);
    let h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let got = session
        .transact(&get_info(), Duration::from_secs(30), &h.sink, &mut cancel)
        .await
        .expect("under-filled fragments are legal");
    assert_eq!(got, expected);
}

#[tokio::test(start_paused = true)]
async fn keepalives_are_forwarded_and_never_swallowed() {
    let expected = Response::new(StatusCode::OK, vec![0x01]);
    let device = FakeDevice::always(
        size(64),
        Reply::KeepalivesThen {
            count: 5,
            status: KeepAliveStatus::UpNeeded,
            then: Box::new(Reply::Ctap(expected.clone())),
        },
    );
    let mut session = Session::new(device);
    let mut h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let got = session
        .transact(&get_info(), Duration::from_secs(30), &h.sink, &mut cancel)
        .await
        .unwrap();

    assert_eq!(got, expected);
    // PROJECT.md §15.3: every one of these reaches the client. The daemon has
    // no business deciding the user has "probably" touched the sensor.
    assert_eq!(h.drain(), vec![KeepaliveReason::Up; 5]);
}

#[tokio::test(start_paused = true)]
async fn processing_and_up_keepalives_are_distinguished() {
    let device = FakeDevice::always(
        size(64),
        Reply::KeepalivesThen {
            count: 1,
            status: KeepAliveStatus::Processing,
            then: Box::new(Reply::Ctap(Response::error(StatusCode::OK))),
        },
    );
    let mut session = Session::new(device);
    let mut h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    session
        .transact(&get_info(), Duration::from_secs(30), &h.sink, &mut cancel)
        .await
        .unwrap();
    assert_eq!(h.drain(), vec![KeepaliveReason::Processing]);
}

#[tokio::test(start_paused = true)]
async fn endless_keepalives_still_hit_the_deadline_and_send_cancel() {
    let device = FakeDevice::always(size(64), Reply::KeepaliveForever(KeepAliveStatus::UpNeeded));
    let state = device.state();
    let mut session = Session::new(device);
    let mut h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let err = session
        .transact(&get_info(), Duration::from_secs(30), &h.sink, &mut cancel)
        .await
        .expect_err("a device that never finishes must time out");
    assert_eq!(err, DaemonError::Timeout);

    // A keepalive must not extend the deadline, or a device could hold a
    // transaction open forever just by saying "still working".
    assert!(
        !h.drain().is_empty(),
        "keepalives should still be forwarded"
    );
    assert_eq!(
        state.lock().unwrap().received_commands(),
        vec![Command::Msg, Command::Cancel],
        "the device must be told to abandon the transaction"
    );
}

#[tokio::test(start_paused = true)]
async fn a_silent_device_times_out_and_is_cancelled() {
    let device = FakeDevice::always(size(20), Reply::Silent);
    let state = device.state();
    let mut session = Session::new(device);
    let h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let err = session
        .transact(&get_info(), Duration::from_secs(10), &h.sink, &mut cancel)
        .await
        .expect_err("silence must not hang forever");
    assert_eq!(err, DaemonError::Timeout);
    assert_eq!(
        state.lock().unwrap().received_commands(),
        vec![Command::Msg, Command::Cancel]
    );
}

#[tokio::test(start_paused = true)]
async fn a_transport_error_from_the_device_is_surfaced() {
    let device = FakeDevice::always(size(20), Reply::BleError(BleErrorCode::InvalidLen));
    let mut session = Session::new(device);
    let h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let err = session
        .transact(&get_info(), Duration::from_secs(10), &h.sink, &mut cancel)
        .await
        .expect_err("an ERROR command is a failure");
    assert_eq!(err, DaemonError::DeviceError(BleErrorCode::InvalidLen));
}

#[tokio::test(start_paused = true)]
async fn ctap_error_statuses_are_relayed_verbatim_not_remapped() {
    // The daemon is a relay. A status it does not recognise must reach the host
    // unchanged, or the host acts on something the authenticator never said.
    for byte in [0x27u8, 0x2e, 0x30, 0x3c, 0xdd] {
        let expected = Response::error(StatusCode(byte));
        let device = FakeDevice::always(size(20), Reply::Ctap(expected.clone()));
        let mut session = Session::new(device);
        let h = Harness::new();
        let (_handle, mut cancel) = cancel_pair();

        let got = session
            .transact(&get_info(), Duration::from_secs(10), &h.sink, &mut cancel)
            .await
            .expect("an error status is a successful relay, not a transport failure");
        assert_eq!(got.status, StatusCode(byte));
        assert!(!got.status.is_ok());
    }
}

#[tokio::test(start_paused = true)]
async fn reordered_continuations_are_rejected() {
    let device = FakeDevice::always(size(20), Reply::Reordered(big_response(300)));
    let mut session = Session::new(device);
    let h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let err = session
        .transact(&get_info(), Duration::from_secs(10), &h.sink, &mut cancel)
        .await
        .expect_err("out-of-order fragments must not reassemble");
    assert!(matches!(err, DaemonError::Framing(_)), "got {err:?}");
}

#[tokio::test(start_paused = true)]
async fn an_oversized_fragment_is_rejected() {
    let device = FakeDevice::always(size(20), Reply::OversizedFragment);
    let mut session = Session::new(device);
    let h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let err = session
        .transact(&get_info(), Duration::from_secs(10), &h.sink, &mut cancel)
        .await
        .expect_err("a fragment over the advertised size is malformed");
    assert!(matches!(err, DaemonError::Framing(_)), "got {err:?}");
}

#[tokio::test(start_paused = true)]
async fn a_response_that_stops_mid_stream_times_out() {
    let device = FakeDevice::always(
        size(20),
        Reply::Truncated {
            response: big_response(300),
            fragments: 3,
        },
    );
    let mut session = Session::new(device);
    let h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let err = session
        .transact(&get_info(), Duration::from_secs(10), &h.sink, &mut cancel)
        .await
        .expect_err("a truncated response must not resolve");
    assert_eq!(err, DaemonError::Timeout);
}

#[tokio::test(start_paused = true)]
async fn an_unbonded_link_is_refused_before_anything_is_written() {
    // PROJECT.md §15.2 — no override, anywhere.
    let device = FakeDevice::always(size(20), Reply::Ctap(Response::error(StatusCode::OK)))
        .with_link(LinkState {
            connected: true,
            bonded: true,
            authenticated: false, // Just Works: bonded, but no MITM protection
        });
    let state = device.state();
    let mut session = Session::new(device);
    let h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let err = session
        .transact(&get_info(), Duration::from_secs(10), &h.sink, &mut cancel)
        .await
        .expect_err("a bond without MITM protection is not good enough");
    assert_eq!(err, DaemonError::NotBonded);
    assert!(
        state.lock().unwrap().received.is_empty(),
        "nothing may reach an unbonded device"
    );
}

#[tokio::test(start_paused = true)]
async fn a_disconnected_device_is_reported_as_such() {
    let device = FakeDevice::always(size(20), Reply::Silent).with_link(LinkState::DISCONNECTED);
    let mut session = Session::new(device);
    let h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    let err = session
        .transact(&get_info(), Duration::from_secs(10), &h.sink, &mut cancel)
        .await
        .expect_err("no device, no transaction");
    assert_eq!(err, DaemonError::NotConnected);
}

#[tokio::test(start_paused = true)]
async fn cancelling_before_the_request_starts_writes_nothing() {
    let device = FakeDevice::always(size(20), Reply::Silent);
    let state = device.state();
    let mut session = Session::new(device);
    let h = Harness::new();
    let (handle, mut cancel) = cancel_pair();
    handle.cancel();

    let err = session
        .transact(&get_info(), Duration::from_secs(10), &h.sink, &mut cancel)
        .await
        .expect_err("an already-cancelled transaction must not start");
    assert_eq!(err, DaemonError::Cancelled);
    assert!(state.lock().unwrap().received.is_empty());
}

#[tokio::test(start_paused = true)]
async fn cancelling_mid_flight_tells_the_device() {
    let device = FakeDevice::always(size(64), Reply::KeepaliveForever(KeepAliveStatus::UpNeeded));
    let state = device.state();
    let mut session = Session::new(device);
    let h = Harness::new();
    let (handle, mut cancel) = cancel_pair();

    // Cancel once the user has been asked to touch the sensor.
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(350)).await;
        handle.cancel();
    });

    let err = session
        .transact(&get_info(), Duration::from_secs(600), &h.sink, &mut cancel)
        .await
        .expect_err("cancellation must win");
    canceller.await.unwrap();

    assert_eq!(err, DaemonError::Cancelled);
    assert_eq!(
        state.lock().unwrap().received_commands(),
        vec![Command::Msg, Command::Cancel]
    );
}

#[tokio::test(start_paused = true)]
async fn a_dropped_keepalive_sink_aborts_rather_than_hanging() {
    // If nothing is listening for keepalives, the user is never told to touch
    // the sensor, so the transaction cannot succeed. Fail closed.
    let device = FakeDevice::always(size(64), Reply::KeepaliveForever(KeepAliveStatus::UpNeeded));
    let state = device.state();
    let mut session = Session::new(device);
    let (sink, keepalives) = mpsc::unbounded_channel();
    drop(keepalives);
    let (_handle, mut cancel) = cancel_pair();

    let err = session
        .transact(&get_info(), Duration::from_secs(600), &sink, &mut cancel)
        .await
        .expect_err("nobody is listening; this cannot succeed");
    assert_eq!(err, DaemonError::Cancelled);
    assert_eq!(
        state.lock().unwrap().received_commands(),
        vec![Command::Msg, Command::Cancel]
    );
}

#[tokio::test(start_paused = true)]
async fn a_large_request_is_fragmented_correctly() {
    let request = Request::new(ctap::Command::MAKE_CREDENTIAL, vec![0x5a; 900]);
    let device = FakeDevice::always(size(20), Reply::Ctap(Response::error(StatusCode::OK)));
    let state = device.state();
    let mut session = Session::new(device);
    let h = Harness::new();
    let (_handle, mut cancel) = cancel_pair();

    session
        .transact(&request, Duration::from_secs(30), &h.sink, &mut cancel)
        .await
        .expect("a 900-byte request spans many fragments and a SEQ wrap");

    let state = state.lock().unwrap();
    assert_eq!(state.received[0].payload, request.encode());
}
