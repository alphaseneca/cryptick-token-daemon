//! The full proxy path: CTAPHID in, CTAP BLE out, and back (PROJECT.md §9).
#![cfg(feature = "fake-transport")]

use ble_framing::{FragmentSize, KeepAliveStatus};
use ctap::{Response, StatusCode};
use ctaphid::{
    ChannelId, Cmd, ErrorCode, Message, Packet, PacketKind, CAPABILITY_CBOR, CAPABILITY_WINK,
};
use daemon::{
    fake::{FakeDevice, Reply as DeviceReply},
    Bridge, HidBridge,
};
use std::sync::Arc;
use tokio::sync::mpsc;

const NONCE: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

fn size(n: u16) -> FragmentSize {
    FragmentSize::new(n).expect("legal size")
}

/// A reassembled reply. Deliberately does not use `ctaphid::Assembler`, which
/// validates host-to-authenticator direction and so rejects KEEPALIVE and ERROR.
#[derive(Debug)]
struct Out {
    channel: ChannelId,
    command: Cmd,
    payload: Vec<u8>,
}

struct Harness {
    hid: HidBridge<FakeDevice>,
    out: mpsc::UnboundedSender<Packet>,
    rx: mpsc::UnboundedReceiver<Packet>,
    device: Arc<std::sync::Mutex<daemon::fake::FakeState>>,
}

impl Harness {
    fn new(device: FakeDevice) -> Self {
        let state = device.state();
        let (out, rx) = mpsc::unbounded_channel();
        Self {
            hid: HidBridge::new(Arc::new(Bridge::new(device)), (1, 2, 3)),
            out,
            rx,
            device: state,
        }
    }

    fn feed(&mut self, packet: &Packet) {
        self.hid.handle_packet(packet, &self.out);
    }

    fn feed_message(&mut self, message: &Message) {
        for packet in message.packets().expect("fits") {
            self.feed(&packet);
        }
    }

    async fn next(&mut self) -> Out {
        let first = self.rx.recv().await.expect("a reply packet");
        let PacketKind::Init {
            command,
            message_len,
        } = first.kind()
        else {
            panic!("a reply must start with an initialization packet");
        };
        let declared = message_len as usize;
        let mut payload = Vec::with_capacity(declared);
        let take = declared.min(first.payload().len());
        payload.extend_from_slice(&first.payload()[..take]);

        while payload.len() < declared {
            let next = self.rx.recv().await.expect("a continuation packet");
            let take = (declared - payload.len()).min(next.payload().len());
            payload.extend_from_slice(&next.payload()[..take]);
        }

        Out {
            channel: first.channel(),
            command: Cmd::from_u8(command).expect("we only emit known commands"),
            payload,
        }
    }
}

fn cbor_request(channel: ChannelId, request: &ctap::Request) -> Message {
    Message::new(channel, Cmd::Cbor, request.encode())
}

fn get_info() -> ctap::Request {
    ctap::Request::new(ctap::Command::GET_INFO, Vec::new())
}

#[tokio::test(start_paused = true)]
async fn init_allocates_a_channel_and_echoes_the_nonce() {
    let mut h = Harness::new(FakeDevice::always(size(64), DeviceReply::Silent));
    h.feed_message(&Message::new(
        ChannelId::BROADCAST,
        Cmd::Init,
        NONCE.to_vec(),
    ));

    let reply = h.next().await;
    assert_eq!(reply.command, Cmd::Init);
    assert_eq!(
        reply.channel,
        ChannelId::BROADCAST,
        "reply on the request's channel"
    );
    assert_eq!(reply.payload.len(), 17);
    assert_eq!(
        &reply.payload[..8],
        &NONCE,
        "the nonce must come back unchanged"
    );

    let allocated = ChannelId::from_bytes(reply.payload[8..12].try_into().unwrap());
    assert!(allocated.is_assignable());
    assert_eq!(reply.payload[12], 2, "CTAPHID protocol version");
    assert_eq!(&reply.payload[13..16], &[1, 2, 3], "our version");
    assert_eq!(reply.payload[16], CAPABILITY_CBOR | CAPABILITY_WINK);

    // The token knows nothing about channels; this never left the daemon.
    assert!(h.device.lock().unwrap().received.is_empty());
}

#[tokio::test(start_paused = true)]
async fn each_init_allocates_a_distinct_channel() {
    let mut h = Harness::new(FakeDevice::always(size(64), DeviceReply::Silent));
    let mut seen = std::collections::HashSet::new();
    for _ in 0..8 {
        h.feed_message(&Message::new(
            ChannelId::BROADCAST,
            Cmd::Init,
            NONCE.to_vec(),
        ));
        let reply = h.next().await;
        let allocated = ChannelId::from_bytes(reply.payload[8..12].try_into().unwrap());
        assert!(
            seen.insert(allocated),
            "channel {allocated:?} handed out twice"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn init_on_an_assigned_channel_keeps_it() {
    let mut h = Harness::new(FakeDevice::always(size(64), DeviceReply::Silent));
    h.feed_message(&Message::new(ChannelId(0x4242), Cmd::Init, NONCE.to_vec()));

    let reply = h.next().await;
    let allocated = ChannelId::from_bytes(reply.payload[8..12].try_into().unwrap());
    assert_eq!(allocated, ChannelId(0x4242), "a resync keeps the channel");
}

#[tokio::test(start_paused = true)]
async fn init_with_a_wrong_length_nonce_is_refused() {
    let mut h = Harness::new(FakeDevice::always(size(64), DeviceReply::Silent));
    h.feed_message(&Message::new(ChannelId::BROADCAST, Cmd::Init, vec![0u8; 7]));

    let reply = h.next().await;
    assert_eq!(reply.command, Cmd::Error);
    assert_eq!(reply.payload[0], ErrorCode::InvalidLen.as_u8());
}

#[tokio::test(start_paused = true)]
async fn ping_is_answered_locally_including_across_packets() {
    let mut h = Harness::new(FakeDevice::always(size(64), DeviceReply::Silent));
    let body: Vec<u8> = (0..500).map(|i| i as u8).collect();
    h.feed_message(&Message::new(ChannelId(7), Cmd::Ping, body.clone()));

    let reply = h.next().await;
    assert_eq!(reply.command, Cmd::Ping);
    assert_eq!(reply.payload, body);
    assert!(
        h.device.lock().unwrap().received.is_empty(),
        "PING never reaches the token"
    );
}

#[tokio::test(start_paused = true)]
async fn unsupported_commands_are_refused_consistently_with_our_capabilities() {
    let mut h = Harness::new(FakeDevice::always(size(64), DeviceReply::Silent));
    for cmd in [Cmd::Msg, Cmd::Lock] {
        h.feed_message(&Message::new(ChannelId(3), cmd, vec![0u8; 4]));
        let reply = h.next().await;
        assert_eq!(reply.command, Cmd::Error, "{cmd:?}");
        assert_eq!(reply.payload[0], ErrorCode::InvalidCmd.as_u8(), "{cmd:?}");
    }

    // Wink is supported and answered locally with an empty reply
    h.feed_message(&Message::new(ChannelId(3), Cmd::Wink, Vec::new()));
    let reply = h.next().await;
    assert_eq!(reply.command, Cmd::Wink);
    assert!(reply.payload.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_cbor_request_reaches_the_device_and_the_answer_comes_back() {
    let expected = Response::new(StatusCode::OK, vec![0xa1, 0x01, 0x18, 0x20]);
    let mut h = Harness::new(FakeDevice::always(
        size(64),
        DeviceReply::Ctap(expected.clone()),
    ));

    h.feed_message(&cbor_request(ChannelId(0x99), &get_info()));
    let reply = h.next().await;

    assert_eq!(reply.command, Cmd::Cbor);
    assert_eq!(reply.channel, ChannelId(0x99));
    assert_eq!(reply.payload, expected.encode());

    // The envelope changed; the payload did not.
    let device = h.device.lock().unwrap();
    assert_eq!(device.received_commands(), vec![ble_framing::Command::Msg]);
    assert_eq!(device.received[0].payload, get_info().encode());
}

#[tokio::test(start_paused = true)]
async fn a_large_response_is_split_back_across_packets() {
    let expected = Response::new(StatusCode::OK, (0..2000).map(|i| i as u8).collect());
    let mut h = Harness::new(FakeDevice::always(
        size(64),
        DeviceReply::Ctap(expected.clone()),
    ));

    h.feed_message(&cbor_request(ChannelId(1), &get_info()));
    let reply = h.next().await;
    assert_eq!(reply.payload, expected.encode());
}

#[tokio::test(start_paused = true)]
async fn keepalives_reach_the_host_before_the_answer() {
    let expected = Response::error(StatusCode::OK);
    let mut h = Harness::new(FakeDevice::always(
        size(64),
        DeviceReply::KeepalivesThen {
            count: 3,
            status: KeepAliveStatus::UpNeeded,
            then: Box::new(DeviceReply::Ctap(expected.clone())),
        },
    ));

    h.feed_message(&cbor_request(ChannelId(5), &get_info()));

    for _ in 0..3 {
        let reply = h.next().await;
        assert_eq!(reply.command, Cmd::Keepalive);
        assert_eq!(reply.channel, ChannelId(5));
        assert_eq!(
            reply.payload[0],
            ctaphid::KeepaliveStatus::UpNeeded.as_u8(),
            "the fingerprint prompt must be forwarded, not swallowed"
        );
    }

    let reply = h.next().await;
    assert_eq!(reply.command, Cmd::Cbor);
    assert_eq!(reply.payload, expected.encode());
}

#[tokio::test(start_paused = true)]
async fn cancel_ends_the_transaction_with_the_ctap_cancel_status() {
    let mut h = Harness::new(FakeDevice::always(
        size(64),
        DeviceReply::KeepaliveForever(KeepAliveStatus::UpNeeded),
    ));

    h.feed_message(&cbor_request(ChannelId(11), &get_info()));
    assert_eq!(h.next().await.command, Cmd::Keepalive);

    h.feed_message(&Message::new(ChannelId(11), Cmd::Cancel, Vec::new()));

    loop {
        let reply = h.next().await;
        if reply.command == Cmd::Keepalive {
            continue;
        }
        // A real authenticator answers a cancel with a CBOR status, not a
        // transport error.
        assert_eq!(reply.command, Cmd::Cbor);
        assert_eq!(reply.payload[0], StatusCode::KEEPALIVE_CANCEL.as_u8());
        break;
    }

    assert!(h
        .device
        .lock()
        .unwrap()
        .received_commands()
        .contains(&ble_framing::Command::Cancel));
}

#[tokio::test(start_paused = true)]
async fn a_silent_device_produces_a_transport_timeout() {
    let mut h = Harness::new(FakeDevice::always(size(64), DeviceReply::Silent));
    h.feed_message(&cbor_request(ChannelId(2), &get_info()));

    let reply = h.next().await;
    assert_eq!(reply.command, Cmd::Error);
    assert_eq!(reply.payload[0], ErrorCode::MsgTimeout.as_u8());
}

#[tokio::test(start_paused = true)]
async fn a_second_request_on_a_busy_channel_is_refused() {
    let mut h = Harness::new(FakeDevice::always(
        size(64),
        DeviceReply::KeepaliveForever(KeepAliveStatus::UpNeeded),
    ));

    h.feed_message(&cbor_request(ChannelId(4), &get_info()));
    assert_eq!(h.next().await.command, Cmd::Keepalive);

    h.feed_message(&cbor_request(ChannelId(4), &get_info()));
    loop {
        let reply = h.next().await;
        if reply.command == Cmd::Keepalive {
            continue;
        }
        assert_eq!(reply.command, Cmd::Error);
        assert_eq!(reply.payload[0], ErrorCode::ChannelBusy.as_u8());
        break;
    }
}

#[tokio::test(start_paused = true)]
async fn a_request_on_a_second_channel_is_refused_while_the_device_is_busy() {
    // The token is a single-threaded authenticator; two channels cannot both
    // hold it (PROJECT.md §13).
    let mut h = Harness::new(FakeDevice::always(
        size(64),
        DeviceReply::KeepaliveForever(KeepAliveStatus::UpNeeded),
    ));

    h.feed_message(&cbor_request(ChannelId(1), &get_info()));
    assert_eq!(h.next().await.command, Cmd::Keepalive);

    h.feed_message(&cbor_request(ChannelId(2), &get_info()));
    loop {
        let reply = h.next().await;
        if reply.channel == ChannelId(1) {
            continue;
        }
        assert_eq!(reply.channel, ChannelId(2));
        assert_eq!(reply.command, Cmd::Error);
        assert_eq!(reply.payload[0], ErrorCode::ChannelBusy.as_u8());
        break;
    }
}

#[tokio::test(start_paused = true)]
async fn an_unbonded_link_produces_a_transport_error_not_an_assertion() {
    let device = FakeDevice::always(size(64), DeviceReply::Ctap(Response::error(StatusCode::OK)))
        .with_link(daemon::LinkState {
            connected: true,
            bonded: true,
            authenticated: false,
        });
    let mut h = Harness::new(device);

    h.feed_message(&cbor_request(ChannelId(1), &get_info()));
    let reply = h.next().await;
    assert_eq!(reply.command, Cmd::Error);
    assert_eq!(reply.payload[0], ErrorCode::Other.as_u8());
    assert!(h.device.lock().unwrap().received.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_malformed_packet_gets_an_error_on_its_own_channel() {
    let mut h = Harness::new(FakeDevice::always(size(64), DeviceReply::Silent));
    // A continuation with the wrong sequence number.
    h.feed(&Packet::init(ChannelId(6), Cmd::Cbor, 300, &[0u8; 57]));
    h.feed(&Packet::continuation(ChannelId(6), 5, &[0u8; 59]));

    let reply = h.next().await;
    assert_eq!(reply.channel, ChannelId(6));
    assert_eq!(reply.command, Cmd::Error);
    assert_eq!(reply.payload[0], ErrorCode::InvalidSeq.as_u8());
}
