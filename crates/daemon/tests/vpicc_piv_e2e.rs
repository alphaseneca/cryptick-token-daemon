//! End-to-end PIV integration tests against a faithful software card.
//!
//! This is the harness PROJECT.md §14 is missing for the PIV/vpcd path: every
//! prior PIV fix in this project has been flagged "needs real hardware to
//! confirm" because nothing in CI can exercise the daemon's PC/SC-facing code
//! against anything resembling a real smart card stack. `vpicc-piv` is a
//! line-by-line port of the firmware's actual applet (`core/piv/piv.c` in
//! `cryptick-token-code`); this file wires it in at the real transport
//! boundary and drives it over a real loopback TCP socket, using the real
//! `vpcd` wire protocol codec (`crates/vpcd`).
//!
//! # What runs, and which pieces are real
//!
//! ```text
//! this test  --TCP, real vpcd wire protocol-->  VpcdRelay::connect_and_run()   (real, unmodified daemon code)
//!                                                         |
//!                                                         v  PivCardTransport
//!                                                 PivBleTransport::new_mock()  (real transport-ble fragmentation/
//!                                                         |                     reassembly over the mock GATT boundary)
//!                                                         v  auto-responder closure
//!                                                  vpicc_piv::FirmwareCard     (faithful APDU-level applet model)
//! ```
//!
//! The only thing that is not the real production path is what stands in for
//! `vpcd` itself (a bare `TcpListener` speaking the same wire protocol — see
//! `crates/vpcd`'s doc comment for the framing this reproduces) and what
//! stands in for the firmware behind the BLE GATT boundary (`FirmwareCard`).
//! `VpcdRelay`, the 261-byte ceiling, and the BLE fragmentation/reassembly in
//! `transport_ble::PivBleTransport` are the real, unmodified production code.
//!
//! # What this does and does not prove
//!
//! Proves: the vpcd wire protocol round-trips real PIV APDUs end to end
//! through the daemon's actual relay and BLE-transport framing, against
//! responses shaped exactly like this device's real applet — including its
//! command chaining, `GET RESPONSE` chunking, and PIN/presence gating.
//!
//! Does **not** prove: anything about real hardware timing, USB/BLE
//! enumeration, the real `pcscd`/`vpcd` binary, or cryptographic correctness
//! of the (synthetic) keys and signatures `FirmwareCard` returns. See
//! `NOTES.md`.

use daemon::VpcdRelay;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use transport_ble::PivBleTransport;
use vpicc_piv::{FirmwareCard, OBJ_CERT_9A, OBJ_CHUID};

/// The ATR this device reports over USB CCID today, so a test against this
/// harness and a test against real hardware see the same card identity
/// (`crates/vpcd`'s `atr::T1_MINIMAL`, PROJECT.md §11).
const TEST_ATR: [u8; 4] = [0x3B, 0x80, 0x01, 0x81];

const CORRECT_PIN: &[u8] = b"123456";

/// Reads one framed reply: `[2-byte big-endian length][body]`, the wire
/// shape every `vpcd` message uses in both directions.
async fn read_reply<R: AsyncReadExt + Unpin>(reader: &mut R) -> Vec<u8> {
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), reader.read_exact(&mut len_buf))
        .await
        .expect("read header does not time out")
        .expect("read length prefix succeeds");
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), reader.read_exact(&mut body))
        .await
        .expect("read body does not time out")
        .expect("read body bytes succeeds");
    body
}

/// Frames `apdu`, writes it, and reads back the framed response.
async fn transceive<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    apdu: &[u8],
) -> Vec<u8> {
    let framed = vpcd::frame(apdu).unwrap();
    stream.write_all(&framed).await.unwrap();
    read_reply(stream).await
}

fn status(resp: &[u8]) -> u16 {
    let n = resp.len();
    u16::from_be_bytes([resp[n - 2], resp[n - 1]])
}

/// Builds the SELECT command for the PIV AID (right-truncated to 9 bytes —
/// what OpenSC and CryptoTokenKit actually send).
fn select_apdu() -> Vec<u8> {
    let mut cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x09];
    cmd.extend_from_slice(&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00]);
    cmd
}

fn verify_apdu(pin: &[u8]) -> Vec<u8> {
    let mut block = pin.to_vec();
    block.resize(8, 0xFF);
    let mut cmd = vec![0x00, 0x20, 0x00, 0x80, 0x08];
    cmd.extend_from_slice(&block);
    cmd
}

fn generate_apdu(slot: u8) -> Vec<u8> {
    vec![0x00, 0x47, 0x00, slot, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11]
}

fn sign_apdu(slot: u8, digest: &[u8; 32]) -> Vec<u8> {
    let mut inner = vec![0x81, 0x20];
    inner.extend_from_slice(digest);
    let mut body = vec![0x7C, inner.len() as u8];
    body.extend_from_slice(&inner);
    let mut cmd = vec![0x00, 0x87, 0x11, slot, body.len() as u8];
    cmd.extend_from_slice(&body);
    cmd
}

fn get_data_apdu(tag: u32) -> Vec<u8> {
    let tag_bytes = [(tag >> 16) as u8, (tag >> 8) as u8, tag as u8];
    let mut body = vec![0x5C, 0x03];
    body.extend_from_slice(&tag_bytes);
    let mut cmd = vec![0x00, 0xCB, 0x3F, 0xFF, body.len() as u8];
    cmd.extend_from_slice(&body);
    cmd
}

fn get_response_apdu(le: u8) -> Vec<u8> {
    vec![0x00, 0xC0, 0x00, 0x00, le]
}

/// Wires a [`FirmwareCard`] behind the real `PivBleTransport` mock (so real
/// BLE fragmentation/reassembly is exercised, not just a bare function
/// call), starts a `VpcdRelay` against it, binds a loopback `TcpListener`
/// standing in for the real `vpcd` reader driver, and returns the accepted
/// socket plus the relay's join handle.
async fn start_relay_with_card(
    card: FirmwareCard,
) -> (
    tokio::net::TcpStream,
    tokio::task::JoinHandle<Result<(), daemon::RelayError>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));
    let card = Arc::new(Mutex::new(card));
    handle
        .set_auto_responder(move |cmd| card.lock().unwrap().handle_apdu(cmd))
        .await;

    let relay = VpcdRelay::with_port(transport, port);
    let relay_task = tokio::spawn(async move { relay.connect_and_run().await });

    let (stream, client_addr) = listener.accept().await.unwrap();
    assert!(
        client_addr.ip().is_loopback(),
        "relay must dial loopback only (PROJECT.md §15.6)"
    );
    (stream, relay_task)
}

#[tokio::test]
async fn select_verify_generate_and_sign_round_trip_over_vpcd() {
    let (mut stream, _relay_task) = start_relay_with_card(FirmwareCard::new()).await;

    // ATR negotiation, exactly as pcscd/CryptoTokenKit perform it before any
    // APDU is sent.
    let get_atr = vpcd::frame(&[vpcd::CTRL_ATR]).unwrap();
    stream.write_all(&get_atr).await.unwrap();
    assert_eq!(read_reply(&mut stream).await, TEST_ATR);

    // SELECT the PIV application.
    let resp = transceive(&mut stream, &select_apdu()).await;
    assert_eq!(status(&resp), 0x9000);
    assert_eq!(resp[0], 0x61, "missing application property template");

    // GENERATE ASYMMETRIC KEY PAIR without a PIN is refused.
    let resp = transceive(&mut stream, &generate_apdu(0x9A)).await;
    assert_eq!(status(&resp), 0x6982, "must require a verified PIN");

    // VERIFY the correct PIN.
    let resp = transceive(&mut stream, &verify_apdu(CORRECT_PIN)).await;
    assert_eq!(status(&resp), 0x9000);

    // GENERATE ASYMMETRIC KEY PAIR in slot 9A.
    let resp = transceive(&mut stream, &generate_apdu(0x9A)).await;
    assert_eq!(status(&resp), 0x9000);
    assert_eq!(&resp[..2], &[0x7F, 0x49], "missing public key template");

    // GENERAL AUTHENTICATE: sign a 32-byte digest with the freshly generated key.
    let digest = [0x42u8; 32];
    let resp = transceive(&mut stream, &sign_apdu(0x9A, &digest)).await;
    assert_eq!(status(&resp), 0x9000);
    assert_eq!(resp[0], 0x7C, "missing dynamic authentication template");
}

#[tokio::test]
async fn wrong_pin_decrements_and_eventually_blocks_over_vpcd() {
    let (mut stream, _relay_task) = start_relay_with_card(FirmwareCard::new()).await;

    transceive(&mut stream, &select_apdu()).await;

    let resp = transceive(&mut stream, &verify_apdu(b"999999")).await;
    assert_eq!(status(&resp), 0x63C2, "2 attempts should remain");

    let resp = transceive(&mut stream, &verify_apdu(b"999999")).await;
    assert_eq!(status(&resp), 0x63C1, "1 attempt should remain");

    let resp = transceive(&mut stream, &verify_apdu(b"999999")).await;
    assert_eq!(status(&resp), 0x6983, "card must now be blocked");

    // A blocked PIN stays blocked, even when it's the right one.
    let resp = transceive(&mut stream, &verify_apdu(CORRECT_PIN)).await;
    assert_eq!(status(&resp), 0x6983);
}

#[tokio::test]
async fn chuid_and_ccc_are_synthesised_over_vpcd_with_no_provisioning() {
    let (mut stream, _relay_task) = start_relay_with_card(FirmwareCard::new()).await;
    transceive(&mut stream, &select_apdu()).await;

    // A host that finds neither object concludes there is no card worth
    // talking to (PROJECT.md / piv.c comment on `synthesize_object`), so
    // this is load-bearing for every PIV login path, not a nice-to-have.
    let resp = transceive(&mut stream, &get_data_apdu(OBJ_CHUID)).await;
    assert_eq!(status(&resp), 0x9000);
    assert_eq!(resp[0], 0x53, "CHUID must carry its 53 wrapper");

    let resp = transceive(&mut stream, &get_data_apdu(vpicc_piv::OBJ_CCC)).await;
    assert_eq!(status(&resp), 0x9000);
    assert_eq!(resp[0], 0x53, "CCC must carry its 53 wrapper");

    // A certificate must never be synthesised — an empty one would look like
    // a provisioned card that simply cannot authenticate.
    let resp = transceive(&mut stream, &get_data_apdu(OBJ_CERT_9A)).await;
    assert_eq!(status(&resp), 0x6A82);
}

#[tokio::test]
async fn a_certificate_too_large_for_one_response_is_chained_through_get_response_over_vpcd() {
    let mut card = FirmwareCard::new();
    // 420 bytes: comfortably over the applet's 256-byte GET DATA chunk, and
    // small enough (with its TLV wrapper) that every individual response
    // still fits the 261-byte vpcd/BLE ceiling (PROJECT.md §17) — the point
    // being to exercise *both* ceilings honestly rather than one at a time.
    let cert: Vec<u8> = (0..420u32).map(|i| (i * 11) as u8).collect();
    let mut container = vec![0x53, 0x82, (cert.len() >> 8) as u8, cert.len() as u8];
    container.extend_from_slice(&cert);
    card.preload_object(OBJ_CERT_9A, container.clone());

    let (mut stream, _relay_task) = start_relay_with_card(card).await;
    transceive(&mut stream, &select_apdu()).await;

    let first = transceive(&mut stream, &get_data_apdu(OBJ_CERT_9A)).await;
    let mut sw = status(&first);
    assert_eq!(sw & 0xFF00, 0x6100, "expected a more-data status");
    let mut reassembled = first[..first.len() - 2].to_vec();

    let mut rounds = 0;
    while sw & 0xFF00 == 0x6100 {
        rounds += 1;
        assert!(rounds < 10, "chaining did not converge");
        let le = if sw & 0xFF == 0 {
            0x00
        } else {
            (sw & 0xFF) as u8
        };
        let resp = transceive(&mut stream, &get_response_apdu(le)).await;
        sw = status(&resp);
        reassembled.extend_from_slice(&resp[..resp.len() - 2]);
    }
    assert_eq!(sw, 0x9000);
    assert_eq!(
        reassembled, container,
        "chained GET RESPONSE reassembly lost or reordered bytes"
    );
    assert!(
        rounds >= 1,
        "test is only meaningful if chaining actually happened"
    );
}

#[tokio::test]
async fn put_data_command_chain_round_trips_through_get_data_over_vpcd() {
    let (mut stream, _relay_task) = start_relay_with_card(FirmwareCard::new()).await;
    transceive(&mut stream, &select_apdu()).await;
    transceive(&mut stream, &verify_apdu(CORRECT_PIN)).await;

    // A 300-byte certificate needs a >255-byte PUT DATA body, past the
    // short-form Lc ceiling, so it can only be written as a command chain
    // (CLA 0x10 for every link but the last) — this is the exact mechanism
    // `piv::chaining` builds for the daemon's own provisioning tool.
    let cert: Vec<u8> = (0..300u32).map(|i| (i * 3) as u8).collect();
    let mut container = vec![0x53, 0x82, (cert.len() >> 8) as u8, cert.len() as u8];
    container.extend_from_slice(&cert);
    let mut body = vec![0x5C, 0x03, 0x5F, 0xC1, 0x05];
    body.extend_from_slice(&container);

    let block = 200usize;
    let mut last_status = 0u16;
    for start in (0..body.len()).step_by(block) {
        let end = (start + block).min(body.len());
        let chunk = &body[start..end];
        let last = end >= body.len();
        let cla = if last { 0x00 } else { 0x10 };
        let mut cmd = vec![cla, 0xDB, 0x3F, 0xFF, chunk.len() as u8];
        cmd.extend_from_slice(chunk);
        last_status = status(&transceive(&mut stream, &cmd).await);
    }
    assert_eq!(last_status, 0x9000);

    let first = transceive(&mut stream, &get_data_apdu(OBJ_CERT_9A)).await;
    let mut sw = status(&first);
    let mut got = first[..first.len() - 2].to_vec();
    while sw & 0xFF00 == 0x6100 {
        let le = if sw & 0xFF == 0 {
            0x00
        } else {
            (sw & 0xFF) as u8
        };
        let resp = transceive(&mut stream, &get_response_apdu(le)).await;
        sw = status(&resp);
        got.extend_from_slice(&resp[..resp.len() - 2]);
    }
    assert_eq!(sw, 0x9000);
    assert_eq!(
        got, container,
        "command-chained PUT DATA did not round trip"
    );
}

#[tokio::test]
async fn extended_length_select_is_rejected_through_vpcd_and_ble() {
    // Case 3E encoding: CLA INS P1 P2 00 LenHi LenLo <data>, no Le.
    // `docs/device-protocol.md` states the applet's contract plainly: short
    // APDUs only, extended-length encoding refused with 6700 — no
    // inspection of the declared length, no partial acceptance under any
    // transport's ceiling. This proves that refusal is reachable through
    // the vpcd/BLE path exactly as it is over USB CCID, even for a message
    // that would otherwise fit comfortably under the 261-byte ceiling that
    // path imposes independently — the rejection is unconditional, not a
    // consequence of exceeding that ceiling.
    let (mut stream, _relay_task) = start_relay_with_card(FirmwareCard::new()).await;

    let mut cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x09];
    cmd.extend_from_slice(&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00]);
    assert!(
        cmd.len() <= 261,
        "test input must itself respect the ceiling it is not the one being proven here"
    );

    let resp = transceive(&mut stream, &cmd).await;
    assert_eq!(
        status(&resp),
        0x6700,
        "extended-length SELECT must be refused, unconditionally"
    );
}

#[tokio::test]
async fn card_authentication_slot_signs_without_a_pin_over_vpcd() {
    let (mut stream, _relay_task) = start_relay_with_card(FirmwareCard::new()).await;
    transceive(&mut stream, &select_apdu()).await;

    // 9E is the one slot defined to work PIN-less (contactless door access);
    // every other login slot must refuse (covered by
    // `wrong_pin_decrements_and_eventually_blocks_over_vpcd` and the 6982
    // check in the happy-path test above).
    let digest = [0x07u8; 32];
    let resp = transceive(&mut stream, &sign_apdu(0x9E, &digest)).await;
    assert_eq!(status(&resp), 0x9000);
}

#[tokio::test]
async fn generate_and_sign_are_refused_without_user_presence_over_vpcd() {
    let mut card = FirmwareCard::new();
    card.presence_granted = false;
    let (mut stream, _relay_task) = start_relay_with_card(card).await;
    transceive(&mut stream, &select_apdu()).await;
    transceive(&mut stream, &verify_apdu(CORRECT_PIN)).await;

    // The PIN proves who is asking; presence (a fingerprint, on the real
    // device) proves someone is physically there. Denying presence must
    // refuse even a PIN-verified caller (PROJECT.md §15.3).
    let resp = transceive(&mut stream, &generate_apdu(0x9A)).await;
    assert_eq!(status(&resp), 0x6982);

    let digest = [0x01u8; 32];
    let resp = transceive(&mut stream, &sign_apdu(0x9A, &digest)).await;
    assert_eq!(status(&resp), 0x6982);
}
