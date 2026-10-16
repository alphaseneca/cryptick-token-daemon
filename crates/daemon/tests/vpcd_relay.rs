//! Integration tests for vpcd virtual card relay over loopback TCP.
//!
//! Verifies ATR negotiation (GetAtr, PowerOn, Reset), opaque APDU transceive,
//! short APDU ceiling enforcement, and loopback safety invariants (PROJECT.md §8, §15.6).

use daemon::{RelayError, VpcdRelay};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use transport_ble::PivBleTransport;

const TEST_ATR: [u8; 4] = [0x3B, 0x80, 0x01, 0x81];

/// Reads one framed reply from the vicc relay: [2 bytes big-endian length] + [body].
async fn read_framed_reply<R: AsyncReadExt + Unpin>(reader: &mut R) -> Vec<u8> {
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

#[tokio::test]
async fn vpcd_relay_end_to_end_loopback_negotiation_and_apdu_transceive() {
    // 1. Bind mock vpcd server on loopback
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // 2. Configure mock PIV token BLE transport
    let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));

    let select_piv_apdu = vec![
        0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
    ];
    let select_resp = vec![0x61, 0x11, 0x4F, 0x02, 0x00, 0x00, 0x90, 0x00];

    let get_data_apdu = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05];
    let get_data_resp = vec![0x53, 0x04, 0x01, 0x02, 0x03, 0x04, 0x90, 0x00];

    let select_piv_apdu_clone = select_piv_apdu.clone();
    let select_resp_clone = select_resp.clone();
    let get_data_apdu_clone = get_data_apdu.clone();
    let get_data_resp_clone = get_data_resp.clone();

    handle
        .set_auto_responder(move |cmd| {
            if cmd == select_piv_apdu_clone.as_slice() {
                select_resp_clone.clone()
            } else if cmd == get_data_apdu_clone.as_slice() {
                get_data_resp_clone.clone()
            } else {
                vec![0x6A, 0x82]
            }
        })
        .await;

    // 3. Connect relay to mock server
    let relay = VpcdRelay::with_port(transport, port);
    let relay_task = tokio::spawn(async move { relay.connect_and_run().await });

    // 4. Accept client connection from relay
    let (stream, client_addr) = listener.accept().await.unwrap();
    assert!(client_addr.ip().is_loopback());

    let (mut reader, mut writer) = stream.into_split();

    // 5. Test GetAtr: send 00 01 04 -> expect framed ATR
    let get_atr_wire = vpcd::frame(&[vpcd::CTRL_ATR]).unwrap();
    writer.write_all(&get_atr_wire).await.unwrap();
    let atr_resp = read_framed_reply(&mut reader).await;
    assert_eq!(atr_resp, TEST_ATR);

    // 6. Test PowerOn: send 00 01 01 -> expect framed ATR
    let power_on_wire = vpcd::frame(&[vpcd::CTRL_ON]).unwrap();
    writer.write_all(&power_on_wire).await.unwrap();
    let power_on_resp = read_framed_reply(&mut reader).await;
    assert_eq!(power_on_resp, TEST_ATR);

    // 7. Test Reset: send 00 01 02 -> expect framed ATR
    let reset_wire = vpcd::frame(&[vpcd::CTRL_RESET]).unwrap();
    writer.write_all(&reset_wire).await.unwrap();
    let reset_resp = read_framed_reply(&mut reader).await;
    assert_eq!(reset_resp, TEST_ATR);

    // 8. Test Select PIV APDU
    let apdu_wire = vpcd::frame(&select_piv_apdu).unwrap();
    writer.write_all(&apdu_wire).await.unwrap();
    let apdu_resp = read_framed_reply(&mut reader).await;
    assert_eq!(apdu_resp, select_resp);

    // 9. Test Get Data APDU
    let get_data_wire = vpcd::frame(&get_data_apdu).unwrap();
    writer.write_all(&get_data_wire).await.unwrap();
    let get_data_resp_actual = read_framed_reply(&mut reader).await;
    assert_eq!(get_data_resp_actual, get_data_resp);

    // 10. Test PowerOff: send 00 01 00 -> no response expected
    let power_off_wire = vpcd::frame(&[vpcd::CTRL_OFF]).unwrap();
    writer.write_all(&power_off_wire).await.unwrap();

    // 11. Verify relay remains healthy after PowerOff by transceiving again
    writer.write_all(&apdu_wire).await.unwrap();
    let apdu_resp2 = read_framed_reply(&mut reader).await;
    assert_eq!(apdu_resp2, select_resp);

    // 12. Disconnect mock server and verify relay terminates cleanly
    drop(writer);
    drop(reader);

    let res = relay_task.await.unwrap();
    assert!(res.is_ok(), "relay terminated successfully on disconnect");
}

#[tokio::test]
async fn vpcd_relay_rejects_non_loopback_addresses() {
    let (transport, _handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), None);

    let non_loopback_ips: &[&str] = &[
        "192.168.1.50:35963",
        "10.0.0.1:35963",
        "172.16.0.1:35963",
        "8.8.8.8:35963",
    ];

    for ip_str in non_loopback_ips {
        let addr: SocketAddr = ip_str.parse().unwrap();
        let res = VpcdRelay::with_addr(transport.clone(), addr);
        assert!(
            matches!(res, Err(RelayError::NonLoopbackAddress(_))),
            "must reject non-loopback address {ip_str}"
        );
    }
}

#[tokio::test]
async fn vpcd_relay_enforces_261_byte_short_apdu_ceiling() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (transport, _handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));

    let relay = VpcdRelay::with_port(transport, port);
    let relay_task = tokio::spawn(async move { relay.connect_and_run().await });

    let (mut stream, _) = listener.accept().await.unwrap();

    // Attempt to send an over-large body: 300 bytes (> 261 ceiling)
    let mut over_large = vec![0x01, 0x2C]; // 300 in big-endian u16
    over_large.extend(vec![0x00; 300]);

    stream.write_all(&over_large).await.unwrap();

    // The relay must fail closed with VpcdError::BodyTooLong and terminate
    let res = relay_task.await.unwrap();
    assert!(
        matches!(
            res,
            Err(RelayError::Vpcd(vpcd::VpcdError::BodyTooLong {
                len: 300,
                limit: 261
            }))
        ),
        "relay must refuse bodies exceeding 261 bytes at the decoder level"
    );
}

#[tokio::test]
async fn vpcd_relay_all_four_piv_slots_apdu_exchange_over_ble_and_ccid() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));

    // Define APDUs for all 4 slots: 9A, 9C, 9D, 9E
    // 1. SELECT PIV (truncated AID: A0 00 00 03 08 00 00 10 00)
    let select_apdu = vec![
        0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
    ];
    let select_resp = vec![
        0x61, 0x11, 0x4F, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x90, 0x00,
    ];

    // 2. GET DATA for each slot:
    // 9A: Tag 0x5FC105
    let get_9a = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05];
    let resp_9a = vec![0x53, 0x04, 0x9A, 0x01, 0x02, 0x03, 0x90, 0x00];

    // 9C: Tag 0x5FC10A
    let get_9c = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x0A];
    let resp_9c = vec![0x53, 0x04, 0x9C, 0x01, 0x02, 0x03, 0x90, 0x00];

    // 9D: Tag 0x5FC10B
    let get_9d = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x0B];
    let resp_9d = vec![0x53, 0x04, 0x9D, 0x01, 0x02, 0x03, 0x90, 0x00];

    // 9E: Tag 0x5FC101
    let get_9e = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x01];
    let resp_9e = vec![0x53, 0x04, 0x9E, 0x01, 0x02, 0x03, 0x90, 0x00];

    let select_apdu_c = select_apdu.clone();
    let select_resp_c = select_resp.clone();
    let get_9a_c = get_9a.clone();
    let resp_9a_c = resp_9a.clone();
    let get_9c_c = get_9c.clone();
    let resp_9c_c = resp_9c.clone();
    let get_9d_c = get_9d.clone();
    let resp_9d_c = resp_9d.clone();
    let get_9e_c = get_9e.clone();
    let resp_9e_c = resp_9e.clone();

    handle
        .set_auto_responder(move |cmd| {
            if cmd == select_apdu_c.as_slice() {
                select_resp_c.clone()
            } else if cmd == get_9a_c.as_slice() {
                resp_9a_c.clone()
            } else if cmd == get_9c_c.as_slice() {
                resp_9c_c.clone()
            } else if cmd == get_9d_c.as_slice() {
                resp_9d_c.clone()
            } else if cmd == get_9e_c.as_slice() {
                resp_9e_c.clone()
            } else {
                vec![0x6A, 0x82]
            }
        })
        .await;

    let relay = VpcdRelay::with_port(transport, port);
    let relay_task = tokio::spawn(async move { relay.connect_and_run().await });

    let (stream, _) = listener.accept().await.unwrap();
    let (mut reader, mut writer) = stream.into_split();

    // Verify SELECT
    writer
        .write_all(&vpcd::frame(&select_apdu).unwrap())
        .await
        .unwrap();
    assert_eq!(read_framed_reply(&mut reader).await, select_resp);

    // Verify GET DATA for Slot 9A (Authentication)
    writer
        .write_all(&vpcd::frame(&get_9a).unwrap())
        .await
        .unwrap();
    assert_eq!(read_framed_reply(&mut reader).await, resp_9a);

    // Verify GET DATA for Slot 9C (Digital Signature)
    writer
        .write_all(&vpcd::frame(&get_9c).unwrap())
        .await
        .unwrap();
    assert_eq!(read_framed_reply(&mut reader).await, resp_9c);

    // Verify GET DATA for Slot 9D (Key Management)
    writer
        .write_all(&vpcd::frame(&get_9d).unwrap())
        .await
        .unwrap();
    assert_eq!(read_framed_reply(&mut reader).await, resp_9d);

    // Verify GET DATA for Slot 9E (Card Authentication)
    writer
        .write_all(&vpcd::frame(&get_9e).unwrap())
        .await
        .unwrap();
    assert_eq!(read_framed_reply(&mut reader).await, resp_9e);

    // Clean disconnect
    drop(writer);
    drop(reader);
    let _ = relay_task.await;
}
