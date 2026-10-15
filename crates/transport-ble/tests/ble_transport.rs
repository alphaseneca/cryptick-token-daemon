//! Unit and integration tests for `BleTransport`.

use ble_framing::{
    Command, FragmentSize, FragmentTransport, KeepAliveStatus, LinkState, Message, Reassembler,
    TransportError,
};
use transport_ble::{BleTransport, MockWriteError, DEFAULT_FRAGMENT_SIZE};

#[tokio::test]
async fn test_initial_link_state_and_tentative_authentication() {
    let (transport, handle) = BleTransport::new_mock(None);

    // Initial state must tentatively claim authenticated to challenge token's ATT gate
    let state = transport.link_state();
    assert_eq!(
        state,
        LinkState {
            connected: true,
            bonded: true,
            authenticated: true,
        }
    );
    assert!(state.is_usable());
    assert_eq!(transport.link(), state);

    // Default fragment size is 252
    assert_eq!(transport.fragment_size_value().get(), DEFAULT_FRAGMENT_SIZE);
    assert_eq!(
        transport.fragment_size().await.unwrap().get(),
        DEFAULT_FRAGMENT_SIZE
    );

    // Writing a valid fragment succeeds and is recorded
    let test_frag = vec![0x83, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
    transport.write_fragment(&test_frag).await.unwrap();
    let written = handle.written_fragments().await;
    assert_eq!(written.len(), 1);
    assert_eq!(written[0], test_frag);

    // Sending notification is received via read_fragment
    let notif_data = vec![0x82, 0x00, 0x01, 0x01];
    handle.send_notification(notif_data.clone());
    let recv = transport.read_fragment().await.unwrap();
    assert_eq!(recv, notif_data);
}

#[tokio::test]
async fn test_dynamic_length_adaptation_initial_and_refresh() {
    // Valid lengths within 20..=512
    for len in [20, 64, 128, 252, 512] {
        let (transport, _) = BleTransport::new_mock(Some(len));
        assert_eq!(transport.fragment_size_value().get(), len);
        assert_eq!(transport.fragment_size().await.unwrap().get(), len);
    }

    // Lengths outside 20..=512 clamp to default (252)
    let (transport_too_small, _) = BleTransport::new_mock(Some(19));
    assert_eq!(
        transport_too_small.fragment_size_value().get(),
        DEFAULT_FRAGMENT_SIZE
    );

    let (transport_too_large, _) = BleTransport::new_mock(Some(513));
    assert_eq!(
        transport_too_large.fragment_size_value().get(),
        DEFAULT_FRAGMENT_SIZE
    );

    // Dynamic refresh
    let (transport, handle) = BleTransport::new_mock(Some(64));
    assert_eq!(transport.fragment_size_value().get(), 64);

    // Set mock response to 128 (0x0080 big-endian)
    handle
        .set_cpl_response(Some(Ok(vec![0x00, 0x80])))
        .await;
    let refreshed = transport.refresh_fragment_size().await.unwrap();
    assert_eq!(refreshed.get(), 128);
    assert_eq!(transport.fragment_size_value().get(), 128);

    // Set mock response to invalid clamp (10 -> 0x000A)
    handle
        .set_cpl_response(Some(Ok(vec![0x00, 0x0A])))
        .await;
    let refreshed = transport.refresh_fragment_size().await.unwrap();
    assert_eq!(refreshed.get(), DEFAULT_FRAGMENT_SIZE);

    // Set mock response to error -> fallback to 252
    handle
        .set_cpl_response(Some(Err("GATT read failure".into())))
        .await;
    let refreshed = transport.refresh_fragment_size().await.unwrap();
    assert_eq!(refreshed.get(), DEFAULT_FRAGMENT_SIZE);
}

#[tokio::test]
async fn test_att_authentication_refusal_transitions_link_state() {
    let (transport, handle) = BleTransport::new_mock(None);
    assert!(transport.link_state().is_usable());

    // Configure write to fail with ATT 0x05 Insufficient Authentication
    handle
        .set_write_error(Some(MockWriteError::InsufficientAuthentication))
        .await;

    let err = transport.write_fragment(&[0x83, 0x00, 0x00]).await.unwrap_err();
    assert_eq!(err, TransportError::InsufficientAuthentication);
    assert!(err.is_bond_failure());

    // Link state must transition to unauthenticated and unusable
    let state = transport.link_state();
    assert!(!state.authenticated);
    assert!(!state.bonded);
    assert!(!state.is_usable());

    // Subsequent write attempts immediately fail without attempting hardware write
    let err2 = transport.write_fragment(&[0x83, 0x00, 0x00]).await.unwrap_err();
    assert_eq!(err2, TransportError::InsufficientAuthentication);
}

#[tokio::test]
async fn test_att_encryption_refusal_transitions_link_state() {
    let (transport, handle) = BleTransport::new_mock(None);
    assert!(transport.link_state().is_usable());

    handle
        .set_write_error(Some(MockWriteError::InsufficientEncryption))
        .await;

    let err = transport.write_fragment(&[0x83, 0x00, 0x00]).await.unwrap_err();
    assert_eq!(err, TransportError::InsufficientEncryption);
    assert!(err.is_bond_failure());

    let state = transport.link_state();
    assert!(!state.authenticated);
    assert!(!state.bonded);
    assert!(!state.is_usable());
}

#[tokio::test]
async fn test_bluez_not_permitted_maps_to_insufficient_auth() {
    let (transport, handle) = BleTransport::new_mock(None);
    assert!(transport.link_state().is_usable());

    handle
        .set_write_error(Some(MockWriteError::BluezNotPermitted))
        .await;

    let err = transport.write_fragment(&[0x83, 0x00, 0x00]).await.unwrap_err();
    assert_eq!(err, TransportError::InsufficientAuthentication);
    assert!(err.is_bond_failure());
    assert!(!transport.link_state().is_usable());
}

#[tokio::test]
async fn test_non_bond_gatt_error_preserves_authentication_state() {
    let (transport, handle) = BleTransport::new_mock(None);
    assert!(transport.link_state().is_usable());

    handle
        .set_write_error(Some(MockWriteError::Custom("temporary radio congestion".into())))
        .await;

    let err = transport.write_fragment(&[0x83, 0x00, 0x00]).await.unwrap_err();
    assert!(!err.is_bond_failure());
    assert!(matches!(err, TransportError::Gatt(_)));

    // Link state remains authenticated (not a bond refusal)
    assert!(transport.link_state().authenticated);
    assert!(transport.link_state().is_usable());
}

#[tokio::test]
async fn test_fragment_exceeding_max_size_rejected() {
    let (transport, _) = BleTransport::new_mock(Some(64));
    let oversized = vec![0x00; 65];
    let err = transport.write_fragment(&oversized).await.unwrap_err();
    assert!(matches!(err, TransportError::Gatt(_)));
}

#[tokio::test]
async fn test_keepalive_streaming_and_reassembly_isolation() {
    let (transport, handle) = BleTransport::new_mock(Some(64));

    // Simulate device streaming KeepAlives during fingerprint prompt:
    // KeepAlive UP_NEEDED (0x02)
    handle.send_notification(vec![0x82, 0x00, 0x01, 0x02]);
    // KeepAlive PROCESSING (0x01)
    handle.send_notification(vec![0x82, 0x00, 0x01, 0x01]);
    // KeepAlive PROCESSING (0x01)
    handle.send_notification(vec![0x82, 0x00, 0x01, 0x01]);
    // KeepAlive UP_NEEDED (0x02)
    handle.send_notification(vec![0x82, 0x00, 0x01, 0x02]);

    // Construct a multi-fragment CTAP MSG response:
    // Total payload: 80 bytes
    let mut payload = vec![0x00]; // CTAP2_OK
    for i in 1..80u8 {
        payload.push(i);
    }
    let msg = Message::new(Command::Msg, payload.clone());
    let frags = ble_framing::fragments(&msg, FragmentSize::new(64).unwrap()).unwrap();
    assert!(frags.len() > 1);

    for frag in frags {
        handle.send_notification(frag);
    }

    // Reassembler consuming the stream
    let mut reassembler = Reassembler::new();
    let mut keepalive_count = 0;
    let mut final_message = None;

    for _ in 0..10 {
        let frag = transport.read_fragment().await.unwrap();
        if let Some(completed) = reassembler.push(&frag).unwrap() {
            if completed.command == Command::KeepAlive {
                keepalive_count += 1;
                let status_byte = completed.payload[0];
                let status = KeepAliveStatus::from_u8(status_byte).unwrap();
                match keepalive_count {
                    1 | 4 => assert_eq!(status, KeepAliveStatus::UpNeeded),
                    2 | 3 => assert_eq!(status, KeepAliveStatus::Processing),
                    _ => panic!("unexpected keepalive count"),
                }
            } else if completed.command == Command::Msg {
                final_message = Some(completed);
                break;
            }
        }
    }

    assert_eq!(keepalive_count, 4);
    assert!(final_message.is_some());
    let finished_msg = final_message.unwrap();
    assert_eq!(finished_msg.command, Command::Msg);
    assert_eq!(finished_msg.payload, payload);
}

#[tokio::test]
async fn test_clone_shares_link_state_and_notification_queue() {
    let (transport1, handle) = BleTransport::new_mock(None);
    let transport2 = transport1.clone();

    assert!(transport1.link_state().is_usable());
    assert!(transport2.link_state().is_usable());

    // Trigger ATT error on transport1
    handle
        .set_write_error(Some(MockWriteError::InsufficientAuthentication))
        .await;
    let _ = transport1.write_fragment(&[0x83, 0x00, 0x00]).await;

    // Both instances must observe the revoked authentication
    assert!(!transport1.link_state().authenticated);
    assert!(!transport2.link_state().authenticated);
    assert!(!transport1.link_state().is_usable());
    assert!(!transport2.link_state().is_usable());

    // Notifications sent are read by whichever clone pulls first
    handle.send_notification(vec![0x01, 0x02, 0x03]);
    let recv = transport2.read_fragment().await.unwrap();
    assert_eq!(recv, vec![0x01, 0x02, 0x03]);
}

#[tokio::test]
async fn test_disconnection_behavior() {
    let (transport, handle) = BleTransport::new_mock(None);
    assert!(transport.link_state().connected);

    handle.disconnect();

    assert_eq!(
        transport.write_fragment(&[0x01]).await.unwrap_err(),
        TransportError::Disconnected
    );
    assert_eq!(
        transport.read_fragment().await.unwrap_err(),
        TransportError::Disconnected
    );
    assert_eq!(
        transport.fragment_size().await.unwrap_err(),
        TransportError::Disconnected
    );
    assert_eq!(
        transport.refresh_fragment_size().await.unwrap_err(),
        TransportError::Disconnected
    );
    assert!(!transport.link_state().connected);
}

#[tokio::test]
async fn test_fragment_transport_trait_implementation() {
    let (mut transport, handle) = BleTransport::new_mock(Some(64));

    // Exercise through FragmentTransport trait methods
    assert_eq!(
        FragmentTransport::fragment_size(&mut transport)
            .await
            .unwrap()
            .get(),
        64
    );
    assert_eq!(FragmentTransport::link(&transport), LinkState::READY);

    FragmentTransport::write_fragment(&mut transport, &[0x83, 0x00, 0x01, 0x05])
        .await
        .unwrap();
    let written = handle.written_fragments().await;
    assert_eq!(written.len(), 1);

    handle.send_notification(vec![0x82, 0x00, 0x01, 0x02]);
    let notif = FragmentTransport::next_notification(&mut transport)
        .await
        .unwrap();
    assert_eq!(notif, vec![0x82, 0x00, 0x01, 0x02]);
}
