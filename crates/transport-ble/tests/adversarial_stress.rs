//! Adversarial stress test suite for BLE transports, boundary conditions, and invariants.
//!
//! Stress-tests:
//! 1. Dynamic length boundaries (<20, >512, exact 20, exact 512, malformed responses).
//! 2. Rapid succession of ATT errors and atomic link state transitions.
//! 3. KeepAlive streaming and reassembly isolation under adversarial conditions.
//! 4. Unexpected disconnections during write/read operations.
//! 5. PivBleTransport APDU ceiling enforcement (exact 261, 262, 0 bytes).

use ble_framing::{
    fragments, Command, FragmentSize, FramingError, Message, Reassembler, TransportError,
    MAX_FRAGMENT_SIZE, MIN_FRAGMENT_SIZE,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use transport_ble::{
    BleTransport, MockWriteError, PivBleTransport, PivTransportError, DEFAULT_FRAGMENT_SIZE,
    MAX_APDU_LEN,
};

const TEST_ATR: [u8; 4] = [0x3B, 0x80, 0x01, 0x81];

// ============================================================================
// 1. Dynamic Length Boundary Conditions & Malformed CPL Responses
// ============================================================================

#[tokio::test]
async fn test_adversarial_cpl_underflow_boundary() {
    // Tests values strictly under 20: 0, 1, 10, 19
    for under_val in [0, 1, 10, 19] {
        let (transport, handle) = BleTransport::new_mock(Some(under_val));
        assert_eq!(
            transport.fragment_size_value().get(),
            DEFAULT_FRAGMENT_SIZE,
            "CPL underflow {under_val} must fallback to DEFAULT_FRAGMENT_SIZE (252)"
        );

        // Also test dynamic refresh returning underflow
        handle
            .set_cpl_response(Some(Ok(under_val.to_be_bytes().to_vec())))
            .await;
        let refreshed = transport.refresh_fragment_size().await.unwrap();
        assert_eq!(
            refreshed.get(),
            DEFAULT_FRAGMENT_SIZE,
            "Refreshed CPL underflow {under_val} must fallback to 252"
        );
    }
}

#[tokio::test]
async fn test_adversarial_cpl_overflow_boundary() {
    // Tests values strictly above 512: 513, 1000, 65535
    for over_val in [513, 1000, 65535] {
        let (transport, handle) = BleTransport::new_mock(Some(over_val));
        assert_eq!(
            transport.fragment_size_value().get(),
            DEFAULT_FRAGMENT_SIZE,
            "CPL overflow {over_val} must fallback to DEFAULT_FRAGMENT_SIZE (252)"
        );

        handle
            .set_cpl_response(Some(Ok(over_val.to_be_bytes().to_vec())))
            .await;
        let refreshed = transport.refresh_fragment_size().await.unwrap();
        assert_eq!(
            refreshed.get(),
            DEFAULT_FRAGMENT_SIZE,
            "Refreshed CPL overflow {over_val} must fallback to 252"
        );
    }
}

#[tokio::test]
async fn test_adversarial_cpl_exact_boundaries() {
    // Exact MIN boundary (20)
    let (transport_min, handle_min) = BleTransport::new_mock(Some(MIN_FRAGMENT_SIZE));
    assert_eq!(transport_min.fragment_size_value().get(), 20);
    handle_min
        .set_cpl_response(Some(Ok(vec![0x00, 0x14]))) // 20
        .await;
    assert_eq!(transport_min.refresh_fragment_size().await.unwrap().get(), 20);

    // Exact MAX boundary (512)
    let (transport_max, handle_max) = BleTransport::new_mock(Some(MAX_FRAGMENT_SIZE));
    assert_eq!(transport_max.fragment_size_value().get(), 512);
    handle_max
        .set_cpl_response(Some(Ok(vec![0x02, 0x00]))) // 512
        .await;
    assert_eq!(transport_max.refresh_fragment_size().await.unwrap().get(), 512);
}

#[tokio::test]
async fn test_adversarial_cpl_malformed_responses() {
    let (transport, handle) = BleTransport::new_mock(Some(128));
    assert_eq!(transport.fragment_size_value().get(), 128);

    // Empty byte response
    handle.set_cpl_response(Some(Ok(vec![]))).await;
    assert_eq!(
        transport.refresh_fragment_size().await.unwrap().get(),
        DEFAULT_FRAGMENT_SIZE
    );

    // 1-byte response
    handle.set_cpl_response(Some(Ok(vec![0x40]))).await;
    assert_eq!(
        transport.refresh_fragment_size().await.unwrap().get(),
        DEFAULT_FRAGMENT_SIZE
    );

    // 3-byte response
    handle.set_cpl_response(Some(Ok(vec![0x00, 0x40, 0x00]))).await;
    assert_eq!(
        transport.refresh_fragment_size().await.unwrap().get(),
        DEFAULT_FRAGMENT_SIZE
    );

    // I/O Error response
    handle
        .set_cpl_response(Some(Err("ATT Read Failure".into())))
        .await;
    assert_eq!(
        transport.refresh_fragment_size().await.unwrap().get(),
        DEFAULT_FRAGMENT_SIZE
    );
}

// ============================================================================
// 2. Rapid Succession of ATT Errors & Atomic State Transitions
// ============================================================================

#[tokio::test]
async fn test_rapid_succession_att_errors_lockout_link_state() {
    let (transport, handle) = BleTransport::new_mock(None);
    assert!(transport.link_state().is_usable());

    // Inject ATT 0x05 (InsufficientAuthentication)
    handle
        .set_write_error(Some(MockWriteError::InsufficientAuthentication))
        .await;

    // Concurrently trigger 10 writes across cloned handles
    let mut tasks = Vec::new();
    let auth_refusal_count = Arc::new(AtomicUsize::new(0));

    for _ in 0..10 {
        let t = transport.clone();
        let counter = Arc::clone(&auth_refusal_count);
        tasks.push(tokio::spawn(async move {
            let err = t.write_fragment(&[0x83, 0x00, 0x01, 0xFF]).await.unwrap_err();
            if matches!(err, TransportError::InsufficientAuthentication) {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    assert_eq!(auth_refusal_count.load(Ordering::SeqCst), 10);

    // Link state must be permanently unauthenticated and unusable
    let state = transport.link_state();
    assert!(!state.authenticated);
    assert!(!state.bonded);
    assert!(!state.is_usable());

    // Clear the mock error to simulate backend thinking it recovered;
    // but the transport MUST fail closed and refuse any subsequent write!
    handle.set_write_error(None).await;
    let next_err = transport.write_fragment(&[0x83, 0x00, 0x01, 0xFF]).await.unwrap_err();
    assert_eq!(next_err, TransportError::InsufficientAuthentication);

    // Verify written fragments in handle: only the first call reached mock IO, subsequent were blocked early!
    let written = handle.written_fragments().await;
    assert_eq!(written.len(), 0, "No writes should succeed");
}

#[tokio::test]
async fn test_att_encryption_refusal_lockout() {
    let (transport, handle) = BleTransport::new_mock(None);
    handle
        .set_write_error(Some(MockWriteError::InsufficientEncryption))
        .await;

    let err = transport.write_fragment(&[0x83, 0x00, 0x00]).await.unwrap_err();
    assert_eq!(err, TransportError::InsufficientEncryption);
    assert!(err.is_bond_failure());

    assert!(!transport.link_state().is_usable());
    assert!(!transport.link_state().authenticated);
    assert!(!transport.link_state().bonded);

    // Subsequent write fails closed
    let err2 = transport.write_fragment(&[0x83, 0x00, 0x00]).await.unwrap_err();
    assert_eq!(err2, TransportError::InsufficientAuthentication);
}

// ============================================================================
// 3. KeepAlive Streaming & Interleaving Injection
// ============================================================================

#[tokio::test]
async fn test_adversarial_interleaved_keepalive_fails_closed_without_corruption() {
    let mut rx = Reassembler::new();

    // 1. Deliver the init fragment of a multi-fragment MSG response (declares 40 bytes)
    let init_frag = vec![0x83, 0x00, 0x28, 0x01, 0x02, 0x03, 0x04];
    assert_eq!(rx.push(&init_frag).unwrap(), None);
    assert!(rx.in_progress(), "Transaction must be in progress");

    // 2. Adversarially inject an interleaved KeepAlive frame mid-transaction
    let keepalive_frag = vec![0x82, 0x00, 0x01, 0x01];
    let res = rx.push(&keepalive_frag);

    // 3. Must be strictly rejected as UnexpectedInitFragment (CTAP2 protocol violation)
    assert_eq!(
        res.unwrap_err(),
        FramingError::UnexpectedInitFragment,
        "Interleaved KeepAlive mid-stream must trigger protocol violation"
    );

    // 4. Reassembler MUST reset to Idle and NOT corrupt buffer
    assert!(!rx.in_progress(), "Reassembler must be reset to Idle");

    // 5. Subsequent continuation fragment of the original message is now orphaned
    let continuation_frag = vec![0x00, 0x05, 0x06];
    assert_eq!(
        rx.push(&continuation_frag).unwrap_err(),
        FramingError::ContinuationWithoutInit,
        "Orphaned continuation must be rejected cleanly"
    );
}

#[tokio::test]
async fn test_adversarial_streamed_keepalives_preceding_response() {
    let (transport, handle) = BleTransport::new_mock(Some(64));

    // Stream 100 KeepAlives in rapid succession
    for i in 0..100 {
        let status = if i % 2 == 0 { 0x01 } else { 0x02 };
        handle.send_notification(vec![0x82, 0x00, 0x01, status]);
    }

    // Then deliver a multi-fragment MSG response
    let payload = vec![0x42; 100];
    let msg = Message::new(Command::Msg, payload.clone());
    let frags = fragments(&msg, FragmentSize::new(64).unwrap()).unwrap();
    for f in frags {
        handle.send_notification(f);
    }

    let mut rx = Reassembler::new();
    let mut keepalives_received = 0;
    let mut final_msg = None;

    for _ in 0..102 {
        let notif = transport.read_fragment().await.unwrap();
        if let Some(m) = rx.push(&notif).unwrap() {
            if m.command == Command::KeepAlive {
                keepalives_received += 1;
            } else if m.command == Command::Msg {
                final_msg = Some(m);
                break;
            }
        }
    }

    assert_eq!(keepalives_received, 100);
    assert_eq!(final_msg.unwrap().payload, payload);
    assert!(!rx.in_progress());
}

// ============================================================================
// 4. Unexpected Disconnections
// ============================================================================

#[tokio::test]
async fn test_adversarial_disconnection_during_transceive_piv() {
    let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));

    // Simulate device disconnecting as soon as command APDU is sent
    let handle_clone = handle.clone();
    tokio::spawn(async move {
        while handle_clone.written_fragments().await.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        handle_clone.disconnect();
    });

    let apdu = vec![0x00, 0xA4, 0x04, 0x00, 0x00];
    let err = transport.transceive(&apdu).await.unwrap_err();
    assert!(
        matches!(err, PivTransportError::Transport(TransportError::Disconnected)),
        "Must return Disconnected on mid-operation disconnection"
    );

    let state = transport.link_state();
    assert!(!state.connected);
    assert!(!state.is_usable());
}

// ============================================================================
// 5. PivBleTransport APDU Ceilings & Boundaries
// ============================================================================

#[tokio::test]
async fn test_adversarial_piv_apdu_ceiling_boundaries() {
    let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));

    // 1. Exact 261 bytes (MAX_APDU_LEN) -> MUST succeed
    let boundary_apdu = vec![0x5A; MAX_APDU_LEN];
    let expected_resp = vec![0x90, 0x00];
    let exp_clone = expected_resp.clone();
    handle
        .set_auto_responder(move |_| exp_clone.clone())
        .await;

    let res = transport.transceive(&boundary_apdu).await.unwrap();
    assert_eq!(res, expected_resp);

    // 2. Exact 262 bytes (MAX_APDU_LEN + 1) -> MUST fail with ApduTooLong
    let over_apdu = vec![0x5A; MAX_APDU_LEN + 1];
    let err = transport.transceive(&over_apdu).await.unwrap_err();
    assert!(
        matches!(err, PivTransportError::ApduTooLong { len: 262 }),
        "262-byte APDU must be refused with ApduTooLong"
    );

    // 3. Huge 1000-byte APDU -> MUST fail with ApduTooLong
    let huge_apdu = vec![0x5A; 1000];
    let err_huge = transport.transceive(&huge_apdu).await.unwrap_err();
    assert!(
        matches!(err_huge, PivTransportError::ApduTooLong { len: 1000 }),
        "1000-byte APDU must be refused with ApduTooLong"
    );

    // 4. Empty APDU (0 bytes) -> MUST fail with EmptyApdu
    let empty_err = transport.transceive(&[]).await.unwrap_err();
    assert!(
        matches!(empty_err, PivTransportError::EmptyApdu),
        "0-byte APDU must be refused with EmptyApdu"
    );
}

#[tokio::test]
async fn test_adversarial_piv_response_exceeding_ceiling_is_rejected() {
    let (transport, handle) = PivBleTransport::new_mock(TEST_ATR.to_vec(), Some(252));

    let handle_clone = handle.clone();
    tokio::spawn(async move {
        while handle_clone.written_fragments().await.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        // Send a response declaring 262 bytes (> 261 ceiling)
        let mut malformed_resp_init = vec![0x83, 0x01, 0x06]; // 262 in hex: 0x0106
        malformed_resp_init.resize(252, 0xAA);
        handle_clone.send_notification(malformed_resp_init);
    });

    let err = transport.transceive(&[0x00, 0x01]).await.unwrap_err();
    assert!(
        matches!(
            err,
            PivTransportError::Framing(FramingError::DeclaredLengthTooLarge {
                declared: 262,
                max: 261
            })
        ),
        "Response APDU declaring > 261 must be rejected by reassembler limit"
    );
}
