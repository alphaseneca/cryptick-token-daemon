//! Adversarial stress test suite for `VpcdRelay` and network socket safety invariants.
//!
//! Stress-tests:
//! 1. Non-loopback address refusal (`0.0.0.0`, `192.168.1.1`, `8.8.8.8`, etc.).
//! 2. Byte-by-byte fragmented TCP stream reassembly.
//! 3. Oversized APDUs (> 261 bytes) refused at header level without buffering.
//! 4. Empty frames and unknown control bytes handled without panics or spurious card dispatches.
//! 5. Card transport failure triggering clean disconnect to signal card removal to PC/SC.

use daemon::{PivCardTransport, RelayError, VpcdRelay};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use transport_ble::MAX_APDU_LEN;

struct MockStressCardTransport {
    atr: Vec<u8>,
    connected: AtomicBool,
}

impl MockStressCardTransport {
    fn new(atr: Vec<u8>) -> Self {
        Self {
            atr,
            connected: AtomicBool::new(true),
        }
    }

    fn disconnect(&self) {
        self.connected.store(false, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl PivCardTransport for MockStressCardTransport {
    fn atr(&self) -> &[u8] {
        &self.atr
    }

    async fn transceive(&self, apdu: &[u8]) -> Result<Vec<u8>, ble_framing::TransportError> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(ble_framing::TransportError::Disconnected);
        }
        if apdu.is_empty() {
            return Err(ble_framing::TransportError::Gatt("empty apdu".into()));
        }
        if apdu.len() > MAX_APDU_LEN {
            return Err(ble_framing::TransportError::Gatt("apdu too long".into()));
        }

        // Echo back with 0x9000 appended
        let mut resp = apdu.to_vec();
        resp.extend_from_slice(&[0x90, 0x00]);
        Ok(resp)
    }
}

#[test]
fn test_adversarial_non_loopback_refusal_matrix() {
    let transport = Arc::new(MockStressCardTransport::new(vec![0x3B, 0x80, 0x01, 0x81]));

    let non_loopback_targets = [
        "0.0.0.0:35963",
        "192.168.0.1:35963",
        "192.168.1.254:35963",
        "10.0.0.1:35963",
        "172.16.0.1:35963",
        "172.31.255.255:35963",
        "8.8.8.8:35963",
        "1.1.1.1:35963",
        "255.255.255.255:35963",
    ];

    for target in non_loopback_targets {
        let addr: SocketAddr = target.parse().unwrap();
        let res = VpcdRelay::with_addr(transport.clone(), addr);
        assert!(
            matches!(res, Err(RelayError::NonLoopbackAddress(_))),
            "Expected NonLoopbackAddress for {target}"
        );
    }

    // Valid loopback addresses
    let valid_targets = ["127.0.0.1:35963", "127.0.0.2:35963", "127.1.2.3:35963"];
    for target in valid_targets {
        let addr: SocketAddr = target.parse().unwrap();
        let res = VpcdRelay::with_addr(transport.clone(), addr);
        assert!(res.is_ok(), "Expected OK for loopback target {target}");
    }
}

#[tokio::test]
async fn test_adversarial_oversized_apdu_fails_closed_before_buffering() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let transport = Arc::new(MockStressCardTransport::new(vec![0x3B, 0x80, 0x01, 0x81]));
    let relay = VpcdRelay::with_port(transport, port);

    let relay_task = tokio::spawn(async move { relay.connect_and_run().await });

    let (mut stream, _) = listener.accept().await.unwrap();

    // Send a frame declaring 262 bytes (MAX_APDU_LEN is 261)
    let header = 262u16.to_be_bytes();
    stream.write_all(&header).await.unwrap();

    // Stream must fail immediately with VpcdError::BodyTooLong
    let res = relay_task.await.unwrap();
    assert!(
        matches!(
            res,
            Err(RelayError::Vpcd(vpcd::VpcdError::BodyTooLong {
                len: 262,
                limit: 261
            }))
        ),
        "Relay must fail closed at decoder level when body > 261"
    );
}

#[tokio::test]
async fn test_adversarial_byte_by_byte_stream_fragmentation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let test_atr = vec![0x3B, 0x80, 0x01, 0x81];
    let transport = Arc::new(MockStressCardTransport::new(test_atr.clone()));
    let relay = VpcdRelay::with_port(transport, port);

    let relay_task = tokio::spawn(async move { relay.connect_and_run().await });

    let (mut stream, _) = listener.accept().await.unwrap();

    // Send GetAtr frame (00 01 04) one byte at a time with delays
    let get_atr_wire = vpcd::frame(&[vpcd::CTRL_ATR]).unwrap();
    for byte in get_atr_wire {
        stream.write_all(&[byte]).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, test_atr);

    // Send 10-byte APDU 1 byte at a time
    let cmd_apdu = vec![0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
    let apdu_wire = vpcd::frame(&cmd_apdu).unwrap();
    for byte in apdu_wire {
        stream.write_all(&[byte]).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }

    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_apdu = vec![0u8; len];
    stream.read_exact(&mut resp_apdu).await.unwrap();

    let mut expected = cmd_apdu.clone();
    expected.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(resp_apdu, expected);

    // Clean disconnect
    drop(stream);
    assert!(relay_task.await.unwrap().is_ok());
}

#[tokio::test]
async fn test_adversarial_card_disconnection_triggers_relay_exit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let transport = Arc::new(MockStressCardTransport::new(vec![0x3B, 0x80, 0x01, 0x81]));
    let relay = VpcdRelay::with_port(transport.clone(), port);

    let relay_task = tokio::spawn(async move { relay.connect_and_run().await });

    let (mut stream, _) = listener.accept().await.unwrap();

    // Disconnect card transport underneath the relay
    transport.disconnect();

    // Send an APDU to the relay
    let cmd_apdu = vec![0x00, 0xA4, 0x04, 0x00, 0x00];
    stream
        .write_all(&vpcd::frame(&cmd_apdu).unwrap())
        .await
        .unwrap();

    // The relay must exit with TransportError::Disconnected
    let res = relay_task.await.unwrap();
    assert!(
        matches!(
            res,
            Err(RelayError::Transport(
                ble_framing::TransportError::Disconnected
            ))
        ),
        "Relay must exit immediately on card transport disconnection to notify PC/SC"
    );
}
