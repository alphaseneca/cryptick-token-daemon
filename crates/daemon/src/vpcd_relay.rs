//! Virtual smart card reader relay (vpcd / vicc).
//!
//! Connects as a virtual card (vicc) over loopback TCP (port 35963 / 35964)
//! to the vsmartcard `vpcd` driver, allowing OS smart card services (macOS
//! CryptoTokenKit / Linux PCSC-Lite / pam_pkcs11) to reach the Cryptick
//! PIV token over BLE (PROJECT.md §8, §11, §15.6).
//!
//! # Strict Opaque APDU Isolation
//!
//! Per PROJECT.md §8 and §15.6, this module and `crates/daemon` MUST NOT
//! depend on `crates/piv`. APDUs are handled strictly as opaque `Vec<u8>` or
//! byte slices without inspecting or interpreting their contents.

use ble_framing::TransportError;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use transport_ble::PivBleTransport;

/// Errors that can occur during vpcd virtual card relay execution.
#[derive(Debug, Error)]
pub enum RelayError {
    /// An I/O error occurred on the TCP stream.
    #[error("socket I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A vpcd framing or decoding error occurred.
    #[error("vpcd wire protocol error: {0}")]
    Vpcd(#[from] vpcd::VpcdError),

    /// The underlying card transport failed.
    #[error("card transport error: {0}")]
    Transport(#[from] TransportError),

    /// A non-loopback IP address was rejected.
    #[error("non-loopback IP address rejected: {0}")]
    NonLoopbackAddress(SocketAddr),
}

/// A transport that can provide card ATR bytes and transceive opaque APDUs.
#[async_trait::async_trait]
pub trait PivCardTransport: Send + Sync {
    /// Returns the card's Answer-to-Reset (ATR) bytes.
    fn atr(&self) -> &[u8];

    /// Transceives an opaque command APDU, returning the card's response APDU.
    async fn transceive(&self, apdu: &[u8]) -> Result<Vec<u8>, TransportError>;
}

#[async_trait::async_trait]
impl PivCardTransport for PivBleTransport {
    fn atr(&self) -> &[u8] {
        self.atr()
    }

    async fn transceive(&self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.transceive(apdu).await.map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl<T: PivCardTransport + ?Sized> PivCardTransport for Arc<T> {
    fn atr(&self) -> &[u8] {
        (**self).atr()
    }

    async fn transceive(&self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        (**self).transceive(apdu).await
    }
}

/// A virtual ICC relay connecting to a local `vpcd` driver over loopback TCP.
///
/// Dispatches decoded incoming messages:
/// - `Message::GetAtr`, `Message::Reset`, `Message::PowerOn`: responds with framed ATR bytes.
/// - `Message::PowerOff`: handles card power-off without sending a reply.
/// - `Message::Apdu(bytes)`: forwards raw opaque APDU bytes to [`PivCardTransport::transceive`]
///   and returns framed response APDU bytes.
pub struct VpcdRelay<T> {
    transport: T,
    addr: SocketAddr,
}

impl<T: PivCardTransport> VpcdRelay<T> {
    /// Creates a new relay connecting to the default vpcd loopback port (35963).
    pub fn new(transport: T) -> Self {
        Self::with_port(transport, vpcd::DEFAULT_PORT)
    }

    /// Creates a new relay connecting to the specified loopback port.
    pub fn with_port(transport: T, port: u16) -> Self {
        Self {
            transport,
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    /// Creates a new relay connecting to the specified socket address.
    ///
    /// # Safety Invariant
    /// Strictly rejects non-loopback addresses (PROJECT.md §15.6).
    pub fn with_addr(transport: T, addr: SocketAddr) -> Result<Self, RelayError> {
        if !addr.ip().is_loopback() {
            return Err(RelayError::NonLoopbackAddress(addr));
        }
        Ok(Self { transport, addr })
    }

    /// Returns the configured destination address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Connects to vpcd over loopback TCP and runs the relay loop until the socket closes.
    pub async fn connect_and_run(&self) -> Result<(), RelayError> {
        let stream = TcpStream::connect(self.addr).await?;
        self.serve_stream(stream).await
    }

    /// Connects to vpcd over loopback TCP and runs until cancelled or the socket closes.
    pub async fn connect_and_run_with_cancel(
        &self,
        mut cancel: crate::cancel::CancelToken,
    ) -> Result<(), RelayError> {
        tokio::select! {
            res = self.connect_and_run() => res,
            () = cancel.cancelled() => Ok(()),
        }
    }

    /// Serves an established stream (e.g. `TcpStream` or in-memory duplex stream).
    pub async fn serve_stream<S>(&self, stream: S) -> Result<(), RelayError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut decoder = vpcd::Decoder::new(261);
        let mut buf = [0u8; 1024];

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                // Remote closed the socket
                break;
            }
            decoder.push(&buf[..n]);

            while let Some(msg) = decoder.next_message()? {
                match msg {
                    vpcd::Message::GetAtr | vpcd::Message::Reset | vpcd::Message::PowerOn => {
                        let atr = self.transport.atr();
                        let framed = vpcd::frame(atr)?;
                        writer.write_all(&framed).await?;
                        writer.flush().await?;
                    }
                    vpcd::Message::PowerOff => {
                        // Reader powered the card down; no reply expected per vpcd protocol.
                    }
                    vpcd::Message::Apdu(apdu_bytes) => {
                        // Forward raw opaque APDU bytes without interpreting them
                        let resp_bytes = self.transport.transceive(&apdu_bytes).await?;
                        let framed = vpcd::frame(&resp_bytes)?;
                        writer.write_all(&framed).await?;
                        writer.flush().await?;
                    }
                    vpcd::Message::Empty | vpcd::Message::UnknownControl(_) => {
                        // Logged/ignored per reference vicc implementation
                    }
                }
            }
        }

        Ok(())
    }
}

/// Connects to vpcd on loopback and serves the virtual card relay, retrying on disconnect.
pub async fn run_vpcd_relay<T: PivCardTransport>(
    transport: T,
    port: Option<u16>,
) -> Result<(), RelayError> {
    let relay = match port {
        Some(p) => VpcdRelay::with_port(transport, p),
        None => VpcdRelay::new(transport),
    };
    loop {
        match relay.connect_and_run().await {
            Ok(()) => {
                eprintln!("vpcd socket disconnected, reconnecting in 2s...");
            }
            Err(RelayError::Transport(TransportError::Disconnected)) => {
                eprintln!("vpcd card transport disconnected, terminating relay task");
                return Ok(());
            }
            Err(e) => {
                eprintln!("vpcd connection attempt ({e}), retrying in 2s...");
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
}

/// Checks whether a vpcd reader driver is listening on the loopback port.
pub fn is_loopback_port_active(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(150)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCardTransport {
        atr: Vec<u8>,
        expected_apdu: Vec<u8>,
        apdu_response: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl PivCardTransport for MockCardTransport {
        fn atr(&self) -> &[u8] {
            &self.atr
        }

        async fn transceive(&self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
            assert_eq!(apdu, self.expected_apdu.as_slice());
            Ok(self.apdu_response.clone())
        }
    }

    #[tokio::test]
    async fn relay_handles_atr_and_apdu_over_duplex_stream() {
        let atr = vec![0x3B, 0x80, 0x01, 0x81];
        let cmd_apdu = vec![
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00,
        ];
        let resp_apdu = vec![0x61, 0x05, 0x4F, 0x02, 0x00, 0x00, 0x90, 0x00];

        let mock_transport = Arc::new(MockCardTransport {
            atr: atr.clone(),
            expected_apdu: cmd_apdu.clone(),
            apdu_response: resp_apdu.clone(),
        });

        let relay = VpcdRelay::new(mock_transport);

        let (client, server) = tokio::io::duplex(4096);

        let relay_task = tokio::spawn(async move {
            relay.serve_stream(server).await.unwrap();
        });

        let (mut client_rx, mut client_tx) = tokio::io::split(client);

        // 1. Send GetAtr
        let get_atr_frame = vpcd::frame(&[vpcd::CTRL_ATR]).unwrap();
        client_tx.write_all(&get_atr_frame).await.unwrap();

        let mut len_buf = [0u8; 2];
        client_rx.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; len];
        client_rx.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(resp_buf, atr);

        // 2. Send PowerOn
        let power_on_frame = vpcd::frame(&[vpcd::CTRL_ON]).unwrap();
        client_tx.write_all(&power_on_frame).await.unwrap();
        client_rx.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; len];
        client_rx.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(resp_buf, atr);

        // 3. Send Reset
        let reset_frame = vpcd::frame(&[vpcd::CTRL_RESET]).unwrap();
        client_tx.write_all(&reset_frame).await.unwrap();
        client_rx.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; len];
        client_rx.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(resp_buf, atr);

        // 4. Send APDU
        let apdu_frame = vpcd::frame(&cmd_apdu).unwrap();
        client_tx.write_all(&apdu_frame).await.unwrap();
        client_rx.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; len];
        client_rx.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(resp_buf, resp_apdu);

        // 5. Send PowerOff
        let power_off_frame = vpcd::frame(&[vpcd::CTRL_OFF]).unwrap();
        client_tx.write_all(&power_off_frame).await.unwrap();

        // Close client stream
        drop(client_tx);
        drop(client_rx);

        relay_task.await.unwrap();
    }

    #[test]
    fn non_loopback_address_is_rejected() {
        let mock_transport = Arc::new(MockCardTransport {
            atr: vec![],
            expected_apdu: vec![],
            apdu_response: vec![],
        });

        let bad_addr: SocketAddr = "192.168.1.1:35963".parse().unwrap();
        let res = VpcdRelay::with_addr(mock_transport, bad_addr);
        assert!(matches!(res, Err(RelayError::NonLoopbackAddress(_))));
    }

    #[test]
    fn loopback_address_is_accepted() {
        let mock_transport = Arc::new(MockCardTransport {
            atr: vec![],
            expected_apdu: vec![],
            apdu_response: vec![],
        });

        let good_addr: SocketAddr = "127.0.0.1:35963".parse().unwrap();
        let res = VpcdRelay::with_addr(mock_transport, good_addr);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().addr(), good_addr);
    }
}
