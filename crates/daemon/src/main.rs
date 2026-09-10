//! The daemon binary.
//!
//! Today it only runs against the in-process fake device (PROJECT.md §14, L2).
//! `transport-ble` does not exist yet, so there is no radio to own — but the
//! IPC surface, the transaction core and the adapters are all real, which is
//! enough to drive `ssh-keygen` end to end and see where the pieces do not fit.

use std::sync::Arc;

#[cfg(feature = "fake-transport")]
mod fake_main {
    use ble_framing::FragmentSize;
    use daemon::{
        fake::{FakeDevice, Reply},
        server::{serve_connection, unix::IpcListener},
        Bridge,
    };
    use std::sync::Arc;

    pub async fn run(socket: std::path::PathBuf) -> std::io::Result<()> {
        // Fixtures are built by ctap-client's own encoder, not transcribed.
        // A hex constant here was mangled by a line-reflow once already.
        let device = FakeDevice::always(
            FragmentSize::new(64).expect("64 is in range"),
            Reply::ByCtapCommand {
                make_credential: ctap_client::fixtures::make_credential_response(),
                get_assertion: ctap_client::fixtures::get_assertion_response(),
            },
        );
        let bridge = Arc::new(Bridge::new(device));
        let listener = IpcListener::bind(&socket)?;
        eprintln!("listening on {}", listener.path().display());
        eprintln!("fake device, no radio — PROJECT.md §14 L2");

        loop {
            match listener.accept().await {
                Ok(Some(stream)) => {
                    tokio::spawn(serve_connection(stream, Arc::clone(&bridge)));
                }
                // A peer that is not the owner. Refused, and we keep serving.
                Ok(None) => eprintln!("refused a connection from another user"),
                Err(e) => eprintln!("accept failed: {e}"),
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let _ = Arc::new(());

    let socket = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "--socket")
        .map(|w| std::path::PathBuf::from(&w[1]))
        .or_else(ipc::default_socket_path)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no socket path given and none could be derived",
            )
        })?;

    #[cfg(feature = "fake-transport")]
    return fake_main::run(socket).await;

    #[cfg(not(feature = "fake-transport"))]
    {
        let _ = socket;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no BLE transport is implemented yet; build with --features fake-transport",
        ))
    }
}
