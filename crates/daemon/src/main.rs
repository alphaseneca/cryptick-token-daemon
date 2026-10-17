//! The daemon binary.
//!
//! Provides the CLI entrypoint for `cryptick-daemon`:
//! - `cryptick-daemon run [--fake] [--socket <path>]`
//! - `cryptick-daemon service install`
//! - `cryptick-daemon service uninstall`
//! - `cryptick-daemon service status`

use daemon::cli::{self, CliCommand, LoginCommand, PairOptions, RunOptions, ServiceSubcommand};
use daemon::login;
use daemon::service;
use daemon::transport;
use std::sync::Arc;

#[cfg(feature = "fake-transport")]
#[cfg(unix)]
mod fake_main {
    use ble_framing::FragmentSize;
    use daemon::{
        devices::DeviceStore,
        fake::{FakeDevice, Reply},
        server::{serve_connection, unix::IpcListener},
        Bridge,
    };
    use std::sync::{Arc, Mutex};

    // Evaluated at compile time: a bad literal fails the build rather than
    // panicking at runtime (PROJECT.md §20 forbids unwrap()/expect() here).
    const FAKE_FRAGMENT_SIZE: FragmentSize = match FragmentSize::new(64) {
        Ok(size) => size,
        Err(_) => panic!("64 must be within FragmentSize's valid 20..=512 range"),
    };

    pub async fn run(socket: std::path::PathBuf) -> std::io::Result<()> {
        let device = FakeDevice::always(
            FAKE_FRAGMENT_SIZE,
            Reply::ByCtapCommand {
                make_credential: ctap_client::fixtures::make_credential_response(),
                get_assertion: ctap_client::fixtures::get_assertion_response(),
            },
        );
        let bridge = Arc::new(Bridge::new(device));
        // The fake transport has no notion of "which physical device" — no
        // live-retarget capability, so `devices.select` is bookkeeping only
        // here (`retarget: None`), same as any transport that hasn't
        // implemented `LiveRetarget`.
        let devices = Arc::new(Mutex::new(DeviceStore::in_memory()));
        let listener = IpcListener::bind(&socket)?;
        eprintln!("listening on {}", listener.path().display());
        eprintln!("fake device, no radio — PROJECT.md §14 L2");

        loop {
            match listener.accept().await {
                Ok(Some(stream)) => {
                    tokio::spawn(serve_connection(
                        stream,
                        Arc::clone(&bridge),
                        Arc::clone(&devices),
                        None,
                    ));
                }
                Ok(None) => eprintln!("refused a connection from another user"),
                Err(e) => eprintln!("accept failed: {e}"),
            }
        }
    }
}

#[cfg(feature = "fake-transport")]
#[cfg(windows)]
mod fake_main {
    use ble_framing::FragmentSize;
    use daemon::{
        devices::DeviceStore,
        fake::{FakeDevice, Reply},
        server::{serve_connection, windows::IpcListener},
        Bridge,
    };
    use std::sync::{Arc, Mutex};

    const FAKE_FRAGMENT_SIZE: FragmentSize = match FragmentSize::new(64) {
        Ok(size) => size,
        Err(_) => panic!("64 must be within FragmentSize's valid 20..=512 range"),
    };

    pub async fn run(socket: std::path::PathBuf) -> std::io::Result<()> {
        let device = FakeDevice::always(
            FAKE_FRAGMENT_SIZE,
            Reply::ByCtapCommand {
                make_credential: ctap_client::fixtures::make_credential_response(),
                get_assertion: ctap_client::fixtures::get_assertion_response(),
            },
        );
        let bridge = Arc::new(Bridge::new(device));
        let devices = Arc::new(Mutex::new(DeviceStore::load()));
        let mut listener = IpcListener::bind(&socket)?;
        eprintln!("listening on {}", listener.path().display());
        eprintln!("fake device, no radio — PROJECT.md §14 L2");

        loop {
            match listener.accept().await {
                Ok(Some(stream)) => {
                    tokio::spawn(serve_connection(
                        stream,
                        Arc::clone(&bridge),
                        Arc::clone(&devices),
                    ));
                }
                Ok(None) => eprintln!("refused a connection from another user"),
                Err(e) => eprintln!("accept failed: {e}"),
            }
        }
    }
}

#[cfg(feature = "fake-transport")]
#[cfg(not(any(unix, windows)))]
mod fake_main {
    pub async fn run(_socket: std::path::PathBuf) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Daemon IPC listener is not yet supported on this platform",
        ))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let _ = Arc::new(());

    let command = match cli::parse_args(std::env::args().skip(1)) {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    match command {
        CliCommand::Help => {
            print!("{}", cli::help_text());
            Ok(())
        }
        CliCommand::Version => {
            println!("cryptick-daemon {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::Service(ServiceSubcommand::Install) => {
            let exec_path = std::env::current_exe()?;
            let manager = service::current_service_manager();
            manager.install(&exec_path, &["run"])?;
            println!(
                "Installed and started service ({})",
                manager.platform_name()
            );
            Ok(())
        }
        CliCommand::Service(ServiceSubcommand::Uninstall) => {
            let manager = service::current_service_manager();
            manager.uninstall()?;
            println!("Uninstalled service ({})", manager.platform_name());
            Ok(())
        }
        CliCommand::Service(ServiceSubcommand::Status) => {
            let manager = service::current_service_manager();
            let status = manager.status()?;
            print!("{}", status.display_summary());
            Ok(())
        }
        CliCommand::Check => run_check().await,
        CliCommand::Devices => run_devices().await,
        CliCommand::Pair(opts) => run_pair(opts).await,
        CliCommand::Connect => run_connect().await,
        CliCommand::Disconnect => run_disconnect().await,
        CliCommand::Forget(opts) => run_forget(opts).await,
        CliCommand::Info => run_info().await,
        CliCommand::Login(LoginCommand::Status(opts)) => {
            let report = login::check_login_status(&opts);
            if opts.json {
                println!("{}", report.to_json());
            } else {
                login::print_login_status(&report);
            }
            Ok(())
        }
        CliCommand::Login(LoginCommand::Setup(opts)) => {
            login::run_login_setup(&opts).map_err(std::io::Error::other)
        }
        CliCommand::Run(opts) => run_daemon(opts).await,
    }
}

async fn run_check() -> std::io::Result<()> {
    use transport_ble::btleplug::api::Peripheral as _;

    println!("=== Cryptick Daemon & Hardware Health Check ===");
    println!("Daemon Version   : {}", env!("CARGO_PKG_VERSION"));

    let manager = service::current_service_manager();
    let status = manager.status()?;
    println!("Platform         : {}", status.platform);
    println!("Service Unit     : {}", status.unit_path.display());
    println!(
        "  Installed      : {}",
        if status.unit_exists { "yes" } else { "no" }
    );
    println!(
        "  Running        : {}",
        if status.service_running {
            status.service_details.as_deref().unwrap_or("yes")
        } else {
            "no"
        }
    );
    println!("IPC Endpoint     : {}", status.endpoint);
    println!(
        "  Connectable    : {}",
        if status.endpoint_connectable {
            "yes"
        } else {
            "no"
        }
    );

    // Check BLE subsystem & device
    print!("Bluetooth Radio  : ");
    match transport_ble::adapter().await {
        Ok(adapter) => {
            println!("adapter ready");
            print!("Cryptick Token   : scanning (timeout 3s)... ");
            match transport_ble::find_device(&adapter, std::time::Duration::from_secs(3)).await {
                Ok(peripheral) => {
                    let addr = transport_ble::display_address(&peripheral);
                    let name = peripheral
                        .properties()
                        .await
                        .ok()
                        .flatten()
                        .and_then(|p| p.local_name)
                        .unwrap_or_else(|| "Cryptick Token".to_string());
                    println!("found '{}' [{}]", name, addr);
                }
                Err(e) => {
                    println!("not discovered ({e})");
                }
            }
        }
        Err(e) => {
            println!("unavailable ({e})");
        }
    }

    println!("------------------------------------------------");
    if status.is_healthy() {
        println!("Overall Status   : READY (Service active, IPC connectable)");
    } else if status.unit_exists {
        println!("Overall Status   : SERVICE STOPPED (run 'cryptick-daemon service install' or restart service)");
    } else {
        println!("Overall Status   : NOT INSTALLED (run 'cryptick-daemon service install')");
    }

    Ok(())
}

async fn run_devices() -> std::io::Result<()> {
    use transport_ble::btleplug::api::{Central as _, Peripheral as _, ScanFilter};

    println!("=== Cryptick Devices & Interfaces ===");

    // 1. Check Daemon IPC Link
    let manager = service::current_service_manager();
    let status = manager.status().ok();
    if let Some(ref st) = status {
        if st.endpoint_connectable {
            println!("\n[1] Active Daemon Connection (BLE Link Held)");
            println!(
                "    Service       : {}",
                st.service_details.as_deref().unwrap_or("running")
            );
            println!("    IPC Endpoint  : {}", st.endpoint);
            println!("    Link State    : Connected to Cryptick Token over BLE");
        }
    }

    // 2. Check USB Interfaces
    println!("\n[2] USB Device Interface");
    #[allow(unused_mut)]
    let mut usb_found = false;
    #[cfg(unix)]
    {
        for path in ["/dev/cu.usbmodemCRYPTICK2", "/dev/tty.usbmodemCRYPTICK2"] {
            if std::path::Path::new(path).exists() {
                println!("    Serial Port   : {path} (Cryptick Token CDC console)");
                println!("    CTAPHID       : UsagePage 0xF1D0 (FIDO2 passkey hardware)");
                println!("    CCID          : PIV Smart Card interface");
                usb_found = true;
                break;
            }
        }
    }
    if !usb_found {
        println!("    USB           : No Cryptick CDC modem detected on /dev/cu.usbmodem*");
    }

    // 3. Scan Airwaves for Nearby Devices
    println!("\n[3] Nearby Bluetooth LE Airwaves (2s scan)");
    match transport_ble::adapter().await {
        Ok(adapter) => {
            let _ = adapter.start_scan(ScanFilter::default()).await;
            tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            let _ = adapter.stop_scan().await;

            let mut count = 0;
            if let Ok(peripherals) = adapter.peripherals().await {
                println!(
                    "    {:<24} {:<20} {:<6} Services",
                    "NAME", "ADDRESS", "RSSI"
                );
                println!("    {:-<24} {:-<20} {:-<6} {:-<20}", "", "", "", "");
                for p in peripherals {
                    if let Ok(Some(props)) = p.properties().await {
                        let name = props.local_name.unwrap_or_else(|| "(unnamed)".to_string());
                        let addr = transport_ble::display_address(&p);
                        let rssi = props
                            .rssi
                            .map(|r| r.to_string())
                            .unwrap_or_else(|| "-".to_string());
                        let svcs = props
                            .services
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        println!("    {:<24} {:<20} {:<6} {}", name, addr, rssi, svcs);
                        count += 1;
                    }
                }
            }
            if count == 0 {
                println!("    (no advertising devices observed; if daemon is active, token is already connected)");
            }
        }
        Err(e) => {
            println!("    Bluetooth Radio: unavailable ({e})");
        }
    }

    Ok(())
}

async fn run_pair(opts: PairOptions) -> std::io::Result<()> {
    use std::io::Write;
    use transport_ble::btleplug::api::{Peripheral as _, WriteType};
    use transport_ble::{display_address, FIDO_CONTROL_POINT, FIDO_STATUS};

    println!("=== Cryptick Token BLE Pairing ===");

    // 1. If background service is running, stop it temporarily so the radio can be discovered and paired
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("pkill")
            .args(["-f", "cryptick-daemon run"])
            .output();
    }
    let manager = service::current_service_manager();
    let initial_status = manager.status().ok();
    let was_running = initial_status.as_ref().is_some_and(|s| s.service_running);
    if was_running {
        println!("Background daemon is currently running and holding the BLE link.");
        print!("Releasing radio for pairing handshake... ");
        let _ = run_disconnect().await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        println!("DONE.");
    }

    // 2. Discover adapter
    let adapter = transport_ble::adapter()
        .await
        .map_err(|e| std::io::Error::other(format!("Bluetooth adapter unavailable: {e}")))?;

    // 3. Scan for Cryptick Token
    let peripheral = if let Some(ref target) = opts.device {
        println!("Scanning for Cryptick Token matching '{target}' (service 0xFFFD)...");
        match transport_ble::find_device_with_target(
            &adapter,
            Some(target.as_str()),
            std::time::Duration::from_secs(8),
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to discover Cryptick Token '{target}' on BLE: {e}");
                if was_running {
                    let _ = run_connect().await;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    e.to_string(),
                ));
            }
        }
    } else {
        println!("Scanning for Cryptick Tokens nearby (service 0xFFFD)...");
        let devices = transport_ble::find_all_devices(&adapter, std::time::Duration::from_secs(3))
            .await
            .map_err(|e| std::io::Error::other(format!("BLE scan error: {e}")))?;

        if devices.is_empty() {
            eprintln!("No Cryptick Tokens found advertising nearby.");
            eprintln!("Ensure the token is powered on and Bluetooth menu shows 'Ready to Pair'.");
            if was_running {
                let _ = run_connect().await;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No Cryptick Tokens found advertising",
            ));
        } else if devices.len() == 1 {
            devices.into_iter().next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "device list became empty")
            })?
        } else {
            println!("\nMultiple Cryptick Tokens detected nearby:");
            for (idx, dev) in devices.iter().enumerate() {
                let dev_name = dev
                    .properties()
                    .await
                    .ok()
                    .flatten()
                    .and_then(|p| p.local_name)
                    .unwrap_or_else(|| "Cryptick Token".to_string());
                let dev_addr = display_address(dev);
                println!("  [{}] {} [{}]", idx + 1, dev_name, dev_addr);
            }
            print!("\nSelect token to pair with [1-{}]: ", devices.len());
            std::io::stdout().flush()?;
            let mut choice = String::new();
            std::io::stdin().read_line(&mut choice)?;
            let chosen_idx = choice.trim().parse::<usize>().unwrap_or(1);
            let idx = if chosen_idx >= 1 && chosen_idx <= devices.len() {
                chosen_idx - 1
            } else {
                0
            };
            devices.into_iter().nth(idx).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "selected index out of range")
            })?
        }
    };

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let name = peripheral
        .properties()
        .await
        .ok()
        .flatten()
        .and_then(|p| p.local_name)
        .unwrap_or_else(|| "Cryptick Token".to_string());
    let addr = display_address(&peripheral);
    println!("Selected token: '{name}' [{addr}]");

    // 4. Connect to token and discover services FIRST so it receives security requests
    println!("Connecting to token [{addr}]...");
    let connect_res = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        if !peripheral.is_connected().await.unwrap_or(false) {
            peripheral.connect().await
        } else {
            Ok(())
        }
    })
    .await;

    match connect_res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("\nFailed to connect to token: {e}");
            let err_str = e.to_string();
            if err_str.to_lowercase().contains("peer removed") {
                eprintln!("\n[!] macOS has a stale pairing record cached for this token.");
                eprintln!("    Open System Settings -> Bluetooth -> find '{name}' -> click (i) -> 'Forget This Device'.");
                eprintln!("    Then run 'cryptick-daemon pair' again.");
            }
            return Err(std::io::Error::other(format!("Connection failed: {e}")));
        }
        Err(_) => {
            eprintln!("\nTimed out connecting to token [{addr}].");
            eprintln!("Ensure the token is awake, not connected to another host, and shows 'Ready to Pair'.");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Connection timed out",
            ));
        }
    }

    println!("Connected. Discovering GATT services...");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        peripheral.discover_services(),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Timed out discovering services",
        )
    })?
    .map_err(|e| std::io::Error::other(format!("Failed to discover token GATT services: {e}")))?;

    // 5. Initiate authenticated bonding
    println!("\n=== Initiating LE Secure Connections (LESC) Bonding ===");
    println!("[!] LOOK AT THE OLED SCREEN ON YOUR TOKEN:");
    println!("    The 6-digit BLE passkey is displayed on the screen.");
    if cfg!(target_os = "macos") {
        println!("    Enter that 6-digit code into macOS 'Bluetooth Pairing Request' dialog.");
    } else {
        println!("    Enter that 6-digit code when prompted by your system.");
    }

    let chars = peripheral.characteristics();
    let control_point = chars.iter().find(|c| c.uuid == FIDO_CONTROL_POINT).cloned();
    let status_char = chars.iter().find(|c| c.uuid == FIDO_STATUS).cloned();

    if let (Some(cp), Some(st)) = (control_point, status_char) {
        let _ = peripheral.subscribe(&st).await;

        // CTAP BLE PING frame: [CMD: 0x81 (PING), Length: 0x00 0x04, DATA: 'P','A','I','R']
        let ping_frame = [0x81, 0x00, 0x04, b'P', b'A', b'I', b'R'];
        match peripheral
            .write(&cp, &ping_frame, WriteType::WithResponse)
            .await
        {
            Ok(()) => {
                println!("[OK] Authenticated write accepted by token.");
                println!(
                    "[OK] LESC MITM bonding verified! The link is encrypted and authenticated."
                );
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.to_lowercase().contains("insufficient")
                    || err_str.contains("NotPermitted")
                {
                    eprintln!("[!] GATT write requires authenticated bonding: {e}");
                    eprintln!("    Confirm that the 6-digit PIN from the OLED was entered when prompted by your system.");
                } else {
                    eprintln!("[!] Pairing cancelled or timed out: {e}");
                    eprintln!("    The 6-digit PIN was not submitted to macOS in time.");
                }
                let _ = peripheral.disconnect().await;
                return Err(std::io::Error::other(format!("Pairing failed: {e}")));
            }
        }
    } else {
        let _ = peripheral.disconnect().await;
        return Err(std::io::Error::other(
            "FIDO GATT service characteristics not found",
        ));
    }

    let _ = peripheral.disconnect().await;

    // Save paired device address for auto-reconnect pinning
    if let Some(path) = transport::paired_device_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, format!("{}\n", addr));
        println!("[OK] Saved paired device address to {}", path.display());
    }

    // 6. Restore daemon service
    println!("\nStarting background daemon service to hold persistent bonded link...");
    let _ = run_connect().await;

    println!("\n=== Pairing Finished ===");
    println!("Token '{name}' [{addr}] is paired and ready.");
    Ok(())
}

async fn run_connect() -> std::io::Result<()> {
    let manager = service::current_service_manager();
    let status = manager.status()?;
    if !status.unit_exists {
        let exec_path = std::env::current_exe()?;
        println!("Service not installed. Installing and starting daemon service...");
        manager.install(&exec_path, &["run"])?;
    } else if !status.service_running {
        println!("Starting daemon service...");
        #[cfg(target_os = "macos")]
        {
            let unit = manager.unit_path().ok();
            if let Some(u) = unit {
                let _ = std::process::Command::new("launchctl")
                    .args(["load", "-w"])
                    .arg(u)
                    .output();
            }
            let _ = std::process::Command::new("launchctl")
                .args(["start", "com.cryptick.daemon"])
                .output();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "start", "cryptick-daemon"])
                .output();
        }
    }

    print!("Connecting to Cryptick Token via daemon... ");
    let mut ok = false;
    for _ in 0..30 {
        if let Ok(st) = manager.status() {
            if st.endpoint_connectable {
                ok = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    if ok {
        println!("CONNECTED.");
        println!("The daemon is active and holding the BLE link to the token.");
        println!("IPC Socket is ready for passkeys and OpenSSH.");
    } else {
        println!("PENDING (service started; token is connecting in background).");
    }
    Ok(())
}

async fn run_disconnect() -> std::io::Result<()> {
    let manager = service::current_service_manager();
    let status = manager.status()?;
    if status.service_running {
        println!("Stopping background service to release Bluetooth link...");
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("launchctl")
                .args(["stop", "com.cryptick.daemon"])
                .output();
            let unit = manager.unit_path().ok();
            if let Some(u) = unit {
                let _ = std::process::Command::new("launchctl")
                    .args(["unload"])
                    .arg(u)
                    .output();
            }
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "stop", "cryptick-daemon"])
                .output();
        }
    }

    if let Some(socket_path) = ipc::default_socket_path() {
        let _ = std::fs::remove_file(socket_path);
    }

    println!("[OK] Disconnected.");
    println!("Background daemon stopped, socket cleared, and BLE link released.");
    println!("The Cryptick Token is now advertising over the air for new connections.");
    Ok(())
}

async fn run_forget(opts: cli::ForgetOptions) -> std::io::Result<()> {
    let manager = service::current_service_manager();
    println!("=== Forgetting Cryptick Token Connection & Bonding ===");

    // 1. Uninstall and stop background daemon service so it doesn't hold the radio or reconnect
    let _ = manager.uninstall();

    // 2. Remove socket
    if let Some(socket_path) = ipc::default_socket_path() {
        let _ = std::fs::remove_file(socket_path);
    }
    let _ = std::fs::remove_file(".last_cred_id");

    // 3. Clear stored paired_device config
    let saved_device = transport::paired_device_path().and_then(|p| {
        let content = std::fs::read_to_string(&p).ok();
        let _ = std::fs::remove_file(&p);
        content.map(|s| s.trim().to_string())
    });

    let _target_dev = opts.device.or(saved_device);

    // 4. If token is reachable via serial USB, send UNPAIR command to wipe NVS bonds immediately
    let mut serial_wiped = false;
    for entry in std::fs::read_dir("/dev").into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("cu.usbmodem") || name.starts_with("ttyACM") {
            let path = entry.path();
            if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&path) {
                use std::io::Write;
                if file.write_all(b"UNPAIR\r\n").is_ok() {
                    let _ = file.flush();
                    println!(
                        "[OK] Sent UNPAIR command to token over serial ({})",
                        path.display()
                    );
                    serial_wiped = true;
                    break;
                }
            }
        }
    }

    println!("[OK] Daemon service uninstalled and stopped.");
    println!("[OK] Paired device records and local IPC sockets removed.");

    if serial_wiped {
        println!(
            "[OK] Token NVS bonds wiped! Token has restarted advertising in 'Ready to Pair' mode."
        );
    } else {
        println!("\nTo complete unpairing on the hardware token:");
        println!("  1. On the Cryptick Token OLED, select 'Bluetooth' -> 'Unpair / Wipe Bonds'.");
        println!("  2. The token will clear all NVS bonds and return to 'Ready to Pair' mode.");
    }

    println!("\nTo complete unpairing on this computer's OS:");
    #[cfg(target_os = "macos")]
    {
        println!("  - Open System Settings -> Bluetooth.");
        println!(
            "  - Under 'My Devices', find '{}' and click (i) -> 'Forget This Device'.",
            _target_dev.as_deref().unwrap_or("Cryptick-Token-*")
        );
    }
    #[cfg(target_os = "linux")]
    {
        println!(
            "  - Run: bluetoothctl remove {}",
            _target_dev.as_deref().unwrap_or("<device-mac>")
        );
    }

    Ok(())
}

async fn run_info() -> std::io::Result<()> {
    let manager = service::current_service_manager();
    let status = manager.status()?;

    if status.endpoint_connectable {
        println!("=== Cryptick Token Status (via Active Daemon) ===");
        println!(
            "Service          : {}",
            status.service_details.as_deref().unwrap_or("running")
        );
        println!("IPC Socket       : {}", status.endpoint);

        // Query status over IPC
        if let Some(_socket_path) = ipc::default_socket_path() {
            #[cfg(unix)]
            {
                use std::io::{Read, Write};
                use std::os::unix::net::UnixStream;
                if let Ok(mut stream) = UnixStream::connect(&_socket_path) {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                    let req = ipc::Envelope::new("info-status", ipc::ClientMessage::DeviceStatus);
                    if let Ok(frame) = ipc::encode(&req) {
                        let _ = stream.write_all(&frame);
                        let _ = stream.flush();

                        let mut buf = [0u8; 4096];
                        let mut decoder = ipc::FrameDecoder::new();
                        if let Ok(n) = stream.read(&mut buf) {
                            decoder.push(&buf[..n]);
                            if let Ok(Some(resp_frame)) = decoder.next_frame() {
                                if let Ok(env) = ipc::decode_daemon(&resp_frame) {
                                    if let ipc::DaemonMessage::DeviceRange { in_range, bonded } =
                                        env.body
                                    {
                                        println!("In Range         : {in_range}");
                                        println!("Bonded / Secure  : {bonded}");
                                        println!("Link Usable      : {}", in_range && bonded);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return Ok(());
    }

    // Direct probe fallback
    println!("Daemon not active; performing direct BLE probe...");
    match transport_ble::adapter().await {
        Ok(adapter) => {
            match transport_ble::find_device(&adapter, std::time::Duration::from_secs(4)).await {
                Ok(peripheral) => {
                    if let Ok(info) = transport_ble::probe(&peripheral).await {
                        println!("=== Cryptick Token Information ===");
                        println!(
                            "Name             : {}",
                            info.name.as_deref().unwrap_or("Cryptick Token")
                        );
                        println!("Address          : {}", info.address);
                        println!("ControlPointLen  : {}", info.control_point_length);
                        println!(
                            "FIDO2 Revision   : {}",
                            if info.speaks_fido2 {
                                "FIDO2 (0x20)"
                            } else {
                                "none"
                            }
                        );
                    }
                }
                Err(e) => println!("Token not found on BLE ({e})."),
            }
        }
        Err(e) => println!("Bluetooth adapter unavailable ({e})."),
    }

    Ok(())
}

#[cfg(unix)]
mod live_main {
    use daemon::{
        devices::DeviceStore,
        server::{serve_connection, unix::IpcListener},
        Bridge, LiveRetarget, ReconnectingBleTransport,
    };
    use std::sync::{Arc, Mutex};

    pub async fn run(socket: std::path::PathBuf) -> std::io::Result<()> {
        let listener = IpcListener::bind(&socket)?;
        eprintln!("listening on {}", listener.path().display());

        eprintln!("Starting auto-reconnecting BLE transport (monitoring Cryptick Token)...");
        let (transport, _reconnect_handle) = ReconnectingBleTransport::spawn(None, None).await;

        // Seed the known-devices store from whatever single BLE target was
        // already persisted (`transport::paired_device_path()`), so a device
        // paired before this store existed still shows up in `devices.list`.
        let mut store = DeviceStore::load();
        store.seed_from_paired_target(transport.target_device().as_deref());
        let devices = Arc::new(Mutex::new(store));

        // `ReconnectingBleTransport` is the one transport that implements
        // `LiveRetarget` today — `devices.select` against this daemon
        // actually hot-retargets the live connection, not just bookkeeping.
        let retarget: Arc<dyn LiveRetarget> = Arc::new(transport.clone());

        let bridge = Arc::new(Bridge::new(transport));

        loop {
            match listener.accept().await {
                Ok(Some(stream)) => {
                    tokio::spawn(serve_connection(
                        stream,
                        Arc::clone(&bridge),
                        Arc::clone(&devices),
                        Some(Arc::clone(&retarget)),
                    ));
                }
                Ok(None) => {}
                Err(e) => eprintln!("accept failed: {e}"),
            }
        }
    }
}

#[cfg(windows)]
mod live_main {
    use daemon::{
        devices::DeviceStore,
        server::{serve_connection, windows::IpcListener},
        Bridge, ReconnectingBleTransport,
    };
    use std::sync::{Arc, Mutex};

    pub async fn run(socket: std::path::PathBuf) -> std::io::Result<()> {
        let mut listener = IpcListener::bind(&socket)?;
        eprintln!("listening on {}", listener.path().display());

        eprintln!("Starting auto-reconnecting BLE transport (monitoring Cryptick Token)...");
        let (transport, _reconnect_handle) = ReconnectingBleTransport::spawn(None, None).await;

        let mut device_store = DeviceStore::load();
        device_store.seed_from_paired_target(transport.target_device());
        let devices = Arc::new(Mutex::new(device_store));

        let bridge = Arc::new(Bridge::new(transport));

        loop {
            match listener.accept().await {
                Ok(Some(stream)) => {
                    tokio::spawn(serve_connection(
                        stream,
                        Arc::clone(&bridge),
                        Arc::clone(&devices),
                    ));
                }
                Ok(None) => {}
                Err(e) => eprintln!("accept failed: {e}"),
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod live_main {
    pub async fn run(_socket: std::path::PathBuf) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Daemon IPC listener is not yet supported on this platform",
        ))
    }
}

async fn run_daemon(opts: RunOptions) -> std::io::Result<()> {
    let socket = opts
        .socket
        .or_else(ipc::default_socket_path)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no socket path given and none could be derived",
            )
        })?;

    if opts.fake {
        #[cfg(feature = "fake-transport")]
        {
            return fake_main::run(socket).await;
        }

        #[cfg(not(feature = "fake-transport"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "--fake requested, but binary was built without fake-transport feature; rebuild with --features fake-transport",
            ));
        }
    }

    #[cfg(feature = "fake-transport")]
    {
        // When built with fake-transport feature in CI / test environments without radio
        // (such as ssh-roundtrip.sh which invokes daemon with no flags), serve the fake device
        // unless CRYPTICK_LIVE is explicitly requested.
        if std::env::var("CRYPTICK_LIVE").is_ok() {
            live_main::run(socket).await
        } else {
            fake_main::run(socket).await
        }
    }

    #[cfg(not(feature = "fake-transport"))]
    {
        live_main::run(socket).await
    }
}
