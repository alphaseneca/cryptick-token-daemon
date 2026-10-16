use btleplug::api::{Peripheral as _, WriteType};
use ctap_client::request::MakeCredential;
use futures::stream::StreamExt;
use std::time::Duration;
use transport_ble::{adapter, find_device, FIDO_CONTROL_POINT, FIDO_STATUS};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg = std::env::args().nth(1);
    if let Some(ref a) = arg {
        if a == "--version" || a == "-V" {
            println!("ble-ctap {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        if a == "--help" || a == "-h" {
            println!("ble-ctap — interact with Cryptick token CTAP2 over BLE\n\nUsage: ble-ctap [getinfo|register|auth|reset]\n");
            return Ok(());
        }
    }
    let mode = arg.unwrap_or_else(|| "getinfo".to_string());

    println!("Scanning for Cryptick Token (0xFFFD)...");
    let adapter = adapter().await?;
    let peripheral = find_device(&adapter, Duration::from_secs(10)).await?;

    println!("Connecting to Cryptick Token...");
    peripheral.connect().await?;
    peripheral.discover_services().await?;

    let characteristics = peripheral.characteristics();
    let cp = characteristics
        .iter()
        .find(|c| c.uuid == FIDO_CONTROL_POINT)
        .cloned()
        .ok_or("fidoControlPoint not found")?;
    let status = characteristics
        .iter()
        .find(|c| c.uuid == FIDO_STATUS)
        .cloned()
        .ok_or("fidoStatus not found")?;

    println!("Subscribing to fidoStatus notifications...");
    peripheral.subscribe(&status).await?;
    let mut notifications = peripheral.notifications().await?;

    let msg = match mode.as_str() {
        "register" | "make-credential" => {
            println!("\nPreparing CTAP2 MakeCredential request...");
            let mc = MakeCredential {
                challenge: b"test_challenge_1234567890123456",
                rp_id: "cryptick.token",
                user_id: b"test_user_id",
                alg: -7, // ES256
                resident_key: false,
                user_verification: false, // user presence (fingerprint match)
            };
            let ctap_req = mc.encode();
            let payload = ctap_req.encode();
            println!(
                "Prepared CTAP2 MakeCredential request ({} bytes payload)",
                payload.len()
            );
            println!(">>> PLEASE TOUCH YOUR ENROLLED FINGER ON THE TOKEN SENSOR WHEN PROMPTED <<<");
            ble_framing::Message::new(ble_framing::Command::Msg, payload)
        }
        "auth" | "get-assertion" | "assert" => {
            println!("\nPreparing CTAP2 GetAssertion request...");
            let cred_id = std::fs::read(".last_cred_id")
                .expect("No credential found in .last_cred_id. Run make-credential first.");
            let ga = ctap_client::request::GetAssertion {
                challenge: b"auth_challenge_9876543210123456",
                rp_id: "cryptick.token",
                credential_id: &cred_id,
                user_verification: false,
            };
            let ctap_req = ga.encode();
            let payload = ctap_req.encode();
            println!(
                "Prepared CTAP2 GetAssertion request ({} bytes payload)",
                payload.len()
            );
            println!(
                ">>> PLEASE TOUCH YOUR ENROLLED FINGER ON THE TOKEN SENSOR TO AUTHENTICATE <<<"
            );
            ble_framing::Message::new(ble_framing::Command::Msg, payload)
        }
        "reset" => {
            println!("\nSending CTAP2 Reset (0x07) over BLE...");
            println!(
                ">>> PLEASE TOUCH YOUR ENROLLED FINGER ON THE TOKEN SENSOR TO CONFIRM RESET <<<"
            );
            ble_framing::Message::new(ble_framing::Command::Msg, vec![0x07])
        }
        _ => {
            println!("Sending CTAP2 GetInfo (0x04) over BLE...");
            ble_framing::Message::new(ble_framing::Command::Msg, vec![0x04])
        }
    };

    let frag_size = ble_framing::FragmentSize::new(252).unwrap();
    let frags = ble_framing::fragments(&msg, frag_size)?;
    for frag in frags {
        peripheral
            .write(&cp, &frag, WriteType::WithResponse)
            .await?;
    }

    let wait_secs = if mode == "register"
        || mode == "make-credential"
        || mode == "reset"
        || mode == "auth"
        || mode == "get-assertion"
        || mode == "assert"
    {
        40
    } else {
        10
    };
    println!(
        "Waiting for response on fidoStatus (up to {}s)...",
        wait_secs
    );

    let timeout = Duration::from_secs(wait_secs);
    let mut rx = ble_framing::Reassembler::new();
    let mut completed_msg = None;

    loop {
        match tokio::time::timeout(timeout, notifications.next()).await {
            Ok(Some(notif)) => {
                let val = notif.value;
                if val.is_empty() {
                    continue;
                }
                println!("Received fragment: {} bytes (0x{:02X})", val.len(), val[0]);

                match rx.push(&val) {
                    Ok(Some(msg)) => {
                        if msg.command == ble_framing::Command::KeepAlive {
                            let status = ble_framing::KeepAliveStatus::from_u8(
                                msg.payload.first().copied().unwrap_or(0),
                            );
                            match status {
                                Ok(ble_framing::KeepAliveStatus::UpNeeded) => {
                                    println!(">> Token keepalive: UP_NEEDED (Touch enrolled fingerprint sensor now!) <<");
                                }
                                Ok(ble_framing::KeepAliveStatus::Processing) => {
                                    println!(">> Token keepalive: PROCESSING... <<");
                                }
                                Err(_) => {
                                    println!(">> Token keepalive: unknown status byte");
                                }
                            }
                            continue;
                        } else {
                            println!(
                                "Reassembled complete {:?} message ({} bytes payload)",
                                msg.command,
                                msg.payload.len()
                            );
                            completed_msg = Some(msg);
                            break;
                        }
                    }
                    Ok(None) => {
                        println!("Fragment buffered, waiting for continuation fragments...");
                    }
                    Err(e) => {
                        eprintln!("Framing error: {:?}", e);
                        break;
                    }
                }
            }
            Ok(None) => {
                println!("Notification stream closed");
                break;
            }
            Err(_) => {
                println!("Timed out waiting for response");
                break;
            }
        }
    }

    if let Some(msg) = completed_msg {
        let status_byte = msg.payload.first().copied().unwrap_or(0xFF);
        if status_byte == 0x00 {
            println!("\n=== SUCCESS: CTAP2 Transaction over BLE Complete! ===");
            println!("Status: 0x00 (CTAP2_OK)");
            println!("Payload length: {} bytes", msg.payload.len());
            if mode == "register" || mode == "make-credential" {
                match ctap_client::response::MakeCredentialResponse::parse(&msg.payload[1..]) {
                    Ok(mc_resp) => {
                        println!("\n--- WebAuthn Attested Passkey Created Successfully ---");
                        println!("Attestation format : {}", mc_resp.fmt);
                        println!(
                            "User Present (UP)  : {}",
                            mc_resp.auth_data.flags & 0x01 != 0
                        );
                        println!(
                            "User Verified (UV) : {}",
                            mc_resp.auth_data.flags & 0x04 != 0
                        );
                        if let Some(att_cred) = &mc_resp.auth_data.attested_credential {
                            println!(
                                "Credential ID (len={}): {:02X?}",
                                att_cred.credential_id.len(),
                                att_cred.credential_id
                            );
                            println!("AAGUID: {:02X?}", att_cred.aaguid);
                            let _ = std::fs::write(".last_cred_id", &att_cred.credential_id);
                        }
                    }
                    Err(e) => println!("Note: MakeCredentialResponse parse note: {:?}", e),
                }
            } else if mode == "auth" || mode == "get-assertion" || mode == "assert" {
                match ctap_client::response::GetAssertionResponse::parse(&msg.payload[1..]) {
                    Ok(ga_resp) => {
                        println!("\n--- WebAuthn Passkey Assertion Signed Successfully ---");
                        println!(
                            "User Present (UP)  : {}",
                            ga_resp.auth_data.flags & 0x01 != 0
                        );
                        println!(
                            "User Verified (UV) : {}",
                            ga_resp.auth_data.flags & 0x04 != 0
                        );
                        println!(
                            "Signature (DER, len={}): {:02X?}",
                            ga_resp.signature.len(),
                            ga_resp.signature
                        );
                    }
                    Err(e) => println!("Note: GetAssertionResponse parse note: {:?}", e),
                }
            } else if msg.payload.len() > 1 {
                match ctap_client::cbor::Value::decode(&msg.payload[1..]) {
                    Ok(val) => println!("Parsed CBOR: {:#?}", val),
                    Err(e) => println!("CBOR decode error: {:?}", e),
                }
            }
        } else {
            println!("\n=== CTAP2 Error: 0x{:02X} ===", status_byte);
        }
    }

    Ok(())
}
