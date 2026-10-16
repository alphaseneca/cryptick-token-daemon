//! Top-level CLI router and dispatcher for `cryptick-manager`.

pub mod apdu_cli;
pub mod base_cli;
pub mod config_cli;
pub mod fido_cli;
pub mod oath_cli;
pub mod piv_cli;

use crate::transport::DualTransport;

/// Dispatches raw argument lists to subcommands.
pub fn dispatch(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        print_main_help();
        return Ok(());
    }

    let mut device_filter = None;
    let mut command_args = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" if command_args.is_empty() => {
                print_main_help();
                return Ok(());
            }
            "-v" | "--version" if command_args.is_empty() => {
                println!("cryptick-manager {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-d" | "--device" => {
                i += 1;
                if i < args.len() {
                    device_filter = Some(args[i].clone());
                }
            }
            "-l" | "--log-level" => {
                i += 1; // Log level parsed
            }
            _ => {
                command_args.extend_from_slice(&args[i..]);
                break;
            }
        }
        i += 1;
    }

    if command_args.is_empty() {
        print_main_help();
        return Ok(());
    }

    let subcommand = command_args[0].as_str();
    let sub_args = &command_args[1..];

    // Commands that do not require an active hardware connection prior to execution
    match subcommand {
        "list" => {
            return base_cli::run_base_list(sub_args);
        }
        "script" => {
            return base_cli::run_base_script(sub_args, dispatch);
        }
        _ => {}
    }

    // Connect to token via DualTransport (Direct USB first, then BLE Daemon fallback)
    let mut transport = DualTransport::connect_with_device(device_filter.as_deref())?;

    match subcommand {
        "oath" => oath_cli::handle_oath_command(transport.active(), sub_args),
        "fido" => fido_cli::handle_fido_command(transport.active(), sub_args),
        "piv" => piv_cli::handle_piv_command(transport.active(), sub_args),
        "info" => base_cli::run_base_info(transport.active(), sub_args),
        "apdu" => apdu_cli::run_apdu_command(transport.active(), sub_args),
        "config" => config_cli::handle_config_command(transport.active(), sub_args),
        unknown => Err(format!(
            "Unknown command '{unknown}'. Run 'cryptick-manager --help' for available commands."
        )),
    }
}

pub fn print_main_help() {
    println!(
        "Usage: cryptick-manager [OPTIONS] COMMAND [ARGS]...\n\n\
         Configure and manage Cryptick Token (0x1209:0xBEEE) over USB and Bluetooth Low Energy.\n\n\
         Commands:\n\
           info          Show information about the connected token\n\
           list          List connected tokens\n\
           fido          Manage FIDO2 passkeys, PINs, and on-chip biometric fingerprints\n\
           piv           Manage PIV smart card application, slots, keys, and certificates\n\
           oath          Manage OATH (TOTP / HOTP) authentication accounts\n\
           config        Configure token modes, USB applications, and lock codes\n\
           apdu          Send raw ISO 7816 APDUs to on-device applets\n\
           script        Execute batch commands from a script file\n\n\
         Options:\n\
           -d, --device <SERIAL>   Specify target device serial number or path\n\
           -l, --log-level <LVL>   Logging level (DEBUG, INFO, WARNING, ERROR)\n\
           -v, --version           Show version information\n\
           -h, --help              Show this help message\n"
    );
}
