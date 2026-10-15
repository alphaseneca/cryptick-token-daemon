//! Command-line argument parsing for `cryptick-daemon`.
//!
//! Provides lightweight, zero-dependency parsing for daemon subcommands and options:
//! - `cryptick-daemon run [--fake] [--socket <path>]`
//! - `cryptick-daemon service install`
//! - `cryptick-daemon service uninstall`
//! - `cryptick-daemon service status`
//!
//! Bare invocations (e.g. `cryptick-daemon [--fake] [--socket <path>]` or `daemon`)
//! are preserved for backwards compatibility with existing tooling.

use std::path::PathBuf;

/// Parsed top-level command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    /// Run the daemon process.
    Run(RunOptions),
    /// Manage the background user service.
    Service(ServiceSubcommand),
    /// Perform a health and connectivity check.
    Check,
    /// List connected token and visible nearby devices.
    Devices,
    /// Connect to the Cryptick Token.
    Connect,
    /// Disconnect from the Cryptick Token and release the radio.
    Disconnect,
    /// Delete / forget the connection, wipe bonds, and clean state.
    Forget(ForgetOptions),
    /// Pair with the Cryptick Token using the 6-digit BLE passkey/PIN displayed on OLED.
    Pair(PairOptions),
    /// Query token hardware & CTAP2 information.
    Info,
    /// Setup or inspect computer login pairing (macOS SmartCard / Linux PAM).
    Login(LoginCommand),
    /// Display help information.
    Help,
    /// Display version information.
    Version,
}

/// Subcommands and options for `login`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginCommand {
    /// 1-click wizard to setup computer login authentication.
    Setup(LoginSetupOptions),
    /// Query status of computer login, CryptoTokenKit / PAM, and token pairing.
    Status(LoginStatusOptions),
}

/// Options for `login setup`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoginSetupOptions {
    /// Target username (defaults to current user).
    pub user: Option<String>,
    /// Explicit public key hash (auto-detected from token if omitted).
    pub hash: Option<String>,
    /// Simulate without modifying system configuration.
    pub dry_run: bool,
    /// Configure screen lock on token departure / disconnect.
    pub lock_on_removal: bool,
    /// Force pairing even if already paired.
    pub force: bool,
    /// Token PIN if required for authentication.
    pub pin: Option<String>,
}

/// Options for `login status`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoginStatusOptions {
    /// Target username (defaults to current user).
    pub user: Option<String>,
    /// Output diagnostics in JSON format.
    pub json: bool,
}

/// Options for the `pair` subcommand.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PairOptions {
    /// 6-digit pairing PIN shown on the token's OLED display.
    pub pin: Option<String>,
    /// Optional target device address or UUID to pair with when multiple tokens are present.
    pub device: Option<String>,
}

/// Options for the `forget` subcommand.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ForgetOptions {
    /// Optional target device address or UUID to forget.
    pub device: Option<String>,
}

/// Options for the `run` subcommand.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunOptions {
    /// Force in-process fake device mode.
    pub fake: bool,
    /// Custom IPC endpoint/socket path.
    pub socket: Option<PathBuf>,
}

/// Subcommands under `service`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceSubcommand {
    /// Install and enable the background service.
    Install,
    /// Stop and uninstall the background service.
    Uninstall,
    /// Query the status of the background service and IPC endpoint.
    Status,
}

/// An error encountered while parsing command-line arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// Parses command-line arguments.
///
/// Accepts an iterator over argument strings (typically `std::env::args().skip(1)`).
pub fn parse_args<I, T>(args: I) -> Result<CliCommand, ParseError>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();

    if args.is_empty() {
        return Ok(CliCommand::Run(RunOptions::default()));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CliCommand::Help),
        "version" | "--version" | "-V" => Ok(CliCommand::Version),
        "check" => Ok(CliCommand::Check),
        "status" => Ok(CliCommand::Service(ServiceSubcommand::Status)),
        "devices" | "scan" | "list" => Ok(CliCommand::Devices),
        "connect" => Ok(CliCommand::Connect),
        "disconnect" => Ok(CliCommand::Disconnect),
        "forget" | "delete-connection" | "unpair" | "delete" => parse_forget_options(&args[1..]),
        "pair" | "pair-device" => parse_pair_options(&args[1..]),
        "info" => Ok(CliCommand::Info),
        "login" => parse_login_command(&args[1..]),
        "service" => parse_service_subcommand(&args[1..]),
        "run" => parse_run_options(&args[1..]),
        arg if arg.starts_with('-') => {
            // Backwards compatibility: flags passed directly without `run` subcommand
            parse_run_options(&args)
        }
        unknown => Err(ParseError(format!(
            "unknown command '{unknown}'. Use --help for usage."
        ))),
    }
}

fn parse_service_subcommand(args: &[String]) -> Result<CliCommand, ParseError> {
    if args.is_empty() {
        return Err(ParseError(
            "missing service subcommand. Expected 'install', 'uninstall', 'status', 'check', or 'forget'.".into(),
        ));
    }

    if args.iter().any(|a| a == "-h" || a == "--help" || a == "help") {
        return Ok(CliCommand::Help);
    }

    let subcmd = match args[0].as_str() {
        "install" => ServiceSubcommand::Install,
        "uninstall" => ServiceSubcommand::Uninstall,
        "status" => ServiceSubcommand::Status,
        "check" => return Ok(CliCommand::Check),
        "forget" | "delete" => return parse_forget_options(&args[1..]),
        unknown => {
            return Err(ParseError(format!(
                "unknown service subcommand '{unknown}'. Expected 'install', 'uninstall', 'status', 'check', or 'forget'."
            )));
        }
    };

    if args.len() > 1 {
        return Err(ParseError(format!(
            "unexpected argument '{}' for 'service {}'",
            args[1], args[0]
        )));
    }

    Ok(CliCommand::Service(subcmd))
}

fn parse_run_options(args: &[String]) -> Result<CliCommand, ParseError> {
    let mut opts = RunOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--fake" => {
                opts.fake = true;
                i += 1;
            }
            "--socket" => {
                i += 1;
                if i >= args.len() {
                    return Err(ParseError("flag '--socket' requires a path argument".into()));
                }
                opts.socket = Some(PathBuf::from(&args[i]));
                i += 1;
            }
            "-h" | "--help" | "help" => return Ok(CliCommand::Help),
            "-V" | "--version" | "version" => return Ok(CliCommand::Version),
            unknown => {
                return Err(ParseError(format!(
                    "unknown option '{unknown}'. Supported options for run: --fake, --socket <path>"
                )));
            }
        }
    }

    Ok(CliCommand::Run(opts))
}

fn parse_pair_options(args: &[String]) -> Result<CliCommand, ParseError> {
    let mut opts = PairOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--pin" => {
                i += 1;
                if i >= args.len() {
                    return Err(ParseError("flag '--pin' requires a 6-digit PIN argument".into()));
                }
                opts.pin = Some(args[i].clone());
                i += 1;
            }
            "-d" | "--device" => {
                i += 1;
                if i >= args.len() {
                    return Err(ParseError("flag '--device' requires a device address or UUID argument".into()));
                }
                opts.device = Some(args[i].clone());
                i += 1;
            }
            "-h" | "--help" | "help" => return Ok(CliCommand::Help),
            arg if !arg.starts_with('-') => {
                if arg.len() == 6 && arg.chars().all(|c| c.is_ascii_digit()) && opts.pin.is_none() {
                    opts.pin = Some(arg.to_string());
                } else if opts.device.is_none() {
                    opts.device = Some(arg.to_string());
                } else if opts.pin.is_none() {
                    opts.pin = Some(arg.to_string());
                } else {
                    return Err(ParseError(format!(
                        "unexpected extra argument '{arg}' for pair. Usage: cryptick-daemon pair [device] [--pin <PIN>]"
                    )));
                }
                i += 1;
            }
            unknown => {
                return Err(ParseError(format!(
                    "unknown option '{unknown}' for pair. Usage: cryptick-daemon pair [device] [--pin <6-digit-pin>] [--device <UUID/MAC>]"
                )));
            }
        }
    }

    Ok(CliCommand::Pair(opts))
}

fn parse_forget_options(args: &[String]) -> Result<CliCommand, ParseError> {
    let mut opts = ForgetOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--device" => {
                i += 1;
                if i >= args.len() {
                    return Err(ParseError("flag '--device' requires a device address or UUID argument".into()));
                }
                opts.device = Some(args[i].clone());
                i += 1;
            }
            "-h" | "--help" | "help" => return Ok(CliCommand::Help),
            arg if !arg.starts_with('-') && opts.device.is_none() => {
                opts.device = Some(arg.to_string());
                i += 1;
            }
            unknown => {
                return Err(ParseError(format!(
                    "unknown option '{unknown}' for forget. Usage: cryptick-daemon forget [device]"
                )));
            }
        }
    }

    Ok(CliCommand::Forget(opts))
}

fn parse_login_command(args: &[String]) -> Result<CliCommand, ParseError> {
    if args.is_empty() {
        return Ok(CliCommand::Login(LoginCommand::Status(LoginStatusOptions::default())));
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => Ok(CliCommand::Help),
        "status" => parse_login_status_options(&args[1..]),
        "setup" => parse_login_setup_options(&args[1..]),
        unknown => Err(ParseError(format!(
            "unknown login subcommand '{unknown}'. Supported subcommands: setup, status"
        ))),
    }
}

fn parse_login_status_options(args: &[String]) -> Result<CliCommand, ParseError> {
    let mut opts = LoginStatusOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => {
                i += 1;
                if i >= args.len() {
                    return Err(ParseError("flag '--user' requires a username".into()));
                }
                opts.user = Some(args[i].clone());
                i += 1;
            }
            "--json" => {
                opts.json = true;
                i += 1;
            }
            "-h" | "--help" | "help" => return Ok(CliCommand::Help),
            unknown => {
                return Err(ParseError(format!(
                    "unknown option '{unknown}' for 'login status'. Usage: cryptick-daemon login status [--user <user>] [--json]"
                )));
            }
        }
    }
    Ok(CliCommand::Login(LoginCommand::Status(opts)))
}

fn parse_login_setup_options(args: &[String]) -> Result<CliCommand, ParseError> {
    let mut opts = LoginSetupOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--user" => {
                i += 1;
                if i >= args.len() {
                    return Err(ParseError("flag '--user' requires a username".into()));
                }
                opts.user = Some(args[i].clone());
                i += 1;
            }
            "-H" | "--hash" => {
                i += 1;
                if i >= args.len() {
                    return Err(ParseError("flag '--hash' requires an identity hash argument".into()));
                }
                opts.hash = Some(args[i].clone());
                i += 1;
            }
            "-n" | "--dry-run" => {
                opts.dry_run = true;
                i += 1;
            }
            "-l" | "--lock-on-removal" | "--lock" => {
                opts.lock_on_removal = true;
                i += 1;
            }
            "-f" | "--force" => {
                opts.force = true;
                i += 1;
            }
            "-p" | "--pin" => {
                i += 1;
                if i >= args.len() {
                    return Err(ParseError("flag '--pin' requires a PIN argument".into()));
                }
                opts.pin = Some(args[i].clone());
                i += 1;
            }
            "-h" | "--help" | "help" => return Ok(CliCommand::Help),
            unknown => {
                return Err(ParseError(format!(
                    "unknown option '{unknown}' for 'login setup'. Usage: cryptick-daemon login setup [--user <user>] [--hash <hash>] [--dry-run] [--lock-on-removal] [--force]"
                )));
            }
        }
    }
    Ok(CliCommand::Login(LoginCommand::Setup(opts)))
}

/// Formats the top-level help string.
pub fn help_text() -> &'static str {
    "Usage: cryptick-daemon [COMMAND] [OPTIONS]\n\n\
     Commands:\n\
       run                                  Run the daemon (default if omitted)\n\
       devices, scan                        List connected token and visible nearby BLE/USB devices\n\
       pair [--pin <PIN>] [--device <UUID>] Pair with Cryptick Token using the 6-digit OLED passkey\n\
       connect                              Connect to the token and start background service\n\
       disconnect                           Disconnect token and release Bluetooth radio\n\
       forget [device]                      Delete bonds, forget saved device, stop service, and clean sockets\n\
       info                                 Query CTAP2 capabilities and info from token\n\
       login status [--user <user>]         Query computer login status (CryptoTokenKit / PAM / vpcd)\n\
       login setup [--dry-run]              1-click automated setup for computer login with token\n\
       check                                Run health and connectivity check on daemon, service, and BLE token\n\
       service install                      Install and start the background user service\n\
       service uninstall                    Stop and remove the background user service\n\
       service status                       Query status of the background service and IPC socket\n\
       help                                 Print this help message\n\n\
     Options for 'run':\n\
       --fake                               Run against the in-process fake CTAP2 device (no radio required)\n\
       --socket <path>                      Override default IPC socket/named-pipe path\n\
       -h, --help                           Print help\n\
       -V, --version                        Print version\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_run() {
        let cmd = parse_args(Vec::<String>::new()).unwrap();
        assert_eq!(cmd, CliCommand::Run(RunOptions::default()));
    }

    #[test]
    fn test_parse_pair() {
        let cmd = parse_args(["pair"]).unwrap();
        assert_eq!(cmd, CliCommand::Pair(PairOptions::default()));

        let cmd = parse_args(["pair", "--pin", "123456"]).unwrap();
        assert_eq!(
            cmd,
            CliCommand::Pair(PairOptions {
                pin: Some("123456".to_string()),
                device: None,
            })
        );

        let cmd = parse_args(["pair", "-p", "654321"]).unwrap();
        assert_eq!(
            cmd,
            CliCommand::Pair(PairOptions {
                pin: Some("654321".to_string()),
                device: None,
            })
        );

        let cmd = parse_args(["pair", "987654"]).unwrap();
        assert_eq!(
            cmd,
            CliCommand::Pair(PairOptions {
                pin: Some("987654".to_string()),
                device: None,
            })
        );

        let cmd = parse_args(["pair", "--device", "Cryptick-5C6E", "--pin", "123456"]).unwrap();
        assert_eq!(
            cmd,
            CliCommand::Pair(PairOptions {
                pin: Some("123456".to_string()),
                device: Some("Cryptick-5C6E".to_string()),
            })
        );
    }

    #[test]
    fn test_parse_devices_and_lifecycle() {
        assert_eq!(parse_args(["devices"]).unwrap(), CliCommand::Devices);
        assert_eq!(parse_args(["scan"]).unwrap(), CliCommand::Devices);
        assert_eq!(parse_args(["connect"]).unwrap(), CliCommand::Connect);
        assert_eq!(parse_args(["disconnect"]).unwrap(), CliCommand::Disconnect);
        assert_eq!(parse_args(["forget"]).unwrap(), CliCommand::Forget(ForgetOptions::default()));
        assert_eq!(
            parse_args(["forget", "Cryptick-5C6E"]).unwrap(),
            CliCommand::Forget(ForgetOptions {
                device: Some("Cryptick-5C6E".to_string()),
            })
        );
        assert_eq!(parse_args(["info"]).unwrap(), CliCommand::Info);
        assert_eq!(parse_args(["check"]).unwrap(), CliCommand::Check);
    }

    #[test]
    fn test_parse_service() {
        assert_eq!(
            parse_args(["service", "install"]).unwrap(),
            CliCommand::Service(ServiceSubcommand::Install)
        );
        assert_eq!(
            parse_args(["service", "uninstall"]).unwrap(),
            CliCommand::Service(ServiceSubcommand::Uninstall)
        );
        assert_eq!(
            parse_args(["service", "status"]).unwrap(),
            CliCommand::Service(ServiceSubcommand::Status)
        );
    }

    #[test]
    fn test_parse_login() {
        // Default login is status
        assert_eq!(
            parse_args(["login"]).unwrap(),
            CliCommand::Login(LoginCommand::Status(LoginStatusOptions::default()))
        );

        // login status
        assert_eq!(
            parse_args(["login", "status"]).unwrap(),
            CliCommand::Login(LoginCommand::Status(LoginStatusOptions::default()))
        );

        assert_eq!(
            parse_args(["login", "status", "--user", "aurelius", "--json"]).unwrap(),
            CliCommand::Login(LoginCommand::Status(LoginStatusOptions {
                user: Some("aurelius".to_string()),
                json: true,
            }))
        );

        // login setup
        assert_eq!(
            parse_args(["login", "setup"]).unwrap(),
            CliCommand::Login(LoginCommand::Setup(LoginSetupOptions::default()))
        );

        assert_eq!(
            parse_args([
                "login",
                "setup",
                "--user",
                "alice",
                "--hash",
                "3B564922614AFE0917FB12449A9E62EE36863CC9",
                "--dry-run",
                "--lock-on-removal",
                "--force"
            ])
            .unwrap(),
            CliCommand::Login(LoginCommand::Setup(LoginSetupOptions {
                user: Some("alice".to_string()),
                hash: Some("3B564922614AFE0917FB12449A9E62EE36863CC9".to_string()),
                dry_run: true,
                lock_on_removal: true,
                force: true,
                pin: None,
            }))
        );
    }
}

