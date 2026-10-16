//! Tests for CLI service controller, unit generators, service status, and socket precedence.

use daemon::{
    cli::{parse_args, CliCommand, RunOptions, ServiceSubcommand},
    service::{
        current_service_manager,
        generator::{
            generate_launchd_plist, generate_systemd_unit, generate_windows_task_xml, xml_escape,
        },
        ServiceStatus,
    },
};
use std::path::{Path, PathBuf};

#[test]
fn test_generate_systemd_unit_default_args() {
    let exec = Path::new("/usr/local/bin/cryptick-daemon");
    let unit = generate_systemd_unit(exec, &[]);

    assert!(unit.contains("[Unit]"));
    assert!(unit.contains("Description=Cryptick Token Host Daemon"));
    assert!(unit.contains("Documentation=https://github.com/alphaseneca/cryptick-token-daemon"));
    assert!(unit.contains("ExecStart=\"/usr/local/bin/cryptick-daemon\" run"));
    assert!(unit.contains("Restart=on-failure"));
    assert!(unit.contains("RestartSec=3"));
    assert!(unit.contains("WantedBy=default.target"));
}

#[test]
fn test_generate_systemd_unit_custom_args() {
    let exec = Path::new("/opt/cryptick/cryptick-daemon");
    let unit = generate_systemd_unit(exec, &["run", "--socket", "/run/user/1000/daemon.sock"]);

    assert!(unit.contains(
        "ExecStart=\"/opt/cryptick/cryptick-daemon\" run --socket /run/user/1000/daemon.sock"
    ));
}

#[test]
fn test_generate_systemd_unit_path_with_spaces() {
    let exec = Path::new("/home/user name/.local/bin/cryptick-daemon");
    let unit = generate_systemd_unit(exec, &[]);
    assert!(unit.contains("ExecStart=\"/home/user name/.local/bin/cryptick-daemon\" run"));
}

#[test]
#[should_panic(expected = "executable path must not contain newline characters")]
fn test_generate_systemd_unit_rejects_newline_in_path() {
    let exec = Path::new("/bin/daemon\nExecStartPre=/bin/evil");
    generate_systemd_unit(exec, &[]);
}

#[test]
#[should_panic(expected = "arguments must not contain newline characters")]
fn test_generate_systemd_unit_rejects_newline_in_args() {
    let exec = Path::new("/bin/daemon");
    generate_systemd_unit(exec, &["run\nExecStartPre=/bin/evil"]);
}

#[test]
fn test_generate_launchd_plist_structure() {
    let exec = Path::new("/Applications/Cryptick.app/Contents/MacOS/cryptick-daemon");
    let label = "com.cryptick.daemon";
    let log_dir = Path::new("/Users/tester/Library/Logs");
    let plist = generate_launchd_plist(exec, label, log_dir, &[]);

    assert!(plist.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(plist.contains("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""));
    assert!(plist.contains("<key>Label</key>\n    <string>com.cryptick.daemon</string>"));
    assert!(plist.contains(&format!("<string>{}</string>", exec.display())));
    assert!(plist.contains("<string>run</string>"));
    assert!(plist.contains("<key>RunAtLoad</key>\n    <true/>"));
    assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
    assert!(plist.contains(&format!(
        "<string>{}</string>",
        log_dir.join("cryptick-daemon.log").display()
    )));
    assert!(plist.contains(&format!(
        "<string>{}</string>",
        log_dir.join("cryptick-daemon.err.log").display()
    )));
}

#[test]
fn test_generate_launchd_plist_extra_args() {
    let exec = Path::new("/usr/local/bin/cryptick-daemon");
    let label = "com.cryptick.daemon";
    let log_dir = Path::new("/var/log");
    let plist = generate_launchd_plist(exec, label, log_dir, &["run", "--fake"]);

    assert!(plist.contains(&format!("<string>{}</string>", exec.display())));
    assert!(plist.contains("<string>run</string>"));
    assert!(plist.contains("<string>--fake</string>"));
}

#[test]
fn test_generate_windows_task_xml_structure() {
    let exec = Path::new(r"C:\Program Files\Cryptick\cryptick-daemon.exe");
    let task_name = "CryptickDaemon";
    let xml = generate_windows_task_xml(exec, task_name, &["run"]);

    assert!(xml.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
    assert!(xml.contains(
        r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"#
    ));
    assert!(xml.contains(r"<URI>\CryptickDaemon</URI>"));
    assert!(xml.contains("<LogonTrigger>"));
    assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
    assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
    assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
    assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
    assert!(xml.contains(r"<Command>C:\Program Files\Cryptick\cryptick-daemon.exe</Command>"));
    assert!(xml.contains("<Arguments>run</Arguments>"));
}

#[test]
fn test_xml_escaping() {
    assert_eq!(
        xml_escape("foo&bar<baz>\"qux'"),
        "foo&amp;bar&lt;baz&gt;&quot;qux&apos;"
    );
}

#[test]
fn test_cli_parsing() {
    // Default / no args
    assert_eq!(
        parse_args([] as [&str; 0]).unwrap(),
        CliCommand::Run(RunOptions {
            fake: false,
            socket: None
        })
    );

    // Subcommands
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

    // Run options
    assert_eq!(
        parse_args(["run", "--fake"]).unwrap(),
        CliCommand::Run(RunOptions {
            fake: true,
            socket: None
        })
    );
    assert_eq!(
        parse_args(["run", "--socket", "/tmp/custom.sock"]).unwrap(),
        CliCommand::Run(RunOptions {
            fake: false,
            socket: Some(PathBuf::from("/tmp/custom.sock"))
        })
    );
    assert_eq!(
        parse_args(["run", "--fake", "--socket", "/tmp/custom.sock"]).unwrap(),
        CliCommand::Run(RunOptions {
            fake: true,
            socket: Some(PathBuf::from("/tmp/custom.sock"))
        })
    );

    // Bare flags (backward compatibility)
    assert_eq!(
        parse_args(["--socket", "/tmp/custom.sock"]).unwrap(),
        CliCommand::Run(RunOptions {
            fake: false,
            socket: Some(PathBuf::from("/tmp/custom.sock"))
        })
    );
    assert_eq!(
        parse_args(["--fake"]).unwrap(),
        CliCommand::Run(RunOptions {
            fake: true,
            socket: None
        })
    );

    // Help & Version
    assert_eq!(parse_args(["--help"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["-h"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["help"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["run", "--help"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["run", "-h"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["run", "help"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["--fake", "--help"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["--fake", "-h"]).unwrap(), CliCommand::Help);
    assert_eq!(
        parse_args(["run", "--socket", "/tmp/custom.sock", "--help"]).unwrap(),
        CliCommand::Help
    );
    assert_eq!(
        parse_args(["service", "install", "--help"]).unwrap(),
        CliCommand::Help
    );
    assert_eq!(
        parse_args(["service", "install", "-h"]).unwrap(),
        CliCommand::Help
    );
    assert_eq!(
        parse_args(["service", "uninstall", "--help"]).unwrap(),
        CliCommand::Help
    );
    assert_eq!(
        parse_args(["service", "status", "--help"]).unwrap(),
        CliCommand::Help
    );
    assert_eq!(parse_args(["service", "--help"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["service", "-h"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["--version"]).unwrap(), CliCommand::Version);
    assert_eq!(parse_args(["-V"]).unwrap(), CliCommand::Version);
    assert_eq!(parse_args(["version"]).unwrap(), CliCommand::Version);
    assert_eq!(
        parse_args(["run", "--version"]).unwrap(),
        CliCommand::Version
    );
    assert_eq!(parse_args(["run", "-V"]).unwrap(), CliCommand::Version);

    // Errors
    assert!(parse_args(["service", "unknown"]).is_err());
    assert!(parse_args(["service"]).is_err());
    assert!(parse_args(["service", "install", "--dry-run"]).is_err());
    assert!(parse_args(["service", "install", "extra"]).is_err());
    assert!(parse_args(["service", "status", "--invalid"]).is_err());
    assert!(parse_args(["unknown_cmd"]).is_err());
    assert!(parse_args(["run", "--socket"]).is_err());
    assert!(parse_args(["run", "--unknown-flag"]).is_err());
}

#[test]
fn test_service_status_query_runs_without_panic() {
    let manager = current_service_manager();
    let status = manager
        .status()
        .expect("status query should not error or panic");
    assert!(!status.platform.is_empty());
    assert!(!status.endpoint.is_empty());

    let summary = status.display_summary();
    assert!(summary.contains("Platform:"));
    assert!(summary.contains("Service Unit:"));
    assert!(summary.contains("IPC Endpoint:"));
    assert!(summary.contains("Overall:"));
}

#[test]
fn test_service_status_mock_states() {
    let healthy = ServiceStatus {
        platform: "TestPlatform".to_string(),
        unit_path: PathBuf::from("/test/unit"),
        unit_exists: true,
        service_running: true,
        service_details: Some("active".to_string()),
        endpoint: "/test/sock".to_string(),
        endpoint_connectable: true,
    };
    assert!(healthy.is_healthy());
    assert!(healthy.display_summary().contains("Overall: ACTIVE"));

    let stopped = ServiceStatus {
        unit_exists: true,
        service_running: false,
        endpoint_connectable: false,
        ..healthy.clone()
    };
    assert!(!stopped.is_healthy());
    assert!(stopped.display_summary().contains("Overall: STOPPED"));

    let not_installed = ServiceStatus {
        unit_exists: false,
        service_running: false,
        endpoint_connectable: false,
        ..healthy.clone()
    };
    assert!(!not_installed.is_healthy());
    assert!(not_installed
        .display_summary()
        .contains("Overall: NOT_INSTALLED"));

    let degraded = ServiceStatus {
        unit_exists: true,
        service_running: true,
        endpoint_connectable: false,
        ..healthy
    };
    assert!(!degraded.is_healthy());
    assert!(degraded.display_summary().contains("Overall: DEGRADED"));
}

#[test]
fn test_socket_path_precedence() {
    use std::ffi::OsStr;

    // macOS precedence: macOS MUST ignore XDG_RUNTIME_DIR even when set
    let macos_path = ipc::socket_path_from_env(
        true,
        Some(OsStr::new("/tmp/xdg_runtime")),
        Some(OsStr::new("/Users/alice")),
    );
    assert_eq!(
        macos_path,
        Some(PathBuf::from(
            "/Users/alice/Library/Application Support/cryptick/daemon.sock"
        ))
    );

    // Linux with XDG_RUNTIME_DIR
    let linux_xdg = ipc::socket_path_from_env(
        false,
        Some(OsStr::new("/run/user/1000")),
        Some(OsStr::new("/home/bob")),
    );
    assert_eq!(
        linux_xdg,
        Some(PathBuf::from("/run/user/1000/cryptick/daemon.sock"))
    );

    // Linux without XDG_RUNTIME_DIR
    let linux_fallback = ipc::socket_path_from_env(false, None, Some(OsStr::new("/home/bob")));
    assert_eq!(
        linux_fallback,
        Some(PathBuf::from("/home/bob/.cryptick/daemon.sock"))
    );

    // Missing home and xdg
    assert_eq!(ipc::socket_path_from_env(false, None, None), None);
    assert_eq!(ipc::socket_path_from_env(true, None, None), None);
}
