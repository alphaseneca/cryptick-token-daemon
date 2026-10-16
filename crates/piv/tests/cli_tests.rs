//! Tests for `cryptick-piv` CLI argument parsing and dry-run execution.

use piv::cli::{help_text, parse_args, parse_slot, run_provision, CliCommand};
use piv::objects::Slot;

#[test]
fn default_invocation_provisions_slot_9a_in_dry_run() {
    let cmd = parse_args::<[&str; 0], &str>([]).unwrap();
    match cmd {
        CliCommand::Provision(opts) => {
            assert_eq!(opts.slots, vec![Slot::PivAuthentication]);
            assert!(opts.dry_run);
        }
        other => panic!("expected Provision, got {other:?}"),
    }
}

#[test]
fn help_and_version_flags() {
    assert_eq!(parse_args(["help"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["--help"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["-h"]).unwrap(), CliCommand::Help);

    assert_eq!(parse_args(["version"]).unwrap(), CliCommand::Version);
    assert_eq!(parse_args(["--version"]).unwrap(), CliCommand::Version);
    assert_eq!(parse_args(["-V"]).unwrap(), CliCommand::Version);

    assert!(help_text().contains("cryptick-piv"));
    assert!(help_text().contains("--slot"));
}

#[test]
fn provision_slot_flags() {
    // 9A
    let cmd = parse_args(["provision", "--slot", "9A"]).unwrap();
    if let CliCommand::Provision(opts) = cmd {
        assert_eq!(opts.slots, vec![Slot::PivAuthentication]);
    } else {
        panic!("expected Provision");
    }

    // 9D
    let cmd = parse_args(["provision", "--slot", "9d"]).unwrap();
    if let CliCommand::Provision(opts) = cmd {
        assert_eq!(opts.slots, vec![Slot::KeyManagement]);
    } else {
        panic!("expected Provision");
    }

    // Bare slot arg
    let cmd = parse_args(["provision", "9D"]).unwrap();
    if let CliCommand::Provision(opts) = cmd {
        assert_eq!(opts.slots, vec![Slot::KeyManagement]);
    } else {
        panic!("expected Provision");
    }

    // 9C
    let cmd = parse_args(["provision", "--slot", "9C"]).unwrap();
    if let CliCommand::Provision(opts) = cmd {
        assert_eq!(opts.slots, vec![Slot::DigitalSignature]);
    } else {
        panic!("expected Provision");
    }

    // 9E
    let cmd = parse_args(["provision", "--slot", "9E"]).unwrap();
    if let CliCommand::Provision(opts) = cmd {
        assert_eq!(opts.slots, vec![Slot::CardAuthentication]);
    } else {
        panic!("expected Provision");
    }

    // Comma-separated slots
    let cmd = parse_args(["provision", "--slot", "9A,9C,9D,9E"]).unwrap();
    if let CliCommand::Provision(opts) = cmd {
        assert_eq!(opts.slots, Slot::ALL.to_vec());
    } else {
        panic!("expected Provision");
    }

    // --all
    let cmd = parse_args(["--all"]).unwrap();
    if let CliCommand::Provision(opts) = cmd {
        assert_eq!(
            opts.slots,
            vec![Slot::PivAuthentication, Slot::KeyManagement]
        );
    } else {
        panic!("expected Provision");
    }

    // --all-slots
    let cmd = parse_args(["--all-slots"]).unwrap();
    if let CliCommand::Provision(opts) = cmd {
        assert_eq!(opts.slots, Slot::ALL.to_vec());
    } else {
        panic!("expected Provision");
    }
}

#[test]
fn provision_full_options() {
    let cmd = parse_args([
        "provision",
        "--all",
        "--dry-run",
        "--pin",
        "888888",
        "--cn",
        "Custom Subject CN",
        "--print-apdus",
    ])
    .unwrap();

    if let CliCommand::Provision(opts) = cmd {
        assert_eq!(
            opts.slots,
            vec![Slot::PivAuthentication, Slot::KeyManagement]
        );
        assert!(opts.dry_run);
        assert_eq!(opts.pin, Some("888888".to_string()));
        assert_eq!(opts.common_name, Some("Custom Subject CN".to_string()));
        assert!(opts.print_apdus);
    } else {
        panic!("expected Provision");
    }
}

#[test]
fn invalid_slot_or_flag_returns_error() {
    assert!(parse_args(["--slot", "INVALID"]).is_err());
    assert!(parse_args(["--unknown-flag"]).is_err());
    assert!(parse_args(["--slot"]).is_err()); // missing arg
    assert!(parse_args(["--pin"]).is_err()); // missing arg
}

#[test]
fn parse_slot_names() {
    assert_eq!(parse_slot("9A").unwrap(), Slot::PivAuthentication);
    assert_eq!(
        parse_slot("authentication").unwrap(),
        Slot::PivAuthentication
    );
    assert_eq!(parse_slot("9D").unwrap(), Slot::KeyManagement);
    assert_eq!(parse_slot("key_management").unwrap(), Slot::KeyManagement);
    assert_eq!(parse_slot("9C").unwrap(), Slot::DigitalSignature);
    assert_eq!(parse_slot("9E").unwrap(), Slot::CardAuthentication);
}

#[test]
fn run_provision_dry_run_executes_successfully() {
    let cmd = parse_args(["--all", "--dry-run", "--print-apdus"]).unwrap();
    if let CliCommand::Provision(opts) = cmd {
        assert!(run_provision(opts).is_ok());
    } else {
        panic!("expected Provision");
    }
}

#[test]
fn reject_empty_common_name_flag() {
    assert!(parse_args(["--cn", ""]).is_err());
    assert!(parse_args(["--cn", "   "]).is_err());
    assert!(parse_args(["--common-name", ""]).is_err());
    assert!(parse_args(["provision", "--cn", ""]).is_err());
}
