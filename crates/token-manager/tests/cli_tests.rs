//! Test suite covering CLI argument parsing, script tokenizer, and mode validation.

use cryptick_manager::cli::apdu_cli::resolve_aid;
use cryptick_manager::cli::dispatch;
use cryptick_manager::config::DeviceMode;
use cryptick_manager::script::{substitute_args, tokenize_line};

#[test]
fn test_help_and_version_flags() {
    // --help and -h must exit Ok without requiring a token connection
    assert!(dispatch(&["--help".to_string()]).is_ok());
    assert!(dispatch(&["-h".to_string()]).is_ok());
    assert!(dispatch(&["--version".to_string()]).is_ok());
    assert!(dispatch(&["-v".to_string()]).is_ok());

    // list without a token connected must succeed cleanly (reporting no tokens found)
    assert!(dispatch(&["list".to_string()]).is_ok());
    assert!(dispatch(&["list".to_string(), "-s".to_string()]).is_ok());
}

#[test]
fn test_script_tokenizer() {
    let line1 = "oath accounts add \"GitHub:alice\" JBSWY3DPEHPK3PXP --touch";
    let tokens1 = tokenize_line(line1).expect("tokenize quoted line");
    assert_eq!(
        tokens1,
        vec![
            "oath",
            "accounts",
            "add",
            "GitHub:alice",
            "JBSWY3DPEHPK3PXP",
            "--touch"
        ]
    );

    let line2 = "apdu '00 A4 04 00 07 A0 00 00 05 27 21 01' -v";
    let tokens2 = tokenize_line(line2).expect("tokenize single quoted line");
    assert_eq!(
        tokens2,
        vec!["apdu", "00 A4 04 00 07 A0 00 00 05 27 21 01", "-v"]
    );

    let line3 = "config mode FIDO+OATH+PIV -f";
    let tokens3 = tokenize_line(line3).expect("tokenize unquoted line");
    assert_eq!(tokens3, vec!["config", "mode", "FIDO+OATH+PIV", "-f"]);

    // Unmatched quote must error
    assert!(tokenize_line("oath accounts add \"broken").is_err());
    assert!(tokenize_line("oath accounts add 'broken").is_err());
}

#[test]
fn test_script_argument_substitution() {
    let template = "oath accounts add $1 $2 --touch";
    let args = vec!["AWS:admin".to_string(), "MZXW6YTB".to_string()];
    let res = substitute_args(template, &args);
    assert_eq!(res, "oath accounts add AWS:admin MZXW6YTB --touch");

    let template2 = "oath accounts code -s $1";
    let args2 = vec!["GitHub".to_string()];
    let res2 = substitute_args(template2, &args2);
    assert_eq!(res2, "oath accounts code -s GitHub");
}

#[test]
fn test_device_mode_parsing() {
    assert_eq!(DeviceMode::parse("FIDO").unwrap(), DeviceMode::Fido);
    assert_eq!(DeviceMode::parse("fido2").unwrap(), DeviceMode::Fido);
    assert_eq!(DeviceMode::parse("CCID").unwrap(), DeviceMode::Ccid);
    assert_eq!(DeviceMode::parse("piv").unwrap(), DeviceMode::Ccid);
    assert_eq!(DeviceMode::parse("OTP").unwrap(), DeviceMode::Otp);
    assert_eq!(DeviceMode::parse("FIDO+CCID").unwrap(), DeviceMode::FidoCcid);
    assert_eq!(DeviceMode::parse("ALL").unwrap(), DeviceMode::All);
    assert_eq!(
        DeviceMode::parse("FIDO+OATH+PIV").unwrap(),
        DeviceMode::All
    );

    assert!(DeviceMode::parse("NON_EXISTENT_MODE").is_err());
}

#[test]
fn test_aid_resolution() {
    let oath_aid = resolve_aid("oath").expect("resolve oath");
    assert_eq!(
        oath_aid,
        vec![0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
    );

    let piv_aid = resolve_aid("piv").expect("resolve piv");
    assert_eq!(
        piv_aid,
        vec![0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]
    );

    let fido_aid = resolve_aid("fido").expect("resolve fido");
    assert_eq!(fido_aid, vec![0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);

    let custom = resolve_aid("0011223344").expect("resolve hex");
    assert_eq!(custom, vec![0x00, 0x11, 0x22, 0x33, 0x44]);
}
