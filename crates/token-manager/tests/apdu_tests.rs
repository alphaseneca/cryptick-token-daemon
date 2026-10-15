//! Comprehensive test suite for ISO 7816 APDU parsing, status words, and AID routing.

use cryptick_manager::apdu::{aid, format_hex, parse_hex, CommandApdu, ResponseApdu, StatusWord};

#[test]
fn test_status_words_and_descriptions() {
    let success = StatusWord::SUCCESS;
    assert_eq!(success.value(), 0x9000);
    assert!(success.is_success());
    assert_eq!(success.sw1(), 0x90);
    assert_eq!(success.sw2(), 0x00);
    assert_eq!(success.description(), "Success (OK)");

    let uv_needed = StatusWord::SECURITY_STATUS_NOT_SATISFIED;
    assert_eq!(uv_needed.value(), 0x6982);
    assert!(!uv_needed.is_success());
    assert!(uv_needed.description().contains("Security status"));

    let touch_timeout = StatusWord::CONDITIONS_NOT_SATISFIED;
    assert_eq!(touch_timeout.value(), 0x6985);
    assert!(!touch_timeout.is_success());
    assert!(touch_timeout.description().contains("Conditions of use"));

    let bad_param = StatusWord::INCORRECT_PARAMETERS;
    assert_eq!(bad_param.value(), 0x6A80);
    assert_eq!(bad_param.description(), "Incorrect parameters (malformed TLV or bad payload)");

    let not_found = StatusWord::NOT_FOUND;
    assert_eq!(not_found.value(), 0x6A82);

    let mem_full = StatusWord::MEMORY_FULL;
    assert_eq!(mem_full.value(), 0x6A84);

    let ref_not_found = StatusWord::REFERENCED_DATA_NOT_FOUND;
    assert_eq!(ref_not_found.value(), 0x6A88);

    let wrong_len = StatusWord::WRONG_LENGTH;
    assert_eq!(wrong_len.value(), 0x6700);

    let ins_unsupported = StatusWord::INS_NOT_SUPPORTED;
    assert_eq!(ins_unsupported.value(), 0x6D00);

    let cla_unsupported = StatusWord::CLA_NOT_SUPPORTED;
    assert_eq!(cla_unsupported.value(), 0x6E00);

    let hw_err = StatusWord::INTERNAL_ERROR;
    assert_eq!(hw_err.value(), 0x6F00);

    // 0x61XX get response
    let more_data = StatusWord(0x6124);
    assert!(more_data.is_success());
    assert_eq!(more_data.has_more_data(), Some(0x24));
}

#[test]
fn test_command_apdu_case1_and_case2() {
    // Case 1: 4 bytes header only
    let apdu1 = CommandApdu::new(0x00, 0x04, 0x00, 0x00);
    let bytes1 = apdu1.to_bytes();
    assert_eq!(bytes1, vec![0x00, 0x04, 0x00, 0x00]);

    let parsed1 = CommandApdu::parse(&bytes1).expect("parse case 1");
    assert_eq!(parsed1.cla, 0x00);
    assert_eq!(parsed1.ins, 0x04);
    assert!(parsed1.data.is_empty());
    assert_eq!(parsed1.le, None);

    // Case 2: 4 bytes header + Le
    let apdu2 = CommandApdu::new(0x00, 0xC0, 0x00, 0x00).with_le(32);
    let bytes2 = apdu2.to_bytes();
    assert_eq!(bytes2, vec![0x00, 0xC0, 0x00, 0x00, 32]);

    let parsed2 = CommandApdu::parse(&bytes2).expect("parse case 2");
    assert_eq!(parsed2.le, Some(32));
    assert!(parsed2.data.is_empty());
}

#[test]
fn test_command_apdu_case3_and_case4() {
    // Case 3: Header + Lc + Data
    let data = vec![0x71, 0x04, 0x54, 0x65, 0x73, 0x74];
    let apdu3 = CommandApdu::with_data(0x00, 0x01, 0x00, 0x00, data.clone());
    let bytes3 = apdu3.to_bytes();
    assert_eq!(bytes3[0..4], [0x00, 0x01, 0x00, 0x00]);
    assert_eq!(bytes3[4], 6); // Lc = 6
    assert_eq!(&bytes3[5..], &data[..]);

    let parsed3 = CommandApdu::parse(&bytes3).expect("parse case 3");
    assert_eq!(parsed3.data, data);
    assert_eq!(parsed3.le, None);

    // Case 4: Header + Lc + Data + Le
    let apdu4 = CommandApdu::with_data(0x00, 0xA2, 0x00, 0x00, data.clone()).with_le(256);
    let bytes4 = apdu4.to_bytes();
    let parsed4 = CommandApdu::parse(&bytes4).expect("parse case 4");
    assert_eq!(parsed4.data, data);
}

#[test]
fn test_select_applet_aids() {
    let oath_select = CommandApdu::select_applet(aid::OATH);
    assert_eq!(
        oath_select.to_bytes(),
        vec![0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
    );

    let piv_select = CommandApdu::select_applet(aid::PIV);
    assert_eq!(piv_select.to_bytes()[0..5], [0x00, 0xA4, 0x04, 0x00, 0x0B]);

    let mgmt_select = CommandApdu::select_applet(aid::MANAGEMENT);
    assert_eq!(mgmt_select.to_bytes()[0..5], [0x00, 0xA4, 0x04, 0x00, 0x08]);
}

#[test]
fn test_response_apdu_parsing() {
    // Standard 90 00
    let resp1 = ResponseApdu::parse(&[0x90, 0x00]).expect("parse empty success");
    assert!(resp1.is_success());
    assert!(resp1.data.is_empty());
    assert_eq!(resp1.sw, StatusWord::SUCCESS);

    // Payload + 90 00
    let raw = vec![0x75, 0x04, 0x00, 0x0C, 0xDB, 0xE7, 0x90, 0x00];
    let resp2 = ResponseApdu::parse(&raw).expect("parse response with payload");
    assert!(resp2.is_success());
    assert_eq!(resp2.data, vec![0x75, 0x04, 0x00, 0x0C, 0xDB, 0xE7]);
    assert_eq!(resp2.sw, StatusWord::SUCCESS);

    // Error status word
    let err_raw = vec![0x6A, 0x88];
    let resp3 = ResponseApdu::parse(&err_raw).expect("parse error response");
    assert!(!resp3.is_success());
    assert_eq!(resp3.sw, StatusWord::REFERENCED_DATA_NOT_FOUND);
    assert!(resp3.check_success().is_err());

    // Truncated (less than 2 bytes)
    assert!(ResponseApdu::parse(&[0x90]).is_err());
    assert!(ResponseApdu::parse(&[]).is_err());
}

#[test]
fn test_hex_conversion_helpers() {
    let original = vec![0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00];
    let formatted = format_hex(&original);
    assert_eq!(formatted, "00 A4 04 00 07 A0 00");

    let parsed = parse_hex("00 A4 04 00 07 A0 00").expect("parse space-separated");
    assert_eq!(parsed, original);

    let parsed2 = parse_hex("00a4040007a000").expect("parse lowercase continuous");
    assert_eq!(parsed2, original);

    let parsed3 = parse_hex("0x00:A4:04:00:07:A0:00").expect("parse prefixed colons");
    assert_eq!(parsed3, original);

    assert!(parse_hex("ABC").is_err(), "odd length must fail");
    assert!(parse_hex("ZZ").is_err(), "invalid hex digit must fail");
}
