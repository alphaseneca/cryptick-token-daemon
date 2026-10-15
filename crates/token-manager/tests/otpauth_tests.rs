//! Comprehensive tests for RFC 4648 Base32 and RFC 6238 / RFC 4226 URI parsing.

use cryptick_manager::otpauth::{
    decode_base32, encode_base32, url_decode, HashAlgorithm, OathType, OtpAuthUri,
};

#[test]
fn test_rfc4648_base32_vectors() {
    // Standard RFC 4648 test vectors
    let vectors: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "MY"),
        (b"fo", "MZXQ"),
        (b"foo", "MZXW6"),
        (b"foob", "MZXW6YQ"),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI"),
    ];

    for &(plain, encoded) in vectors {
        if !plain.is_empty() {
            let enc = encode_base32(plain);
            assert_eq!(enc, encoded, "encoding failure for {:?}", plain);
        }
        if !encoded.is_empty() {
            let dec = decode_base32(encoded).expect("decode valid");
            assert_eq!(dec, plain, "decoding failure for {encoded}");

            // Padded variation
            let mut padded = encoded.to_string();
            while padded.len() % 8 != 0 {
                padded.push('=');
            }
            let dec_padded = decode_base32(&padded).expect("decode padded");
            assert_eq!(dec_padded, plain, "decoding padded failure for {padded}");
        }
    }
}

#[test]
fn test_base32_permissive_decoding() {
    // Lowercase and interspersed spaces/hyphens
    let input = "  jbswy 3dpe-hpk3 pxp ==";
    let decoded = decode_base32(input).expect("permissive decode");
    assert_eq!(decoded, b"Hello!\xde\xad\xbe\xef");

    // Invalid characters
    assert!(decode_base32("JBSWY8").is_err(), "'8' is not base32");
    assert!(decode_base32("JBSWY9").is_err(), "'9' is not base32");
    assert!(decode_base32("JBSWY1").is_err(), "'1' is not base32");
    assert!(decode_base32("").is_err(), "empty input");
}

#[test]
fn test_url_decoding() {
    assert_eq!(url_decode("hello%20world"), "hello world");
    assert_eq!(url_decode("GitHub%3Aalice%40example.com"), "GitHub:alice@example.com");
    assert_eq!(url_decode("no_escapes_here"), "no_escapes_here");
    assert_eq!(url_decode("%2Fpath%2F%2B%3D"), "/path/+=");
}

#[test]
fn test_parse_standard_totp_uri() {
    let uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
    let parsed = OtpAuthUri::parse(uri).expect("parse valid TOTP URI");

    assert_eq!(parsed.oath_type, OathType::Totp);
    assert_eq!(parsed.account, "alice@example.com");
    assert_eq!(parsed.issuer, Some("GitHub".to_string()));
    assert_eq!(parsed.canonical_name(), "GitHub:alice@example.com");
    assert_eq!(parsed.secret, decode_base32("JBSWY3DPEHPK3PXP").unwrap());
    assert_eq!(parsed.algorithm, HashAlgorithm::Sha1);
    assert_eq!(parsed.digits, 6);
    assert_eq!(parsed.period, 30);
    assert_eq!(parsed.counter, 0);
}

#[test]
fn test_parse_hotp_with_custom_parameters() {
    let uri = "otpauth://hotp/Bank%20Corp:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=105&digits=8&algorithm=SHA256&issuer=Bank%20Corp";
    let parsed = OtpAuthUri::parse(uri).expect("parse valid HOTP URI");

    assert_eq!(parsed.oath_type, OathType::Hotp);
    assert_eq!(parsed.account, "bob");
    assert_eq!(parsed.issuer, Some("Bank Corp".to_string()));
    assert_eq!(parsed.canonical_name(), "Bank Corp:bob");
    assert_eq!(parsed.algorithm, HashAlgorithm::Sha256);
    assert_eq!(parsed.digits, 8);
    assert_eq!(parsed.counter, 105);
}

#[test]
fn test_parse_uri_with_custom_period_and_sha512() {
    let uri = "otpauth://totp/ServerAdmin?secret=MZXW6YTBOI&algorithm=SHA512&period=60";
    let parsed = OtpAuthUri::parse(uri).expect("parse SHA512 60s");

    assert_eq!(parsed.oath_type, OathType::Totp);
    assert_eq!(parsed.canonical_name(), "ServerAdmin");
    assert_eq!(parsed.algorithm, HashAlgorithm::Sha512);
    assert_eq!(parsed.period, 60);
    assert_eq!(parsed.digits, 6);
}

#[test]
fn test_parse_invalid_uris() {
    // Bad scheme
    assert!(OtpAuthUri::parse("https://example.com").is_err());
    // Missing secret
    assert!(OtpAuthUri::parse("otpauth://totp/Test?issuer=Test").is_err());
    // Unsupported type
    assert!(OtpAuthUri::parse("otpauth://steam/Test?secret=JBSWY3DPEHPK3PXP").is_err());
    // Unsupported digits
    assert!(OtpAuthUri::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=7").is_err());
    // Zero period
    assert!(OtpAuthUri::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0").is_err());
}
