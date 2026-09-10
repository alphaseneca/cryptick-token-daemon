//! COSE public keys, narrowed to the two algorithms SSH uses.

use crate::cbor::{CborError, Value};
use thiserror::Error;

/// COSE `alg` for ECDSA over P-256 with SHA-256.
pub const ALG_ES256: i64 = -7;
/// COSE `alg` for EdDSA.
pub const ALG_EDDSA: i64 = -8;

const KEY_KTY: u64 = 1;
const KEY_ALG: u64 = 3;
// Negative COSE labels: -1 is crv, -2 is x, -3 is y.
const LABEL_CRV: i64 = -1;
const LABEL_X: i64 = -2;
const LABEL_Y: i64 = -3;

const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

/// A credential public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseKey {
    /// ECDSA over P-256, as affine coordinates.
    Es256 {
        /// The x coordinate.
        x: [u8; 32],
        /// The y coordinate.
        y: [u8; 32],
    },
    /// Ed25519.
    Ed25519 {
        /// The public key.
        x: [u8; 32],
    },
}

/// A COSE key would not parse, or is not one we can use.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoseError {
    /// The key was not valid CBOR.
    #[error("COSE key is not valid CBOR: {0}")]
    Cbor(#[from] CborError),
    /// A required label was absent.
    #[error("COSE key is missing label {label}")]
    MissingLabel {
        /// The label.
        label: i64,
    },
    /// A field had the wrong CBOR type.
    #[error("COSE label {label} has the wrong type")]
    WrongType {
        /// The label.
        label: i64,
    },
    /// A key type, curve or algorithm combination we do not implement.
    #[error("unsupported COSE key: kty {kty}, alg {alg}, crv {crv}")]
    Unsupported {
        /// The key type.
        kty: i64,
        /// The algorithm.
        alg: i64,
        /// The curve.
        crv: i64,
    },
    /// A coordinate that was not 32 bytes.
    #[error("COSE coordinate for label {label} is {len} bytes, expected 32")]
    BadCoordinate {
        /// The label.
        label: i64,
        /// The length found.
        len: usize,
    },
}

fn label(value: &Value, label: i64) -> Option<&Value> {
    let wanted = if label < 0 {
        Value::Negative(u64::try_from(-1 - label).ok()?)
    } else {
        Value::Unsigned(u64::try_from(label).ok()?)
    };
    match value {
        Value::Map(entries) => entries.iter().find(|(k, _)| *k == wanted).map(|(_, v)| v),
        _ => None,
    }
}

fn int(value: &Value, l: i64) -> Result<i64, CoseError> {
    label(value, l)
        .ok_or(CoseError::MissingLabel { label: l })?
        .as_i64()
        .ok_or(CoseError::WrongType { label: l })
}

fn coordinate(value: &Value, l: i64) -> Result<[u8; 32], CoseError> {
    let bytes = label(value, l)
        .ok_or(CoseError::MissingLabel { label: l })?
        .as_bytes()
        .ok_or(CoseError::WrongType { label: l })?;
    bytes.try_into().map_err(|_| CoseError::BadCoordinate {
        label: l,
        len: bytes.len(),
    })
}

impl CoseKey {
    /// Parses a COSE key from a decoded CBOR value.
    pub fn from_value(value: &Value) -> Result<Self, CoseError> {
        let kty = int(value, KEY_KTY as i64)?;
        let alg = int(value, KEY_ALG as i64)?;
        let crv = int(value, LABEL_CRV)?;

        match (kty, alg, crv) {
            (KTY_EC2, ALG_ES256, CRV_P256) => Ok(CoseKey::Es256 {
                x: coordinate(value, LABEL_X)?,
                y: coordinate(value, LABEL_Y)?,
            }),
            (KTY_OKP, ALG_EDDSA, CRV_ED25519) => Ok(CoseKey::Ed25519 {
                x: coordinate(value, LABEL_X)?,
            }),
            _ => Err(CoseError::Unsupported { kty, alg, crv }),
        }
    }

    /// Parses a COSE key from raw CBOR.
    pub fn parse(bytes: &[u8]) -> Result<Self, CoseError> {
        Self::from_value(&Value::decode(bytes)?)
    }

    /// The COSE algorithm identifier.
    pub const fn alg(&self) -> i64 {
        match self {
            CoseKey::Es256 { .. } => ALG_ES256,
            CoseKey::Ed25519 { .. } => ALG_EDDSA,
        }
    }

    /// The key in the form OpenSSH's `sk_enroll_response.public_key` expects.
    ///
    /// Read from OpenSSH's own middleware (`sk-usbhid.c` at `V_10_3_P1`) rather
    /// than inferred: `pack_public_key_ecdsa` runs the coordinates through
    /// `EC_POINT_point2oct` with `POINT_CONVERSION_UNCOMPRESSED`, giving
    /// `0x04 || X || Y`; `pack_public_key_ed25519` copies the 32 raw bytes.
    pub fn to_openssh_public_key(&self) -> Vec<u8> {
        match self {
            CoseKey::Es256 { x, y } => {
                let mut out = Vec::with_capacity(65);
                out.push(0x04);
                out.extend_from_slice(x);
                out.extend_from_slice(y);
                out
            }
            CoseKey::Ed25519 { x } => x.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn es256_value(x: u8, y: u8) -> Value {
        Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(2)),        // kty: EC2
            (Value::Unsigned(3), Value::Negative(6)),        // alg: -7
            (Value::Negative(0), Value::Unsigned(1)),        // crv: P-256
            (Value::Negative(1), Value::Bytes(vec![x; 32])), // x
            (Value::Negative(2), Value::Bytes(vec![y; 32])), // y
        ])
    }

    fn ed25519_value() -> Value {
        Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(1)), // kty: OKP
            (Value::Unsigned(3), Value::Negative(7)), // alg: -8
            (Value::Negative(0), Value::Unsigned(6)), // crv: Ed25519
            (Value::Negative(1), Value::Bytes(vec![0xcc; 32])),
        ])
    }

    #[test]
    fn an_es256_key_parses_and_packs_uncompressed() {
        let key = CoseKey::parse(&es256_value(0xaa, 0xbb).encode()).unwrap();
        assert_eq!(key.alg(), ALG_ES256);

        let packed = key.to_openssh_public_key();
        assert_eq!(packed.len(), 65, "uncompressed point is 1 + 32 + 32");
        assert_eq!(packed[0], 0x04, "uncompressed point marker");
        assert_eq!(&packed[1..33], &[0xaa; 32]);
        assert_eq!(&packed[33..], &[0xbb; 32]);
    }

    #[test]
    fn an_ed25519_key_packs_as_the_raw_32_bytes() {
        let key = CoseKey::parse(&ed25519_value().encode()).unwrap();
        assert_eq!(key.alg(), ALG_EDDSA);
        assert_eq!(key.to_openssh_public_key(), vec![0xcc; 32]);
    }

    #[test]
    fn a_mismatched_curve_is_refused_rather_than_coerced() {
        // EC2 with the Ed25519 curve is not a key we can use, and guessing
        // which field was wrong would produce a subtly broken credential.
        let mut value = es256_value(1, 2);
        if let Value::Map(entries) = &mut value {
            entries[2].1 = Value::Unsigned(6);
        }
        assert!(matches!(
            CoseKey::parse(&value.encode()),
            Err(CoseError::Unsupported { .. })
        ));
    }

    #[test]
    fn a_short_coordinate_is_refused() {
        let mut value = es256_value(1, 2);
        if let Value::Map(entries) = &mut value {
            entries[3].1 = Value::Bytes(vec![0u8; 31]);
        }
        assert!(matches!(
            CoseKey::parse(&value.encode()),
            Err(CoseError::BadCoordinate { len: 31, .. })
        ));
    }

    #[test]
    fn a_missing_label_names_which_one() {
        let value = Value::Map(vec![(Value::Unsigned(1), Value::Unsigned(2))]);
        assert_eq!(
            CoseKey::parse(&value.encode()),
            Err(CoseError::MissingLabel { label: 3 })
        );
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for bytes in [&b""[..], &[0x00], &[0xa1, 0x01], &[0xff; 8]] {
            assert!(CoseKey::parse(bytes).is_err());
        }
    }
}
