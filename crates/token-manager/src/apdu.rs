//! ISO 7816-4 APDU commands, response structures, and status words.
//!
//! Provides encoding, decoding, and parsing for APDUs exchanged with
//! Cryptick Token on-device applets (OATH, PIV, Management).

use std::fmt;

use crate::error::ManagerError;

/// Well-known Application Identifiers (AIDs).
pub mod aid {
    /// Cryptick OATH Applet AID: `A0 00 00 05 27 21 01`
    pub const OATH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

    /// PIV (Personal Identity Verification) Applet AID: `A0 00 00 03 08 00 00 10 00 01 00`
    pub const PIV: &[u8] = &[
        0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    ];

    /// Cryptick Device Management Applet AID: `A0 00 00 05 27 47 11 17`
    pub const MANAGEMENT: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

    /// CTAP / FIDO2 / U2F Applet AID: `A0 00 00 06 47 2F 00 01`
    pub const FIDO: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
}

/// An ISO 7816-4 Status Word (SW1, SW2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusWord(pub u16);

impl StatusWord {
    /// Success: `0x90 0x00`
    pub const SUCCESS: Self = Self(0x9000);

    /// Security status not satisfied: `0x69 0x82` (Biometric touch, PIN, or auth needed)
    pub const SECURITY_STATUS_NOT_SATISFIED: Self = Self(0x6982);

    /// Authentication method blocked: `0x69 0x83`
    pub const AUTH_METHOD_BLOCKED: Self = Self(0x6983);

    /// Reference data not usable: `0x69 0x84`
    pub const DATA_INVALID: Self = Self(0x6984);

    /// Conditions of use not satisfied: `0x69 0x85` (Touch timeout / UV failed)
    pub const CONDITIONS_NOT_SATISFIED: Self = Self(0x6985);

    /// Incorrect parameters in the command data: `0x6A 0x80`
    pub const INCORRECT_PARAMETERS: Self = Self(0x6A80);

    /// Function not supported: `0x6A 0x81`
    pub const FUNCTION_NOT_SUPPORTED: Self = Self(0x6A81);

    /// File, account, or application not found: `0x6A 0x82`
    pub const NOT_FOUND: Self = Self(0x6A82);

    /// Not enough memory / storage full: `0x6A 0x84`
    pub const MEMORY_FULL: Self = Self(0x6A84);

    /// Incorrect P1/P2 parameters: `0x6A 0x86`
    pub const INCORRECT_P1_P2: Self = Self(0x6A86);

    /// Referenced data not found (e.g. account label does not exist): `0x6A 0x88`
    pub const REFERENCED_DATA_NOT_FOUND: Self = Self(0x6A88);

    /// Wrong length: `0x67 0x00`
    pub const WRONG_LENGTH: Self = Self(0x6700);

    /// Instruction code not supported or invalid: `0x6D 0x00`
    pub const INS_NOT_SUPPORTED: Self = Self(0x6D00);

    /// Class not supported: `0x6E 0x00`
    pub const CLA_NOT_SUPPORTED: Self = Self(0x6E00);

    /// No precise diagnosis / hardware execution error: `0x6F 0x00`
    pub const INTERNAL_ERROR: Self = Self(0x6F00);

    /// Returns the raw 16-bit status word.
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Returns SW1 (high byte).
    pub const fn sw1(self) -> u8 {
        (self.0 >> 8) as u8
    }

    /// Returns SW2 (low byte).
    pub const fn sw2(self) -> u8 {
        (self.0 & 0xFF) as u8
    }

    /// Whether this status word represents success (`0x9000` or `0x61XX`).
    pub const fn is_success(self) -> bool {
        self.0 == 0x9000 || (self.0 >> 8) == 0x61
    }

    /// Whether more data is available to read via `GET RESPONSE` (`0x61XX`).
    pub const fn has_more_data(self) -> Option<u8> {
        if (self.0 >> 8) == 0x61 {
            Some((self.0 & 0xFF) as u8)
        } else {
            None
        }
    }

    /// Returns a human-readable description of the status word.
    pub fn description(self) -> &'static str {
        match self {
            Self::SUCCESS => "Success (OK)",
            Self::SECURITY_STATUS_NOT_SATISFIED => {
                "Security status not satisfied (touch/biometric or access key required)"
            }
            Self::AUTH_METHOD_BLOCKED => "Authentication method blocked (too many wrong attempts)",
            Self::DATA_INVALID => "Reference data not usable",
            Self::CONDITIONS_NOT_SATISFIED => {
                "Conditions of use not satisfied (user verification timed out or sensor touched)"
            }
            Self::INCORRECT_PARAMETERS => "Incorrect parameters (malformed TLV or bad payload)",
            Self::FUNCTION_NOT_SUPPORTED => "Function or instruction not supported by applet",
            Self::NOT_FOUND => "Referenced account or application not found",
            Self::MEMORY_FULL => "Not enough non-volatile memory on token",
            Self::INCORRECT_P1_P2 => "Incorrect P1 or P2 parameters",
            Self::REFERENCED_DATA_NOT_FOUND => "Referenced data not found (account does not exist)",
            Self::WRONG_LENGTH => "Wrong length field (Lc or Le)",
            Self::INS_NOT_SUPPORTED => "Instruction code not supported (INS unknown)",
            Self::CLA_NOT_SUPPORTED => "Class byte not supported (CLA unknown)",
            Self::INTERNAL_ERROR => "Internal hardware execution error",
            _ if (self.0 >> 8) == 0x61 => "Success, more response data available (GET RESPONSE)",
            _ if (self.0 >> 8) == 0x6C => "Wrong Le field, correct length indicated in SW2",
            _ => "Unknown ISO 7816 status word",
        }
    }
}

impl fmt::Display for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06X} ({})", self.0, self.description())
    }
}

/// An ISO 7816-4 Command APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandApdu {
    /// Class byte (usually 0x00).
    pub cla: u8,
    /// Instruction byte (e.g. 0xA1, 0xA2, 0x01, 0x04).
    pub ins: u8,
    /// Parameter 1 byte.
    pub p1: u8,
    /// Parameter 2 byte.
    pub p2: u8,
    /// Command data payload (empty if no data).
    pub data: Vec<u8>,
    /// Expected response length (optional Le).
    pub le: Option<usize>,
}

impl CommandApdu {
    /// Creates a new Command APDU without data or Le.
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    /// Creates a new Command APDU with data payload.
    pub fn with_data(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le: None,
        }
    }

    /// Sets the expected response length (Le).
    pub fn with_le(mut self, le: usize) -> Self {
        self.le = Some(le);
        self
    }

    /// Builds a SELECT FILE / APPLICATION Command APDU for a given AID.
    pub fn select_applet(aid: &[u8]) -> Self {
        Self::with_data(0x00, 0xA4, 0x04, 0x00, aid.to_vec())
    }

    /// Serializes this APDU into ISO 7816 short or extended wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 + self.data.len());
        buf.push(self.cla);
        buf.push(self.ins);
        buf.push(self.p1);
        buf.push(self.p2);

        if !self.data.is_empty() {
            if self.data.len() <= 255 {
                // Short APDU
                buf.push(self.data.len() as u8);
                buf.extend_from_slice(&self.data);
            } else {
                // Extended APDU: 0x00 followed by 2-byte big-endian length
                buf.push(0x00);
                buf.push(((self.data.len() >> 8) & 0xFF) as u8);
                buf.push((self.data.len() & 0xFF) as u8);
                buf.extend_from_slice(&self.data);
            }
        } else if let Some(le) = self.le {
            // Case 2 APDU (no data, with Le)
            if le <= 256 {
                buf.push(if le == 256 { 0x00 } else { le as u8 });
            } else {
                buf.push(0x00);
                buf.push(((le >> 8) & 0xFF) as u8);
                buf.push((le & 0xFF) as u8);
            }
        }

        buf
    }

    /// Parses raw bytes into a Command APDU.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManagerError> {
        if bytes.len() < 4 {
            return Err(ManagerError::InvalidInput(
                "APDU must be at least 4 bytes (CLA, INS, P1, P2)".to_string(),
            ));
        }

        let cla = bytes[0];
        let ins = bytes[1];
        let p1 = bytes[2];
        let p2 = bytes[3];

        if bytes.len() == 4 {
            return Ok(Self::new(cla, ins, p1, p2));
        }

        let lc = bytes[4] as usize;
        if bytes.len() == 5 {
            // Case 2 APDU: 4 bytes header + 1 byte Le
            let le = if lc == 0 { 256 } else { lc };
            return Ok(Self::new(cla, ins, p1, p2).with_le(le));
        }

        if bytes.len() < 5 + lc {
            return Err(ManagerError::InvalidInput(format!(
                "APDU truncated: expected {} data bytes, got {}",
                lc,
                bytes.len() - 5
            )));
        }

        let data = bytes[5..5 + lc].to_vec();
        let mut apdu = Self::with_data(cla, ins, p1, p2, data);
        if bytes.len() > 5 + lc {
            let le_byte = bytes[5 + lc];
            let le = if le_byte == 0 { 256 } else { le_byte as usize };
            apdu.le = Some(le);
        }

        Ok(apdu)
    }
}

/// An ISO 7816-4 Response APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseApdu {
    /// Response payload bytes (excluding the trailing 2-byte status word).
    pub data: Vec<u8>,
    /// Status Word (SW1, SW2).
    pub sw: StatusWord,
}

impl ResponseApdu {
    /// Creates a Response APDU from data and status word.
    pub fn new(data: Vec<u8>, sw: StatusWord) -> Self {
        Self { data, sw }
    }

    /// Parses a raw response byte buffer. The last two bytes are always SW1 and SW2.
    pub fn parse(raw: &[u8]) -> Result<Self, ManagerError> {
        if raw.len() < 2 {
            return Err(ManagerError::InvalidInput(
                "Response APDU must be at least 2 bytes (SW1, SW2)".to_string(),
            ));
        }

        let sw_bytes = [raw[raw.len() - 2], raw[raw.len() - 1]];
        let sw = StatusWord(u16::from_be_bytes(sw_bytes));
        let data = raw[..raw.len() - 2].to_vec();

        Ok(Self { data, sw })
    }

    /// Returns whether this response indicates success (`0x9000`).
    pub fn is_success(&self) -> bool {
        self.sw.is_success()
    }

    /// Checks success and returns an error with description if non-zero.
    pub fn check_success(&self) -> Result<&[u8], ManagerError> {
        if self.sw.is_success() {
            Ok(&self.data)
        } else {
            Err(ManagerError::DeviceStatus(self.sw))
        }
    }
}

/// Parses a hex string into a byte vector, ignoring spaces, colons, and prefixes like `0x`.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, ManagerError> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();

    let clean = clean.trim_start_matches("0x").trim_start_matches("0X");

    if !clean.len().is_multiple_of(2) {
        return Err(ManagerError::InvalidInput(format!(
            "Hex string has odd length ({} digits)",
            clean.len()
        )));
    }

    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte_str = &clean[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("Invalid hex digit in '{byte_str}': {e}"))?;
        out.push(byte);
    }

    Ok(out)
}

/// Formats a byte slice into an uppercase space-separated hex string.
pub fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}
