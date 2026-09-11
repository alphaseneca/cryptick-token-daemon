//! ISO 7816-4 command and response APDUs, in the short form PIV uses.
//!
//! # Why short form only
//!
//! Extended-length APDUs exist and PIV permits them, but the applet on our
//! device answers command chaining with a 2 KiB reassembly buffer and short
//! APDUs, and `GET RESPONSE` for anything long coming back. Emitting extended
//! APDUs would be emitting something the other end cannot read, which §20
//! forbids. A payload over 255 bytes is therefore an error here, pointing at
//! [`crate::chaining`], rather than a silent switch to a second encoding.

use thiserror::Error;

/// The largest data field a short-form APDU can carry.
pub const MAX_SHORT_DATA: usize = 255;

/// `GET RESPONSE`, used to collect a reply the card could not send at once.
pub const INS_GET_RESPONSE: u8 = 0xC0;

/// Set in CLA to mark a command as "more of this command follows".
pub const CLA_CHAIN: u8 = 0x10;

/// An APDU could not be built or read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApduError {
    /// The data field is longer than the short form can express.
    #[error("data field is {len} bytes; the short form holds {MAX_SHORT_DATA}, so this needs command chaining")]
    DataTooLong {
        /// How long the field was.
        len: usize,
    },

    /// A response was shorter than the two status bytes every response carries.
    #[error("response is {len} bytes; every response carries at least the two status bytes")]
    ResponseTooShort {
        /// How many bytes arrived.
        len: usize,
    },

    /// The card answered with a status word that is not success.
    #[error("card returned status word {0}")]
    Status(StatusWord),
}

/// A command APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// Class byte. `0x10` set means the chain continues.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// First parameter.
    pub p1: u8,
    /// Second parameter.
    pub p2: u8,
    /// The command data field, possibly empty.
    pub data: Vec<u8>,
    /// Expected response length. `Some(0)` is the spec's `Le '00'`, meaning
    /// "as much as you have"; `None` means no response data is expected.
    pub le: Option<u8>,
}

impl Command {
    /// A command with no data field and no expected response (ISO case 1).
    pub const fn case1(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Command {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    /// A command with a data field.
    pub fn with_data(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Command {
            cla,
            ins,
            p1,
            p2,
            data,
            le: None,
        }
    }

    /// Sets `Le`, the expected response length.
    pub const fn expecting(mut self, le: u8) -> Self {
        self.le = Some(le);
        self
    }

    /// Marks this command as one link of a chain.
    pub const fn chained(mut self) -> Self {
        self.cla |= CLA_CHAIN;
        self
    }

    /// Serialises the APDU.
    pub fn encode(&self) -> Result<Vec<u8>, ApduError> {
        if self.data.len() > MAX_SHORT_DATA {
            return Err(ApduError::DataTooLong {
                len: self.data.len(),
            });
        }

        let mut out = Vec::with_capacity(5 + self.data.len() + 1);
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        if !self.data.is_empty() {
            out.push(self.data.len() as u8);
            out.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            out.push(le);
        }
        Ok(out)
    }

    /// The `GET RESPONSE` command for a card that has `available` bytes left.
    ///
    /// `available` comes from SW2 of a `61xx`, where `00` means 256.
    pub const fn get_response(cla: u8, available: u8) -> Self {
        Command {
            cla,
            ins: INS_GET_RESPONSE,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
            le: Some(available),
        }
    }
}

/// A two-byte status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusWord(pub u16);

impl StatusWord {
    /// Successful execution.
    pub const SUCCESS: StatusWord = StatusWord(0x9000);
    /// Wrong length.
    pub const WRONG_LENGTH: StatusWord = StatusWord(0x6700);
    /// Security status not satisfied — the PIN has not been verified.
    pub const SECURITY_STATUS_NOT_SATISFIED: StatusWord = StatusWord(0x6982);
    /// Authentication method blocked — the retry counter reached zero.
    pub const AUTHENTICATION_METHOD_BLOCKED: StatusWord = StatusWord(0x6983);
    /// The last command of a chain is missing.
    pub const LAST_COMMAND_EXPECTED: StatusWord = StatusWord(0x6883);
    /// Incorrect parameter in the command data field.
    pub const INCORRECT_PARAMETER_IN_DATA: StatusWord = StatusWord(0x6A80);
    /// Function not supported.
    pub const FUNCTION_NOT_SUPPORTED: StatusWord = StatusWord(0x6A81);
    /// File or application not found — a SELECT of an AID the card lacks.
    pub const FILE_NOT_FOUND: StatusWord = StatusWord(0x6A82);
    /// Not enough memory.
    pub const NOT_ENOUGH_MEMORY: StatusWord = StatusWord(0x6A84);
    /// Incorrect parameter P1 or P2.
    pub const INCORRECT_PARAMETERS: StatusWord = StatusWord(0x6A86);

    /// Builds a status word from the two trailing response bytes.
    pub const fn from_bytes(sw1: u8, sw2: u8) -> Self {
        StatusWord(((sw1 as u16) << 8) | sw2 as u16)
    }

    /// The first status byte.
    pub const fn sw1(self) -> u8 {
        (self.0 >> 8) as u8
    }

    /// The second status byte.
    pub const fn sw2(self) -> u8 {
        self.0 as u8
    }

    /// Whether the command succeeded outright.
    ///
    /// `61xx` is deliberately **not** success: it means the answer is
    /// incomplete, and treating it as success is how you end up signing a
    /// truncated response.
    pub const fn is_success(self) -> bool {
        self.0 == 0x9000
    }

    /// For `61xx`, how many bytes the card still has. `00` means 256.
    pub const fn bytes_available(self) -> Option<u16> {
        if self.sw1() == 0x61 {
            Some(match self.sw2() {
                0 => 256,
                n => n as u16,
            })
        } else {
            None
        }
    }

    /// For `63Cx`, how many PIN attempts remain.
    pub const fn retries_left(self) -> Option<u8> {
        if self.0 & 0xFFF0 == 0x63C0 {
            Some(self.sw2() & 0x0F)
        } else {
            None
        }
    }
}

impl std::fmt::Display for StatusWord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let meaning = match *self {
            StatusWord::SUCCESS => " (success)",
            StatusWord::WRONG_LENGTH => " (wrong length)",
            StatusWord::SECURITY_STATUS_NOT_SATISFIED => " (security status not satisfied)",
            StatusWord::AUTHENTICATION_METHOD_BLOCKED => " (authentication method blocked)",
            StatusWord::LAST_COMMAND_EXPECTED => " (last command of chain expected)",
            StatusWord::INCORRECT_PARAMETER_IN_DATA => " (incorrect parameter in data field)",
            StatusWord::FUNCTION_NOT_SUPPORTED => " (function not supported)",
            StatusWord::FILE_NOT_FOUND => " (file or application not found)",
            StatusWord::NOT_ENOUGH_MEMORY => " (not enough memory)",
            StatusWord::INCORRECT_PARAMETERS => " (incorrect parameter P1 or P2)",
            other if other.bytes_available().is_some() => " (more data available)",
            other if other.retries_left().is_some() => " (verification failed)",
            _ => "",
        };
        write!(f, "{:04X}{meaning}", self.0)
    }
}

/// A response APDU: the data the card sent, and how it finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The response data field, possibly empty.
    pub data: Vec<u8>,
    /// The status word.
    pub status: StatusWord,
}

impl Response {
    /// Splits a raw response into its data field and status word.
    pub fn decode(raw: &[u8]) -> Result<Self, ApduError> {
        let Some(split) = raw.len().checked_sub(2) else {
            return Err(ApduError::ResponseTooShort { len: raw.len() });
        };
        Ok(Response {
            data: raw[..split].to_vec(),
            status: StatusWord::from_bytes(raw[split], raw[split + 1]),
        })
    }

    /// The data field, or an error naming the status word.
    pub fn into_data(self) -> Result<Vec<u8>, ApduError> {
        if self.status.is_success() {
            Ok(self.data)
        } else {
            Err(ApduError::Status(self.status))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_iso_cases_encode_as_the_spec_writes_them() {
        // Case 1: header only.
        assert_eq!(
            Command::case1(0x00, 0xA4, 0x04, 0x00).encode().unwrap(),
            vec![0x00, 0xA4, 0x04, 0x00]
        );
        // Case 2: header and Le.
        assert_eq!(
            Command::case1(0x00, 0xC0, 0x00, 0x00)
                .expecting(0x00)
                .encode()
                .unwrap(),
            vec![0x00, 0xC0, 0x00, 0x00, 0x00]
        );
        // Case 3: header, Lc, data.
        assert_eq!(
            Command::with_data(0x00, 0x20, 0x00, 0x80, vec![0x31, 0x32])
                .encode()
                .unwrap(),
            vec![0x00, 0x20, 0x00, 0x80, 0x02, 0x31, 0x32]
        );
        // Case 4: header, Lc, data, Le.
        assert_eq!(
            Command::with_data(0x00, 0xCB, 0x3F, 0xFF, vec![0x5C])
                .expecting(0x00)
                .encode()
                .unwrap(),
            vec![0x00, 0xCB, 0x3F, 0xFF, 0x01, 0x5C, 0x00]
        );
    }

    #[test]
    fn a_data_field_too_long_for_the_short_form_is_refused() {
        // Refused rather than silently promoted to extended length: the applet
        // reassembles chained short APDUs and would not read an extended one.
        let error = Command::with_data(0x00, 0xDB, 0x3F, 0xFF, vec![0u8; 256])
            .encode()
            .unwrap_err();
        assert_eq!(error, ApduError::DataTooLong { len: 256 });

        // One byte less is fine, so the boundary is where it is claimed to be.
        assert!(Command::with_data(0x00, 0xDB, 0x3F, 0xFF, vec![0u8; 255])
            .encode()
            .is_ok());
    }

    #[test]
    fn chaining_sets_the_class_bit_without_disturbing_the_rest() {
        let chained = Command::with_data(0x00, 0xDB, 0x3F, 0xFF, vec![1]).chained();
        assert_eq!(chained.cla, 0x10);
        // Secure messaging uses 0x0C, which must become 0x1C and not 0x10.
        let secure = Command::with_data(0x0C, 0xDB, 0x3F, 0xFF, vec![1]).chained();
        assert_eq!(secure.cla, 0x1C);
    }

    #[test]
    fn a_response_splits_into_data_and_status() {
        let response = Response::decode(&[0xAA, 0xBB, 0x90, 0x00]).unwrap();
        assert_eq!(response.data, vec![0xAA, 0xBB]);
        assert_eq!(response.status, StatusWord::SUCCESS);
        assert_eq!(response.into_data().unwrap(), vec![0xAA, 0xBB]);

        // A bare status word is a complete response.
        let empty = Response::decode(&[0x90, 0x00]).unwrap();
        assert!(empty.data.is_empty());
        assert!(empty.status.is_success());

        assert_eq!(
            Response::decode(&[0x90]).unwrap_err(),
            ApduError::ResponseTooShort { len: 1 }
        );
    }

    #[test]
    fn sixty_one_xx_is_not_success() {
        // The response is incomplete. Calling it success is how a truncated
        // certificate or signature gets used as if it were whole.
        let more = StatusWord::from_bytes(0x61, 0x2F);
        assert!(!more.is_success());
        assert_eq!(more.bytes_available(), Some(0x2F));

        // SW2 '00' means 256, not zero.
        assert_eq!(
            StatusWord::from_bytes(0x61, 0x00).bytes_available(),
            Some(256)
        );
        assert_eq!(StatusWord::SUCCESS.bytes_available(), None);
    }

    #[test]
    fn sixty_three_c_x_carries_the_retry_count() {
        assert_eq!(StatusWord::from_bytes(0x63, 0xC3).retries_left(), Some(3));
        assert_eq!(StatusWord::from_bytes(0x63, 0xC0).retries_left(), Some(0));
        assert_eq!(StatusWord::SUCCESS.retries_left(), None);
        // 0x6983 is the blocked case, which is not a retry count.
        assert_eq!(
            StatusWord::AUTHENTICATION_METHOD_BLOCKED.retries_left(),
            None
        );
    }

    #[test]
    fn a_failing_status_word_names_itself() {
        let error = Response::decode(&[0x69, 0x82])
            .unwrap()
            .into_data()
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "card returned status word 6982 (security status not satisfied)"
        );
    }
}
