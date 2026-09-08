//! Commands and status bytes defined by the CTAP BLE transport.

use crate::error::FramingError;

/// A CTAP BLE command, carried in the first byte of an initialization fragment.
///
/// The high bit distinguishes an initialization fragment from a continuation,
/// so every command byte has it set. Values are from PROJECT.md §12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    /// `PING` — echo the payload back unchanged.
    Ping,
    /// `KEEPALIVE` — the authenticator is still working. Payload is one
    /// [`KeepAliveStatus`] byte.
    KeepAlive,
    /// `MSG` — a CTAP message. This is what carries CTAP2 CBOR.
    Msg,
    /// `CANCEL` — abandon the transaction in progress. Carries no payload.
    Cancel,
    /// `ERROR` — the request failed. Payload is one
    /// [`BleErrorCode`](crate::BleErrorCode) byte.
    Error,
}

impl Command {
    /// The command's wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            Command::Ping => 0x81,
            Command::KeepAlive => 0x82,
            Command::Msg => 0x83,
            Command::Cancel => 0xbe,
            Command::Error => 0xbf,
        }
    }

    /// Parses a command byte.
    ///
    /// Unknown values are rejected rather than passed through: a command we do
    /// not recognise is either a firmware mismatch or an attack, and PROJECT.md
    /// §15.8 says to fail closed in both cases.
    pub const fn from_u8(byte: u8) -> Result<Self, FramingError> {
        match byte {
            0x81 => Ok(Command::Ping),
            0x82 => Ok(Command::KeepAlive),
            0x83 => Ok(Command::Msg),
            0xbe => Ok(Command::Cancel),
            0xbf => Ok(Command::Error),
            other => Err(FramingError::UnknownCommand(other)),
        }
    }
}

/// The one-byte payload of a `KEEPALIVE` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeepAliveStatus {
    /// The authenticator is busy and the client should keep waiting.
    Processing,
    /// The authenticator is waiting for user presence — on this device, a
    /// fingerprint. The daemon must forward this and never satisfy it itself
    /// (PROJECT.md §15.3); it becomes `ctap.keepalive` with `reason: "up"` on
    /// the IPC boundary (§13).
    UpNeeded,
}

impl KeepAliveStatus {
    /// The status byte as it appears on the wire.
    pub const fn as_u8(self) -> u8 {
        match self {
            KeepAliveStatus::Processing => 0x01,
            KeepAliveStatus::UpNeeded => 0x02,
        }
    }

    /// Parses a keepalive status byte.
    pub const fn from_u8(byte: u8) -> Result<Self, FramingError> {
        match byte {
            0x01 => Ok(KeepAliveStatus::Processing),
            0x02 => Ok(KeepAliveStatus::UpNeeded),
            other => Err(FramingError::UnknownKeepAliveStatus(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_byte_has_the_high_bit_set() {
        // The reassembler tells initialization fragments from continuations by
        // that bit alone, so a command without it would be unreachable.
        for cmd in [
            Command::Ping,
            Command::KeepAlive,
            Command::Msg,
            Command::Cancel,
            Command::Error,
        ] {
            assert_ne!(cmd.as_u8() & 0x80, 0, "{cmd:?}");
        }
    }

    #[test]
    fn command_bytes_round_trip() {
        for cmd in [
            Command::Ping,
            Command::KeepAlive,
            Command::Msg,
            Command::Cancel,
            Command::Error,
        ] {
            assert_eq!(Command::from_u8(cmd.as_u8()), Ok(cmd));
        }
    }

    #[test]
    fn unknown_commands_are_rejected() {
        // 0x84 has the high bit set but is not a defined command.
        assert_eq!(
            Command::from_u8(0x84),
            Err(FramingError::UnknownCommand(0x84))
        );
        assert_eq!(
            Command::from_u8(0xff),
            Err(FramingError::UnknownCommand(0xff))
        );
    }

    #[test]
    fn keepalive_status_round_trips() {
        assert_eq!(
            KeepAliveStatus::from_u8(0x01),
            Ok(KeepAliveStatus::Processing)
        );
        assert_eq!(
            KeepAliveStatus::from_u8(0x02),
            Ok(KeepAliveStatus::UpNeeded)
        );
        assert!(KeepAliveStatus::from_u8(0x00).is_err());
    }
}
