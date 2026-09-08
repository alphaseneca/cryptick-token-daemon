//! CTAPHID commands, error codes and keepalive statuses.

use crate::CtaphidError;

/// A CTAPHID command.
///
/// On the wire an initialization packet carries the command with its high bit
/// set; these are the values without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cmd {
    /// Echo the payload back unchanged.
    Ping,
    /// A raw U2F (CTAP1) message.
    Msg,
    /// Reserve the device for one channel.
    Lock,
    /// Synchronise a channel, and allocate one when sent on the broadcast CID.
    Init,
    /// Flash the device to identify it.
    Wink,
    /// A CTAP2 CBOR message. This is the one that matters.
    Cbor,
    /// Abandon the transaction on this channel.
    Cancel,
    /// The authenticator is still working. Response only.
    Keepalive,
    /// The request failed. Response only.
    Error,
}

impl Cmd {
    /// The command value, without the high bit.
    pub const fn as_u8(self) -> u8 {
        match self {
            Cmd::Ping => 0x01,
            Cmd::Msg => 0x03,
            Cmd::Lock => 0x04,
            Cmd::Init => 0x06,
            Cmd::Wink => 0x08,
            Cmd::Cbor => 0x10,
            Cmd::Cancel => 0x11,
            Cmd::Keepalive => 0x3b,
            Cmd::Error => 0x3f,
        }
    }

    /// The byte as it appears in an initialization packet, high bit set.
    pub const fn as_init_byte(self) -> u8 {
        self.as_u8() | 0x80
    }

    /// Parses a command value, with or without the high bit.
    pub const fn from_u8(byte: u8) -> Result<Self, CtaphidError> {
        match byte & 0x7f {
            0x01 => Ok(Cmd::Ping),
            0x03 => Ok(Cmd::Msg),
            0x04 => Ok(Cmd::Lock),
            0x06 => Ok(Cmd::Init),
            0x08 => Ok(Cmd::Wink),
            0x10 => Ok(Cmd::Cbor),
            0x11 => Ok(Cmd::Cancel),
            0x3b => Ok(Cmd::Keepalive),
            0x3f => Ok(Cmd::Error),
            _ => Err(CtaphidError::UnknownCommand(byte)),
        }
    }

    /// Whether the host may send this command. `KEEPALIVE` and `ERROR` only
    /// ever travel authenticator-to-host.
    pub const fn is_request(self) -> bool {
        !matches!(self, Cmd::Keepalive | Cmd::Error)
    }
}

/// A CTAPHID error code, the one-byte payload of an `ERROR` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The command is invalid.
    InvalidCmd,
    /// A parameter is invalid.
    InvalidPar,
    /// The length is invalid.
    InvalidLen,
    /// The sequence number is invalid.
    InvalidSeq,
    /// The transaction timed out.
    MsgTimeout,
    /// The device is busy with another channel.
    ChannelBusy,
    /// A lock is held by another channel.
    LockRequired,
    /// The channel id is not valid.
    InvalidChannel,
    /// Unspecified failure.
    Other,
}

impl ErrorCode {
    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            ErrorCode::InvalidCmd => 0x01,
            ErrorCode::InvalidPar => 0x02,
            ErrorCode::InvalidLen => 0x03,
            ErrorCode::InvalidSeq => 0x04,
            ErrorCode::MsgTimeout => 0x05,
            ErrorCode::ChannelBusy => 0x06,
            ErrorCode::LockRequired => 0x0a,
            ErrorCode::InvalidChannel => 0x0b,
            ErrorCode::Other => 0x7f,
        }
    }
}

/// The one-byte payload of a `KEEPALIVE` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeepaliveStatus {
    /// Busy.
    Processing,
    /// Waiting for a physical touch — on this device, a fingerprint.
    UpNeeded,
}

impl KeepaliveStatus {
    /// The wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            KeepaliveStatus::Processing => 0x01,
            KeepaliveStatus::UpNeeded => 0x02,
        }
    }

    /// Parses a status byte.
    pub const fn from_u8(byte: u8) -> Result<Self, CtaphidError> {
        match byte {
            0x01 => Ok(KeepaliveStatus::Processing),
            0x02 => Ok(KeepaliveStatus::UpNeeded),
            other => Err(CtaphidError::UnknownKeepaliveStatus(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[Cmd] = &[
        Cmd::Ping,
        Cmd::Msg,
        Cmd::Lock,
        Cmd::Init,
        Cmd::Wink,
        Cmd::Cbor,
        Cmd::Cancel,
        Cmd::Keepalive,
        Cmd::Error,
    ];

    #[test]
    fn commands_round_trip_with_and_without_the_high_bit() {
        for &cmd in ALL {
            assert_eq!(Cmd::from_u8(cmd.as_u8()), Ok(cmd));
            assert_eq!(Cmd::from_u8(cmd.as_init_byte()), Ok(cmd));
        }
    }

    #[test]
    fn the_init_byte_always_sets_the_high_bit() {
        // That bit is the only thing telling an init packet from a
        // continuation, so a command without it would be unreachable.
        for &cmd in ALL {
            assert_ne!(cmd.as_init_byte() & 0x80, 0, "{cmd:?}");
            assert_eq!(cmd.as_u8() & 0x80, 0, "{cmd:?}");
        }
    }

    #[test]
    fn unknown_commands_are_rejected() {
        for byte in [0x00u8, 0x02, 0x05, 0x12, 0x7e] {
            assert_eq!(Cmd::from_u8(byte), Err(CtaphidError::UnknownCommand(byte)));
        }
    }

    #[test]
    fn response_only_commands_are_not_requests() {
        assert!(!Cmd::Keepalive.is_request());
        assert!(!Cmd::Error.is_request());
        assert!(Cmd::Cbor.is_request());
        assert!(Cmd::Init.is_request());
    }

    #[test]
    fn keepalive_statuses_round_trip() {
        assert_eq!(
            KeepaliveStatus::from_u8(0x01),
            Ok(KeepaliveStatus::Processing)
        );
        assert_eq!(
            KeepaliveStatus::from_u8(0x02),
            Ok(KeepaliveStatus::UpNeeded)
        );
        assert!(KeepaliveStatus::from_u8(0x00).is_err());
        assert!(KeepaliveStatus::from_u8(0x03).is_err());
    }
}
