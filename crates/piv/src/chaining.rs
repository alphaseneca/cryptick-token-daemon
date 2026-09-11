//! Command chaining and `GET RESPONSE`, with no I/O.
//!
//! Both directions of a long exchange are state machines the caller drives, in
//! the same style as `ble-framing`: this crate decides *what* to send and what
//! an answer means, and never touches a reader. That keeps the interesting
//! logic testable without a card.

use crate::apdu::{ApduError, Command, Response, StatusWord, CLA_CHAIN, MAX_SHORT_DATA};
use thiserror::Error;

/// A long exchange went wrong.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChainError {
    /// An APDU could not be built or read.
    #[error(transparent)]
    Apdu(#[from] ApduError),

    /// The card kept promising more data past the ceiling we allow.
    #[error("response exceeded the {limit}-byte ceiling while collecting")]
    ResponseTooLong {
        /// The ceiling that was hit.
        limit: usize,
    },

    /// The card answered a `GET RESPONSE` with a failure.
    #[error("card returned {0} part-way through a response")]
    Interrupted(StatusWord),
}

/// Splits a command whose data field is too long into a chain.
///
/// `chunk` is how much data each link carries, capped at
/// [`MAX_SHORT_DATA`]. Only the final link carries `Le`: an intermediate link
/// asking for a response would be asking the card to answer a command it has
/// not finished receiving.
///
/// A command that already fits comes back as a single un-chained link, so the
/// caller never needs a special case for the short path.
pub fn chain(command: &Command, chunk: usize) -> Result<Vec<Command>, ChainError> {
    let chunk = chunk.clamp(1, MAX_SHORT_DATA);
    if command.data.len() <= chunk {
        return Ok(vec![command.clone()]);
    }

    let pieces: Vec<&[u8]> = command.data.chunks(chunk).collect();
    let last = pieces.len() - 1;
    Ok(pieces
        .into_iter()
        .enumerate()
        .map(|(index, piece)| {
            let mut link = Command {
                cla: command.cla,
                ins: command.ins,
                p1: command.p1,
                p2: command.p2,
                data: piece.to_vec(),
                le: if index == last { command.le } else { None },
            };
            if index != last {
                link.cla |= CLA_CHAIN;
            }
            link
        })
        .collect())
}

/// What to do after feeding a response to a [`Collector`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Send this command and feed the answer back in.
    Send(Command),
    /// The response is complete.
    Done(Vec<u8>),
}

/// Reassembles a response the card delivered across several `61xx` rounds.
#[derive(Debug, Clone)]
pub struct Collector {
    cla: u8,
    limit: usize,
    buffer: Vec<u8>,
}

impl Collector {
    /// Collects with `cla` on the `GET RESPONSE` commands and a byte ceiling.
    ///
    /// The ceiling is not a formality. `61xx` is a loop the card controls, and
    /// a card that answers every `GET RESPONSE` with another `61xx` would grow
    /// this buffer forever; §15.8 says the ambiguous case ends in an error.
    pub fn new(cla: u8, limit: usize) -> Self {
        Collector {
            // The chaining bit belongs to the command being continued, not to
            // the GET RESPONSE that collects its answer.
            cla: cla & !CLA_CHAIN,
            limit,
            buffer: Vec::new(),
        }
    }

    /// Feeds one response in and says what to do next.
    pub fn push(&mut self, response: Response) -> Result<Next, ChainError> {
        if self.buffer.len() + response.data.len() > self.limit {
            return Err(ChainError::ResponseTooLong { limit: self.limit });
        }
        self.buffer.extend_from_slice(&response.data);

        if let Some(available) = response.status.bytes_available() {
            // SW2 is a hint about what remains; Le '00' asks for everything
            // the card has, which is what every PIV example does.
            let _ = available;
            return Ok(Next::Send(Command::get_response(self.cla, 0x00)));
        }

        if !response.status.is_success() {
            return Err(ChainError::Interrupted(response.status));
        }

        Ok(Next::Done(std::mem::take(&mut self.buffer)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_data(len: usize) -> Command {
        Command::with_data(0x00, 0xDB, 0x3F, 0xFF, vec![0xAB; len]).expecting(0x00)
    }

    #[test]
    fn a_command_that_fits_is_not_chained() {
        let links = chain(&put_data(100), 255).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].cla, 0x00);
        assert_eq!(links[0].le, Some(0x00));
    }

    #[test]
    fn only_the_last_link_carries_le() {
        // An intermediate link with Le asks the card to answer a command it has
        // not finished receiving.
        let links = chain(&put_data(600), 255).unwrap();
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].cla, 0x10);
        assert_eq!(links[1].cla, 0x10);
        assert_eq!(links[2].cla, 0x00);
        assert_eq!(links[0].le, None);
        assert_eq!(links[1].le, None);
        assert_eq!(links[2].le, Some(0x00));

        let rejoined: Vec<u8> = links.iter().flat_map(|l| l.data.clone()).collect();
        assert_eq!(rejoined, vec![0xAB; 600]);
    }

    #[test]
    fn every_link_encodes_within_the_short_form() {
        // The whole point of chaining, so assert it rather than assuming it.
        for link in chain(&put_data(2000), 255).unwrap() {
            assert!(link.encode().is_ok());
        }
    }

    #[test]
    fn an_oversized_chunk_is_clamped_rather_than_trusted() {
        let links = chain(&put_data(600), 9999).unwrap();
        assert!(links.iter().all(|l| l.data.len() <= MAX_SHORT_DATA));
    }

    #[test]
    fn a_response_arriving_in_pieces_is_rejoined() {
        let mut collector = Collector::new(0x00, 4096);

        let next = collector
            .push(Response {
                data: vec![1, 2, 3],
                status: StatusWord::from_bytes(0x61, 0x02),
            })
            .unwrap();
        assert_eq!(
            next,
            Next::Send(Command::get_response(0x00, 0x00)),
            "a 61xx must be followed by GET RESPONSE"
        );

        let next = collector
            .push(Response {
                data: vec![4, 5],
                status: StatusWord::SUCCESS,
            })
            .unwrap();
        assert_eq!(next, Next::Done(vec![1, 2, 3, 4, 5]));
    }

    #[test]
    fn get_response_drops_the_chaining_bit() {
        // 0x10 belongs to the command being continued; carrying it onto the
        // GET RESPONSE would claim a chain that is not there.
        let mut collector = Collector::new(0x10, 4096);
        let next = collector
            .push(Response {
                data: vec![],
                status: StatusWord::from_bytes(0x61, 0x10),
            })
            .unwrap();
        assert_eq!(next, Next::Send(Command::get_response(0x00, 0x00)));
    }

    #[test]
    fn a_card_that_never_stops_sending_is_cut_off() {
        // 61xx is a loop the card controls. Without a ceiling it is unbounded
        // memory growth driven by the other end.
        let mut collector = Collector::new(0x00, 8);
        let error = loop {
            match collector.push(Response {
                data: vec![0xFF; 4],
                status: StatusWord::from_bytes(0x61, 0x04),
            }) {
                Ok(_) => continue,
                Err(error) => break error,
            }
        };
        assert_eq!(error, ChainError::ResponseTooLong { limit: 8 });
    }

    #[test]
    fn a_failure_part_way_through_is_reported_not_returned_as_data() {
        // The half-collected buffer must never reach the caller as if whole.
        let mut collector = Collector::new(0x00, 4096);
        collector
            .push(Response {
                data: vec![1, 2],
                status: StatusWord::from_bytes(0x61, 0x02),
            })
            .unwrap();
        let error = collector
            .push(Response {
                data: vec![],
                status: StatusWord::SECURITY_STATUS_NOT_SATISFIED,
            })
            .unwrap_err();
        assert_eq!(
            error,
            ChainError::Interrupted(StatusWord::SECURITY_STATUS_NOT_SATISFIED)
        );
    }
}
