//! An in-process fake device, for the L2 layer of PROJECT.md §14.
//!
//! This is the highest-value test surface in the project: it exercises framing,
//! reassembly, timeouts, cancellation and error handling on three OSes in
//! seconds, with no radio and no firmware.
//!
//! **It is deliberately hostile.** A cooperative fake that only ever does the
//! right thing agrees with our bugs and proves nothing. This one fragments at
//! awkward boundaries, keeps saying "still working" forever, reorders
//! continuations, truncates mid-transaction, oversizes fragments and returns
//! error statuses on every branch.
//!
//! Note what it does *not* do: it speaks real CTAP framing throughout. The CBOR
//! bodies are opaque on both sides, exactly as they are in the real daemon, so
//! nothing here mocks the layer under test.

use crate::transport::{FragmentTransport, LinkState, TransportError};
use ble_framing::{
    fragments, BleErrorCode, Command, FragmentSize, KeepAliveStatus, Message, Reassembler,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

/// How the fake answers one request.
#[derive(Debug, Clone)]
pub enum Reply {
    /// A well-formed CTAP response.
    Ctap(ctap::Response),
    /// `count` keepalives, then the wrapped reply.
    KeepalivesThen {
        /// How many keepalives to send first.
        count: usize,
        /// What the keepalives say.
        status: KeepAliveStatus,
        /// What follows them.
        then: Box<Reply>,
    },
    /// Keepalives forever. The client's timeout is the only way out.
    KeepaliveForever(KeepAliveStatus),
    /// A transport-level `ERROR`.
    BleError(BleErrorCode),
    /// Nothing at all, ever.
    Silent,
    /// A valid response whose continuation fragments arrive out of order.
    Reordered(ctap::Response),
    /// A response cut off after `fragments` fragments.
    Truncated {
        /// The response that gets cut off.
        response: ctap::Response,
        /// How many fragments actually arrive.
        fragments: usize,
    },
    /// One fragment longer than the transport's ceiling.
    ///
    /// Deliberately beyond `MAX_FRAGMENT_SIZE` rather than merely beyond the
    /// advertised `fidoControlPointLength`: the latter bounds writes to the
    /// control point, not notifications, so it is not a limit the reassembler
    /// may enforce.
    OversizedFragment,
    /// Exactly these fragments, for cases the variants above do not cover.
    Raw(Vec<Vec<u8>>),

    /// Answers according to the CTAP command byte in the request.
    ///
    /// The other variants are scripted in advance, which is right for framing
    /// tests but useless when the request order is decided by whatever client
    /// happens to connect.
    ByCtapCommand {
        /// Response body for `authenticatorMakeCredential`.
        make_credential: Vec<u8>,
        /// Response body for `authenticatorGetAssertion`.
        get_assertion: Vec<u8>,
    },
}

/// What the fake saw and what it has left to say.
#[derive(Debug)]
pub struct FakeState {
    /// Every complete message the daemon sent, in order. Tests assert on this —
    /// notably that a `CANCEL` follows a timeout.
    pub received: Vec<Message>,
    script: VecDeque<Reply>,
    outbox: VecDeque<Vec<u8>>,
    repeat: Option<Vec<u8>>,
    fragment_size: FragmentSize,
    response_fragment_size: FragmentSize,
    link: LinkState,
    rx: Reassembler,
}

impl FakeState {
    /// The commands of every message received, for terser assertions.
    pub fn received_commands(&self) -> Vec<Command> {
        self.received.iter().map(|m| m.command).collect()
    }
}

/// A fake CTAP BLE device.
#[derive(Debug, Clone)]
pub struct FakeDevice {
    state: Arc<Mutex<FakeState>>,
}

impl FakeDevice {
    /// A device that advertises `fragment_size` and works through `script`, one
    /// reply per request.
    pub fn new(fragment_size: FragmentSize, script: Vec<Reply>) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState {
                received: Vec::new(),
                script: script.into(),
                outbox: VecDeque::new(),
                repeat: None,
                fragment_size,
                response_fragment_size: fragment_size,
                link: LinkState::READY,
                rx: Reassembler::new(),
            })),
        }
    }

    /// A device that answers every request the same way.
    pub fn always(fragment_size: FragmentSize, reply: Reply) -> Self {
        Self::new(fragment_size, vec![reply; 16])
    }

    /// Fragments its responses at `size` rather than at the advertised size.
    ///
    /// Under-filling is legal — `HLEN` is authoritative — so the daemon has to
    /// cope with a device that fragments differently from the way we do.
    pub fn with_response_fragment_size(self, size: FragmentSize) -> Self {
        self.state
            .lock()
            .expect("fake state")
            .response_fragment_size = size;
        self
    }

    /// Overrides the link state, for the bonding checks in §15.2.
    pub fn with_link(self, link: LinkState) -> Self {
        self.state.lock().expect("fake state").link = link;
        self
    }

    /// A handle for inspecting what the fake saw.
    pub fn state(&self) -> Arc<Mutex<FakeState>> {
        Arc::clone(&self.state)
    }
}

/// Turns a reply into the fragments the device will notify.
fn render(
    reply: &Reply,
    size: FragmentSize,
    out: &mut VecDeque<Vec<u8>>,
    request: &[u8],
) -> Option<Vec<u8>> {
    let emit = |message: &Message, out: &mut VecDeque<Vec<u8>>| {
        if let Ok(frags) = fragments(message, size) {
            out.extend(frags);
        }
    };

    match reply {
        Reply::Ctap(response) => {
            emit(&Message::new(Command::Msg, response.encode()), out);
            None
        }
        Reply::KeepalivesThen {
            count,
            status,
            then,
        } => {
            for _ in 0..*count {
                emit(&Message::new(Command::KeepAlive, vec![status.as_u8()]), out);
            }
            render(then, size, out, request)
        }
        Reply::KeepaliveForever(status) => {
            let message = Message::new(Command::KeepAlive, vec![status.as_u8()]);
            fragments(&message, size).ok().and_then(|mut f| f.next())
        }
        Reply::BleError(code) => {
            emit(&Message::new(Command::Error, vec![code.as_u8()]), out);
            None
        }
        Reply::Silent => None,
        Reply::Reordered(response) => {
            let message = Message::new(Command::Msg, response.encode());
            if let Ok(frags) = fragments(&message, size) {
                let mut frags: Vec<_> = frags.collect();
                if frags.len() >= 3 {
                    frags.swap(1, 2);
                }
                out.extend(frags);
            }
            None
        }
        Reply::Truncated {
            response,
            fragments: keep,
        } => {
            let message = Message::new(Command::Msg, response.encode());
            if let Ok(frags) = fragments(&message, size) {
                out.extend(frags.take(*keep));
            }
            None
        }
        Reply::OversizedFragment => {
            let over = ble_framing::MAX_FRAGMENT_SIZE as usize + 1;
            let mut fragment = vec![Command::Msg.as_u8(), 0x00, 0x01];
            fragment.resize(over, 0xaa);
            out.push_back(fragment);
            None
        }
        Reply::Raw(frags) => {
            out.extend(frags.iter().cloned());
            None
        }
        Reply::ByCtapCommand {
            make_credential,
            get_assertion,
        } => {
            // The first byte of a CTAP request is the command.
            let response = match request.first() {
                Some(0x01) => ctap::Response::new(ctap::StatusCode::OK, make_credential.clone()),
                Some(0x02) => ctap::Response::new(ctap::StatusCode::OK, get_assertion.clone()),
                // Anything else, including getInfo, is refused rather than
                // answered with something plausible-looking.
                _ => ctap::Response::error(ctap::StatusCode::INVALID_COMMAND),
            };
            // A CTAP response is a status byte followed by CBOR, never bare
            // CBOR — encode() is what puts the status on.
            emit(&Message::new(Command::Msg, response.encode()), out);
            None
        }
    }
}

#[async_trait::async_trait]
impl FragmentTransport for FakeDevice {
    async fn fragment_size(&mut self) -> Result<FragmentSize, TransportError> {
        Ok(self.state.lock().expect("fake state").fragment_size)
    }

    async fn write_fragment(&mut self, fragment: &[u8]) -> Result<(), TransportError> {
        let mut state = self.state.lock().expect("fake state");

        // A real device would reject this at the ATT layer.
        if fragment.len() > state.fragment_size.get() as usize {
            return Err(TransportError::Gatt(format!(
                "fragment of {} bytes exceeds the advertised {}",
                fragment.len(),
                state.fragment_size.get()
            )));
        }

        let Ok(Some(message)) = state.rx.push(fragment) else {
            // The daemon sent something malformed. Say nothing and let it time
            // out, which is what a real device that could not parse us would do.
            return Ok(());
        };
        let command = message.command;
        state.received.push(message);

        // CANCEL is an instruction, not a request; it gets no reply and must not
        // consume a scripted one.
        if command == Command::Cancel {
            state.outbox.clear();
            state.repeat = None;
            return Ok(());
        }

        if let Some(reply) = state.script.pop_front() {
            let size = state.response_fragment_size;
            let request = state
                .received
                .last()
                .map(|m| m.payload.clone())
                .unwrap_or_default();
            let mut outbox = std::mem::take(&mut state.outbox);
            let repeat = render(&reply, size, &mut outbox, &request);
            state.outbox = outbox;
            state.repeat = repeat;
        }
        Ok(())
    }

    async fn next_notification(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            let repeated = {
                let mut state = self.state.lock().expect("fake state");
                if let Some(fragment) = state.outbox.pop_front() {
                    return Ok(fragment);
                }
                state.repeat.clone()
            };
            if let Some(fragment) = repeated {
                // A device repeating itself paces its notifications; without a
                // gap here the caller's deadline could never be reached.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                return Ok(fragment);
            }
            // Nothing to say. A silent device is a real failure mode, and the
            // caller's deadline is what rescues it.
            std::future::pending::<()>().await;
        }
    }

    fn link(&self) -> LinkState {
        self.state.lock().expect("fake state").link
    }
}
