//! A software **vicc** (virtual ICC) that reproduces the Cryptick Token
//! firmware's PIV applet — `core/piv/piv.c` in the `cryptick-token-code`
//! repository — at the APDU level.
//!
//! # What this is
//!
//! [`FirmwareCard`] is a line-by-line transliteration of `piv_handle_apdu()`
//! and its helpers, read from `core/piv/piv.c` on the `cryptick-token-code`
//! side. First transcribed from a checkout at commit `3002531`
//! (2026-10-17); that checkout turned out to be stale relative to this
//! machine's actual current firmware tree by exactly one change — a
//! `diff` against the live file turned up a single hunk, in the
//! extended-length-APDU branch of the header parser (see
//! [`parse_header`]'s doc comment for what changed and why). Every other
//! line of `piv_handle_apdu()` is byte-for-byte identical between the two,
//! so the rest of this module's transcription stands as originally
//! written. It is not a generic PIV card and
//! does not aim to be SP 800-73-5 conformant in general — it reproduces
//! *this device's* applet: its exact status words, its exact TLV shapes, its
//! exact command-chaining and `GET RESPONSE` chunking, and its exact gating
//! (PIN, then user presence) on `GENERATE ASYMMETRIC KEY PAIR` and
//! `GENERAL AUTHENTICATE`.
//!
//! Every method here cites the C function and line range it mirrors so a
//! firmware change can be diffed against this file directly, per
//! `cryptick-token-daemon`'s own PROJECT.md §20 ("verify constants against
//! the specification, not against the other side's code" — here the
//! "specification" is the firmware we are standing in for, named as such).
//!
//! # What this is not
//!
//! No cryptography. `GENERATE ASYMMETRIC KEY PAIR` and `GENERAL AUTHENTICATE`
//! return well-formed but synthetic key material and signatures — the same
//! approach `crates/piv`'s own `SimulatedCard` (used for provisioning
//! dry-runs) already takes. A response's *shape* (TLV tags, lengths, status
//! words) is faithful to the firmware; its cryptographic *content* is not,
//! and nothing here should be used to validate a signature against a real
//! public key. See `NOTES.md` for exactly what this does and does not prove.
//!
//! No I/O, no transport, no async. This crate is deliberately at the same
//! layer as `crates/piv` and `crates/vpcd`: a pure function of bytes in to
//! bytes out ([`FirmwareCard::handle_apdu`]), so it can be dropped into any
//! transport — the daemon's real `transport_ble::PivBleTransport` mock, a
//! bespoke `PivCardTransport`, or a unit test — without pulling in tokio or
//! BLE types.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;

// --- Constants, transcribed from core/piv/piv.h ----------------------------

/// `SELECT`.
pub const INS_SELECT: u8 = 0xA4;
/// `GET RESPONSE`.
pub const INS_GET_RESPONSE: u8 = 0xC0;
/// `GET DATA`.
pub const INS_GET_DATA: u8 = 0xCB;
/// `PUT DATA`.
pub const INS_PUT_DATA: u8 = 0xDB;
/// `VERIFY`.
pub const INS_VERIFY: u8 = 0x20;
/// `CHANGE REFERENCE DATA`.
pub const INS_CHANGE_REFERENCE: u8 = 0x24;
/// `GENERATE ASYMMETRIC KEY PAIR`.
pub const INS_GENERATE_KEYPAIR: u8 = 0x47;
/// `GENERAL AUTHENTICATE`.
pub const INS_GENERAL_AUTHENTICATE: u8 = 0x87;

/// `9A` — PIV Authentication.
pub const SLOT_AUTHENTICATION: u8 = 0x9A;
/// `9C` — Digital Signature.
pub const SLOT_SIGNATURE: u8 = 0x9C;
/// `9D` — Key Management.
pub const SLOT_KEY_MANAGEMENT: u8 = 0x9D;
/// `9E` — Card Authentication. The one slot that signs without a PIN.
pub const SLOT_CARD_AUTH: u8 = 0x9E;

/// Card Capability Container.
pub const OBJ_CCC: u32 = 0x5F_C107;
/// Card Holder Unique Identifier.
pub const OBJ_CHUID: u32 = 0x5F_C102;
/// Certificate, slot 9A.
pub const OBJ_CERT_9A: u32 = 0x5F_C105;
/// Certificate, slot 9C.
pub const OBJ_CERT_9C: u32 = 0x5F_C10A;
/// Certificate, slot 9D.
pub const OBJ_CERT_9D: u32 = 0x5F_C10B;
/// Certificate, slot 9E.
pub const OBJ_CERT_9E: u32 = 0x5F_C101;

const SW_OK: u16 = 0x9000;
const SW_WRONG_LENGTH: u16 = 0x6700;
const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
const SW_AUTH_BLOCKED: u16 = 0x6983;
const SW_WRONG_DATA: u16 = 0x6A80;
const SW_NOT_FOUND: u16 = 0x6A82;
const SW_WRONG_P1P2: u16 = 0x6A86;
const SW_INS_UNSUPPORTED: u16 = 0x6D00;
const SW_CLA_UNSUPPORTED: u16 = 0x6E00;

/// `63Cx`, VERIFY/CHANGE REFERENCE DATA failed, `retries` attempts remain.
const fn sw_verify_failed(retries: u8) -> u16 {
    0x63C0 | (retries & 0x0F) as u16
}

const PIV_AID: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];
const PIV_AID_MIN_LEN: usize = 9;
const PIV_AID_LEN: usize = 11;

const PIN_BLOCK_LEN: usize = 8;
const PIN_MIN_LEN: usize = 6;
const PIN_MAX_LEN: usize = 8;
const PIN_MAX_RETRIES: u8 = 3;

/// `piv.h`'s `PIV_MAX_CHAIN`: the largest command body a command chain may
/// assemble.
const MAX_CHAIN: usize = 2048;

/// `piv.h`'s `PIV_PUBKEY_LEN`: an uncompressed P-256 point, `04 || X || Y`.
const PUBKEY_LEN: usize = 65;

/// `piv.h`'s `PIV_GUID_LEN`.
const GUID_LEN: usize = 16;

/// Set in CLA to mark "more of this command follows" (ISO 7816-4 command
/// chaining).
const CLA_CHAIN: u8 = 0x10;

// --- BER-TLV helpers, transliterated from piv.c's tlv_get_len/tlv_put_len --

/// Reads a BER length at `buf[*off]`, advancing `*off` past it.
///
/// Mirrors `tlv_get_len()`, `piv.c` lines 128-149, exactly: it accepts the
/// short form and the `0x81`/`0x82` long forms only. `0x83` and above —
/// legal BER, never emitted or expected by this applet — are refused, the
/// same as an indefinite length would be. This is deliberately *not* the
/// more permissive reader in `crates/piv::tlv`: that crate parses BER-TLV in
/// general; this function parses exactly what the firmware's bespoke, hand
/// -rolled reader parses, including what it does not accept.
fn tlv_get_len(buf: &[u8], off: &mut usize) -> Option<usize> {
    let b = *buf.get(*off)?;
    *off += 1;
    if b < 0x80 {
        return Some(b as usize);
    }
    if b == 0x81 {
        let v = *buf.get(*off)? as usize;
        *off += 1;
        return Some(v);
    }
    if b == 0x82 {
        let hi = *buf.get(*off)? as usize;
        let lo = *buf.get(*off + 1)? as usize;
        *off += 2;
        return Some((hi << 8) | lo);
    }
    None
}

/// Writes a BER length the way `tlv_put_len()` does, `piv.c` lines 103-121.
fn tlv_put_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

/// `GET DATA`'s object id, from a `5C` tag-list. Mirrors `parse_object_tag()`,
/// `piv.c` lines 188-205.
fn parse_object_tag(data: &[u8]) -> Option<u32> {
    if data.len() < 2 || data[0] != 0x5C {
        return None;
    }
    let mut off = 1;
    let tl = tlv_get_len(data, &mut off)?;
    if tl == 0 || tl > 3 || off + tl > data.len() {
        return None;
    }
    let mut tag: u32 = 0;
    for &b in &data[off..off + tl] {
        tag = (tag << 8) | b as u32;
    }
    Some(tag)
}

/// The eight-byte PIN block, stripped of its `FF`/`00` padding. Mirrors
/// `pin_block_len()`, `piv.c` lines 568-579: scans up to `PIN_BLOCK_LEN`
/// bytes (regardless of how much of `block` is supplied) and stops at the
/// first padding byte, then requires the unpadded run to be 6-8 bytes.
fn pin_block_len(block: &[u8]) -> usize {
    if block.len() < PIN_MIN_LEN {
        return 0;
    }
    let mut n = 0usize;
    while n < block.len() && n < PIN_BLOCK_LEN && block[n] != 0xFF && block[n] != 0x00 {
        n += 1;
    }
    if (PIN_MIN_LEN..=PIN_MAX_LEN).contains(&n) {
        n
    } else {
        0
    }
}

/// The last-parsed ISO 7816-4 case, used only to size the TLV walker loops
/// in `general_authenticate`/`generate_keypair` identically to the C code's
/// `while (off + 1 < end)`.
struct ParsedHeader {
    data: Option<Vec<u8>>,
    le: usize,
}

/// A response the card is still delivering across `GET RESPONSE` calls.
/// Mirrors the file-scope `_pending`/`_pending_len`/`_pending_off` triple,
/// `piv.c` lines 39-41.
struct Pending {
    data: Vec<u8>,
    offset: usize,
}

/// A software stand-in for the Cryptick Token's PIV applet.
///
/// Construct with [`FirmwareCard::new`], feed it whole command APDUs with
/// [`FirmwareCard::handle_apdu`], and read back whole response APDUs
/// (data field plus the trailing two-byte status word, exactly as
/// `piv_handle_apdu()` fills its `out` buffer).
pub struct FirmwareCard {
    pin: Vec<u8>,
    pin_verified: bool,
    retries: u8,
    objects: HashMap<u32, Vec<u8>>,
    /// Per-slot generation counter, standing in for the device's key store.
    /// `GENERATE ASYMMETRIC KEY PAIR` increments it; the synthetic public
    /// key is derived from the slot and this counter so two successive
    /// generations visibly differ, the property `piv.c`'s own HAL-backed
    /// `key_generate`/`public_key` pair provides.
    key_generation: HashMap<u8, u32>,
    guid: [u8; GUID_LEN],
    pending: Option<Pending>,
    chain: Vec<u8>,
    chain_active: bool,
    chain_ins: u8,
    chain_p1: u8,
    chain_p2: u8,
    /// Whether the next user-presence check (fingerprint, in the real
    /// device) succeeds. Defaults to `true` so PIN-gated flows can be
    /// exercised without also having to model the fingerprint ceremony;
    /// set to `false` to exercise the `GENERAL AUTHENTICATE`/
    /// `GENERATE ASYMMETRIC KEY PAIR` presence gate (PROJECT.md §15.3,
    /// `piv.c` lines 270-279 and 538-539).
    pub presence_granted: bool,
    /// Every slot a user-presence check was performed against, in order.
    /// Test-observability only; the real applet has no equivalent log.
    pub presence_calls: Vec<u8>,
}

impl Default for FirmwareCard {
    fn default() -> Self {
        Self::new()
    }
}

impl FirmwareCard {
    /// A freshly "booted" card: PIN `123456`, 3 retries, no stored objects or
    /// generated keys, presence always granted.
    ///
    /// The default PIN matches the SP 800-73 factory default this device
    /// ships with (`core/piv/piv_hal_esp32.cpp`), the same default the
    /// daemon's own `piv::provision` module assumes.
    pub fn new() -> Self {
        FirmwareCard {
            pin: b"123456".to_vec(),
            pin_verified: false,
            retries: PIN_MAX_RETRIES,
            objects: HashMap::new(),
            key_generation: HashMap::new(),
            guid: [0xAB; GUID_LEN],
            pending: None,
            chain: Vec::new(),
            chain_active: false,
            chain_ins: 0,
            chain_p1: 0,
            chain_p2: 0,
            presence_granted: true,
            presence_calls: Vec::new(),
        }
    }

    /// Whether `VERIFY` has succeeded this session. Mirrors
    /// `piv_pin_is_verified()`.
    pub fn pin_is_verified(&self) -> bool {
        self.pin_verified
    }

    /// Remaining PIN attempts.
    pub fn retries_remaining(&self) -> u8 {
        self.retries
    }

    /// Stores a data object directly, bypassing `PUT DATA` — the moral
    /// equivalent of provisioning the device before BLE/vpcd is ever
    /// reached. `contents` must already carry its `53` wrapper, as
    /// `GET DATA` returns it (`piv.c` lines 921-932).
    pub fn preload_object(&mut self, tag: u32, contents: Vec<u8>) {
        self.objects.insert(tag, contents);
    }

    /// Resets session state: PIN verification, any pending `GET RESPONSE`,
    /// and any in-progress command chain. Mirrors `piv_reset()`, called on
    /// `SELECT` and on whatever plays the role of a card reset over vpcd
    /// (`piv.c` lines 716-721).
    pub fn reset(&mut self) {
        self.pin_verified = false;
        self.pending = None;
        self.chain_active = false;
        self.chain.clear();
        self.chain_ins = 0;
        self.chain_p1 = 0;
        self.chain_p2 = 0;
    }

    /// Handles one command APDU and returns one response APDU — the data
    /// field followed by the two-byte status word, exactly the bytes
    /// `piv_handle_apdu()` would have written into `out`.
    ///
    /// Infallible: every input either executes or earns a status word, the
    /// same contract `piv_handle_apdu` has (its only failure return, `-1`,
    /// is a caller bug — a null pointer or too-small output buffer — neither
    /// of which `Vec<u8>` can manifest).
    pub fn handle_apdu(&mut self, cmd: &[u8]) -> Vec<u8> {
        // piv.c lines 727-730.
        if cmd.len() < 4 {
            return sw_bytes(SW_WRONG_LENGTH);
        }
        let cla = cmd[0];
        let ins = cmd[1];
        let p1 = cmd[2];
        let p2 = cmd[3];

        // piv.c lines 743-744. 0x0C (secure messaging) and 0x03 (logical
        // channels) are not masked off: a chained command's body is not a
        // whole body, and masking would misread it rather than refuse it.
        if cla != 0x00 && cla != CLA_CHAIN {
            return sw_bytes(SW_CLA_UNSUPPORTED);
        }

        let header = match parse_header(cmd) {
            Ok(h) => h,
            Err(sw) => return sw_bytes(sw),
        };
        let ParsedHeader { data, le } = header;

        // piv.c lines 800-806: any command but GET RESPONSE abandons a
        // pending chained response.
        if ins != INS_GET_RESPONSE && self.pending.is_some() {
            self.pending = None;
        }

        // piv.c lines 808-821: a chain that changes INS/P1/P2 is abandoned,
        // whether the arriving command continues the chain or (wrongly)
        // tries to end it.
        if self.chain_active
            && (ins != self.chain_ins || p1 != self.chain_p1 || p2 != self.chain_p2)
        {
            self.chain_clear();
            return sw_bytes(SW_WRONG_DATA);
        }

        // piv.c lines 823-841: accumulate a chain link and stop.
        if cla == CLA_CHAIN {
            let Some(data) = data else {
                self.chain_clear();
                return sw_bytes(SW_WRONG_LENGTH);
            };
            if data.is_empty() || self.chain.len() + data.len() > MAX_CHAIN {
                self.chain_clear();
                return sw_bytes(SW_WRONG_LENGTH);
            }
            if !self.chain_active {
                self.chain_active = true;
                self.chain_ins = ins;
                self.chain_p1 = p1;
                self.chain_p2 = p2;
            }
            self.chain.extend_from_slice(&data);
            return sw_bytes(SW_OK);
        }

        // piv.c lines 843-857: the final block of a chain, assembled into
        // one whole command.
        let data = if self.chain_active {
            if let Some(ref d) = data {
                if self.chain.len() + d.len() > MAX_CHAIN {
                    self.chain_clear();
                    return sw_bytes(SW_WRONG_LENGTH);
                }
                self.chain.extend_from_slice(d);
            }
            let assembled = std::mem::take(&mut self.chain);
            self.chain_active = false;
            Some(assembled)
        } else {
            data
        };

        match ins {
            INS_SELECT => self.select(p1, p2, data.as_deref(), le),
            INS_GET_RESPONSE => self.get_response(p1, p2, le),
            INS_GET_DATA => self.get_data(p1, p2, data.as_deref(), le),
            INS_PUT_DATA => self.put_data(p1, p2, data.as_deref()),
            INS_VERIFY => self.verify(p1, p2, data.as_deref()),
            INS_CHANGE_REFERENCE => self.change_reference(p1, p2, data.as_deref()),
            INS_GENERATE_KEYPAIR => self.generate_keypair(p1, p2, data.as_deref(), le),
            INS_GENERAL_AUTHENTICATE => match data {
                Some(ref d) => self.general_authenticate(p1, p2, d, le),
                None => sw_bytes(SW_WRONG_DATA),
            },
            _ => sw_bytes(SW_INS_UNSUPPORTED),
        }
    }

    fn chain_clear(&mut self) {
        self.chain.clear();
        self.chain_active = false;
        self.chain_ins = 0;
        self.chain_p1 = 0;
        self.chain_p2 = 0;
    }

    /// Starts (or restarts) a chained response, truncated to `le` bytes.
    /// Mirrors `respond()`, `piv.c` lines 88-98.
    fn respond(&mut self, data: Vec<u8>, le: usize) -> Vec<u8> {
        let le = if le == 0 { 256 } else { le };
        self.pending = Some(Pending { data, offset: 0 });
        self.emit_pending(le)
    }

    /// Emits up to `le` bytes of the pending response. Mirrors
    /// `emit_pending()`, `piv.c` lines 62-86.
    fn emit_pending(&mut self, le: usize) -> Vec<u8> {
        let Some(pending) = &self.pending else {
            // Unreachable from handle_apdu (GET_RESPONSE checks first), kept
            // total for safety.
            return sw_bytes(SW_INS_UNSUPPORTED);
        };
        let remaining_before = pending.data.len() - pending.offset;
        let chunk = remaining_before.min(le);
        let start = pending.offset;
        let out_data = pending.data[start..start + chunk].to_vec();

        let pending = self.pending.as_mut().expect("checked above");
        pending.offset += chunk;
        let remaining_after = pending.data.len() - pending.offset;

        let mut out = out_data;
        if remaining_after == 0 {
            self.pending = None;
            out.extend_from_slice(&SW_OK.to_be_bytes());
        } else {
            let sw2 = if remaining_after > 255 {
                0
            } else {
                remaining_after as u8
            };
            out.push(0x61);
            out.push(sw2);
        }
        out
    }

    /// `SELECT`. Mirrors the `PIV_INS_SELECT` arm, `piv.c` lines 860-877,
    /// and `select_response()`, lines 158-180.
    fn select(&mut self, p1: u8, p2: u8, data: Option<&[u8]>, le: usize) -> Vec<u8> {
        if p1 != 0x04 || p2 != 0x00 {
            return sw_bytes(SW_WRONG_P1P2);
        }
        let Some(data) = data else {
            return sw_bytes(SW_NOT_FOUND);
        };
        // Prefix match against the full AID (ISO 7816-4 P1=0x04): the real
        // client sends the 9-byte right-truncated AID, and this device's
        // own test suite (tests/host/test_piv_apdu.py) requires every
        // length from 9 to 11 to work.
        if data.len() < PIV_AID_MIN_LEN
            || data.len() > PIV_AID_LEN
            || data != &PIV_AID[..data.len()]
        {
            return sw_bytes(SW_NOT_FOUND);
        }
        self.reset();
        self.select_response(le)
    }

    fn select_response(&mut self, le: usize) -> Vec<u8> {
        let mut body = vec![0x61, 0x00, 0x4F, 0x09];
        body.extend_from_slice(&PIV_AID[..9]);
        body.extend_from_slice(&[0x79, 0x07, 0x4F, 0x05]);
        body.extend_from_slice(&PIV_AID[..5]);
        let len = body.len() - 2;
        body[1] = len as u8;
        self.respond(body, le)
    }

    /// `GET RESPONSE`. Mirrors the `PIV_INS_GET_RESPONSE` arm, `piv.c`
    /// lines 879-885.
    fn get_response(&mut self, p1: u8, p2: u8, le: usize) -> Vec<u8> {
        if self.pending.is_none() {
            return sw_bytes(SW_INS_UNSUPPORTED);
        }
        if p1 != 0x00 || p2 != 0x00 {
            return sw_bytes(SW_WRONG_P1P2);
        }
        self.emit_pending(if le == 0 { 256 } else { le })
    }

    /// `GET DATA`. Mirrors the `PIV_INS_GET_DATA` arm, `piv.c` lines
    /// 887-908, falling back to [`FirmwareCard::synthesize_object`] for
    /// CCC/CHUID exactly as `synthesize_object()` does.
    fn get_data(&mut self, p1: u8, p2: u8, data: Option<&[u8]>, le: usize) -> Vec<u8> {
        if p1 != 0x3F || p2 != 0xFF {
            return sw_bytes(SW_WRONG_P1P2);
        }
        let Some(tag) = data.and_then(parse_object_tag) else {
            return sw_bytes(SW_WRONG_DATA);
        };
        if let Some(obj) = self.objects.get(&tag) {
            if !obj.is_empty() {
                return self.respond(obj.clone(), le);
            }
        }
        if let Some(synthesized) = self.synthesize_object(tag) {
            return self.respond(synthesized, le);
        }
        sw_bytes(SW_NOT_FOUND)
    }

    /// CCC and CHUID, built on demand when nothing is stored. Mirrors
    /// `synthesize_object()`/`build_chuid()`/`build_ccc()`, `piv.c` lines
    /// 337-478. A stored object always wins (checked by the caller before
    /// this is reached), matching "Nothing is spent in flash unless someone
    /// provisions a real one".
    fn synthesize_object(&self, tag: u32) -> Option<Vec<u8>> {
        match tag {
            OBJ_CHUID => Some(self.build_chuid()),
            OBJ_CCC => Some(self.build_ccc()),
            _ => None,
        }
    }

    fn build_chuid(&self) -> Vec<u8> {
        // FASC-N placeholder for a non-federal issuer, piv.c lines 371-375.
        const FASCN: [u8; 25] = [
            0xD4, 0xE7, 0x39, 0xDA, 0x50, 0x1C, 0xA0, 0x5C, 0x17, 0x94, 0x58, 0x21, 0x08, 0x42,
            0x10, 0xC3, 0xF5, 0x34, 0x10, 0xC3, 0xF5, 0x34, 0x10, 0xC3, 0xF5,
        ];
        // Far-future expiry, piv.c lines 377-383.
        const EXPIRY: &[u8; 8] = b"20500101";

        let mut body = Vec::new();
        tlv_append(&mut body, 0x30, &FASCN);
        tlv_append(&mut body, 0x34, &self.guid);
        tlv_append(&mut body, 0x35, EXPIRY);
        tlv_append(&mut body, 0x3E, &[]); // issuer signature: empty, honestly
        tlv_append(&mut body, 0xFE, &[]); // error detection code: empty

        wrap_53(&body)
    }

    fn build_ccc(&self) -> Vec<u8> {
        const GSC_RID: [u8; 6] = [0xA0, 0x00, 0x00, 0x01, 0x16, 0xFF];
        let mut card_id = GSC_RID.to_vec();
        card_id.extend_from_slice(&self.guid[..21 - GSC_RID.len()]);

        let mut body = Vec::new();
        tlv_append(&mut body, 0xF0, &card_id);
        tlv_append(&mut body, 0xF1, &[0x21]); // container + grammar version
        tlv_append(&mut body, 0xF2, &[0x21]);
        tlv_append(&mut body, 0xF3, &[]);
        tlv_append(&mut body, 0xF4, &[0x00]); // no PKCS#15
        tlv_append(&mut body, 0xF5, &[0x10]); // registered data model
        for tag in [0xF6u8, 0xF7, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE] {
            tlv_append(&mut body, tag, &[]);
        }

        wrap_53(&body)
    }

    /// `PUT DATA`. Mirrors the `PIV_INS_PUT_DATA` arm, `piv.c` lines
    /// 910-949: stores the whole `53 LL <value>` container, wrapper
    /// included, exactly as a stored object is read back by `GET DATA`.
    fn put_data(&mut self, p1: u8, p2: u8, data: Option<&[u8]>) -> Vec<u8> {
        if p1 != 0x3F || p2 != 0xFF {
            return sw_bytes(SW_WRONG_P1P2);
        }
        if !self.pin_verified {
            return sw_bytes(SW_SECURITY_NOT_SATISFIED);
        }
        let Some(data) = data else {
            return sw_bytes(SW_WRONG_DATA);
        };
        let Some(tag) = parse_object_tag(data) else {
            return sw_bytes(SW_WRONG_DATA);
        };

        // Skip the already-parsed 5C tag-list element to find the 53
        // container that follows it (piv.c lines 932-947).
        let mut off = 1usize;
        let Some(tl) = tlv_get_len(data, &mut off) else {
            return sw_bytes(SW_WRONG_DATA);
        };
        off += tl;
        if off + 1 >= data.len() || data[off] != 0x53 {
            return sw_bytes(SW_WRONG_DATA);
        }
        let container_start = off;
        off += 1;
        let Some(vlen) = tlv_get_len(data, &mut off) else {
            return sw_bytes(SW_WRONG_DATA);
        };
        if off + vlen > data.len() {
            return sw_bytes(SW_WRONG_DATA);
        }
        let container = data[container_start..off + vlen].to_vec();
        self.objects.insert(tag, container);
        sw_bytes(SW_OK)
    }

    /// `VERIFY`. Mirrors `verify()`, `piv.c` lines 581-644.
    fn verify(&mut self, p1: u8, p2: u8, data: Option<&[u8]>) -> Vec<u8> {
        if p2 != 0x80 {
            return sw_bytes(SW_WRONG_P1P2);
        }
        if p1 == 0xFF {
            if data.is_some_and(|d| !d.is_empty()) {
                return sw_bytes(SW_WRONG_LENGTH);
            }
            self.pin_verified = false;
            return sw_bytes(SW_OK);
        }
        if p1 != 0x00 {
            return sw_bytes(SW_WRONG_P1P2);
        }

        let data = data.unwrap_or(&[]);
        if data.is_empty() {
            if self.retries == 0 {
                return sw_bytes(SW_AUTH_BLOCKED);
            }
            return if self.pin_verified {
                sw_bytes(SW_OK)
            } else {
                sw_bytes(sw_verify_failed(self.retries))
            };
        }

        if self.retries == 0 {
            return sw_bytes(SW_AUTH_BLOCKED);
        }
        if data.len() < PIN_MIN_LEN || data.len() > PIN_BLOCK_LEN {
            return sw_bytes(SW_WRONG_LENGTH);
        }
        let pin_len = pin_block_len(data);
        if pin_len == 0 {
            return sw_bytes(SW_WRONG_DATA);
        }

        if data[..pin_len] == self.pin[..] {
            self.pin_verified = true;
            self.retries = PIN_MAX_RETRIES;
            return sw_bytes(SW_OK);
        }

        self.pin_verified = false;
        self.retries -= 1;
        if self.retries == 0 {
            sw_bytes(SW_AUTH_BLOCKED)
        } else {
            sw_bytes(sw_verify_failed(self.retries))
        }
    }

    /// `CHANGE REFERENCE DATA`. Mirrors `change_reference()`, `piv.c` lines
    /// 655-699.
    fn change_reference(&mut self, p1: u8, p2: u8, data: Option<&[u8]>) -> Vec<u8> {
        if p1 != 0x00 || p2 != 0x80 {
            return sw_bytes(SW_WRONG_P1P2);
        }
        if self.retries == 0 {
            return sw_bytes(SW_AUTH_BLOCKED);
        }
        let Some(data) = data else {
            return sw_bytes(SW_WRONG_LENGTH);
        };
        if data.len() != 2 * PIN_BLOCK_LEN {
            return sw_bytes(SW_WRONG_LENGTH);
        }
        let old_len = pin_block_len(&data[..PIN_BLOCK_LEN]);
        let new_len = pin_block_len(&data[PIN_BLOCK_LEN..]);
        if old_len == 0 || new_len == 0 {
            return sw_bytes(SW_WRONG_DATA);
        }

        if data[..old_len] != self.pin[..] {
            self.pin_verified = false;
            self.retries -= 1;
            return if self.retries == 0 {
                sw_bytes(SW_AUTH_BLOCKED)
            } else {
                sw_bytes(sw_verify_failed(self.retries))
            };
        }

        self.pin = data[PIN_BLOCK_LEN..PIN_BLOCK_LEN + new_len].to_vec();
        self.pin_verified = true;
        self.retries = PIN_MAX_RETRIES;
        sw_bytes(SW_OK)
    }

    /// `GENERATE ASYMMETRIC KEY PAIR`. Mirrors `generate_keypair()`,
    /// `piv.c` lines 492-564.
    ///
    /// Gated on a verified PIN *then* user presence, in that order — the
    /// same order `piv.c` checks them in, and worth keeping in that order
    /// because a test that only ever grants presence would not notice the
    /// gates being swapped.
    fn generate_keypair(&mut self, p1: u8, slot: u8, data: Option<&[u8]>, le: usize) -> Vec<u8> {
        if p1 != 0x00 {
            return sw_bytes(SW_WRONG_P1P2);
        }
        if !is_known_slot(slot) {
            return sw_bytes(SW_WRONG_P1P2);
        }
        let Some(data) = data else {
            return sw_bytes(SW_WRONG_DATA);
        };
        if data.len() < 5 || data[0] != 0xAC {
            return sw_bytes(SW_WRONG_DATA);
        }
        let mut off = 1usize;
        let Some(tl) = tlv_get_len(data, &mut off) else {
            return sw_bytes(SW_WRONG_DATA);
        };
        if off + tl > data.len() {
            return sw_bytes(SW_WRONG_DATA);
        }
        let end = off + tl;
        let mut alg_seen = false;
        while off + 1 < end {
            let t = data[off];
            off += 1;
            let Some(l) = tlv_get_len(data, &mut off) else {
                return sw_bytes(SW_WRONG_DATA);
            };
            if off + l > end {
                return sw_bytes(SW_WRONG_DATA);
            }
            if t == 0x80 {
                if l != 1 || data[off] != 0x11 {
                    return sw_bytes(SW_WRONG_P1P2);
                }
                alg_seen = true;
            }
            off += l;
        }
        if !alg_seen {
            return sw_bytes(SW_WRONG_DATA);
        }

        if !self.pin_verified {
            return sw_bytes(SW_SECURITY_NOT_SATISFIED);
        }
        self.presence_calls.push(slot);
        if !self.presence_granted {
            return sw_bytes(SW_SECURITY_NOT_SATISFIED);
        }

        let generation = self.key_generation.entry(slot).or_insert(0);
        *generation += 1;
        let point = synthetic_public_key(slot, *generation);

        let mut body = vec![0x7F, 0x49];
        let mut inner = vec![0x86];
        tlv_put_len(&mut inner, PUBKEY_LEN);
        inner.extend_from_slice(&point);
        tlv_put_len(&mut body, inner.len());
        body.extend_from_slice(&inner);

        self.respond(body, le)
    }

    /// `GENERAL AUTHENTICATE`. Mirrors `general_authenticate()`, `piv.c`
    /// lines 214-333. Implements the ECDSA-sign path (tag `81`, the only
    /// path this daemon's `piv::provision` module drives) and the ECDH
    /// path (tag `85`) with synthetic output; see the module docs for what
    /// "synthetic" means here.
    fn general_authenticate(&mut self, alg: u8, slot: u8, data: &[u8], le: usize) -> Vec<u8> {
        if alg != 0x11 {
            return sw_bytes(SW_WRONG_P1P2);
        }
        if !is_known_slot(slot) {
            return sw_bytes(SW_WRONG_P1P2);
        }
        if data.len() < 2 || data[0] != 0x7C {
            return sw_bytes(SW_WRONG_DATA);
        }
        let mut off = 1usize;
        let Some(tmpl_len) = tlv_get_len(data, &mut off) else {
            return sw_bytes(SW_WRONG_DATA);
        };
        if off + tmpl_len > data.len() {
            return sw_bytes(SW_WRONG_DATA);
        }
        let end = off + tmpl_len;

        let mut challenge: Option<&[u8]> = None;
        let mut peer_pub: Option<&[u8]> = None;
        while off + 1 < end {
            let t = data[off];
            off += 1;
            let Some(l) = tlv_get_len(data, &mut off) else {
                return sw_bytes(SW_WRONG_DATA);
            };
            if off + l > end {
                return sw_bytes(SW_WRONG_DATA);
            }
            if t == 0x81 {
                challenge = Some(&data[off..off + l]);
            } else if t == 0x85 {
                peer_pub = Some(&data[off..off + l]);
            }
            off += l;
        }
        if challenge.is_none() && peer_pub.is_none() {
            return sw_bytes(SW_WRONG_DATA);
        }

        // 9E signs without a PIN (contactless door access); every other
        // slot is a login credential (piv.c lines 265-271).
        if slot != SLOT_CARD_AUTH && !self.pin_verified {
            return sw_bytes(SW_SECURITY_NOT_SATISFIED);
        }
        self.presence_calls.push(slot);
        if !self.presence_granted {
            return sw_bytes(SW_SECURITY_NOT_SATISFIED);
        }

        if let Some(peer_pub) = peer_pub {
            if peer_pub.len() != PUBKEY_LEN || peer_pub[0] != 0x04 {
                return sw_bytes(SW_WRONG_DATA);
            }
            let shared = synthetic_shared_secret(slot, peer_pub);
            let mut body = vec![0x7C, 0x22, 0x82, 0x20];
            body.extend_from_slice(&shared);
            return self.respond(body, le);
        }

        let challenge = challenge.expect("checked above: one of the two is Some");
        if challenge.len() != 32 {
            return sw_bytes(SW_WRONG_DATA);
        }
        let der = synthetic_signature(slot, challenge);

        let mut inner = vec![0x82];
        tlv_put_len(&mut inner, der.len());
        inner.extend_from_slice(&der);
        let mut body = vec![0x7C];
        tlv_put_len(&mut body, inner.len());
        body.extend_from_slice(&inner);

        self.respond(body, le)
    }
}

fn is_known_slot(slot: u8) -> bool {
    matches!(
        slot,
        SLOT_AUTHENTICATION | SLOT_SIGNATURE | SLOT_KEY_MANAGEMENT | SLOT_CARD_AUTH
    )
}

fn sw_bytes(sw: u16) -> Vec<u8> {
    sw.to_be_bytes().to_vec()
}

fn tlv_append(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

fn wrap_53(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x53];
    tlv_put_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// A synthetic but well-formed uncompressed P-256 point. Not on the curve —
/// see the module docs — but the right shape and length, and visibly
/// different across generations and slots.
fn synthetic_public_key(slot: u8, generation: u32) -> [u8; PUBKEY_LEN] {
    let mut point = [0u8; PUBKEY_LEN];
    point[0] = 0x04;
    for i in 0..32 {
        point[1 + i] = (i as u8)
            .wrapping_add(slot)
            .wrapping_add((generation as u8).wrapping_mul(31));
    }
    for i in 0..32 {
        point[33 + i] = !(i as u8)
            .wrapping_add(slot)
            .wrapping_add((generation as u8).wrapping_mul(31));
    }
    point
}

/// A synthetic DER ECDSA signature: `SEQUENCE { INTEGER r, INTEGER s }`,
/// correctly minimal-encoded (leading-zero stripped, re-added only to keep
/// a high bit from reading as negative), so a real ASN.1 parser accepts the
/// shape even though `r`/`s` are not a real signature over `challenge`.
fn synthetic_signature(slot: u8, challenge: &[u8]) -> Vec<u8> {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    for i in 0..32 {
        r[i] = challenge[i].wrapping_add(slot);
        s[i] = challenge[i] ^ slot ^ 0x5A;
    }
    der_sequence_of_integers(&r, &s)
}

fn synthetic_shared_secret(slot: u8, peer_pub: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = peer_pub[1 + i] ^ peer_pub[33 + i] ^ slot;
    }
    out
}

fn der_integer(out: &mut Vec<u8>, raw: &[u8; 32]) {
    let mut bytes = &raw[..];
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] < 0x80 {
        bytes = &bytes[1..];
    }
    out.push(0x02); // INTEGER
    if bytes[0] & 0x80 != 0 {
        tlv_put_len(out, bytes.len() + 1);
        out.push(0x00);
    } else {
        tlv_put_len(out, bytes.len());
    }
    out.extend_from_slice(bytes);
}

fn der_sequence_of_integers(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::new();
    der_integer(&mut body, r);
    der_integer(&mut body, s);
    let mut out = vec![0x30]; // SEQUENCE
    tlv_put_len(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

/// Parses the ISO 7816-4 header into `(data, le)`, mirroring `piv.c`'s
/// current header-parsing block exactly: the four short-form cases, plus an
/// **unconditional refusal** of extended-length encoding.
///
/// Extended-length APDUs (`cmd[4] == 0 && cmd.len() >= 7`) used to be parsed
/// here (cases 2E/3E/4E) — that was this device's actual behavior for a
/// while, and it is *not* what this applet does today. `docs/device-protocol.md`
/// states the contract plainly: "The applet accepts short APDUs only;
/// extended-length encoding is rejected with 6700." Accepting it over USB
/// CCID let that assumption quietly hold for every transport but one: a
/// certificate too big for a short `Lc` goes through `GET RESPONSE` chaining
/// (the `61xx` path), the same way on every transport, including PIV-over
/// -BLE's 261-byte ceiling, which cannot carry an extended APDU intact in the
/// first place. Parsing it here was a real protocol-contract violation, not
/// a harmless extra, which is why the fix is an unconditional `6700` and not
/// a conditional one gated on transport.
///
/// `cmd.len() >= 4` and the CLA check are the caller's responsibility
/// (checked first in both `piv_handle_apdu` and [`FirmwareCard::handle_apdu`]).
fn parse_header(cmd: &[u8]) -> Result<ParsedHeader, u16> {
    let len = cmd.len();

    if len == 4 {
        // Case 1: header only.
        return Ok(ParsedHeader { data: None, le: 0 });
    }
    if len == 5 {
        // Case 2: Le only. '00' means 256.
        let le = if cmd[4] == 0 { 256 } else { cmd[4] as usize };
        return Ok(ParsedHeader { data: None, le });
    }
    if cmd[4] == 0 && len >= 7 {
        // Extended-length encoding. No case 2E/3E/4E parsing — see the
        // function doc comment above. Unconditional refusal, matching the
        // real applet exactly: no inspection of the declared Lc, no partial
        // acceptance within whatever ceiling a given transport imposes.
        return Err(SW_WRONG_LENGTH);
    }

    // Short APDU (cases 3 and 4).
    let lc = cmd[4] as usize;
    if lc == 0 || len < 5 + lc {
        return Err(SW_WRONG_LENGTH);
    }
    let data = cmd[5..5 + lc].to_vec();
    if len == 5 + lc {
        return Ok(ParsedHeader {
            data: Some(data),
            le: 256,
        });
    }
    if len == 5 + lc + 1 {
        let le = if cmd[5 + lc] == 0 {
            256
        } else {
            cmd[5 + lc] as usize
        };
        return Ok(ParsedHeader {
            data: Some(data),
            le,
        });
    }
    Err(SW_WRONG_LENGTH)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORRECT_PIN: &[u8] = b"123456";

    fn select_short(card: &mut FirmwareCard) -> Vec<u8> {
        let mut cmd = vec![0x00, INS_SELECT, 0x04, 0x00, 0x09];
        cmd.extend_from_slice(&PIV_AID[..9]);
        card.handle_apdu(&cmd)
    }

    fn verify(card: &mut FirmwareCard, pin: &[u8]) -> u16 {
        let mut block = pin.to_vec();
        block.resize(8, 0xFF);
        let resp = card.handle_apdu(&[&[0x00, INS_VERIFY, 0x00, 0x80, 0x08], &block[..]].concat());
        status(&resp)
    }

    fn status(resp: &[u8]) -> u16 {
        let n = resp.len();
        u16::from_be_bytes([resp[n - 2], resp[n - 1]])
    }

    #[test]
    fn select_accepts_every_valid_aid_prefix_length() {
        let mut card = FirmwareCard::new();
        for len in PIV_AID_MIN_LEN..=PIV_AID_LEN {
            let mut cmd = vec![0x00, INS_SELECT, 0x04, 0x00, len as u8];
            cmd.extend_from_slice(&PIV_AID[..len]);
            assert_eq!(status(&card.handle_apdu(&cmd)), SW_OK, "len={len}");
        }
    }

    #[test]
    fn select_rejects_short_or_foreign_aid() {
        let mut card = FirmwareCard::new();
        let mut cmd = vec![0x00, INS_SELECT, 0x04, 0x00, 0x05];
        cmd.extend_from_slice(&PIV_AID[..5]);
        assert_eq!(status(&card.handle_apdu(&cmd)), SW_NOT_FOUND);
    }

    #[test]
    fn select_resets_pin_verification() {
        let mut card = FirmwareCard::new();
        select_short(&mut card);
        assert_eq!(verify(&mut card, CORRECT_PIN), SW_OK);
        assert!(card.pin_is_verified());
        select_short(&mut card);
        assert!(!card.pin_is_verified(), "re-select must reset the session");
    }

    #[test]
    fn wrong_pin_decrements_then_blocks() {
        let mut card = FirmwareCard::new();
        assert_eq!(verify(&mut card, b"999999"), 0x63C2);
        assert_eq!(verify(&mut card, b"999999"), 0x63C1);
        assert_eq!(verify(&mut card, b"999999"), SW_AUTH_BLOCKED);
        assert_eq!(
            verify(&mut card, CORRECT_PIN),
            SW_AUTH_BLOCKED,
            "a blocked PIN must stay blocked"
        );
    }

    #[test]
    fn correct_pin_restores_the_retry_counter() {
        let mut card = FirmwareCard::new();
        verify(&mut card, b"999999");
        assert_eq!(card.retries_remaining(), 2);
        assert_eq!(verify(&mut card, CORRECT_PIN), SW_OK);
        assert_eq!(card.retries_remaining(), 3);
    }

    #[test]
    fn empty_verify_queries_retries_without_spending_one() {
        let mut card = FirmwareCard::new();
        let resp = card.handle_apdu(&[0x00, INS_VERIFY, 0x00, 0x80]);
        assert_eq!(status(&resp), 0x63C3);
        assert_eq!(card.retries_remaining(), 3);
    }

    #[test]
    fn generate_requires_pin_then_presence() {
        let mut card = FirmwareCard::new();
        let gen = |c: &mut FirmwareCard| {
            let body = [0xACu8, 0x03, 0x80, 0x01, 0x11];
            c.handle_apdu(
                &[
                    &[0x00, INS_GENERATE_KEYPAIR, 0x00, SLOT_AUTHENTICATION, 0x05],
                    &body[..],
                ]
                .concat(),
            )
        };
        assert_eq!(status(&gen(&mut card)), SW_SECURITY_NOT_SATISFIED);

        verify(&mut card, CORRECT_PIN);
        card.presence_granted = false;
        assert_eq!(status(&gen(&mut card)), SW_SECURITY_NOT_SATISFIED);
        assert_eq!(card.presence_calls, vec![SLOT_AUTHENTICATION]);

        card.presence_granted = true;
        let resp = gen(&mut card);
        assert_eq!(status(&resp), SW_OK);
        assert_eq!(&resp[..2], &[0x7F, 0x49]);
    }

    #[test]
    fn generate_rolls_the_key() {
        let mut card = FirmwareCard::new();
        verify(&mut card, CORRECT_PIN);
        let body = [0xACu8, 0x03, 0x80, 0x01, 0x11];
        let cmd = [
            &[0x00, INS_GENERATE_KEYPAIR, 0x00, SLOT_AUTHENTICATION, 0x05],
            &body[..],
        ]
        .concat();
        let first = card.handle_apdu(&cmd);
        let second = card.handle_apdu(&cmd);
        assert_ne!(
            first, second,
            "generate must roll the key, not re-derive one"
        );
    }

    #[test]
    fn card_authentication_slot_signs_without_pin() {
        let mut card = FirmwareCard::new();
        let digest = [0x11u8; 32];
        let inner = [&[0x81u8, 0x20][..], &digest[..]].concat();
        let body = [&[0x7Cu8, inner.len() as u8][..], &inner[..]].concat();
        let cmd = [
            &[
                0x00,
                INS_GENERAL_AUTHENTICATE,
                0x11,
                SLOT_CARD_AUTH,
                body.len() as u8,
            ][..],
            &body[..],
        ]
        .concat();
        assert_eq!(status(&card.handle_apdu(&cmd)), SW_OK);
    }

    #[test]
    fn login_slots_never_sign_without_a_pin() {
        let mut card = FirmwareCard::new();
        let digest = [0x11u8; 32];
        let inner = [&[0x81u8, 0x20][..], &digest[..]].concat();
        let body = [&[0x7Cu8, inner.len() as u8][..], &inner[..]].concat();
        for slot in [SLOT_AUTHENTICATION, SLOT_SIGNATURE, SLOT_KEY_MANAGEMENT] {
            let cmd = [
                &[0x00, INS_GENERAL_AUTHENTICATE, 0x11, slot, body.len() as u8][..],
                &body[..],
            ]
            .concat();
            assert_eq!(
                status(&card.handle_apdu(&cmd)),
                SW_SECURITY_NOT_SATISFIED,
                "slot {slot:#x}"
            );
        }
    }

    #[test]
    fn generated_key_is_immediately_usable_for_signing() {
        let mut card = FirmwareCard::new();
        verify(&mut card, CORRECT_PIN);
        let gen_body = [0xACu8, 0x03, 0x80, 0x01, 0x11];
        let gen_cmd = [
            &[0x00, INS_GENERATE_KEYPAIR, 0x00, SLOT_AUTHENTICATION, 0x05],
            &gen_body[..],
        ]
        .concat();
        assert_eq!(status(&card.handle_apdu(&gen_cmd)), SW_OK);

        let digest = [0x22u8; 32];
        let inner = [&[0x81u8, 0x20][..], &digest[..]].concat();
        let sign_body = [&[0x7Cu8, inner.len() as u8][..], &inner[..]].concat();
        let sign_cmd = [
            &[
                0x00,
                INS_GENERAL_AUTHENTICATE,
                0x11,
                SLOT_AUTHENTICATION,
                sign_body.len() as u8,
            ][..],
            &sign_body[..],
        ]
        .concat();
        let resp = card.handle_apdu(&sign_cmd);
        assert_eq!(status(&resp), SW_OK);
        assert_eq!(resp[0], 0x7C);
    }

    #[test]
    fn chuid_is_synthesised_when_absent() {
        let mut card = FirmwareCard::new();
        let body = [0x5Cu8, 0x03, 0x5F, 0xC1, 0x02];
        let cmd = [
            &[0x00, INS_GET_DATA, 0x3F, 0xFF, body.len() as u8][..],
            &body[..],
        ]
        .concat();
        let resp = card.handle_apdu(&cmd);
        assert_eq!(status(&resp), SW_OK);
        assert_eq!(resp[0], 0x53, "must carry its 53 wrapper");
        assert_eq!(
            resp[1] as usize,
            resp.len() - 2 - 2,
            "declared length matches body"
        );
    }

    #[test]
    fn only_ccc_and_chuid_are_synthesised() {
        let mut card = FirmwareCard::new();
        for tag in [OBJ_CERT_9A, OBJ_CERT_9C, OBJ_CERT_9D, OBJ_CERT_9E] {
            let tag_bytes = [(tag >> 16) as u8, (tag >> 8) as u8, tag as u8];
            let body = [&[0x5Cu8, 0x03][..], &tag_bytes[..]].concat();
            let cmd = [
                &[0x00, INS_GET_DATA, 0x3F, 0xFF, body.len() as u8][..],
                &body[..],
            ]
            .concat();
            assert_eq!(status(&card.handle_apdu(&cmd)), SW_NOT_FOUND, "{tag:#x}");
        }
    }

    #[test]
    fn put_data_requires_pin_then_round_trips_through_get_data() {
        let mut card = FirmwareCard::new();
        let tag_bytes = [0x5Fu8, 0xC1, 0x05];
        let container = [0x53u8, 0x03, b'A', b'B', b'C'];
        let body = [&[0x5Cu8, 0x03][..], &tag_bytes[..], &container[..]].concat();
        let put_cmd = [
            &[0x00, INS_PUT_DATA, 0x3F, 0xFF, body.len() as u8][..],
            &body[..],
        ]
        .concat();

        assert_eq!(
            status(&card.handle_apdu(&put_cmd)),
            SW_SECURITY_NOT_SATISFIED
        );

        verify(&mut card, CORRECT_PIN);
        assert_eq!(status(&card.handle_apdu(&put_cmd)), SW_OK);

        let get_body = [&[0x5Cu8, 0x03][..], &tag_bytes[..]].concat();
        let get_cmd = [
            &[0x00, INS_GET_DATA, 0x3F, 0xFF, get_body.len() as u8][..],
            &get_body[..],
        ]
        .concat();
        let resp = card.handle_apdu(&get_cmd);
        assert_eq!(status(&resp), SW_OK);
        assert_eq!(&resp[..resp.len() - 2], &container[..]);
    }

    #[test]
    fn certificate_larger_than_one_response_is_chained_via_get_response() {
        let mut card = FirmwareCard::new();
        let cert: Vec<u8> = (0..900u32).map(|i| (i * 7) as u8).collect();
        let mut container = vec![0x53];
        tlv_put_len(&mut container, cert.len());
        container.extend_from_slice(&cert);
        card.preload_object(OBJ_CERT_9A, container.clone());

        let tag_bytes = [0x5Fu8, 0xC1, 0x05];
        let get_body = [&[0x5Cu8, 0x03][..], &tag_bytes[..]].concat();
        let get_cmd = [
            &[0x00, INS_GET_DATA, 0x3F, 0xFF, get_body.len() as u8][..],
            &get_body[..],
        ]
        .concat();

        let first = card.handle_apdu(&get_cmd);
        let mut sw = status(&first);
        assert_eq!(sw & 0xFF00, 0x6100, "expected more-data status");
        let mut whole = first[..first.len() - 2].to_vec();

        // Drive GET RESPONSE until the card reports success.
        while sw & 0xFF00 == 0x6100 {
            let le = if sw & 0xFF == 0 {
                0x00
            } else {
                (sw & 0xFF) as u8
            };
            let resp = card.handle_apdu(&[0x00, INS_GET_RESPONSE, 0x00, 0x00, le]);
            sw = status(&resp);
            whole.extend_from_slice(&resp[..resp.len() - 2]);
        }
        assert_eq!(sw, SW_OK);
        assert_eq!(
            whole, container,
            "chained reassembly lost or reordered bytes"
        );
    }

    #[test]
    fn command_chain_assembles_a_put_data_too_large_for_one_short_apdu() {
        let mut card = FirmwareCard::new();
        verify(&mut card, CORRECT_PIN);

        let tag_bytes = [0x5Fu8, 0xC1, 0x05];
        let cert: Vec<u8> = (0..700u32).map(|i| (i * 7) as u8).collect();
        let mut container = vec![0x53];
        tlv_put_len(&mut container, cert.len());
        container.extend_from_slice(&cert);
        let body = [&[0x5Cu8, 0x03][..], &tag_bytes[..], &container[..]].concat();

        let block = 200usize;
        let mut last_sw = 0u16;
        for chunk_start in (0..body.len()).step_by(block) {
            let chunk = &body[chunk_start..(chunk_start + block).min(body.len())];
            let last = chunk_start + block >= body.len();
            let cla = if last { 0x00 } else { CLA_CHAIN };
            let cmd = [
                &[cla, INS_PUT_DATA, 0x3F, 0xFF, chunk.len() as u8][..],
                chunk,
            ]
            .concat();
            last_sw = status(&card.handle_apdu(&cmd));
        }
        assert_eq!(last_sw, SW_OK);

        let get_body = [&[0x5Cu8, 0x03][..], &tag_bytes[..]].concat();
        let get_cmd = [
            &[0x00, INS_GET_DATA, 0x3F, 0xFF, get_body.len() as u8][..],
            &get_body[..],
        ]
        .concat();
        let mut got = Vec::new();
        let first = card.handle_apdu(&get_cmd);
        let mut sw = status(&first);
        got.extend_from_slice(&first[..first.len() - 2]);
        while sw & 0xFF00 == 0x6100 {
            let le = if sw & 0xFF == 0 {
                0x00
            } else {
                (sw & 0xFF) as u8
            };
            let resp = card.handle_apdu(&[0x00, INS_GET_RESPONSE, 0x00, 0x00, le]);
            sw = status(&resp);
            got.extend_from_slice(&resp[..resp.len() - 2]);
        }
        assert_eq!(got, container);
    }

    #[test]
    fn a_chain_that_changes_command_is_abandoned() {
        let mut card = FirmwareCard::new();
        verify(&mut card, CORRECT_PIN);
        let body = b"\x5c\x03\x5f\xc1\x05\x53\x03AB";
        assert_eq!(
            status(
                &card.handle_apdu(
                    &[
                        &[CLA_CHAIN, INS_PUT_DATA, 0x3F, 0xFF, body.len() as u8][..],
                        body
                    ]
                    .concat()
                )
            ),
            SW_OK
        );
        // Different INS mid-chain: abandoned.
        assert_eq!(
            status(&card.handle_apdu(&[0x00, INS_GET_DATA, 0x3F, 0xFF, 0x01, b'C'])),
            SW_WRONG_DATA
        );
        // The chain is gone, not merely paused.
        let get_body = b"\x5c\x03\x5f\xc1\x05";
        assert_eq!(
            status(
                &card.handle_apdu(
                    &[
                        &[0x00, INS_GET_DATA, 0x3F, 0xFF, get_body.len() as u8][..],
                        get_body
                    ]
                    .concat()
                )
            ),
            SW_NOT_FOUND
        );
    }

    #[test]
    fn extended_length_case_3e_select_is_unconditionally_rejected() {
        // Case 3E: CLA INS P1 P2 00 LenHi LenLo <data>, no Le. The applet
        // refuses this outright — no inspection of the declared length, no
        // partial acceptance — regardless of whether the whole message
        // would otherwise fit comfortably under any transport's ceiling.
        let mut card = FirmwareCard::new();
        let mut cmd = vec![0x00, INS_SELECT, 0x04, 0x00, 0x00, 0x00, 0x09];
        cmd.extend_from_slice(&PIV_AID[..9]);
        assert_eq!(status(&card.handle_apdu(&cmd)), SW_WRONG_LENGTH);
    }

    #[test]
    fn extended_length_case_4e_select_is_unconditionally_rejected() {
        // Case 4E: CLA INS P1 P2 00 LenHi LenLo <data> LeHi LeLo.
        let mut card = FirmwareCard::new();
        let mut cmd = vec![0x00, INS_SELECT, 0x04, 0x00, 0x00, 0x00, 0x09];
        cmd.extend_from_slice(&PIV_AID[..9]);
        cmd.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(status(&card.handle_apdu(&cmd)), SW_WRONG_LENGTH);
    }

    #[test]
    fn extended_length_case_2e_le_only_is_unconditionally_rejected() {
        // Case 2E: CLA INS P1 P2 00 00 00 — Le only, no data at all. Even
        // this minimal extended-length form is refused; the applet does not
        // special-case an empty Lc.
        let mut card = FirmwareCard::new();
        let cmd = vec![0x00, INS_SELECT, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(status(&card.handle_apdu(&cmd)), SW_WRONG_LENGTH);
    }

    #[test]
    fn truncated_header_is_wrong_length() {
        let mut card = FirmwareCard::new();
        assert_eq!(
            status(&card.handle_apdu(&[0x00, INS_SELECT, 0x04])),
            SW_WRONG_LENGTH
        );
    }

    #[test]
    fn unsupported_class_is_rejected() {
        let mut card = FirmwareCard::new();
        for cla in [0x80u8, 0xFF, 0x0C, 0x01] {
            assert_eq!(
                status(&card.handle_apdu(&[cla, INS_SELECT, 0x04, 0x00])),
                SW_CLA_UNSUPPORTED
            );
        }
    }

    #[test]
    fn unknown_instruction_is_rejected() {
        let mut card = FirmwareCard::new();
        assert_eq!(
            status(&card.handle_apdu(&[0x00, 0xFF, 0x00, 0x00])),
            SW_INS_UNSUPPORTED
        );
    }

    #[test]
    fn change_pin_then_old_pin_stops_working() {
        let mut card = FirmwareCard::new();
        let mut body = CORRECT_PIN.to_vec();
        body.resize(8, 0xFF);
        let mut new_pin = b"654321".to_vec();
        new_pin.resize(8, 0xFF);
        body.extend_from_slice(&new_pin);
        let cmd = [
            &[0x00, INS_CHANGE_REFERENCE, 0x00, 0x80, body.len() as u8][..],
            &body[..],
        ]
        .concat();
        assert_eq!(status(&card.handle_apdu(&cmd)), SW_OK);
        assert_eq!(verify(&mut card, b"654321"), SW_OK);
        assert_ne!(verify(&mut card, CORRECT_PIN), SW_OK);
    }
}
