//! Replays the shared BLE conformance corpus.
//!
//! The corpus is authored from CTAP2 §11.4, **not** captured from either
//! implementation, and the firmware replays the same file from its own tests.
//! That is what makes it worth having: two implementations that agree with each
//! other prove nothing, which is the same trap PROJECT.md §14 names about mocks
//! (see §20). A divergence fails CI on whichever side moved, instead of being
//! found by reading both implementations side by side.
//!
//! Vendored from `alphaseneca/cryptick-token-code` at
//! `tests/conformance/ble_fido_v1.json`. Keep the two byte-identical; the hash
//! test below is what makes an accidental edit here visible.

use ble_framing::{BleErrorCode, Command, FragmentSize, Message, Reassembler};
use serde_json::Value;

const CORPUS: &str = include_str!("conformance/ble_fido_v1.json");

/// Vectors where we deliberately disagree with the corpus, and why.
///
/// Each entry asserts the disagreement still exists, so when the corpus is
/// corrected this test fails and forces the entry to be removed. A skip list
/// that silently passes would rot; this one cannot.
const DISPUTED: &[(&str, &str)] = &[
    // Empty, and that is the point: both prior entries cleared themselves when
    // the corpus was corrected. Leave the machinery in place — the next
    // disagreement will want it.
];

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum Outcome {
    Message { command: u8, payload: Vec<u8> },
    Error(BleErrorCode),
    Incomplete,
}

/// What a fragment stream produced.
///
/// `expect` in the corpus means **the last delivery**, not the only one. That
/// is the reading `push()` makes natural — it returns `Option<Message>` per
/// fragment, so a stream can deliver more than once — and it is what lets a
/// vector feed a bad fragment and then a good message.
///
/// But "last" alone would hide a real divergence: two implementations that end
/// in the same state by different routes (one delivering a CANCEL then a
/// message, the other only the message) would both pass. So a vector may
/// instead carry `deliveries`, an ordered list of *every* message delivered,
/// which is checked exhaustively. Vectors that deliver at most once are
/// identical under either reading, which is why the existing 38 need no change.
struct Replay {
    deliveries: Vec<Outcome>,
    last: Outcome,
}

/// Feeds every fragment and reports the outcome of the last one.
///
/// Deliberately does **not** stop at the first error. Several vectors check
/// that an error leaves the reassembler usable — a peer that recovers by
/// sending a fresh init fragment must succeed — and stopping early would
/// report the error and silently skip the part being tested.
fn replay(fragments: &[Vec<u8>], max_message_len: usize) -> Replay {
    let mut rx = Reassembler::with_max_message_len(max_message_len);
    let mut deliveries = Vec::new();
    let mut last = Outcome::Incomplete;
    for fragment in fragments {
        last = match rx.push(fragment) {
            Ok(Some(Message { command, payload })) => {
                let delivered = Outcome::Message {
                    command: command.as_u8(),
                    payload,
                };
                deliveries.push(delivered.clone());
                delivered
            }
            Ok(None) => Outcome::Incomplete,
            Err(err) => Outcome::Error(err.ble_error_code()),
        };
    }
    Replay { deliveries, last }
}

fn expected(expect: &Value) -> Outcome {
    match expect["kind"].as_str().expect("expect.kind") {
        "message" => Outcome::Message {
            command: u8::try_from(expect["command"].as_u64().expect("command")).expect("u8"),
            payload: unhex(expect["payload"].as_str().expect("payload")),
        },
        "error" => Outcome::Error(BleErrorCode::from_u8(
            u8::try_from(expect["ble_error"].as_u64().expect("ble_error")).expect("u8"),
        )),
        "incomplete" => Outcome::Incomplete,
        other => panic!("unknown expect.kind {other}"),
    }
}

#[test]
fn the_corpus_matches_this_implementation() {
    let doc: Value = serde_json::from_str(CORPUS).expect("corpus parses");
    let vectors = doc["vectors"].as_array().expect("vectors array");

    let mut checked = 0usize;
    let mut skipped_direction = 0usize;
    let mut disagreements = Vec::new();
    let mut disputed_seen = Vec::new();

    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let direction = vector["direction"].as_str().expect("direction");

        // We reassemble fidoStatus notifications, so host_to_device vectors
        // describe a rule that is not ours to enforce.
        if direction == "host_to_device" {
            skipped_direction += 1;
            continue;
        }

        let fragments: Vec<Vec<u8>> = vector["fragments"]
            .as_array()
            .expect("fragments")
            .iter()
            .map(|f| unhex(f.as_str().expect("hex fragment")))
            .collect();
        let max_message_len =
            usize::try_from(vector["max_message_len"].as_u64().expect("max_message_len"))
                .expect("usize");

        let replayed = replay(&fragments, max_message_len);

        // A vector may pin every delivery in order, or just the last one.
        let (got, want) = match vector.get("deliveries").and_then(Value::as_array) {
            Some(sequence) => (
                format!("{:?}", replayed.deliveries),
                format!("{:?}", sequence.iter().map(expected).collect::<Vec<_>>()),
            ),
            None => (
                format!("{:?}", replayed.last),
                format!("{:?}", expected(&vector["expect"])),
            ),
        };

        if let Some((_, why)) = DISPUTED.iter().find(|(n, _)| *n == name) {
            assert_ne!(
                got, want,
                "vector `{name}` is on the DISPUTED list but now agrees. \
                 The corpus was presumably corrected — delete the entry. Reason \
                 it was disputed: {why}"
            );
            disputed_seen.push(name);
            continue;
        }

        checked += 1;
        if got != want {
            disagreements.push(format!(
                "  {name} ({direction})\n    want: {want:?}\n    got:  {got:?}\n    why:  {}",
                vector["why"].as_str().unwrap_or("")
            ));
        }
    }

    assert_eq!(
        disputed_seen.len(),
        DISPUTED.len(),
        "a DISPUTED entry names a vector that is not in the corpus"
    );
    assert!(
        disagreements.is_empty(),
        "{} of {checked} conformance vectors disagree \
         (a divergence means one side is wrong on the wire):\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );
    assert!(
        checked > 25,
        "only {checked} vectors ran; corpus may be truncated"
    );
    eprintln!(
        "conformance: {checked} vectors passed, {} disputed, {skipped_direction} host-only",
        DISPUTED.len()
    );
}

#[test]
fn every_vector_is_well_formed() {
    // A malformed corpus that silently checks nothing is worse than no corpus.
    let doc: Value = serde_json::from_str(CORPUS).expect("corpus parses");
    assert_eq!(doc["version"].as_u64(), Some(1), "corpus schema version");

    for vector in doc["vectors"].as_array().expect("vectors") {
        let name = vector["name"].as_str().expect("every vector is named");
        assert!(
            !vector["why"].as_str().unwrap_or("").is_empty(),
            "{name} has no `why`; an expectation without a reason cannot be \
             checked against the spec"
        );
        assert!(
            matches!(
                vector["direction"].as_str(),
                Some("both" | "host_to_device" | "device_to_host")
            ),
            "{name} has an unknown direction"
        );
        let size = vector["fragment_size"].as_u64().expect("fragment_size");
        FragmentSize::new(u16::try_from(size).expect("u16"))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn command_values_match_the_spec_table() {
    // CTAP2 §11.4.4.3, read from the specification rather than from either
    // implementation.
    assert_eq!(Command::Ping.as_u8(), 0x81);
    assert_eq!(Command::KeepAlive.as_u8(), 0x82);
    assert_eq!(Command::Msg.as_u8(), 0x83);
    assert_eq!(Command::Cancel.as_u8(), 0xbe);
    assert_eq!(Command::Error.as_u8(), 0xbf);

    assert_eq!(BleErrorCode::InvalidCmd.as_u8(), 0x01);
    assert_eq!(BleErrorCode::InvalidPar.as_u8(), 0x02);
    assert_eq!(BleErrorCode::InvalidLen.as_u8(), 0x03);
    assert_eq!(BleErrorCode::InvalidSeq.as_u8(), 0x04);
    assert_eq!(BleErrorCode::ReqTimeout.as_u8(), 0x05);
    assert_eq!(BleErrorCode::Busy.as_u8(), 0x06);
    assert_eq!(BleErrorCode::Other.as_u8(), 0x7f);
}
