# PIV over BLE — wire protocol

Status: **implemented on both sides.** Daemon side — `crates/transport-ble`
(`PivBleTransport`), `crates/ble-framing` (shared framing/reassembly),
`crates/vpcd`, and `crates/daemon` (`vpcd_relay`, wired into
`ReconnectingBleTransport::spawn`) relay opaque APDUs over this service
exactly as specified below: `pivControlPointLength` is read from the device
(20–512, never assumed), the reassembler bounds inbound fragments by the
transport ceiling rather than that characteristic, and `CANCEL` is delivered
on its first fragment and never reassembled or answered. Firmware side —
`alphaseneca/cryptick-token-code`'s `core/ble_fido/ble_piv_gatt_esp32.cpp`
and `ble_piv.h` implement this service and were audited line-by-line against
this document (see that repo's `NOTES.md`, "PIV correctness"): framing,
`SEQ` wrap, the `CANCEL` rule, and the 261-byte ceiling (`BLE_PIV_MAX_MSG`)
all match exactly. What that audit did *not* cover is a live BLE connection
actually exercising this path end-to-end on real hardware — that remains
unverified (PROJECT.md §14 L4). Version 1.

This is the private GATT service PROJECT.md §4 and §12 refer to. It carries
ISO 7816 APDUs between the daemon's virtual smart card reader and the PIV
applet on the device.

## Why a second service is not a second door

PROJECT.md §19 rules out a "non-standard secondary GATT service" on the grounds
that it adds *a second untested door to the same key material*. That is not what
this is, and the distinction is the whole justification:

- §15.9 requires PIV authentication keys and FIDO2 credentials to be **distinct
  material in distinct slots**, with PIN semantics that do not map between the
  protocols.
- This service is the **only** door to the PIV material, not a second door to
  the FIDO material.
- Nothing here can reach a FIDO credential. An implementation that routes a
  request from this service into `ctap_request()` has violated §15.9.

**The applet boundary is not what enforces that, and an earlier draft of this
document said it was.** Both key families derive from one master secret through
`HMAC(master_secret, input)`, so separation reduces to the two never being
handed the same input. Routing was never the risk; derivation-input collision
was. The firmware is expected to **enforce** separation rather than merely have
it — today by length disjointness pinned with `static_assert`s, and properly by
domain-separating the derivation input (`"piv" ‖ label` against
`"fido" ‖ credential_id`) so collision is impossible by construction. See
PROJECT.md §15.9.

Exposing CTAP over a vendor service *alongside* `0xFFFD` remains a dead end.

## Framing: identical to `0xFFFD`, deliberately

The framing is the CTAP BLE transport's, byte for byte:

- **Initialization fragment**: `CMD` (1 byte, high bit set) ‖ `HLEN` (1) ‖
  `LLEN` (1) ‖ data, the two length bytes being the whole message length,
  big-endian.
- **Continuation fragment**: `SEQ` (1 byte, high bit clear, `0x00`–`0x7f`,
  **wrapping to 0 after `0x7f`**) ‖ data.
- Fragment size is read from `pivControlPointLength`, between 20 and 512.
  Read it; never assume.
- The reassembler bounds inbound fragments by the transport ceiling, not by
  `pivControlPointLength` — that characteristic governs *writes to the control
  point*, while notifications follow the negotiated ATT MTU and may exceed it.

Reusing it rather than inventing a second framing is not laziness. `SEQ`
wrapping, padding, and declared-length handling are each a place to be wrong,
`crates/ble-framing` already implements them, they are already fuzzed, and the
shared conformance corpus (`tests/conformance/ble_fido_v1.json`) then covers
both services for free.

**Consequence:** every framing rule settled for `0xFFFD` applies here unchanged,
including the one that took two rounds to get right — a `CANCEL` is delivered on
its first fragment, whatever its declared length, and is **never** answered.
See CTAP2 §11.4.8.

## GATT service

| | UUID | Properties |
|---|---|---|
| Cryptick PIV Service | `FBF6EB90-7F39-41B1-A191-9527CC42F8BE` | Primary Service |
| `pivControlPoint` | `FBF6EB91-7F39-41B1-A191-9527CC42F8BE` | Write (request), encrypted + authenticated |
| `pivStatus` | `FBF6EB92-7F39-41B1-A191-9527CC42F8BE` | Notify, encrypted + authenticated |
| `pivControlPointLength` | `FBF6EB93-7F39-41B1-A191-9527CC42F8BE` | Read, 2 bytes big-endian, 20–512 |
| `pivAtr` | `FBF6EB94-7F39-41B1-A191-9527CC42F8BE` | Read, 4–33 bytes |

Randomly generated, sharing a base so tooling groups them the way the FIDO
family does. They are not derived from anything and carry no meaning.

**`pivControlPoint` and `pivStatus` require encryption *and* authentication.**
Same bar as `0xFFFD`: LE Secure Connections with MITM protection (§15.2). An
unbonded peer must not reach them at all. This service reaches signing keys, so
there is no weaker tier available.

### `pivAtr`

The Answer To Reset the daemon presents to PC/SC. A static property of the
applet, so it is a characteristic rather than a command — readable before any
transaction, exactly as `pivControlPointLength` is.

`vpcd` requires an ATR to answer `POWER_ON` and `GET_ATR`. Those are handled
entirely in the daemon; the device never sees them.

## Commands

Values are the CTAP BLE ones, so the corpus applies unchanged:

| Constant | Value | Direction | Meaning |
|---|---|---|---|
| `KEEPALIVE` | `0x82` | device → host | Still working. One status byte. |
| `APDU` | `0x83` | both | A command APDU, or a response APDU. |
| `CANCEL` | `0xbe` | host → device | Abandon the outstanding APDU. Never answered. |
| `ERROR` | `0xbf` | device → host | Transport-level failure. One error-code byte. |

`APDU` reuses `MSG`'s value on purpose: it occupies the same slot in the
protocol and shares every framing rule.

`KEEPALIVE` statuses and `ERROR` codes are the CTAP BLE ones —
`PROCESSING 0x01`, `UP_NEEDED 0x02`; `ERR_INVALID_CMD 0x01`, `ERR_INVALID_PAR
0x02`, `ERR_INVALID_LEN 0x03`, `ERR_INVALID_SEQ 0x04`, `ERR_REQ_TIMEOUT 0x05`,
`ERR_BUSY 0x06`, `ERR_OTHER 0x7f`.

`UP_NEEDED` means the applet is waiting for a fingerprint before a private-key
operation. The daemon forwards it and never satisfies it (§15.3).

## APDU chaining is the applet's, not the transport's

An `APDU` message carries **one complete command APDU** and its reply carries
**one complete response APDU**, status word included.

Chaining — `61xx`, `GET RESPONSE`, and command chaining with `CLA` bit `0x10` —
is handled **inside the applet**, above this transport, exactly as it is over
CCID. The transport moves whatever bytes the applet produced.

Two reasons, and the second is the load-bearing one:

1. It already works over CCID and is transport-independent by construction.
2. Duplicating it here would give two places to get the same off-by-one wrong.
   The firmware has already had one such bug — `Lc` decoded unconditionally, so
   every `00 C0 00 00 xx` `GET RESPONSE` was misread as a truncated body, which
   would have broken certificate reads and therefore login on every OS.

A 900-byte certificate therefore arrives as several `APDU` exchanges, each one
complete in itself, each fragmented by this transport as needed.

## Transactions

- **One APDU in flight.** The applet is single-threaded, and PIV shares the
  device's user-presence gate with FIDO. A second `APDU` while one is
  outstanding is answered `ERR_BUSY`.
- **PIV and FIDO do not run concurrently.** They serialise through the same
  single-consumer path on the device. One fingerprint touch must never be able
  to satisfy whichever ceremony reads the flag first.
- The daemon reads `pivControlPointLength` and `pivAtr` after bonding and
  before the first `APDU`.

## Message length: 261 bytes, both directions

The applet accepts **short APDUs only**; extended-length encoding is rejected
with `6700`. The longest legal command is therefore
`CLA INS P1 P2 Lc ‖ 255 bytes ‖ Le` = **261**. Responses never exceed 258
(256 data plus status word), because the applet chains at 256.

`HLEN` above 261 is rejected at the initialization fragment, before anything is
buffered — the same shape as the 1200-byte ceiling on `0xFFFD`. One constant
serves both directions.

## Not advertised

`0xFFFD` **must** appear in the advertisement; the CTAP BLE spec requires it. So
the device is already identifiable as a FIDO token to any passing scanner, and
that cannot be helped. Advertising this service as well would additionally tell
that scanner the hardware is a smart card — strictly more information, for zero
gain, since the daemon discovers the service after bonding anyway.

The service exists and is discoverable. It is simply not in the advertisement.

## `PING` is not implemented here

It earns nothing in the PIV path, and the FIDO service already provides an echo
on identical framing for bring-up. See below for why an extra command costs more
than it looks.

## Implementation cost, which is not zero

Reusing the framing is right, but "byte for byte" describes the *format*, not
the implementation. The firmware's `ble_fido.c` currently holds its entire state
at module scope — one in-flight message, one `SEQ`, one control-point length,
one set of callbacks. Two GATT services need two independent reassemblers,
including two different ceilings (1200 against 261), so serving both requires
refactoring that file into a context struct threaded through every entry point.

Mechanical, but it touches the best-tested file in the firmware, and it has to
land **before** the second service rather than alongside it. Still the right
call against maintaining a second framing — it should simply be sequenced as its
own change.

## Open

Nothing outstanding on the wire format. The remaining risk is the
derivation-input domain separation in PROJECT.md §15.9, which is not a transport
question.
