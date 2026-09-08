# Issue draft 1 — `ble_fido`: scaffold targets CTAPHID-over-BLE, but FIDO BLE is a different transport

**Repo:** `alphaseneca/cryptick-token-code`
**Labels:** `ble`, `fido2`, `design`
**Priority:** do this before any BLE code is written — it is a five-minute change now and a rewrite later.

## What the scaffold currently says

`core/ble_fido/ble_fido.h:9-11`:

> Goal: reassemble GATT notifications into the same CTAPHID pipeline used on USB.

`core/ble_fido/ble_fido.h:21`:

```c
void ble_fido_push_ctaphid_report(const uint8_t report[64]);
```

`core/ble_fido/ble_fido.c:19`:

```c
/* When BLE is live: ctaphid_push_report(report); */
```

## Why this is the wrong target

That describes **CTAPHID tunnelled over BLE**. CTAPHID is the USB HID transport and nothing else:
64-byte reports, 4-byte channel IDs, a 7-byte init header and a 5-byte continuation header
(`core/fido2/ctaphid.h:55-69`), `CTAPHID_BROADCAST_CID`, and an `INIT` handshake to allocate a CID.

The FIDO **BLE** transport shares none of that. It is GATT service `0xFFFD` with its own framing:

| | CTAPHID (USB) | FIDO BLE |
|---|---|---|
| Unit | 64-byte report, fixed | fragment sized by `fidoControlPointLength` (20–512) |
| Init header | CID(4) ‖ CMD(1) ‖ BCNT(2) = 7 bytes | CMD(1, high bit set) ‖ HLEN(2, big-endian) = 3 bytes |
| Cont header | CID(4) ‖ SEQ(1) = 5 bytes | SEQ(1, high bit clear, wraps 0x7f→0x00) = 1 byte |
| Channels | yes, CIDs, `INIT` handshake | **none** |
| Commands | `INIT`/`MSG`/`CBOR`/`PING`/`CANCEL`/`KEEPALIVE`/`ERROR`/`WINK` | `PING 0x81`, `KEEPALIVE 0x82`, `MSG 0x83`, `CANCEL 0xBE`, `ERROR 0xBF` |

There is no CID on the wire and no `CTAPHID_INIT` equivalent, so a 64-byte-report entry point cannot
express a BLE transaction. CTAP2 CBOR rides directly inside `MSG`, not inside a CTAPHID frame.

**Consequence if built as scaffolded:** Windows' native BLE FIDO stack, `libfido2`, Chrome/Edge and
`webauthn-authenticator-rs` all fail to talk to the device. You end up with a token only a bespoke
host daemon can drive, which removes the main reason to pick BLE FIDO over a private protocol —
and removes the ability to check spec compliance against a host that has no software installed.

## The seam is already in the right place

`core/fido2/ctap.h:386` is transport-independent:

```c
uint8_t ctap_request(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp);
```

`ctaphid.c:639` is just one caller of it. BLE should be a **sibling** caller, not a layer that
squeezes itself through `ctaphid.c`. `ctaphid.c` stays USB-only and untouched.

```
USB HID report ──► ctaphid_handle_packet() ──┐
                                             ├──► ctap_request() ──► CTAP_RESPONSE
BLE fragment ────► ble_fido_rx_fragment() ───┘
```

> **This is a layering diagram, not a threading one.** `ctap_request()` has no
> lock; it is safe today only because a single FreeRTOS task is its only caller.
> BLE must feed that same task, never call `ctap_request()` from a NimBLE
> callback. **Read issue draft 6 before implementing this** — getting it wrong
> gives you state corruption and a user-presence confusion bug.

Since USB and BLE are both product transports, both callers are live at once and
the arbitration in draft 6 is mandatory, not optional.

## Proposed GATT service

Advertisement must carry the 16-bit FIDO Service UUID `0xFFFD`.

| Characteristic | UUID | Properties |
|---|---|---|
| fidoControlPoint | `F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB` | Write (request, **not** write-without-response), encrypted + authenticated |
| fidoStatus | `F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB` | Notify, encrypted + authenticated |
| fidoControlPointLength | `F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB` | Read, 2 bytes big-endian, value 20–512 |
| fidoServiceRevisionBitfield | `F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB` | Read/Write, 1 byte; bit 5 (`0x20`) = FIDO2, bit 6 (`0x40`) = U2F 1.2, bit 7 (`0x80`) = U2F 1.1 |

Set `fidoControlPointLength` from the negotiated ATT MTU (`ATT_MTU - 3`), clamped to `[20, 512]`.
Never send a fragment larger than the value you published.

## Proposed replacement API

```c
/* Feed one fragment received on fidoControlPoint.
   Returns 0 on success, or a FIDO BLE error code to be emitted as CMD_ERROR (0xBF). */
uint8_t ble_fido_rx_fragment(const uint8_t *frag, uint16_t len);

/* Called on MTU exchange; recomputes and republishes fidoControlPointLength. */
void ble_fido_set_mtu(uint16_t att_mtu);

/* Abort any in-flight reassembly (disconnect, CANCEL, timeout). */
void ble_fido_reset(void);
```

Error codes for `CMD_ERROR`: `ERR_INVALID_CMD 0x01`, `ERR_INVALID_PAR 0x02`, `ERR_INVALID_LEN 0x03`,
`ERR_INVALID_SEQ 0x04`, `ERR_REQ_TIMEOUT 0x05`, `ERR_OTHER 0x7f`.

## Bound the reassembly buffer

`HLEN` is 16-bit, so a peer can declare up to 65535 bytes. Do not allocate that. The stack's own
ceiling is `CTAP_MAX_MESSAGE_SIZE = 1200` (`core/fido2/ctap.h:130`); reject any `HLEN` above it with
`ERR_INVALID_LEN` at the init fragment, before allocating. Also reject:

- a continuation with no active transaction → `ERR_INVALID_SEQ`
- a `SEQ` that is not `(prev + 1) & 0x7f` → `ERR_INVALID_SEQ`
- a continuation carrying zero data bytes → `ERR_INVALID_LEN` (otherwise a peer can stall forever)
- total delivered bytes exceeding the declared `HLEN` → `ERR_INVALID_LEN`
- any fragment longer than the published `fidoControlPointLength` → `ERR_INVALID_LEN`

Any error aborts the transaction and returns to idle. Half-flashed firmware and interrupted OTAs
produce exactly this class of malformed-but-authenticated input, so it is worth being strict.

## Pairing — the OLED earns its keep here

CTAP requires LE Secure Connections bonding **with MITM protection**. Just Works pairing does not
provide it. The board already has the peripheral that fixes this: display a 6-digit passkey on the
OLED and use Passkey Entry.

```c
ble_hs_cfg.sm_sc      = 1;                      /* LE Secure Connections */
ble_hs_cfg.sm_mitm    = 1;                      /* MITM protection */
ble_hs_cfg.sm_bonding  = 1;
ble_hs_cfg.sm_io_cap  = BLE_HS_IO_DISPLAY_ONLY; /* passkey shown on the OLED */
```

Mark fidoControlPoint and fidoStatus as requiring encryption *and* authentication, so an unbonded
peer cannot reach them at all.

## Keepalive

Blocked on the transport coupling in issue draft 2 — `ctap_user_presence_test()` already ticks at
100 ms, which satisfies the BLE keepalive cadence; it just calls `ctaphid_update_status()` directly.
