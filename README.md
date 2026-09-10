# cryptick-token-daemon

Host-side daemon for the [Cryptick token](https://github.com/alphaseneca/cryptick-token-code):
an ESP32-S3 that is a FIDO2 authenticator and a PIV smart card over **both USB
and BLE**.

Over USB the device needs no host software at all — every OS already speaks
CTAPHID and CCID. **This daemon exists to make the BLE transport look like the
USB one**, because nothing else does: Chrome dropped BLE CTAP2 in 2020, and
Windows 11 appears to have regressed what native support existed.

Design, research and build order live in **[PROJECT.md](PROJECT.md)**. Read it
before changing anything here; §15 in particular is a list of release blockers,
not review nits.

## Status

| Crate | Does | State |
|---|---|---|
| `ble-framing` | CTAP BLE fragmentation and reassembly (§12) | done |
| `ctap` | Command/status bytes and message framing | done |
| `ctaphid` | 64-byte packets, channels, reassembly (the OS-facing envelope) | done |
| `ipc` | Wire types and length-prefixed framing (§13) | done |
| `ctap-client` | CBOR, COSE, authdata, DER, CTAP2 requests — the browser's half | done |
| `sk-middleware` | OpenSSH `SecurityKeyProvider` cdylib | **working** — enrols and signs |
| `daemon` | Transaction core, one-in-flight bridge, IPC server, CTAPHID↔BLE adapter | core done |
| `transport-ble` | The real radio, and bonding checks per platform | **not started** |
| `vhid-linux` | `/dev/uhid` node → the adapter above | not started |
| `vhid-windows` | USB/IP → VHCI → the adapter above | not started |
| `vpcd-client` | PIV relay for login and screen unlock | not started |

**`ssh-keygen -t ed25519-sk` works today.** The real OpenSSH binary enrols a key
and signs with it, through the middleware, the IPC socket and the daemon — see
`tools/ci/ssh-roundtrip.sh`. The device at the far end is an in-process fake
rather than a radio, so the credential and signature are fixtures.

The CTAPHID path works end to end too — packets in, CTAP BLE fragments out,
answer back. That is the L2 layer of §14 and deliberately where most of the test
effort sits. The three `vhid-*` crates are thin: they open a device node and feed
bytes to `daemon::HidBridge`, which is already written and tested.

## Build and test

```bash
cargo test --workspace --all-features
```

```bash
cargo clippy --workspace --all-targets --all-features
```

Fuzzing needs a nightly toolchain:

```bash
cargo fuzz run ble_reassembly -- -max_total_time=60
```

## What this daemon does not do

It holds no key material, caches no credentials, builds no client data, makes no
origin decisions, implements no PIN/UV protocol, and never satisfies user
presence on the device's behalf. It reads one byte to route a message and relays
the rest untouched. See PROJECT.md §15 and §21 — those are constraints, not
current limitations.

It also binds no network socket, ever. There is a test that fails if one is even
named (§15.6).
