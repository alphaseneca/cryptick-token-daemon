# BLE Security Device — Architecture, Research and Build Guide

Single reference for the project. Guidance for humans and AI coding agents.

Sections marked **[HW]** contain values that depend on final hardware and
firmware details, and must be revisited when those land — see §17.

---

# Part I — What this is

## 1. Goal

An ESP32-S3 acts as both a FIDO2 authenticator and a PIV smart card **over two
transports — USB and BLE** — serving:

- browser passkeys (WebAuthn)
- SSH authentication (`ecdsa-sk` / `ed25519-sk`)
- desktop login and screen unlock
- proximity lock/unlock

on **Linux, macOS and Windows**, with no internet connection, no browser flags,
no tunnel server, and no QR codes.

**The two transports are not equal, and that is the whole reason this repo
exists.** Over USB the device is an ordinary security key and an ordinary CCID
smart card reader: every OS already speaks both, and **no host software is
needed at all**. Over BLE nothing speaks to it — Chrome dropped BLE CTAP2 in
2020, and Windows 11 appears to have regressed what little native support
existed (§18). So:

> **The daemon's entire job is to make the BLE transport look like the USB one
> to the host.** Anything that already works over USB is not the daemon's
> problem. If a capability can be delivered by plugging the cable in, the daemon
> should stay out of the way.

This also gives every feature a fallback: if a BLE path is blocked by an
entitlement, a driver signature or an OS regression, the USB path still works,
and the device is still useful.

## 2. Feasibility verdict

**This table describes the BLE path only.** Over USB every row is ✅ on all three
OSes with nothing installed, because the device presents as a standard HID
security key and a standard CCID reader. The difficulty below is the price of
going wireless, not the price of the feature.

| Use case (over BLE) | Linux | macOS | Windows |
|---|---|---|---|
| Browser passkeys | ✅ `/dev/uhid` | ✅ CoreHID, needs Apple entitlement | ✅ USB/IP, needs driver signing |
| SSH | ✅ SK middleware — no virtual HID needed | ✅ same | ✅ same |
| Login + screen unlock | ✅ PIV → `pam_pkcs11` | ✅ PIV → Apple's `pivtoken` | ⚠️ PIV + third-party credential provider |
| Proximity lock/unlock | ✅ | ✅ | ✅ |
| Pre-boot (FileVault / BitLocker) | ❌ | ❌ | ❌ |
| FIDO2 as OS login | — | ❌ PIV only | ❌ Entra-joined only |

## 3. The finding that made this possible

**macOS 15 shipped `HIDVirtualDevice` in the CoreHID framework** — a public,
documented API for creating a virtual HID device from userspace. No kext, no
DriverKit extension.

> "A `HIDVirtualDevice` is an object that emulates a HID device connected to the
> system, without the need for a physical device." — Apple, CoreHID documentation

This was the blocker for the whole daemon approach on macOS. It no longer is.

**Someone has already built this exact project on it.** From the Apple Developer
Forums:

> "We have created an app that enables wireless communication with FIDO2 devices
> over Bluetooth by creating virtual HID devices and translating the packages."

Their code uses `HIDVirtualDevice.Properties(descriptor: VirtualDevice.fidoDescriptor, ...)`.
It works.

### The catch

`HIDVirtualDevice(properties:)` returns `nil` without
`com.apple.developer.hid.virtual.device`. Per Kevin Elliott, DTS Engineer,
CoreOS/Hardware:

> "Your code needs to be signed with the `com.apple.developer.hid.virtual.device`
> entitlement for that API to function. You can apply for that entitlement through
> the DriverKit entitlement request form."

- It is **not** a DriverKit entitlement, despite the request form. Apple: it
  "controls access to the CoreHID virtual device API. This is NOT a DEXT
  entitlement and should never be included in a DEXT."
- Do **not** request `com.apple.developer.driverkit.family.hid.virtual.device` —
  Apple calls it "a defunct entitlement that has no function on any of our
  platforms," scheduled for removal from the docs.
- Approval is discretionary and slow. The build order (§16) puts it last.
- The forum poster's app was **rejected twice by App Review** over the
  Accessibility prompt that virtual HID creation triggers. **Distribute via
  Developer ID.** App Review does not apply to Developer ID distribution.

---

# Part II — Architecture

## 4. Shape

One daemon. One BLE connection. Three adapters, each independently shippable.

```
                 ESP32-S3   (USB + BLE — no WiFi, no internet, ever)
                        │
         USB: CTAPHID + CCID, native on every OS, no daemon
                        │
                        │
                 CTAP over FIDO GATT 0xFFFD
                 PIV APDUs over a private GATT service
                        │
              ┌─────────┴─────────┐
              │   bridge daemon   │  launchd / systemd / Task Scheduler
              │  owns the radio   │
              └─────────┬─────────┘
                        │  local IPC only (§5)
        ┌───────────┬───┴────────┬──────────────┐
        │           │            │              │
   Virtual HID  SK middleware  vpcd/PIV     status IPC
        │           │            │
   browsers,     OpenSSH     login + unlock
   libfido2      (no HID       macOS pivtoken
                  needed)      Linux pam_pkcs11
                               Windows minidriver
```

The daemon holds no key material. It is transport and adaptation only. All
credentials, all crypto, all user-presence decisions live on the device.

**There is no browser-side code in this project.** The virtual HID device makes
the browser see an ordinary security key; there is nothing left for browser code
to do.

## 5. Nothing here touches a network

Stated once, because the naming misleads:

- The device speaks **USB and BLE**. No WiFi role anywhere in this design,
  and no internet in either direction.
- `vpcd` listens on **loopback** ports 35963/35964. Local IPC.
- USB/IP on Windows is a **local socket to the kernel's virtual USB host
  controller**. "IP" is the packet encoding, not a network hop. 127.0.0.1.
- Linux `uhid` and macOS CoreHID use no socket at all.

**The daemon must never bind a socket to anything but a loopback address or a
filesystem/named-pipe endpoint.** Enforced by §15.6.

## 6. Language and process layout

**Rust** for the core and the daemon. **Swift** for exactly one thing: the macOS
virtual HID helper, because CoreHID is Swift-only.

Rust is right here for two specific reasons, not a general one. The BLE client
half exists as a Rust crate (§7). And the OS-facing half is a parser sitting on
the least protected surface in the project (§14) — any local process can write
to the virtual HID node — which is exactly where a memory-safe language pays
for itself.

The macOS helper is a **separate signed process**, not FFI into the daemon. The
entitlement requires a provisioning profile, which embeds into an app bundle; and
isolating the entitled binary keeps its attack surface small. It talks to the
daemon over the same local IPC as everything else.

## 7. Dependencies — use these, don't rewrite them

The daemon is a **CTAP proxy**: an authenticator half facing the OS, a client half
facing the device. Both halves exist.

| Job | Use | Notes |
|---|---|---|
| CTAP over BLE GATT | `webauthn-authenticator-rs`, `bluetooth` feature | The classic `0xFFFD` transport. **Pin exactly.** |
| CTAPHID framing, channels, reassembly | **write it** — `crates/ctaphid` | Evaluated `soft-fido2-transport` 0.17.0 and rejected it; see below. |
| Linux virtual HID | `soft-fido2-transport`, `uhid` feature | Working. |
| BLE radio | `btleplug` (BlueZ / CoreBluetooth / WinRT) | Bonding support is thin — see §15.2. |
| PC/SC for PIV | `pcsc` | Mature. |
| macOS virtual HID | **write it** — Swift helper, CoreHID | No Rust binding exists. |
| Windows virtual HID | **write it** — USB/IP client | `bulwarkid/virtual-fido` (Go) is a reference, not a dependency. |
| OpenSSH SK middleware | **write it** — `cdylib` against `sk-api.h` | Small. See §10. |

`webauthn-authenticator-rs` provides the BLE transport — confirmed by its
`BTLE_KEEPALIVE` / `BTLE_CANCEL` types, which are the `0xFFFD` transport's command
bytes. It also ships `usb`, `nfc` (PC/SC), `win10` and `softtoken` transports
behind feature flags, useful for testing against real keys.

### Why `soft-fido2-transport` was rejected for CTAPHID

Read at 0.17.0 on 2026-09-07, as §7 requires before trusting an abstraction. It
does provide CTAPHID framing, reassembly, channel/CID management and Linux UHID
support — but its core abstraction cannot express what this daemon does:

```rust
pub trait CommandHandler {
    fn handle_command(&mut self, cmd: Cmd, data: &[u8]) -> Result<Vec<u8>>;
}
```

**It is synchronous.** Our handler relays over BLE and waits on a fingerprint —
seconds, not microseconds. While `handle_command` blocks:

- **No `KEEPALIVE` can be sent.** Confirmed by grep: the crate never generates
  one anywhere, it only recognises the opcode (`handler.rs:158` lumps it in with
  `Lock` and `Error` as unhandled). A local soft authenticator answers instantly
  so it never needs one. We are not that, and a browser that gets no keepalive
  during a fingerprint wait times out.
- **No `CTAPHID_CANCEL` can be processed**, because the dispatcher holds
  `&mut self` for the whole call.
- Every handler error collapses to `ErrorCode::Other` (`handler.rs:151`),
  discarding the real CTAP status. A relay that remaps statuses tells the host
  something the authenticator never said — the exact failure `crates/ctap` is
  built to avoid.

This is a mismatch in the trait's shape, not a bug to patch around. Its framing
primitives (`Packet`, `Message`) are sound and could have been used alone, but
that is ~400 lines of well-specified code out of a young crate (ten breaking
releases, low adoption) whose manifest carries `license-file` rather than an
SPDX expression — which `cargo deny check licenses` cannot classify against our
allow-list. For the parser on the least protected surface in the project (§14),
owning and fuzzing it ourselves is the better trade.

`soft-fido2-transport` remains a reasonable reference for the UHID ioctl dance
when `vhid-linux` is written.

**Read `passless` before writing the Linux adapter.** It is a working virtual-UHID
FIDO2 authenticator built on `soft-fido2`, shipping systemd units, udev rules and
sysusers config. It has already solved the uhid permission problem: `modprobe uhid`,
a `fido` group, and `KERNEL=="uhid", GROUP="fido", MODE="0660"`. Copy it.

### Trust these carefully

`webauthn-authenticator-rs` describes itself as pre-1.0, calls its CTAP2 module
"alpha quality code", and states it "is not FIDO certified, and currently lacks a
thorough security review". Documented failure modes include exhausting PIN and UV
retries without warning, which can permanently lock an authenticator.

`soft-fido2` is young: ten breaking releases, low adoption.

Therefore:

- **Pin exact versions.** No caret ranges on either.
- **Vendor or fork** rather than tracking upstream.
- **Read the transport source** before trusting an abstraction, particularly
  anything touching PIN/UV retry counters.
- **Never let a library decide user presence or PIN retry behaviour** — §15.3 and
  §15.8 apply to library code as much as ours.

## 8. Repository layout

```
crates/
  ctap/              CTAP2 CBOR encode/decode. Pure. No I/O.
  ble-framing/       CTAP BLE fragmentation (§12). Pure. No I/O.
  piv/               APDU chunking for BLE + the ATR vpcd needs. Pure. No I/O.
                     NOT an APDU parser — see the note below.
  ipc/               Wire types shared by daemon and every client.
  transport-ble/     btleplug client, bonding verification, range events.
  daemon/            The service. Owns the radio. Hosts the adapters.
  vhid-linux/        /dev/uhid backend.
  vhid-windows/      USB/IP client -> VHCI.
  sk-middleware/     cdylib. OpenSSH SK API. Separate artifact (§10).
  vpcd-client/       vpcd protocol, PIV relay.
macos/
  VirtualHIDHelper/  Swift. CoreHID. Signed with the entitlement.
packaging/
  launchd/ systemd/ windows/
tools/
  replay/            replays captured BLE transcripts against the core
  ci/                scripts used by the workflow
tests/golden/        captured BLE transcripts (§14)
docs/
  uuids.md           GATT services, kept in sync with firmware   [HW]
  device-protocol.md PIV-over-BLE framing — ours, not a spec     [HW]
  manual-tests.md    the pre-release checklist CI can't automate
```

The four pure crates (`ctap`, `ble-framing`, `piv`, `ipc`) must build and test
with **no platform APIs and no hardware**. Anything needing a radio is an
integration test behind `--features hardware`.

### The daemon pipes payloads; it does not understand them

`ctap` and `piv` are much smaller than their names suggest, deliberately.

The browser builds `clientDataHash` and decides origins. The OS builds APDUs. The
device does the crypto and owns user presence. **The daemon in between reads one
byte and relays the rest untouched** — a command or status byte for CTAP, so it
can route KEEPALIVE from MSG from ERROR and fill in the `status` field the IPC
contract exposes (§13). CBOR bodies and APDU bodies are opaque `Vec<u8>` from end
to end.

This is a security property, not laziness. A relay that parses payloads it has no
business interpreting adds attack surface and a second place for the spec to be
misread, and §21 already forbids the daemon from implementing PIN/UV or making
origin decisions. `ctap` therefore has no CBOR parser and `piv` has no APDU
parser, and neither is a gap to fill in later.

What genuinely cannot be piped is the **framing**. USB CTAPHID (64-byte reports,
4-byte channel IDs, 7-byte init headers) and BLE (fragments, `HLEN`, wrapping
`SEQ`, no channels at all) are different envelopes around the same letter.
Translating envelopes, and nothing else, is the whole job.

---

# Part III — Adapters

## 9. Virtual HID (browser passkeys)

Present a HID device with FIDO usage page `0xF1D0`. Browsers and `libfido2` then
see an ordinary security key.

### Linux — `/dev/uhid`

Userspace creates the device; the kernel publishes a `hidraw` node. Ship a udev
rule granting access for your chosen VID/PID. **[HW]** VID/PID to be assigned.

### macOS — CoreHID, macOS 15+

`HIDVirtualDevice` + `HIDVirtualDeviceDelegate` in `macos/VirtualHIDHelper`:

- `receivedSetReportRequestOfType:` — host → authenticator CTAPHID frames
- `receivedGetReportRequestOfType:` — host polling
- `dispatchInputReport(data:timestamp:)` — authenticator → host

Maps cleanly onto CTAPHID's 64-byte report model. Entitlement and distribution
constraints in §3.

### Windows — USB/IP

Local socket to the VHCI driver. `bulwarkid/virtual-fido` is working precedent.
Driver signing is the friction: test-signing mode or an attestation-signed build.
The alternative is a KMDF driver on Microsoft's Virtual HID Framework, which needs
an EV certificate but uses no socket at all.

Note: since Windows 10 1903, non-admin processes cannot open FIDO HID devices
directly — `webauthn.dll` is the only consumer.

**Check whether this adapter is needed at all.** Windows supports BLE FIDO
natively once the device is paired in Bluetooth settings. If the firmware's
`0xFFFD` service is spec-compliant, the Windows case may already work with nothing
installed. Verify at build step 2 (§16) before writing this.

## 10. SSH — SK middleware, no virtual HID required

The cleanest win in the project: no entitlement, no driver, no signing, on any
platform.

OpenSSH does not require FIDO tokens to be on USB. From the 8.2 release notes:

> "FIDO tokens are most commonly connected via USB but may be attached via other
> means such as Bluetooth or NFC. In OpenSSH, communication with the token is
> managed via a middleware library, specified by the `SecurityKeyProvider`
> directive in `ssh/sshd_config(5)` or the `$SSH_SK_PROVIDER` environment
> variable."

`crates/sk-middleware` builds a **cdylib** exporting `sk_api_version`,
`sk_enroll`, `sk_sign`, `sk_load_resident_keys`. Contract is in `sk-api.h` and
`PROTOCOL.u2f` in the OpenSSH source.

```
SSH_SK_PROVIDER=/usr/local/lib/libsk-blebridge.so ssh-keygen -t ed25519-sk
```

Precedent: `mgbowen/windows-fido-bridge` and `tavrez/openssh-sk-winhello` are the
same shape. libssh 0.12 exposes the same API as `ssh_sk_callbacks_struct` and
notes that OpenSSH middleware adapts with minimal changes.

### Special rules — this library runs inside someone else's process

It is `dlopen`ed into `ssh-sk-helper`. Therefore:

- No global async runtime. Blocking IPC with an explicit timeout.
- No background threads outliving a call.
- No process-global state, no atexit handlers, no signal handlers.
- Never `panic!` across the FFI boundary — catch and return an error code.
- No logging to stdout/stderr; `ssh-sk-helper` uses those.

## 11. Login and screen unlock — PIV, not FIDO

**FIDO2 cannot log you into a Mac or a standalone Windows PC.** PIV is the only
external-credential path either accepts.

**Over USB, none of the rest of this section applies.** A CCID interface makes the
device a real smart card reader: macOS CryptoTokenKit, the Windows inbox PIV
minidriver and Linux PCSC-Lite all bind to it directly. No `vpcd`, no daemon, no
virtual reader. Ship the CCID path first — it is the shortest route to working
login on all three OSes, and it is the fallback when the BLE path is blocked.

Everything below is how to reach the same applet **over BLE**.

`vpcd` from the vsmartcard project is a smart card reader driver for PCSC-Lite and
the Windows smart card service, listening on loopback 35963/35964, letting
applications reach a virtual card through the PC/SC API. The daemon plays the
`vicc` role and relays APDUs over BLE.

**Card-present = device in BLE range.** That is the entire proximity mechanism.

### macOS

Route through Apple's built-in `com.apple.CryptoTokenKit.pivtoken`. Do **not**
write a CryptoTokenKit app extension — the login window doesn't run as your user,
so an appex isn't available there, and OpenSCToken's workaround needs SIP disabled.

macOS 10.10+ ships a proprietary PC/SC layer expecting USB readers, so `vpcd` is
built with a generated `Info.plist` registering it as a USB smart card reader.
Non-CCID readers install bundles into `/usr/local/libexec/SmartcardServices/drivers`.

Then `sc_auth identities` and `sc_auth pair -u <user> -h <hash>`. Set
`tokenRemovalAction=1` for lock-on-departure.

Slots: **9A** (PIV Authentication) for login, **9D** (Key Management) for keychain
and FileVault secret wrapping.

### Linux

`vpcd` → OpenSC PIV driver → `opensc-pkcs11.so` → `pam_pkcs11` → GDM/SDDM, screen
unlock, `sudo`. Cert-to-user mapping in `pam_pkcs11.conf`. PCSC-Lite is `vpcd`'s
native target — easiest of the three.

### Windows

`vpcd` builds for Windows; prebuilt binaries exist, source build wants VS 2019 +
WDK. Windows 8+ ships an inbox PIV minidriver, so a spec-compliant applet needs no
custom CSP.

- **Entra / domain joined**: native smart card logon. Needs real PKI — UPN in the
  cert's SAN, Smart Card Logon EKU `1.3.6.1.4.1.311.20.2.2`, CA in the NTAuth store.
- **Local account**: not native. `EIDAuthenticate` performs smart card
  authentication on standalone computers, inside `lsass.exe`. Proprietary and paid;
  the free Community Edition has been unmaintained since 2013 and is unavailable
  due to a Windows 10 problem.

**Prior art:** certgate's AirID is a BLE smart card reader whose documented demo is
Windows 10 smart card logon over BLE 4.2 with EIDAuthenticate, no domain or PKI,
auto-locking Windows past a configured distance. This exact idea, shipped
commercially.

## 12. CTAP BLE framing **[HW]**

`crates/ble-framing`. Service `0xFFFD`. Characteristics — verify against the
current CTAP spec:

| Characteristic | UUID |
|---|---|
| fidoControlPoint | `F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB` |
| fidoStatus | `F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB` |
| fidoControlPointLength | `F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB` |
| fidoServiceRevisionBitfield | `F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB` |

- **Initialization fragment**: `CMD` (1 byte, high bit set) ‖ `HLEN` (2 bytes,
  big-endian, total payload length) ‖ data
- **Continuation fragment**: `SEQ` (1 byte, high bit clear, `0x00`–`0x7f`,
  wrapping) ‖ data
- Fragment size = value read from `fidoControlPointLength` (20–512).
  **Read it. Never hardcode.**

Commands: `PING 0x81`, `KEEPALIVE 0x82`, `MSG 0x83`, `CANCEL 0xBE`, `ERROR 0xBF`.

PIV rides a separate private GATT service, specified in
`docs/device-protocol.md`. It reuses this framing byte for byte rather than
inventing a second one, so the conformance corpus covers both services and
`SEQ` wrapping has one implementation instead of two. That document also
records why a second service is not the §19 dead end: PIV keys are different
material, which §15.9 requires be kept separate, and this is the only door to
them rather than a second door to the FIDO material.

## 13. Local IPC

Unix domain socket on macOS/Linux, mode `0600`, in `$XDG_RUNTIME_DIR` or the
user's Application Support directory. Named pipe on Windows with a restrictive
DACL — **not** a loopback TCP port, because any local process can connect to a
listening localhost port on Windows.

Length-prefixed JSON, `{v: 1, id, type}` on every message.

```jsonc
// client -> daemon
{"v":1,"id":"...","type":"ctap.request","cbor":"<base64url>","timeoutMs":60000}
{"v":1,"id":"...","type":"ctap.cancel"}
{"v":1,"id":"...","type":"device.status"}

// daemon -> client
{"v":1,"id":"...","type":"ctap.response","status":0,"cbor":"<base64url>"}
{"v":1,"id":"...","type":"ctap.keepalive","reason":"up"}
{"v":1,"id":"...","type":"device.range","inRange":true,"bonded":true}
{"v":1,"id":"...","type":"error","code":"NOT_BONDED","message":"..."}
```

- **One CTAP transaction in flight.** Queue or reject; never interleave. The
  device is a single-threaded authenticator.
- `ctap.keepalive` with `reason: "up"` means the device wants a physical touch.
  Forward it. Never swallow it.
- The daemon builds no client data and makes no origin decisions — for the HID
  adapter the browser does that, exactly as it would for a physical key.

---

# Part IV — Correctness

## 14. Testing

The real system needs a radio and OS device APIs no CI runner has. Tests are
layered by what each layer can prove *without* hardware; only the top layer needs
the device.

**Rule: a test may only use the cheapest layer that can prove the thing.**

| Layer | Proves | Where | Gates a PR |
|---|---|---|---|
| L0 lint | fmt, clippy, no warnings | hosted | yes |
| L1 unit | CTAP CBOR, BLE framing, PIV APDU | hosted, 3 OSes | yes |
| L2 fake device | the whole proxy, no radio | hosted, 3 OSes | yes |
| L3 real uhid | daemon → uhid → hidraw → libfido2 | hosted Linux | yes |
| L3b compile-only | macOS/Windows adapters type-check | hosted | yes |
| L4 hardware | real ESP32, real BLE | self-hosted | **no** |

### L2 matters most

`daemon --features fake-transport` swaps the BLE transport for an in-process fake
speaking real CTAP. It exercises framing, channels, timeouts, cancellation and the
adapters — everything but the radio — on three OSes in seconds. **Put the effort
here.**

The fake must be hostile, not cooperative: fragment at every legal boundary size,
delay past the timeout, return `KEEPALIVE` indefinitely, drop mid-transaction,
reorder continuation fragments, and return CTAP error statuses on every branch.

### L3 runs the real Linux stack

GitHub's Linux runners give root in a VM, so `modprobe uhid` works and the full
path runs for real. Not a mock. A failure here is a shipping bug.

### Shared conformance corpus

`crates/ble-framing/tests/conformance/ble_fido_v1.json`, vendored from the
firmware repo. 37 vectors whose expectations are **authored from CTAP2 §11.4,
not captured from either implementation**, each carrying a `why`. Both sides
replay the same file, so a wire-format divergence fails CI on whichever side
moved instead of being found by reading both implementations side by side.

Two rules keep it honest:

- **A vector's expectation is only as good as its spec citation.** The corpus
  shipped with `cancel_mid_transaction_is_also_an_init_violation` expecting
  `ERR_INVALID_SEQ`, which §11.4.8 forbids — "the authenticator MUST NOT reply
  to the cancel message itself". Both implementations had agreed on it.
- **Disagreements are recorded as self-clearing, never skipped.** The `DISPUTED`
  list in `tests/conformance.rs` asserts that each disputed vector *still*
  disagrees, so correcting the corpus fails the test and forces the entry out. A
  skip list that passes silently would rot.

**`expect` means the last delivery, not the only one**, and a vector may carry
`deliveries` — an ordered list of every message delivered — when that matters.
"Last" alone would hide a real divergence: two implementations reaching the same
final state by different routes, one delivering a CANCEL and then a message, the
other only the message, would both pass. Every vector that delivers at most once
reads identically under either rule, which is why settling this cost nothing.

`direction` (`both` / `host_to_device` / `device_to_host`) is what lets one file
serve both sides. Getting it wrong is a real failure mode: a rule that holds only
for writes to `fidoControlPoint` must not be tagged `both`, or the host side
inherits a constraint the spec never placed on notifications.

### Golden transcripts

Capture real BLE exchanges from the device once, commit under `tests/golden/`,
replay in L1 forever. This catches "we changed the framing and didn't notice"
with no hardware. The L4 job re-captures nightly and **fails if transcripts
drift** — early warning that a firmware change broke the wire format. **[HW]**

### Fuzzing

**Bonding does not remove the need for this.** An established LESC bond means the
controller decrypts before you see anything, so an unbonded attacker cannot inject
into a live connection. That is not where malformed input comes from. It comes
from four places:

1. **Your own firmware** — a bonded device running a half-flashed image, an
   interrupted OTA, or a mismatched version sends garbage that is perfectly
   authenticated. A panic here means the user cannot log in, caused by your own
   device.
2. **Pre-bond paths** — advertisement scanning is unauthenticated by nature.
   Service discovery and the `fidoControlPointLength` read happen before or
   outside the bond.
3. **The OS-facing side** — the virtual HID node is writable by any local process
   passing the permission check, and hands you CTAPHID frames. Bonding protects
   none of this. **This is the least protected surface in the project.**
4. **PC/SC** — APDUs from a system service you don't control.

| Target | Input source |
|---|---|
| `ble_reassembly` | device-side fragments (1, 2) |
| `ctaphid_frames` | OS-side frames on the virtual HID node (3) |
| `ctap_cbor` | both directions |
| `piv_apdu` | PC/SC (4) |

60s smoke per PR, long runs nightly.

### L4 — hardware in the loop

A cheap always-on box (a Pi is fine) with the ESP32 attached, registered as a
self-hosted runner labelled `ble-hardware`. Nightly and manual only.

**It must never gate a PR.** Radio flakiness blocking merges trains everyone to
ignore CI, which costs more than the coverage is worth.

### What CI cannot cover

- **macOS virtual HID** — needs the entitlement and a real login session.
- **Windows USB/IP** — needs a signed driver.
- **Login-window behaviour** on any OS.

These go in `docs/manual-tests.md`, run before every tagged release, against every
OS version you claim to support. Keep it short enough that it gets run.

### Release gates

1. L0–L3 green on all three OSes.
2. L4 passed on the most recent nightly, no golden transcript drift.
3. `cargo deny` clean — advisories, bans, sources, licences.
4. Dependency versions still pinned exactly (§7).
5. Manual checklist signed off per OS in the release notes.
6. IPC protocol version bumped if any message shape changed (§13). Old clients get
   a clean version error, never a misparse.

### Do not

- Mock the CTAP layer in L2. Use a real CTAP implementation with a fake transport.
  A mock that agrees with your bugs tests nothing.
- Let `#[ignore]` accumulate. Hardware tests go behind a `hardware` feature —
  features are visible in CI config, ignores are invisible.
- Add a retry loop to make a flaky test pass. Flakiness in a radio path is
  information about a real bug in reconnection or timeout handling.

### `.github/workflows/ci.yml`

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 3 * * *'   # nightly, drives the hardware job
  workflow_dispatch:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -D warnings

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt, clippy }
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets --all-features

  # Pure crates must pass with no hardware and no platform APIs. If this job
  # needs a radio or a device node, the layering is broken.
  unit:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test -p ctap -p ble-framing -p piv -p ipc
      - run: cargo test -p ctap --test golden -- --nocapture

  # Substitutes the BLE transport for an in-process fake speaking real CTAP.
  # Proves the proxy logic end to end with no radio. Highest-value job.
  fake-device:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test -p daemon --features fake-transport

  # Root in a VM, so uhid loads and the whole Linux stack runs for real.
  linux-uhid:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Load uhid and install libfido2 tools
        run: |
          sudo modprobe uhid
          test -e /dev/uhid
          sudo apt-get update
          sudo apt-get install -y libfido2-dev fido2-tools libudev-dev
      - name: Permissions
        run: |
          sudo groupadd -f fido
          sudo usermod -a -G fido "$USER"
          echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' \
            | sudo tee /etc/udev/rules.d/90-fido.rules
          echo 'KERNEL=="hidraw*", GROUP="fido", MODE="0660"' \
            | sudo tee -a /etc/udev/rules.d/90-fido.rules
          sudo udevadm control --reload-rules && sudo udevadm trigger
      - name: End-to-end — daemon publishes a key, libfido2 reads it back
        run: sudo -E env "PATH=$PATH" cargo test -p vhid-linux --features hardware-uhid
      - name: fido2-token sees the virtual device
        run: |
          sudo -E cargo run -p daemon --features fake-transport -- --detach
          sleep 2
          sudo fido2-token -L | tee /tmp/tokens.txt
          grep -q . /tmp/tokens.txt

  # macOS CoreHID needs an entitlement and a login session; Windows USB/IP needs
  # a signed driver. Type-check only; behaviour is tested on self-hosted.
  gated-adapters:
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: macos-latest
            pkg: vhid-macos
          - os: windows-latest
            pkg: vhid-windows
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo check -p ${{ matrix.pkg }} --all-targets
      - name: Build the Swift helper
        if: matrix.os == 'macos-latest'
        run: xcodebuild -project macos/VirtualHIDHelper/VirtualHIDHelper.xcodeproj -configuration Debug CODE_SIGNING_ALLOWED=NO

  # Malformed input must never panic the daemon. Sources: our own firmware,
  # pre-bond BLE paths, and any local process writing to the virtual HID node.
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - uses: Swatinem/rust-cache@v2
      - run: cargo install cargo-fuzz --locked
      - run: cargo fuzz run ble_reassembly -- -max_total_time=60
      - run: cargo fuzz run ctaphid_frames -- -max_total_time=60
      - run: cargo fuzz run ctap_cbor      -- -max_total_time=60
      - run: cargo fuzz run piv_apdu       -- -max_total_time=60

  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check advisories bans sources licenses
      - name: No caret ranges on the alpha crates
        run: |
          ! grep -E '^(webauthn-authenticator-rs|soft-fido2[a-z-]*)\s*=\s*"\^?[0-9]' Cargo.toml \
            || (echo "Pin these exactly — see PROJECT.md 7" && exit 1)

  # Self-hosted runner with the device attached. Never gates a PR.
  hardware:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    runs-on: [self-hosted, linux, ble-hardware]
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Confirm the device is bonded and present
        run: cargo run -p transport-ble --bin ble-probe -- --require-bonded
      - name: Full CTAP suite over BLE
        run: cargo test -p daemon --features hardware-ble -- --test-threads=1
      - name: SSH round trip
        run: ./tools/ci/ssh-roundtrip.sh
      - name: Capture transcripts for replay
        run: cargo run -p tools --bin capture -- --out tests/golden/
      - name: Fail if golden transcripts drifted
        run: git diff --exit-code tests/golden/
```

## 15. Security invariants

Release blockers, not review nits.

**15.1 No key material in the daemon, ever.** Not cached, not derived, not
"temporarily". If a design needs the daemon to hold a private key, the design is
wrong.

**15.2 Unbonded links are refused, always, with no override flag.** CTAP requires
LE Secure Connections bonding **with MITM protection**. A bond formed by Just
Works pairing is still MITM-able by an attacker present at pairing time, so the
state to verify is *authenticated* encryption, not merely that some bond exists.

**Only one of the three platforms will tell you.** Checked against vendor
documentation on 2026-09-11:

| Platform | Source | Bonded? | With MITM? |
|---|---|---|---|
| Windows | `DeviceInformationPairing.ProtectionLevel` | yes (`IsPaired`) | **yes** — `EncryptionAndAuthentication` (3), readable after pairing |
| Linux | BlueZ `org.bluez.Device1` | yes (`Paired`, `Bonded`) | **no** — the interface has no security-level, key-type or encryption property |
| Linux | `/var/lib/bluetooth/<adapter>/<dev>/info` | yes | yes — `[LongTermKey] Authenticated=1` — but root-only and not a supported API |
| Linux | `getsockopt(SOL_BLUETOOTH, BT_SECURITY)` | — | yes — `BT_SECURITY_HIGH` (3) / `FIPS` (4) mean an authenticated key, but it needs the L2CAP socket, which BlueZ owns when GATT goes over D-Bus |
| macOS | CoreBluetooth | **no** | **no** — no bonding property on `CBPeripheral`; `IOBluetoothDevice.pairedDevices()` is BR/EDR only |

So the host-side query is not portable, and on macOS it does not exist. This
invariant cannot be built on it.

**The portable check is behavioural — and it is the stronger one.** The
peripheral declares `fidoControlPoint` and `fidoStatus` as requiring encrypted
**and authenticated** access. A link that is unbonded, or bonded only by Just
Works, fails at ATT with `Insufficient Authentication` (0x05) or `Insufficient
Encryption` (0x0F). A control-point write that *succeeds* is therefore proof the
link met the requirement, and it is proof produced by the device.

That ordering is the point. A daemon asking its own operating system whether the
link is safe is asking a component that sits inside the trust boundary the
invariant defends; the answer is advisory. The device's ATT permissions are
checked on the device.

Concretely:

- The **first control-point write is the gate.** An `Insufficient
  Authentication` or `Insufficient Encryption` ATT error ends the session
  (§15.8). It is never retried, and never answered by initiating pairing that
  would settle for Just Works.
- Where the platform does answer (Windows), query it and refuse early. That buys
  a better error message, not a different guarantee.
- What every backend must therefore surface is **the ATT error code of a failed
  operation**, distinguishable from a generic I/O error. That, not the bonding
  query, is what makes this invariant enforceable.
- The device side is load-bearing: if the peripheral marks those characteristics
  encryption-only, the whole check silently degrades to "some bond exists".
  Pin it in firmware and assert it from the host conformance run.

**`btleplug` supplies none of it** — checked against 0.13.0 on 2026-09-07: no
pairing, bonding or encryption-state API, no ATT MTU accessor
(deviceplug/btleplug#246, open since 2022, with users "settling for the minimum
MTU of 20"), and write failures arrive without ATT codes. Three platform
backends are still required — BlueZ D-Bus, CoreBluetooth, WinRT — but the table
above changes what they are *for*: ATT error fidelity first, bonding query only
where it happens to exist. Scope `transport-ble` accordingly; it is the largest
and riskiest crate in §8, not a thin wrapper. Test against real hardware.

**15.3 User presence is physical, on the device.** The daemon may never
auto-satisfy a touch. Proximity is not presence.

**15.4 Relay attacks are in scope.** RSSI presence is trivially relayed by an
attacker with two radios. Compounding it, macOS does not verify that certificates
on a smart card match the logged-in user — only that valid certs sit in the
expected PIV slots. Require a button press per unlock. RSSI thresholds and
round-trip timing are defence in depth, not substitutes.

**15.5 No key material, PINs, APDU bodies, or CBOR payload contents are logged.**
Redact by default; debug logging behind an explicit runtime flag. `clientDataHash`
is fine; PIN protocol material is not.

**15.6 No non-loopback sockets.** Enforced by a test inspecting the daemon's
listening sockets. See §5.

**15.7 IPC endpoints are owner-only.** `0600` on Unix sockets; restrictive DACL on
Windows named pipes. Validate peer credentials where the platform allows
(`SO_PEERCRED`, `LOCAL_PEERCRED`, `GetNamedPipeClientProcessId`).

**15.8 Fail closed.** Any ambiguity in bonding, device identity, or transaction
state returns an error. Never guess in the user's favour.

**15.9 Key separation on the device.** PIV authentication keys and FIDO2
credentials must never derive from the same input. PIN semantics don't map
between the protocols; sharing means a weakness in one costs you both.

**"Distinct slots" was the wrong way to state this, and the applet boundary is
not what protects it.** Both families derive through
`HMAC(master_secret, input)`, so separation reduces entirely to the two never
being handed the same input. Routing was never the risk — the applet boundary
stops a PIV request reaching `ctap_request()` and does nothing about a
derivation-input collision.

**Not every FIDO path is dangerous, and that determines the fix.** Checked in
firmware on 2026-09-10:

| Path | Input | Gate |
|---|---|---|
| CTAP2 credential | 70 bytes | HMAC tag verified before deriving |
| U2F key handle | 48 bytes | HMAC tag verified before deriving |
| Wallet / custom | ≥24 bytes | **static 4-byte tag, no MAC** |
| PIV slot label | 16 bytes | — |

The first two are not reachable without the master secret. **The wallet path is
the entire risk**: its input is genuinely attacker-chosen, and the only thing
between a chosen credential id and a PIV signing key is that
`WALLET_MIN_LENGTH` is 24 while the PIV label is 16.

**Domain separation does not fix this, which is not the obvious conclusion.**
`HMAC(master, "piv" ‖ label)` is 19 bytes — still short, still separated by the
same length comparison, a rename of the mechanism rather than a replacement.
Construction-level separation needs the *FIDO* side prefixed too, and that side
is vendored Solo code whose derivation change would invalidate every credential
already registered on every device. Registered passkeys would stop working, in
exchange for a property the length check already enforces.

So **the length assertion is load-bearing, not a stopgap**, and the firmware
pins it two ways: the label is too short to reach the wallet path, and it must
not open with `WALLET_TAG` for the day someone lengthens it past 24. Either
barrier alone suffices; both are asserted at compile time.

The general instinct — prefer construction to arithmetic — is right and was
wrong here, because only one of the two derivations is ours to change and the
one that is not is the one with the weak gate. Record it that way round: the
natural fix is unavailable, not merely unchosen.

---

# Part V — Execution

## 16. Build order

Sequenced so each step is independently testable and the slow-approval item gates
as little as possible.

1. CTAP over a **wired serial link** — `authenticatorGetInfo` answering. Proves
   CBOR and the state machine with no radio.
2. Move to **BLE GATT `0xFFFD`**. ~~Verify against Windows native BLE FIDO.~~
   **That check is no longer dependable** (§18): Chrome dropped BLE CTAP2 in 2020,
   and Windows 11 appears to have regressed BLE enrolment. Nothing in the mainstream
   ecosystem still speaks `0xFFFD` to check ourselves against for free.

   **Replacement: a commercial BLE FIDO key as a reference device.** Drive one
   (Feitian ships them) with our own daemon first. A daemon that works against
   somebody else's spec-compliant key is itself proven; the firmware can then be
   validated against the proven daemon. Without this, daemon and firmware are only
   ever tested against each other, and a shared misreading of the spec stays
   invisible. Budget for one key — it is the cheapest correctness insurance here.
3. **Daemon + SK middleware → SSH.** `ssh-keygen -t ed25519-sk`. First real
   end-to-end win. No entitlements, drivers, or signing on any OS.
   **Reached against the fake device on 2026-09-10**: the real `ssh-keygen`
   enrols an `sk-ssh-ed25519@openssh.com` key and signs with it, through
   `ssh-sk-helper` → our cdylib → the IPC socket → the daemon. Repeatable as
   `tools/ci/ssh-roundtrip.sh`, which the hardware job runs unchanged with
   `FEATURES=hardware-ble`.

   What that does *not* yet prove: the fixture returns a canned credential and
   a signature that is 64 bytes of `0x42`, so `ssh-keygen -Y verify` will
   reject it. Everything above the radio is exercised; nothing below it is.
4. **PIV applet + vpcd on Linux** → `pam_pkcs11` login.
5. **PIV on macOS** → `sc_auth pair`, screen unlock, proximity lock.
6. **Virtual HID on Linux (`uhid`)** → browser passkeys. Validates CTAPHID framing.
7. **Apply for the macOS entitlement** the day step 6 starts. Approval is slow and
   gates nothing else.
8. **Virtual HID on macOS** once the entitlement lands.
9. **Windows**, last, and only if step 2 showed it's needed.

Steps 1–7 need approval from nobody.

## 17. Pending hardware details

Everything marked **[HW]** is provisional until firmware specifics land. When
hardware information arrives, revisit:

Firmware is [`alphaseneca/cryptick-token-code`](https://github.com/alphaseneca/cryptick-token-code).
Rows below marked **answered** were read out of that repo at commit `d3b4701` on
2026-09-07; the rest are still open, mostly because the BLE transport there is a
20-line stub (`core/ble_fido/`) — see `notes/firmware-issues/`.

| Item | Where | What's needed |
|---|---|---|
| USB VID/PID for the virtual HID device | §9, udev rules | **Answered:** `1209:BEEE` (pid.codes), "Cryptick Token". The virtual HID should present the same pair so host rules match the real device. |
| Private GATT service + characteristic UUIDs for PIV | §12, `docs/device-protocol.md` | **Settled** 2026-09-10, not yet implemented either side. Service `FBF6EB90-7F39-41B1-A191-9527CC42F8BE`; framing reused from `0xFFFD`; messages capped at 261 (short APDUs only); not advertised; no `PING`. Nothing open on the wire format. |
| PIV-over-BLE chunking format | §12, `docs/device-protocol.md` | **Answered:** identical to the `0xFFFD` transport, so the conformance corpus covers both. APDU chaining stays in the applet, not the transport. |
| `fidoControlPointLength` actual value | §12 | Open — device now exists and advertises, so this is one characteristic read away. Blocked on a macOS Bluetooth grant, not on firmware. Will follow the negotiated ATT MTU (`MTU-3`), so it varies per connection — read it, never assume. Firmware caps CTAP messages at 1200 bytes (`CTAP_MAX_MESSAGE_SIZE`); `Reassembler::with_max_message_len` takes that ceiling. |
| Advertisement format and device identity | §14 fuzz target 2, §15.2 | How the daemon recognises *this* device vs any FIDO peripheral |
| User-presence signalling | §13 keepalive, §15.3 | **Answered:** R557 fingerprint, not a button (`ctap_user_presence_test`, `core/fido2/hal_esp32.cpp:130`). It is user *verification*, so stronger than §15.4 asks for. Keepalive already ticks at 100 ms but is hardwired to CTAPHID. |
| PIV slot population | §11 | Planned 9A/9D (`docs/MAC_LOGIN.md`), matching §11. Applet today is SELECT-only (`core/piv/piv.c`); no GENERATE, VERIFY or GENERAL AUTHENTICATE. |
| Secure element / key storage | §15.1, §15.9 | **Answered: there is no secure element.** micro-ecc software crypto; FIDO RK blob in NVS/LittleFS; attestation key is a flash constant (dev cert); TOTP secrets plaintext; no flash encryption or secure boot in `platformio.ini`. §15.1 still holds, but means less than it reads — see §15.10. |
| Bonding / pairing method | §15.2 | Must provide MITM protection — confirm which method firmware uses |
| Power and connection behaviour | §14 L4 | Sleep, reconnect, advertisement interval — drives timeout tuning |
| Firmware version reporting | §14 golden transcripts | So drift can be attributed to a specific build |

Golden transcripts (§14) must be recaptured whenever any of these change.

## 18. Open questions

Do not guess. Test and record the answer here.

- **macOS: can a LaunchDaemon use CoreBluetooth at the login window?**
  **Answered 2026-09-07: no, not as a LaunchDaemon.** TCC is not available to root
  daemons — running as root does not bypass it, and a daemon loads before any GUI
  session exists, so there is nothing to prompt. Bluetooth consent is stored in TCC
  against a bundle identifier and signing requirement, which a bare daemon binary
  does not have. A LaunchAgent works; a LaunchDaemon does not.

  **Consequences.** The radio-owning process must be a per-user **LaunchAgent**, not
  a LaunchDaemon (§6, packaging). But PC/SC runs system-wide as root and needs the
  card present *before* any user logs in, so the `vicc` side cannot depend on the
  agent. Login-window proximity unlock on macOS therefore looks unreachable by this
  route; screen unlock *after* first login is still fine, because the agent is
  running by then.

  **Lead not yet exhausted:** a global LaunchAgent with
  `LimitLoadToSessionType = ["LoginWindow"]` runs in the login window's graphical
  domain. Whether that context can hold Bluetooth TCC consent is untested and is the
  one remaining thing to try before declaring login-window unlock dead. **Gates step 5.**

- **Practical corollary, hit on 2026-09-10 during firmware bring-up.** A
  command-line tool that touches CoreBluetooth without a grant is killed on the
  spot — `SIGABRT`, no output, nothing to diagnose. Bluetooth being on at the
  system level is irrelevant; the grant is per-application.

  **A CLI tool inherits the grant from the process that launched it.** So the
  fix is to grant Bluetooth to the *terminal application* — System Settings →
  Privacy & Security → Bluetooth — not to the binary, which cannot hold one.
  Anything running our BLE code on macOS during development hits this, ours and
  the firmware's alike, and it looks like a crash rather than a permission
  error.
- **Does the Accessibility prompt appear for a FIDO-usage-page virtual device**, or
  only for keyboard/pointer descriptors? The one shipped implementation used a FIDO
  descriptor and did see it. Assume yes; confirm.
- **Is the Windows virtual HID adapter needed at all?** **Probably yes.** The Win32
  WebAuthn platform API documents BLE transport on Windows 10 and 11, but multiple
  reports say BLE authenticators that enrolled fine on Windows 10 cannot be added at
  all on Windows 11 — the prompt only offers "insert the security key". Treat native
  BLE as unavailable and plan for the adapter; confirm on real hardware at step 2
  rather than trusting either the docs or the reports.
- **CoreHID behaviour on macOS 26.x.** A reported 26.4-beta regression affected
  DriverKit virtual HID input routing. Different code path, but test on current OS
  versions before committing.
- **Entitlement approval odds and timeline.** Unknown and outside our control. If
  denied, exactly one capability is lost — browser passkeys on macOS. SSH, PIV
  login and screen unlock are unaffected. A denial is not a reason to change the
  architecture.

## 19. Settled dead ends — do not reopen

| Approach | Why it's dead |
|---|---|
| Hybrid transport / caBLE | Needs an internet tunnel server. Also: pairing payloads only supported on Android, so a QR scan every login, and the device has no camera. |
| FIDO2 for Windows login | Entra-joined or Entra hybrid joined only. Microsoft explicitly lists pure on-premises AD DS as unsupported; local accounts aren't a scenario. Use PIV. |
| FIDO2 for macOS login | macOS accepts PIV for local login, not WebAuthn. |
| Pre-boot unlock (FileVault / BitLocker) | No daemon, no Bluetooth stack, no PC/SC service exists pre-boot. Wired USB CCID is the only path, and only when plugged in. |
| CryptoTokenKit app extension on macOS | The login window doesn't run as the user, so an appex isn't available there. OpenSCToken's workaround needs SIP disabled. Use Apple's built-in `pivtoken` via vpcd. |
| PAM module / authorization plugin on macOS | Can't present UI at screen unlock; library validation rejects custom PAM modules in the `coreauthd` path; authorization plugins have an open bug failing to unlock the data protection keychain from the screensaver context. |
| Non-standard secondary GATT service | Adds a second untested door to the same key material for no benefit. One FIDO service, spec-compliant. |

## 20. Conventions

- Rust 2021, `#![forbid(unsafe_code)]` in the four pure crates. Unsafe is confined
  to `vhid-linux` (ioctl structs) and FFI boundaries, with a safety comment per block.
- No `unwrap()`/`expect()` in `daemon/` or `sk-middleware/` outside tests.
- Binary as `Vec<u8>`/`&[u8]` internally; base64url only at the IPC boundary.
- Typed errors with `thiserror`; no stringly-typed failures across crate lines.
- New runtime dependencies in `daemon/` or `sk-middleware/` need discussion.
  Supply chain surface in an authenticator path is a real cost.
- Commits follow **Conventional Commits**: `type(scope): summary`, e.g.
  `feat(transport-ble): read control point length before framing`.
  - Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `ci`, `build`,
    `chore`.
  - Scope is the crate name — `ble-framing`, `ctaphid`, `ctap`, `ipc`, `daemon`,
    `vhid-linux`, `sk-middleware`, `vpcd-client`. Omit it when a change spans
    several.
  - **An IPC message shape change is a breaking change**: mark it `feat(ipc)!:`
    and bump `PROTOCOL_VERSION` in the same commit, or §14's release gate 6 is
    violated the moment the change lands.
  - **Keep them short.** Subject under 72 characters; most commits need no body
    at all. Add one only where the *why* is not visible in the diff — a §15
    invariant, a §7 dependency decision, a §19 dead end — and then a few lines,
    not an essay. The durable reasoning belongs in this document, where it can
    be revised; a commit body cannot be.
  - Write bodies with `git commit -F <file>`, never `-m`. An apostrophe closes
    a single-quoted shell string and the rest of the message becomes pathspecs;
    backticks inside double quotes get executed. Both failure modes are quiet
    enough to produce a wrong commit rather than an error.
- Every behaviour derived from a spec, an OS doc, or a forum answer gets a comment
  citing the source. Future agents will otherwise re-litigate it — that is exactly
  how §19 got long.
- **Anything we emit, the party we emit it to must be able to read back.** An
  encoder that can produce input its own decoder rejects is a bug even when no
  caller currently triggers it, because the guard is the API, not the callers.
  This has already caught three: a multi-fragment `CANCEL` nothing would
  reassemble, a CBOR map whose two keys canonicalised to the same bytes, and
  the same `CANCEL` bug independently in the firmware.

  The qualifier matters in a direction-asymmetric protocol. `KEEPALIVE` and
  `ERROR` travel device-to-host only, so the device emits them and never
  reassembles them — the round trip for those is the *host's* to hold. Assert
  the property per direction, or "fixing" the exclusion later makes the device
  accept `KEEPALIVE` on its control point. For a direction-agnostic codec like
  `ble-framing` both readings collapse into one, which is why it holds there
  unqualified.

- **Verify constants against the specification, not against the other side's
  code.** Daemon and firmware are developed in parallel, often by agents. Two
  implementations that agree with each other prove nothing — it is the same
  failure §14 already names about mocks: *a mock that agrees with your bugs
  tests nothing.* A golden transcript captured from our own firmware is a
  regression check, not a conformance check.

  This is not hypothetical. `ble-framing` shipped with `0x06` commented as
  "reserved for CTAPHID", carried straight from `ERR_BUSY`'s absence in a
  half-remembered table, with a unit test asserting the wrong behaviour. CTAP
  2.1 §11.4.4.3 lists `ERR_BUSY = 0x06` as a real BLE error code; only `0x0a`
  and `0x0b` are HID-reserved. Reading the spec found it in minutes; no amount
  of cross-checking against the firmware would have, because the firmware was
  written from the same assumption.

## 21. Things not to do

- Don't bind a network socket (§5, §15.6).
- Don't cache credentials, keys, or assertions in the daemon (§15.1).
- Don't auto-satisfy user presence (§15.3).
- Don't implement CTAP PIN/UV protocols in the daemon. That's the authenticator's
  job; the daemon relays.
- Don't retry a failed CTAP transaction automatically. Surface it.
- Don't spawn threads or install handlers in `sk-middleware` (§10).
- Don't hardcode anything marked **[HW]** without a comment pointing at §17.
- Don't reopen anything in §19 without new evidence — and if you have new evidence,
  update the table rather than arguing in a PR description.

---

## 22. Sources

- Apple CoreHID: https://developer.apple.com/documentation/corehid/creatingvirtualdevices
- `HIDVirtualDevice`: https://developer.apple.com/documentation/corehid/hidvirtualdevice
- Entitlement requirement (DTS): https://developer.apple.com/forums/thread/764540
- Which HID entitlement is which: https://developer.apple.com/forums/thread/843327
- OpenSSH 8.2 release notes: https://www.openssh.org/txt/release-8.2
- OpenSSH SK API: `sk-api.h`, `PROTOCOL.u2f` in openssh-portable
- libssh FIDO2 callbacks: https://api.libssh.org/master/libssh_tutor_fido2.html
- windows-fido-bridge: https://github.com/mgbowen/windows-fido-bridge
- openssh-sk-winhello: https://github.com/tavrez/openssh-sk-winhello
- virtual-fido: https://github.com/bulwarkid/virtual-fido
- vsmartcard / vpcd: https://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html
- EIDAuthenticate: https://www.mysmartlogon.com/products/eidauthenticate.html
- Windows FIDO2 sign-in requirements: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-windows
- webauthn-authenticator-rs: https://docs.rs/webauthn-authenticator-rs
- soft-fido2: https://github.com/pando85/soft-fido2
- soft-fido2-transport (UHID): https://docs.rs/soft-fido2-transport
- passless: https://lib.rs/crates/passless-core
- BlueZ `org.bluez.Device1` properties: https://github.com/bluez/bluez/blob/master/doc/org.bluez.Device.rst
- Linux `BT_SECURITY` levels: https://manpages.debian.org/unstable/libbluetooth-dev/l2cap.7.en.html
- WinRT `DeviceInformationPairing`: https://learn.microsoft.com/en-us/uwp/api/windows.devices.enumeration.deviceinformationpairing
- WinRT `DevicePairingProtectionLevel`: https://learn.microsoft.com/en-us/uwp/api/windows.devices.enumeration.devicepairingprotectionlevel
- CoreBluetooth bonding (no API): https://punchthrough.com/core-bluetooth-guide/
