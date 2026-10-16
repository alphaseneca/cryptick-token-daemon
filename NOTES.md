# Agent pass — BLE/PIV hardening, encryption audit, cross-platform parity

Branch: `agent/ble-piv-crossplatform`. Scope was the six priorities below, in
that order. No physical device or BLE central hardware was available, so
nothing here is hardware-verified — see the explicit callouts.

## 1. PIV-over-BLE

`docs/device-protocol.md` still said "specification, not yet implemented on
either side." That was stale. The daemon side is implemented and correct:

- `crates/transport-ble::PivBleTransport` reads `pivControlPointLength`
  dynamically (20–512, never assumed), bounds the reassembler by the
  transport ceiling (261 bytes, the real message limit) rather than that
  characteristic, and delivers `CANCEL` on its first fragment without ever
  reassembling or answering it — the exact bug class §20 warns about, and it
  is not present.
- `crates/daemon::vpcd_relay` relays APDUs as opaque `Vec<u8>` between `vpcd`
  and the BLE transport, with `daemon` not depending on `piv` (enforced by
  `crates/daemon/tests/relay_stays_opaque.rs`).
- Wired into `ReconnectingBleTransport::spawn`: on a successful daemon-bridge
  connection, it also attempts `PivBleTransport::connect` and spawns the vpcd
  relay if the PIV service is present.

Fixed: `docs/device-protocol.md`'s status line now says what's actually
implemented and flags firmware-side status as unconfirmed from this repo
(commit `docs: correct device-protocol.md's stale implementation status`).

Left open: firmware-side implementation cannot be verified from this repo —
needs `alphaseneca/cryptick-token-code`. The `piv_apdu` fuzz target PROJECT.md
§14 lists does not exist yet (`fuzz/fuzz_targets/` has `ble_reassembly`,
`ctap_cbor`, `ctaphid_frames` only); not added here since it wasn't broken by
anything in this pass, but it's a real gap in fuzz coverage for the one
narrowing exception to "the daemon doesn't parse payloads" (`piv::apdu`).

## 2. BLE payload encryption/hardening

The design is sound and matches §15.2's reasoning: `btleplug` exposes no
pairing/bonding API on any backend, so the invariant is enforced
behaviorally — the first write to `fidoControlPoint` / `daemonControlPoint` /
`pivControlPoint` is the actual gate, and an ATT `Insufficient
Authentication`/`Insufficient Encryption` failure (`classify_att`) latches
the link to unauthenticated for every later operation. `session.rs`'s
`transact()` and `PivBleTransport::transceive()` both check `link.is_usable()`
before touching the wire. 0xFFFD is never read or written anywhere in
`transport-ble` or `daemon` (confirmed by grep), matching ARCHITECTURE.md §1.

Fixed: the four `.lock().expect(...)` mutex-poisoning panics and one
provably-safe-but-still-forbidden `.unwrap()` that had crept into `daemon/`
(hid.rs, fake.rs, transport.rs, main.rs), violating §20 outside tests. Also
de-obfuscated a `String::from_utf8(vec![89, 117, 98, 105, 99, 111]).unwrap()`
in `login.rs` back into a plain `"Yubico"` literal (see §4 below) — same
unwrap, different reason it existed.

Left open, explicitly: §15.2 says "where the platform does answer (Windows),
query it and refuse early" (`DeviceInformationPairing.ProtectionLevel`). That
is not implemented — `btleplug` doesn't expose it, and a correct
implementation needs the `windows` crate's WinRT bindings, which I did not
write blind. The invariant itself does not depend on this; §15.2 is explicit
that it "buys a better error message, not a different guarantee." Needs a
Windows machine with a bonded device to add and test.

## 3. Cross-platform parity — the big finding

**The daemon's local IPC had no Windows implementation at all.**
`cryptick-daemon run` returned `Unsupported: "Daemon IPC listener is not yet
supported on this platform"` unconditionally on Windows — not a bug in some
feature, the *entire* Mechanism 2 (host-assisted BLE bridge: SSH, the
WebAuthn native host, cryptick-manager's wireless OATH/FIDO/PIV commands) was
nonfunctional there. Worse, two of the three client crates for that same IPC
channel — `sk-middleware` (the OpenSSH SK provider cdylib — PROJECT.md §10
explicitly cites Windows precedent for this exact shape) and `webauthn-host`
— held a bare `std::os::unix::net::UnixStream` field with no `#[cfg(unix)]`
anywhere in the file. That is a **hard compile failure on Windows**, not a
missing feature; `cryptick-manager`'s equivalent was at least correctly
gated, just stubbed to an error.

Fixed, all compile-verified against the real `x86_64-pc-windows-msvc` target
(`cargo check -p daemon --target x86_64-pc-windows-msvc --all-features`
passes; the Windows-only code in the other three crates was verified via a
standalone scratch check, since all three pull in `hidapi`, whose native
build needs real Windows SDK headers this sandbox doesn't have):

- `crates/daemon/src/server.rs` gained `pub mod windows`: a real
  `tokio::net::windows::named_pipe`-backed `IpcListener`, mirroring
  `unix::IpcListener`'s shape closely enough that `serve_connection` (generic
  over any `AsyncRead + AsyncWrite`) runs unmodified. `main.rs`'s
  `live_main`/`fake_main` now use it instead of returning `Unsupported`.
- `sk-middleware`, `webauthn-host`, and `cryptick-manager` all gained a
  `windows_pipe::PipeStream` (duplicated per crate, matching this codebase's
  existing pattern of duplicating the small USB CTAPHID framing shim across
  the same three crates rather than sharing a dependency). Named pipes are
  opened like ordinary files via `CreateFileW`; since `std::fs::File` has no
  read-timeout API the way `UnixStream` does, a background thread owns the
  blocking `ReadFile` calls and hands chunks back over a channel, so `recv()`
  still honours its overall deadline via `recv_timeout`.

Left open, explicitly, both flagged in the code itself rather than patched
with unverified `unsafe` Windows FFI:

- **No restrictive DACL or peer-credential check on the named pipe**
  (§15.7's Windows analogue of the Unix listener's `peer_cred()` uid check —
  `GetNamedPipeClientProcessId` plus a token/SID comparison). It currently
  relies only on `reject_remote_clients`, which blocks the pipe from being
  reached over SMB but not another local user from opening a client handle.
- **sk-middleware's background reader thread can outlive the FFI call that
  started it**, because Windows gives no portable way to cancel a blocking
  read without raw `OVERLAPPED` I/O. §10 asks for no background thread to
  outlive a call. In practice `ssh-sk-helper` is itself a short-lived,
  per-operation process that tears the whole thing down moments later either
  way, but this falls short of the rule in the strict sense.

Both need a real Windows session to close properly and to verify at all —
neither was guessed at.

Also audited and found genuinely solid (no fix needed): `crates/daemon/src/
service/{linux,macos,windows}.rs` — launchd LaunchAgent / systemd --user /
Task Scheduler all implement install/uninstall/status with equivalent
behavior, including crash-restart semantics on all three (`KeepAlive`,
`Restart=on-failure`, `RestartOnFailure`). `packaging/{launchd,systemd,
windows}/*` match the runtime generators byte-for-byte in structure. The
macOS LaunchAgent-not-LaunchDaemon requirement from PROJECT.md §18 is
correctly implemented (`~/Library/LaunchAgents`, not `/Library/
LaunchDaemons`).

One asymmetry left as-is, on purpose: Windows has no automated `login setup`
equivalent to the macOS/Linux PIV+PAM/sc_auth wizard in `daemon/src/
login.rs`. This isn't a bug to patch — PROJECT.md §11 already documents why
(`EIDAuthenticate` is proprietary, paid, and unmaintained; there's no
first-party path). It does mean that crate carries a few Windows-build-only
dead-code warnings (unused on that target by design); left alone since they
don't fail any real CI gate and patching them would just be noise around an
intentional, documented platform difference.

## 4. Code quality (§20 / CI)

`cargo build/clippy/test/fmt --workspace --all-features` are all clean now
(clippy under `RUSTFLAGS="-D warnings"`, matching what the aspirational
PROJECT.md §14 CI config asks for even though the committed `.github/
workflows/ci.yml` doesn't set that env var). Specifically:

- **Found and fixed a severe, unrelated issue while auditing**:
  `cryptick-manager`'s help text, usage strings, and error messages said
  `ykman` throughout (e.g. `"Usage: ykman fido [COMMAND] [OPTIONS]"`), and
  `tools/cryptick` exposed a literal `cryptick ykman` subcommand. Worse,
  `tools/install.sh` and `tools/cryptick` referenced a `cryptick-ykman`
  package that was never defined in any `Cargo.toml` — a preexisting dead
  reference — and `install.sh` installed a file literally named `ykman`
  onto the user's `PATH`. All of this is now `cryptick-manager`
  (`cryptick ykman` → `cryptick manage`); the internal doc comments noting
  this CLI studies YubiKey Manager's command-set conventions as a design
  reference are left alone since they never surface to a user. Marked as a
  breaking change (`fix!:`) because the subcommand rename and removed
  `ykman` binary are user-visible.
- Repo-wide `cargo fmt` had ~3500 lines of drift; the lint job's own fmt
  check was running with `|| true` because of it. Applied and the `|| true`
  is gone from `.github/workflows/ci.yml`.
- Fixed the real §20 unwrap()/expect()-outside-tests violations in
  `daemon/` (see §2 above). `sk-middleware/` had none.
- Fixed every clippy warning the workspace actually had (all in
  `cryptick-manager`, `sk-middleware`, `webauthn-host` — `daemon`,
  `transport-ble`, `ble-framing`, `piv`, `vpcd`, `ipc`, `ctap*` were already
  clean): `op_ref`, `unnecessary_unwrap`, `needless_range_loop`,
  `manual_is_multiple_of`, `explicit_counter_loop`, `vec_init_then_push`,
  `useless_format`, `lines_filter_map_ok`, `needless_lifetimes`,
  `needless_return`, `chunks_exact_to_as_chunks`.
- Confirmed the four/five pure crates (`ctap`, `ble-framing`, `piv`, `vpcd`,
  `ipc`) still carry `#![forbid(unsafe_code)]` and contain zero actual
  `unsafe` blocks.
- Added `piv`/`vpcd` to the `unit` CI job's matrix (they're pure, no-hardware
  crates per §8 but were missing from the job that exists to prove that),
  and added a new `build-workspace` job (3-OS matrix, `cargo build
  --workspace --all-features`) — the job that would have caught the
  sk-middleware/webauthn-host Windows compile failure, since neither `unit`
  nor `fake-device` touch those crates and the release workflow's full
  workspace build only runs on a tag push.

Not run in this sandbox: `cargo deny` (not installed, and installing it
needs network access I didn't try to rely on) and `cargo fuzz` (needs
nightly + the `cargo-fuzz` installer). Neither surfaced anything in review,
but neither is verified either.

## 5. CLI/GUI parity

The actual wire protocol (`crates/ipc::ClientMessage`/`DaemonMessage`) is
deliberately minimal and matches PROJECT.md §13's documented shapes exactly:
`ctap.request`/`ctap.cancel`/`device.status` in, `ctap.response`/
`ctap.keepalive`/`device.range`/`error` out. A GUI built against exactly this
today could do real-time CTAP relay (passkeys, SSH-equivalent flows) with
full keepalive/cancel support — nothing missing there, and `cryptick-
manager`'s OATH/FIDO/PIV/APDU commands over the daemon already reuse this
same generic relay (vendor command bytes are opaque to the daemon by design,
per PROJECT.md §8), so that whole surface is *not* a gap.

What **is** CLI-process-local today, with no IPC equivalent a long-running
GUI could call into the already-running daemon for:

1. **Device discovery** (`cryptick-daemon devices`) — scans with its own,
   separate BLE adapter grab.
2. **Pairing** (`cryptick-daemon pair [--pin] [--device]`).
3. **Forget/unpair** (`cryptick-daemon forget [device]`).
4. **Rich device info** (`cryptick-daemon info`) — CTAP2 capabilities etc.,
   beyond the terse `device.status` the IPC already exposes.
5. **Computer-login status/setup** (`login status`/`login setup`) — shells
   out to `sc_auth`/`pcscd` directly; no IPC surface at all.

`connect`/`disconnect`/`service install|uninstall|status` are arguably fine
to leave as process-lifecycle operations a GUI can invoke the same way the
CLI does (start/stop the OS service), rather than daemon-IPC calls.

I did not add new `ClientMessage`/`DaemonMessage` variants for 1–5. Each
would mean new BLE radio operations invoked through the already-running
daemon's shared adapter (pairing in particular is genuinely risky to get
subtly wrong with zero hardware to test against), and per PROJECT.md §20 any
IPC message shape change needs `feat(ipc)!:` + a `PROTOCOL_VERSION` bump —
not something to do speculatively. This is a real list for whoever builds
the GUI next, not a set of bugs; flagging it is the deliverable here.

## 6. Time sync sanity check

No violation found. `crates/token-manager::oath::calculate_code` computes
`now_secs / period` (the RFC 6238 time-step *counter*) and sends it to the
device as `TAG_CHALLENGE` — exactly the relay duty ARCHITECTURE.md §2
assigns to the host. The `% divisor` / `% 1_000_000` step applied to the
response is decimal-digit formatting of a value the device already computed
and returned (per `docs/OATH_SPEC.md`, `TAG_RESPONSE`/`TAG_TRUNCATED` are
already-truncated integers on this device's protocol, unlike real YKOATH's
raw-HMAC `TAG_RESPONSE`), not HMAC-SHA1 or any cryptographic step performed
on the host. `webauthn-host::main.rs`'s `handle_totp_code`/
`build_oath_set_time_apdu` are pure APDU relays; `build_oath_set_time_apdu`
is the host's own UTC clock forwarded as `INS 0x04 SET_TIME`, exactly per
ARCHITECTURE.md §2. Neither `daemon/` nor `webauthn-host/` compute or cache
TOTP/HMAC state anywhere.

## What still needs real hardware to verify

Everything in this pass was protocol-level review, unit/integration tests
(including the `fake-transport` L2 harness and the shared conformance
corpus — `cargo test --workspace --all-features` is green), and — new for
this pass — a real `x86_64-pc-windows-msvc` cross-compile check for the code
this agent wrote. None of it is hardware-verified:

- PIV-over-BLE against real firmware (§1).
- The Windows named pipe listener and all three named-pipe clients, end to
  end, on a real Windows machine (§3) — including whether the background
  reader thread's lifetime caveat in sk-middleware actually matters in
  practice with `ssh-sk-helper`'s real process lifecycle.
- The Windows `DeviceInformationPairing.ProtectionLevel` early-refusal and
  the named pipe DACL/peer-credential hardening (§2, §3) — not implemented,
  not just unverified.
- Everything PROJECT.md §14 already lists as needing L4 (real ESP32, real
  BLE): golden transcripts, bonding/pairing behavior, power/reconnect
  timing.
