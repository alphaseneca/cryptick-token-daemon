# Cryptick Token Daemon — Agent Guide

This file orients **agents and engineers** working on the Cryptick Token Daemon, host tools, and middleware.

## 1. Core Architecture
- **Purpose**: Bridge the Cryptick Token hardware (`0x1209:0xBEEE`) across USB and Bluetooth Low Energy (BLE) to the host OS.
- **Why the Daemon Exists**:
  - Direct browser BLE FIDO was deprecated by Google/Apple/Microsoft.
  - The daemon connects to the ESP32-S3 over a dedicated custom GATT transport (USB over BLE / Daemon GATT) and surfaces it as a virtual USB CTAPHID device or local socket.
  - When plugged in over USB, the device is a standard CTAPHID and CCID composite — no daemon is required for USB operations.

## 2. OpenSSH Security Key Middleware (`crates/sk-middleware`)
- Implements the OpenSSH `sk-api.h` interface (`libsk_blebridge.dylib` on macOS / `.so` on Linux).
- **Transport Priority**:
  1. **Direct USB (`UsbClient`)**: Scans for `0x1209:0xBEEE` via `hidapi`. Communicates over raw 64-byte CTAPHID reports directly.
  2. **BLE Fallback (`DaemonClient`)**: If USB is absent, connects to the local daemon UNIX domain socket (`daemon.sock`).
- **Installed Artifact**: `~/.local/lib/libsk_blebridge.dylib`.
- **System Configuration**:
  - `~/.ssh/config`: `SecurityKeyProvider ~/.local/lib/libsk_blebridge.dylib`
  - `~/.zshrc`: `export SSH_SK_PROVIDER="$HOME/.local/lib/libsk_blebridge.dylib"`

## 3. Crates Map
- `crates/ctaphid`: Pure CTAPHID packetization, framing, commands, and multi-channel assembler.
- `crates/ctap`: CTAP2 CBOR request and response serialization.
- `crates/daemon`: The background daemon connecting to BLE GATT and exposing virtual HID / socket.
- `crates/sk-middleware`: Unified OpenSSH middleware (USB-first with BLE daemon fallback).

## 4. Building & Testing
```bash
export PATH="$HOME/.local/bin:$PATH"
# Check all workspace crates
cargo check --workspace
# Build release middleware and install
cargo build --release -p sk-middleware
cp target/release/libsk_blebridge.dylib ~/.local/lib/libsk_blebridge.dylib
# Build webauthn-host native messaging binary
cargo build --release -p webauthn-host
cp target/release/cryptick-webauthn-host ~/.local/bin/cryptick-webauthn-host
```

## 5. Dual-GATT & FIDO BLE Isolation Guarantee
- **Standard FIDO BLE (`0xFFFD`)**: Never touched by the daemon. Preserved clean and unhindered for native OS/browser Bluetooth WebAuthn pairing (macOS, Windows Hello, Android, iOS).
- **Custom Daemon GATT (`FBF6EB80-7F39-41B1-A191-9527CC42F8BE`)**: Dedicated transport service used exclusively by `cryptick-daemon` for host bridge communications.
- **Reference**: Detailed breakdown in `docs/ARCHITECTURE.md`.

## 6. On-Device Hardware TOTP Architecture
- **Zero-Trust Host Model**: The browser extension and native host NEVER hold private keys or calculate HMAC hashes. Seeds stay encrypted at rest in LittleFS flash on the ESP32-S3.
- **Vendor CTAPHID Protocol (`CTAPHID_CRYPTICK_OATH = 0xE3`)**:
  - `INS 0xA1` (LIST): Queries stored account labels without requiring user verification.
  - `INS 0xA2` (CALCULATE): Sends current time-step counter (`now_utc / 30`). The hardware performs HMAC-SHA1 on-chip and returns the 6-digit code. Gated by User Verification (fingerprint/touch).

