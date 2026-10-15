# Changelog — Cryptick Token Daemon & Tools

All notable changes to the Cryptick Token Daemon, OpenSSH Security Key Middleware, and Virtual Transports are documented in this file.

## [2026-09-27] - Unified USB-First / BLE-Fallback OpenSSH Security Key Middleware

### Added
- **Unified Transport in `sk-middleware` (`crates/sk-middleware/src/usb.rs`)**:
  - Direct USB CTAPHID client (`UsbClient`) using `hidapi`.
  - Scans for Cryptick Token hardware (`0x1209:0xBEEE`, Interface 0, Usage Page `0xF1D0`, Usage `0x01`).
  - Implements CTAPHID channel negotiation (`CTAPHID_INIT`) and message packetization/reassembly directly over raw HID reports.
- **Automatic Fallback Architecture (`crates/sk-middleware/src/ffi.rs`)**:
  - When OpenSSH invokes `sk_enroll`, `sk_sign`, `sk_load_resident_keys`, or `sk_options`:
    1. First attempts direct high-speed connection over USB CTAPHID.
    2. If USB is not connected, seamlessly connects to the local daemon socket (`daemon.sock`) over BLE.
  - Zero command-line flags required by the user (`ssh -K`, `ssh-keygen -K`, `ssh user@host` work seamlessly).
- **Environment & SSH Configuration**:
  - `SSH_SK_PROVIDER` set in user environment (`~/.zshrc`) pointing to `~/.local/lib/libsk_blebridge.dylib`.
  - `SecurityKeyProvider` in `~/.ssh/config` defaulting to `~/.local/lib/libsk_blebridge.dylib`.

### Clarified
- **Architecture**:
  - Direct browser BLE FIDO is deprecated across modern browser engines.
  - `cryptick-tokend` connects to the ESP32-S3 over a high-throughput custom Daemon GATT service (tunneling raw CTAPHID packets over BLE) and exposes them as a local virtual USB HID / socket bridge.
  - The OpenSSH SK middleware works transparently on any operating system, bridging to USB directly or through the daemon.
