# Cryptick Token Documentation Hub

Welcome to the **Cryptick Token Documentation Hub**, modeled after the industry-standard developer and architecture references. Cryptick is a next-generation, 100% open-source cryptographic security key and biometric hardware enclave bridging USB-C and Bluetooth Low Energy (BLE) to macOS, Linux, and Windows.

---

## 📚 Documentation Directory

```
docs/
├── INDEX.md                   # Documentation Hub & Navigation (You are here)
├── ARCHITECTURE.md            # Core Daemon, Dual-GATT, & Multi-Transport Architecture
├── HARDWARE_SPECIFICATIONS.md # Hardware Architecture, Specifications & Comparative Matrix
├── COMPUTER_LOGIN.md          # Computer Login Guide & Automated Setup Wizard (macOS / Linux)
├── OATH_SPEC.md               # Hardware-Enforced OATH-TOTP Protocol & Zero-Trust Passer Spec
├── BIOMETRIC_ENCLAVE.md       # Biometric Sensor, Display, & Crypto Enclave Architecture
└── device-protocol.md         # PIV over BLE Low-Level Wire Protocol Specification
```

---

## 🎯 Quick Navigation by Topic

### 1. Architecture & Security Model
- [Architecture Overview (ARCHITECTURE.md)](ARCHITECTURE.md): Multi-transport routing (Direct USB, Host-assisted BLE socket, Standard FIDO BLE, and Hardware TOTP engine).
- [Hardware Architecture & Comparative Matrix (HARDWARE_SPECIFICATIONS.md)](HARDWARE_SPECIFICATIONS.md): Comprehensive feature matrix and architectural advantages over conventional closed-source and headless security keys.
- [Biometric & Enclave Architecture (BIOMETRIC_ENCLAVE.md)](BIOMETRIC_ENCLAVE.md): Hardware cryptographic accelerators, flash encryption, capacitive fingerprint sensor, and secure display pipeline.

### 2. Operating System & Computer Login
- [Computer Login Guide & Wizard (COMPUTER_LOGIN.md)](COMPUTER_LOGIN.md): Step-by-step computer login and lock-screen unlock using the automated `cryptick login setup` wizard for macOS (CryptoTokenKit / PIV) and Linux (PAM PKCS#11 / U2F).
- [PIV over BLE Wire Protocol (device-protocol.md)](device-protocol.md): Low-level APDU framing over the private GATT service (`FBF6EB90-...`) for wireless smart card authentication.

### 3. WebAuthn, Passkeys & Hardware TOTP
- [Hardware OATH-TOTP Specification (OATH_SPEC.md)](OATH_SPEC.md): Complete wire format, APDU-lite definitions (`0xE3`), zero-trust passer architecture, on-device RTC calculation, and browser extension pairing.
- [OpenSSH Security Keys](../AGENTS.md#2-openssh-security-key-middleware-cratessk-middleware): FIDO2 `ed25519-sk` and `ecdsa-sk` authentication with automatic direct USB and wireless BLE fallback.

---

## 🚀 Key Advantages of Cryptick Token

| Advantage | Cryptick Token | Conventional Security Keys |
|---|---|---|
| **Wireless Architecture** | **Dual-GATT BLE**: Custom Host Bridge (`FBF6EB80`) + Standard FIDO (`0xFFFD`). Wireless passkeys, SSH, & PIV on laptops. | **No BLE** (strictly tethered USB or mobile NFC). |
| **Transaction Display** | **On-Device Display**: True "What You See Is What You Sign" (WYSIWYS). Displays origin, user handle, and TOTP counter on-token. | **Headless ("Blind Touch")**: User taps contact blindly with zero visual context of what transaction or origin is being signed. |
| **Hardware TOTP Enclave** | **Zero-Trust On-Chip Engine**: Secrets encrypted in LittleFS (`AES-256-GCM`). 100+ accounts. Host NEVER sees seeds or computes HMAC. | Limited to small number of accounts in non-expandable secure element. |
| **Auditability & Freedom** | **100% Open-Source**: Open hardware schematics, firmware, Rust host daemon, and browser extension. Zero proprietary blobs. | **Closed-Source Proprietary Firmware**: Non-upgradable secure element. Vulnerable to unpatchable hardware CVEs (ROCA, side channels). |

---

## 🛠️ Unified Command-Line Interface (`cryptick`)

Cryptick provides a unified host CLI tool for diagnostics, service control, pairing, and login setup:

```bash
# Check end-to-end status of daemon, USB hardware, BLE link, and middleware
cryptick status

# Run automated 5-point self-test diagnostics
cryptick test

# Automated Computer Login wizard (provisions PIV slot 9A and pairs OS account)
cryptick login setup

# Inspect paired smartcard identities and driver status
cryptick login status

# Unpair smartcard login credentials
cryptick login remove

# Stream live background service logs
cryptick logs

# Auto-heal sockets and restart background launchd/systemd service
cryptick fix
```
