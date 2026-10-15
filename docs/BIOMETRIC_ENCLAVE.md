# Hardware Biometric Enclave & Cryptographic Architecture

This document specifies the hardware cryptographic architecture, on-chip biometric enclave, display rendering pipeline, and key-derivation guarantees of the **Cryptick Token**.

---

## 1. Hardware Architecture Overview

Cryptick Token is built on the **Espressif ESP32-S3** system-on-chip (Xtensa 32-bit dual-core LX7 processor running at 240 MHz) with vector instructions, hardware cryptographic engines, and dedicated peripheral buses:

```mermaid
flowchart TD
    subgraph SoC["ESP32-S3 Microcontroller & Security Boundary"]
        Core["Dual-Core 240MHz CPU<br/>(Secure FreeRTOS Execution)"]
        TRNG["Hardware TRNG<br/>(Thermal RF Entropy)"]
        CryptoEngine["Crypto Accelerators<br/>• AES-256-XTS/GCM<br/>• SHA-256 / SHA-1<br/>• RSA-3072<br/>• ECC Point Mult (P-256 / Ed25519)"]
        eFuse["Hardware eFuses<br/>• Flash Encryption Key<br/>• Secure Boot v2 Digest<br/>• Read/Write Disabled"]
        InternalSRAM["512 KB Internal SRAM<br/>(Zero-on-Reset Execution)"]
    end

    subgraph Peripherals["Physical Interfaces & Sensors"]
        Sensor["Capacitive Fingerprint Sensor<br/>(Match-on-Chip Pipeline)"]
        Display["1.47\" IPS TFT LCD (ST7789)<br/>Dedicated Hardware SPI"]
        Knob["Rotary Knob & Tactile Switch<br/>Physical User Presence"]
        USB["USB 2.0 Full-Speed PHY<br/>(CTAPHID & CCID Composite)"]
        Radio["2.4 GHz BLE 5.0 Radio<br/>(LE Secure Connections)"]
        Flash["LittleFS Flash Storage<br/>(Encrypted at Rest via AES-XTS)"]
    end

    Sensor ==>|SPI / Interrupt| Core
    Core ==>|Hardware SPI| Display
    Knob -->|GPIO Interrupt| Core
    USB <===>|TinyUSB Driver| Core
    Radio <===>|NimBLE Stack| Core
    Core <===>|AES-XTS DMA Bus| Flash

    TRNG --> CryptoEngine
    eFuse --> CryptoEngine
    CryptoEngine <--> Core
    Core <--> InternalSRAM
```

### Core Cryptographic Accelerators
- **Asymmetric Cryptography**: Hardware modular exponentiation and elliptic curve point multiplication supporting **NIST P-256 (secp256r1)** and **Curve25519/Ed25519** with side-channel mitigation.
- **Symmetric Cryptography**: High-speed DMA-coupled **AES-128 / AES-256** engine supporting ECB, CBC, OFB, CTR, and GCM modes.
- **Hashing**: Dedicated hardware pipelined **SHA-1** and **SHA-256** blocks.
- **Entropy Generation**: True Random Number Generator (TRNG) sampling thermal noise from the analog radio subsystem.

---

## 2. On-Chip Biometric Enclave

### 2.1 Capacitive Fingerprint Subsystem
Cryptick features an active capacitive fingerprint sensor module integrated directly into the token's ergonomic enclosure:
- **Spatial Resolution**: 508 DPI with 192x192 active capacitive sensing array.
- **False Acceptance Rate (FAR)**: $< 0.001\%$ ($1 \text{ in } 100,000$).
- **False Rejection Rate (FRR)**: $< 1.0\%$.

### 2.2 Template Storage & Zero Raw Image Exposure
Raw fingerprint images captured by the sensor **never leave internal volatile SRAM** and are immediately overwritten with zeros after feature extraction:
1. **Minutiae Extraction**: The core extracts ridge endings, bifurcations, and core vectors into a compact 512-byte biometric template.
2. **Template Encryption**: The template is encrypted using AES-256-GCM under a dedicated biometric key derived from the master secret:
   $$K_{\text{bio}} = \text{HKDF-SHA256}(\text{MasterSecret}, \text{"cryptick-biometrics-v1"})$$
3. **Encrypted Storage**: Stored in LittleFS at `/bio/template_<id>.bin`. Even a physical flash chip desoldering attack reveals only random ciphertext.
4. **Match-on-Chip (MoC)**: Verification compares live extracted minutiae vectors against the decrypted template exclusively within internal SRAM.

### 2.3 Presence Latch & Anti-Replay
When a biometric match or physical knob press succeeds:
- The firmware sets a **User Presence (UP)** and **User Verification (UV)** latch flag.
- The latch is bound to a high-resolution monotonic hardware timer (valid for a maximum of 15 seconds).
- Once an assertion or signing operation consumes the latch, **it is immediately cleared**, preventing replay attacks or secondary transactions from piggybacking on a single touch.

---

## 3. Secure Display Pipeline & Anti-Phishing (WYSIWYS)

### 3.1 Hardware Architecture
The display is a 1.47-inch 320x172 16-bit RGB IPS LCD powered by the **ST7789** controller, connected over a dedicated unidirectional SPI bus.

### 3.2 Host Spoofing Impossibility
Unlike software prompts or smart card applications that accept raw bitmaps from a host computer:
- **No Bitmap Passthrough**: The Cryptick firmware does **not** expose any API or protocol command allowing the host to send arbitrary pixel buffers or raw screen coordinates.
- **Semantic Rendering Only**: The display pipeline only accepts validated protocol structures:
  - Relying Party ID string (e.g. `github.com`) parsed from CTAP CBOR payloads.
  - User Handle and Display Name (e.g. `alice@example.com`).
  - Action Enum (`Create Key`, `Authenticate`, `TOTP`).
  - Remaining transaction countdown (seconds).
- **Anti-Phishing Color Identicon**: Cryptick computes a deterministic visual identicon and border hue from the SHA-256 hash of the Relying Party ID, allowing users to recognize genuine authentication prompts instantly.

---

## 4. Master Secret & Key Derivation Isolation

Cryptick utilizes a single 256-bit hardware master secret stored in write-protected eFuses or encrypted system partitions.

### Domain Separation Principle
To prevent any possibility of cross-protocol key collision (such as a PIV key operation interacting with a FIDO2 credential), all sub-keys are derived through **domain-separated HKDF-SHA256**:

```text
                        ┌─────────────────────────┐
                        │ 256-bit Master Secret   │
                        └────────────┬────────────┘
                                     │
           ┌─────────────────────────┼─────────────────────────┐
           │                         │                         │
           ▼                         ▼                         ▼
┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
│ FIDO2 Credential    │   │ PIV Smart Card      │   │ Hardware OATH       │
│ Sub-Tree            │   │ Slot Keys           │   │ Storage Key         │
│                     │   │                     │   │                     │
│ HKDF(MasterSecret,  │   │ HKDF(MasterSecret,  │   │ HKDF(MasterSecret,  │
│  "fido:" || rp_id   │   │  "piv:" || slot_id  │   │  "oath-storage")    │
│  || cred_id)        │   │  || generation)     │   │                     │
└─────────────────────┘   └─────────────────────┘   └─────────────────────┘
```

1. **FIDO2 Keys**:
   $$K_{\text{fido}} = \text{HKDF-Expand}(\text{MasterSecret}, \text{"fido:"} \parallel \text{RP\_ID} \parallel \text{CredID}, 32)$$
2. **PIV Smart Card Keys (Slots 9A, 9D, 9C, 9E)**:
   $$K_{\text{piv}} = \text{HKDF-Expand}(\text{MasterSecret}, \text{"piv:"} \parallel \text{SlotByte} \parallel \text{GenerationCounter}, 32)$$
   - When a slot key is regenerated (`GENERATE ASYMMETRIC KEY PAIR`), the generation counter increments, instantly rolling the key and invalidating prior certificates with zero flash churn.
3. **Hardware TOTP Secrets**:
   Encrypted in LittleFS under:
   $$K_{\text{oath}} = \text{HKDF-Expand}(\text{MasterSecret}, \text{"oath-storage-v1"}, 32)$$

Because every input domain begins with a distinct ASCII prefix string, **a mathematical collision between key spaces is impossible by construction**.

---

## 5. Physical Security & Anti-Tamper Defenses

### Flash Encryption with Hardware eFuse
- The entire LittleFS external flash partition is encrypted transparently on-the-fly using the ESP32-S3 hardware **AES-256-XTS** flash encryption unit.
- The flash encryption key is burned into eFuse BLOCK4 with read and write permissions permanently revoked.
- Attempting to dump the flash chip using a clip-on programmer or logic analyzer yields completely incomprehensible ciphertext.

### Secure Boot v2
- Bootloader images are digitally signed using **RSA-3072 / ECDSA**.
- The public key digest is burned into hardware eFuse BLOCK0.
- During boot, the ROM bootloader validates the signature before executing any code.
- Refuses to execute unsigned or tampered firmware builds.

### PIN Lockout Defense
- Failed PIN attempts are recorded in an encrypted monotonic counter in NVS.
- **3 consecutive failed attempts** locks the applet, requiring administrative reset.
- Immune to fast power-cycling attacks: the failure counter is committed to flash **prior** to evaluating PIN candidate equality.
