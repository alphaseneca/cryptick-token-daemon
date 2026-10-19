# Hardware OATH-TOTP specification

This document specifies the on-device **OATH-TOTP (RFC 6238 / RFC 4226)**
subsystem for Cryptick Token: the vendor CTAPHID wire protocol (`0xE3`),
data serialization, and biometric gating. Cited directly by
`crates/token-manager/src/oath.rs` (§3.4, the `INS 0x03` fallback) — treat
instruction/tag values below as load-bearing, not illustrative.

Two guarantees this protocol actually gives, kept to what's true elsewhere
in this repo's own docs (see `SECURITY_ROADMAP.md` for the honest at-rest
story, including what flash encryption does *not* yet cover):

1. **Seeds never leave hardware flash over this protocol.** Secret seeds
   are written once during enrollment (`INS 0x01`); there is no firmware
   API in this protocol to read one back or export it.
2. **The host never computes HMAC.** The host passes the current Unix
   timestamp counter; the token computes the step and the code on-chip.

---

## 2. CTAPHID Vendor Framing (`CTAPHID_CRYPTICK_OATH = 0xE3`)

Cryptick transports OATH commands over CTAPHID using vendor-specific command code `0xE3`:

```text
CTAPHID_CMD = TYPE_INIT | 0x63 = 0x80 | 0x63 = 0xE3
```

### 2.1 Request Structure (Host -> Token)
The payload carried inside CTAPHID frames follows an APDU-lite structure:

| Field | Length | Description |
|---|---|---|
| `CLA` | 1 byte | Class byte: always `0x00`. |
| `INS` | 1 byte | Instruction code (`0xA1`, `0xA2`, `0x01`, `0x03`, `0x04`). |
| `P1`  | 1 byte | Parameter 1: always `0x00`. |
| `P2`  | 1 byte | Parameter 2: always `0x00`. |
| `Lc`  | 1 byte | Length of following data payload (0–255 bytes). |
| `Data`| `Lc` bytes | TLV encoded parameters. |

### 2.2 Response Structure (Token -> Host)
The response contains optional TLV fields followed by a 2-byte ISO 7816 Status Word:

```text
[ Response TLVs (0..N bytes) ] || SW1 (1 byte) || SW2 (1 byte)
```

Common Status Words:
- `0x90 0x00`: **Success**.
- `0x69 0x82`: **Security Status Not Satisfied** (Biometric touch / fingerprint required).
- `0x6A 0x80`: **Incorrect Parameters** (Malformed TLVs or invalid length).
- `0x6A 0x88`: **Referenced Data Not Found** (Account label does not exist).
- `0x6F 0x00`: **Internal Hardware Execution Error**.

---

## 3. Instruction Definitions

### 3.1 `INS 0xA1` — LIST ACCOUNTS
Queries all configured TOTP account labels stored in flash.

- **Request**: `00 A1 00 00 00` (Empty data).
- **Response Payload**: Concatenated Tag `0x71` TLVs for every enrolled account:
  ```text
  [0x71] [Len] [Account String UTF-8] ... [90 00]
  ```
- **Example**:
  `71 0E 47 69 74 48 75 62 3A 61 6C 69 63 65 90 00` ("GitHub:alice")

---

### 3.2 `INS 0xA2` — CALCULATE CODE
Calculates the current OTP code for a specified account label.

- **Request Payload**:
  - `Tag 0x71` (`TAG_NAME`): Account label UTF-8.
  - `Tag 0x74` (`TAG_CHALLENGE`): 8-byte big-endian integer representing the current time-step counter:
    $$\text{counter} = \lfloor \frac{\text{now\_utc\_seconds}}{30} \rfloor$$
- **Request Example**:
  ```text
  00 A2 00 00 1A 71 0C 47 69 74 48 75 62 3A 61 6C 69 63 65 74 08 00 00 00 00 03 89 D4 B0
  ```
- **Response Payload**:
  - `Tag 0x75` (`TAG_RESPONSE`), length 5: a digit-count byte (always `6`)
    followed by a 4-byte big-endian integer holding the full decimal code.
    There is no separate "remaining validity seconds" field in the
    response — the 30-second window is fixed and known to the caller, so
    `webauthn-host` computes it host-side from wall-clock time
    (`30 - (now % 30)`) rather than reading it off the wire.
- **Response Example**:
  ```text
  75 05 06 00 0C DB E7 90 00
  ```
  *(digits: 6, code value: `0x000CDBE7` = `842727`, SW: `90 00`)*

---

### 3.3 `INS 0x01` — ENROLL ACCOUNT (PUT)
Enrolls a new TOTP secret seed onto the hardware token. Verified directly
against `src/host/cryptick_oath_hid.cpp`'s `OATH_INS_PUT` handler.

- **Request Payload**:
  - `Tag 0x71` (`TAG_NAME`): Account name string (1-64 bytes, e.g.
    `AWS:prod-admin`).
  - `Tag 0x73` (`TAG_KEY`): three parts, in order — a type/algorithm byte,
    a digit-count byte, then the raw secret seed (1-64 bytes):
    - Type/algorithm byte: `0x21` is the only value this firmware accepts
      (`& 0x0F == 0x01` for SHA1, `& 0xF0 == 0x20` for TOTP — a YKOATH-style
      encoding, not a flat algorithm ID). HMAC-SHA256 is not implemented;
      any other value is refused with `0x69 0x85`.
    - Digit count: must be exactly `6`; any other value is refused with
      `0x69 0x85`.
- **Token Processing**:
  - All accounts live in one AES-256-GCM-encrypted JSON file
    (`/totp_config.json` in LittleFS, `CONFIG_FILE` in `board_config.h`) —
    not one file per account.
  - Answers `0x90 0x00`, or `0x6A 0x84` if the token has no space left.

---

### 3.4 `INS 0x02` — DELETE ACCOUNT
Permanently deletes an account seed from flash.

- **Request Payload**:
  - `Tag 0x71` (`TAG_NAME`): Account label to delete.
- **Token Processing**:
  - Removes the account from `/totp_config.json` and rewrites it.
  - Answers `0x90 0x00`, or `0x6A 0x82` if the name isn't found.

---

### 3.5 `INS 0x04` — SET TIME
Synchronizes the token's internal hardware Real-Time Clock (RTC) with host UTC time.

- **Request Payload**:
  - `Tag 0x74` (`TAG_CHALLENGE`): 8-byte big-endian UTC timestamp (seconds since Unix epoch).
- **Response**: `90 00`.

---

## 4. TLV Tag Dictionary

Checked against `src/host/cryptick_oath_hid.cpp`'s actual tag constants and
handlers — not every tag this document previously listed is real. `0x76`
(`TAG_TRUNCATED`) and `0x78` (`TAG_PROPERTY`) do not exist anywhere in the
firmware; removed rather than left as unverifiable claims.

| Tag Value | Tag Constant | Length | Description |
|---|---|---|---|
| `0x71` | `TAG_NAME` | 1–64 bytes | UTF-8 account identifier (e.g. `Issuer:account@domain`). |
| `0x73` | `TAG_KEY` | 3–66 bytes | Type/algorithm byte (`0x21`, see §3.3) + digit-count byte (`6`) + 1–64 byte secret seed. |
| `0x74` | `TAG_CHALLENGE` | 8 bytes | Big-endian 64-bit integer (time-step counter or epoch seconds). |
| `0x75` | `TAG_RESPONSE` | 5 bytes | Digit-count byte (`6`) + big-endian 32-bit integer holding the calculated OTP code. |

There is also `INS 0x40` (`OATH_INS_PUT_OTPAUTH`), undocumented until now:
enrolls directly from a raw `otpauth://...` URI (no TLV wrapping, body is
the URI bytes verbatim, max 400). The token parses the name, algorithm and
secret itself. Not used by this repo's own clients (`UsbClient::oath_enroll`
builds the explicit TAG_NAME/TAG_KEY form above instead), but real and
available to any client that wants to hand over a URI unparsed.

---

## 5. Security & Cryptographic Boundary

### LittleFS Storage Encryption
Seeds are saved in LittleFS at `/oath/<id>.bin` as AES-256-GCM ciphertext
(IV ‖ ciphertext ‖ tag), keyed from the device master secret. See
`SECURITY_ROADMAP.md` for exactly what this does and does not protect
against: reading the LittleFS partition alone yields ciphertext, but the
wrap key sits in NVS on the *same* unencrypted flash chip today, so a full
flash dump recovers both. Treat this as protection against casual
filesystem inspection, not against an attacker holding the board, until
that gap closes.
