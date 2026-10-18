# Computer Login & Smart Card Authentication Guide

This document describes how the **Cryptick Token** can be used for operating
system login, lock-screen unlock, and `sudo` on **macOS**, **Windows**, and
**Linux** — what is real today, what each OS actually requires at the
protocol level, and exactly what is missing before each path is solid.

It intentionally does not read like a finished feature list. Treat the status
column as the truth and everything below it as the plan to get there. For the
device-side PIV applet/CCID implementation detail referenced throughout the
macOS section, see [`cryptick-token-code/docs/MAC_LOGIN.md`](../../cryptick-token-code/docs/MAC_LOGIN.md),
which is the authoritative source for firmware-level status.

## Status at a glance

| OS | Status | OS-level requirement | What's missing |
|----|--------|----------------------|-----------------|
| **macOS** (login window / FileVault) | **Partial** — applet exists on paper, nothing paired on real hardware | A **PIV (NIST SP 800-73) smart-card applet** behind CryptoTokenKit. Not negotiable; see §1. | CCID USB binding unverified on a real Mac, no certificate-issuance tooling in the daemon, `sc_auth pair` never run against a live card. See [MAC_LOGIN.md](../../cryptick-token-code/docs/MAC_LOGIN.md). |
| **Windows Hello** (lock screen) | **Not started** (no gap in firmware) | **CTAP2 FIDO2 security key** with `hmac-secret`, resident keys, and user verification. Not PIV. See §2. | Nothing in firmware — all four requirements are already met. The real blockers are account/policy (Entra join) and, if an org enforces attestation, FIDO Alliance MDS listing. No daemon or firmware code is required. |
| **Linux** (PAM) | **Real, working — but narrower than advertised** | A PAM module that can validate this device's FIDO/U2F credential, or a PKCS#11 provider for its PIV applet. See §3. | `pam_u2f` path works today for `sudo` only (not configured for the desktop lock screen). The `pam_pkcs11`/PIV path referenced elsewhere in this repo is unimplemented and has the same hardware-verification gap as macOS. |

---

## 1. macOS: this is a PIV requirement, not a preference

**Short answer: yes, it is a hard Apple requirement.** macOS's login window and
FileVault unlock are driven exclusively by **CryptoTokenKit**, and
CryptoTokenKit's built-in smart-card support is scoped to **PIV-compliant
cards** (which includes CAC, since CAC is PIV-compatible under NIST SP
800-73). There is no code path by which a bare FIDO2/WebAuthn credential —
one with no PIV applet behind it — can satisfy the login window or FileVault.
This is architectural, not a missing checkbox: WebAuthn in Safari/Chrome is a
completely different subsystem (`AuthenticationServices`/`ASAuthorization`
inside an app sandbox) that has no hook into `loginwindow` at all. The two
never meet.

Apple's own deployment documentation is explicit about this:

> "Apple offers native support for personal identity verification (PIV) smart
> cards, USB CCID class-compliant readers, and hard tokens that support the
> PIV standard" on "iOS 16.1, iPadOS 16, macOS 10.15, or later." Built-in
> support is "based on the CryptoTokenKit framework."
> — [Intro to smart card integration](https://support.apple.com/guide/deployment/intro-to-smart-card-integration-depd0b888248/web)

> Supported authentication contexts are "Login window, PKINIT, SSH, Lock
> Screen, Safari, authorization dialogs, and third-party apps supporting
> CryptoTokenKit" — all gated on identities populated into "Slot 9a (PIV
> Authentication) and 9d (Key Management)".
> — [Supported smart card functions on Mac](https://support.apple.com/guide/deployment/supported-smart-card-functions-on-mac-depc47f60521/web)

> FileVault unlock supports "CCID and PIV-compatible smart cards."
> — [FileVault and smart card usage in macOS](https://support.apple.com/guide/deployment/filevault-and-smart-card-usage-dep806850525/web)

None of Apple's smart-card deployment documentation mentions FIDO2, WebAuthn,
or any non-PIV authenticator as an alternative for the login window or
FileVault. Independent reporting agrees: "macOS does not natively support
FIDO security keys for user login" at the OS level — third-party tools like
Okta Device Access or `fido2lock` either gate a *password* unlock behind a key
check, or lock the screen on key removal; none of them make a FIDO2 credential
*the* login-window credential the way a PIV card is. This repo's own
architecture notes already independently reached the same conclusion: see
`PROJECT.md`'s feasibility table — `FIDO2 as OS login → macOS: ❌ PIV only`.

**What this means for the on-device PIN-entry UX work:** it must drive the
**PIV VERIFY/CHANGE REFERENCE DATA flow** (slot 9A PIN, `core/piv/piv.c`), not
a CTAP2 `clientPIN` flow. The two PINs are unrelated in this codebase and must
stay that way — conflating them would make the FIDO2 PIN gate the PIV applet
or vice versa, which is not how either OS consumes this device.

### Current reality vs. what this doc used to claim

The previous version of this document described a finished `cryptick login
setup` wizard that generates a Slot 9A keypair, issues a self-signed X.509
certificate, injects it via `PUT DATA`, and pairs it with `sc_auth`. **That
pipeline does not exist.** What's actually implemented, in
`crates/daemon/src/login.rs`:

- The binary is `cryptick-daemon`, not `cryptick` — the command is
  `cryptick-daemon login setup` / `cryptick-daemon login status`.
- `login setup` only *discovers an existing* certificate hash (via `sc_auth
  identities`, `sc_auth hash`, or `sc_auth list`) and calls `sc_auth pair`
  with it. It assumes a Slot 9A identity already exists on the card — it
  does not create one. There is no key-generation or certificate-issuance
  code anywhere in the daemon.
- It does set two real macOS preferences: `sc_auth pairing_ui -s enable` and
  `defaults write .../com.apple.security.smartcard allowSmartCard -bool
  true`. Those two steps are genuine.
- `login setup --pin <pin>` is accepted by the CLI parser but the value is
  never read anywhere in `login.rs` — it is currently a no-op flag.
- There is no `login setup --all` flag (Slot 9A + 9D) despite being
  documented below previously — only Slot 9A discovery exists.
- There is no `login remove` subcommand. `LoginCommand` only has `Setup` and
  `Status` variants; passing `remove` fails CLI parsing with "unknown login
  subcommand".
- `login status` is a real diagnostic: it checks for the CryptoTokenKit
  `pivtoken` plugin, reads `com.apple.security.smartcard` preferences, shells
  out to `sc_auth identities`/`sc_auth list`, and checks USB/BLE/vpcd
  presence. This part is accurate and useful as-is.

So **the certificate has to exist on the card before `login setup` can do
anything** — and per `MAC_LOGIN.md`, certificate issuance tooling doesn't
exist yet, and the CCID USB interface that would let macOS see the card at
all has never been verified against real hardware. `sc_auth pair` in this
code has never been run against a live Cryptick Token. Until the CCID
interface binds and a certificate exists, `login setup` has nothing to
discover.

### What's missing, in bite order

1. **Confirm CCID binds on macOS** — descriptor bytes are asserted in host
   tests (`tests/host/test_ccid_descriptors.py`) but never read off a real
   Mac. See `MAC_LOGIN.md` for the two-strikes latch-off safety mechanism if
   this is wrong.
2. **Certificate issuance**, in the daemon — generate the Slot 9A keypair on
   the token (`GENERATE ASYMMETRIC KEY PAIR`, already implemented in
   `core/piv/piv.c`), build a self-signed cert with `Smart Card Logon`
   (`1.3.6.1.4.1.311.20.2.2`) EKU, and `PUT DATA` it into Tag `0x53`. None of
   this exists in the daemon yet — this is the actual gap the old wording in
   this doc glossed over.
3. **Run `sc_auth pair` against a provisioned card** and confirm FileVault
   unlock via Slot 9D, on real hardware.
4. Only after 1–3 land does the on-device PIN-entry UX (encoder + BLE HID +
   fingerprint confirm) have something real to sit in front of — it is
   gating the PIV VERIFY ceremony, not a CTAP2 PIN.

### Terminal `sudo` via `pam_smartcard`

This part of the doc is generic macOS guidance, independent of Cryptick's own
implementation status — it works the same way for any provisioned PIV card:

```bash
sudo nano /etc/pam.d/sudo
```

```pam
# sudo: auth account password session
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

This only works once a Slot 9A identity is paired via `sc_auth` — which, per
above, requires a certificate on the card first.

### Wireless BLE smart card (PIV-over-BLE)

Carries PIV APDUs over the private GATT service (`FBF6EB90-…`) into
`cryptick-daemon`'s `vpcd` relay (`ifd-vpcd.bundle`), installed with
`sudo ./scripts/install_vpcd.sh`. Per `MAC_LOGIN.md`, this is **written and
unverified on hardware** — it depends on the same unverified CCID/PIV stack,
plus the relay itself.

---

## 2. Windows Hello: a CTAP2 FIDO2 requirement, not a PIV one

**This is the opposite shape of the macOS problem.** Windows's "Security key
sign-in" at the lock screen (part of Windows Hello for Business) is natively a
**FIDO2/CTAP2 feature** — PIV is not involved on Windows at all for this path.
Any CTAP2 authenticator Windows recognizes can be registered as a sign-in
method; no vendor driver, minidriver, or daemon code is required, because
Windows ships native FIDO2 platform support and this device already enumerates
as a standard CTAPHID security key over USB.

Microsoft's current (2026) FIDO2 hardware-vendor attestation requirements spell
out exactly what an authenticator's metadata must declare:

> "Your product metadata needs to be uploaded to the FIDO Alliance MDS... The
> metadata must indicate that your authenticator supports:
> - FIDO 2.0 or higher.
> - User verification or client PIN — Microsoft Entra ID requires user
>   verification with biometrics or PIN for all FIDO2 authentication attempts.
> - Resident keys (or discoverable credentials) — Resident keys are required
>   to use a security key to sign in to Microsoft Entra ID without entering a
>   username.
> - Hash-Based Message Authentication Code (HMAC) secret extension or
>   Pseudo-Random Function (PRF) extension — An HMAC secret extension or PRF
>   extension is required to use a security key to unlock Windows in offline
>   scenarios."
> — [Microsoft Entra ID attestation for FIDO2 security key vendors](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor)

### Firmware check: does Cryptick Token already meet this?

Checked directly against `core/fido2/` (not against the CLI's `fido info`
command — see caveat below):

| Requirement | Status | Where |
|---|---|---|
| CTAP2 (`FIDO_2_0`) | **Yes** | `core/fido2/ctap.c` GetInfo `versions` array (`FIDO_2_0`, `U2F_V2`) |
| `hmac-secret` extension | **Yes — fully implemented**, not a gap | `core/fido2/ctap.c` (`ctap_make_extensions`, GetAssertion handling of `EXT_HMAC_SECRET_*`), `core/fido2/ctap_parse.c` (`ctap_parse_hmac_secret`), advertised in GetInfo's `extensions` array |
| Resident / discoverable keys (`rk`) | **Yes** | GetInfo `options.rk = true`; `CTAP_residentKey` storage in `ctap.c`/`device.h` |
| User verification (`uv`) | **Yes**, via on-token fingerprint | GetInfo `options.uv = true` |
| Attestation statement | **Yes**, `packed` self-signed by default (`none` under a build flag) | `core/fido2/cryptick_attestation.inc`, gated by `CRYPTICK_ATTEST_FMT_NONE` in `ctap.c` |

So **the concrete gap the task brief asked me to go check for (`hmac-secret`)
does not exist** — it's already implemented and wired into both
`authenticatorMakeCredential` and `authenticatorGetAssertion`. There is no
firmware work needed for Windows Hello.

**Caveat — don't trust `tickctl fido info` to verify any of this.**
`run_fido_info` in `crates/token-manager/src/cli/fido_cli.rs` (around lines
102–110) prints a hardcoded capability block — `"FIDO2 protocols: CTAP 2.0,
CTAP 2.1"`, `"Extensions: credProtect, hmac-secret, largeBlobKey,
minPinLength"`, `clientPin: True` unconditionally, `bioEnroll`,
`pinUvAuthToken` — none of it is parsed from the device's real
`authenticatorGetInfo` CBOR response; the command only checks that the
transport is reachable, then prints the same literal text regardless of what
the token actually returns. The device does **not** actually advertise
CTAP2.1, `largeBlobKey`, or `minPinLength` — only `FIDO_2_0`, `credProtect`,
and `hmac-secret` are real (see table above). I flagged this as a follow-up
task rather than fixing it here, since it is a CLI/UX bug unrelated to the
login-requirements research and not a quick fix — see the spawned task.

### What's actually needed, then

Not firmware. Not daemon code. Two things, both outside this repo's code:

1. **Device/account policy**: Windows Hello's security-key sign-in at the lock
   screen is scoped to **Microsoft Entra ID joined or Entra hybrid joined**
   Windows 10/11 devices — it is explicitly **not** available to a plain local
   Windows account or an on-prem-only AD DS-joined device:
   > "Windows Server Active Directory Domain Services (AD DS) domain-joined
   > (on-premises only devices) deployment" is listed under **Unsupported
   > scenarios**.
   > — [FIDO2 Security Key Sign-in to Windows](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-windows)

   This is a customer IT-policy fact to put in front of users, not something
   Cryptick can code around.
2. **FIDO Alliance MDS listing + attestation chain**, only if a tenant turns
   on **Enforce attestation** in its Passkey (FIDO2) policy. With attestation
   *not* enforced (the common default), Microsoft accepts `none`/`tpm`/`packed`
   attestation statements outright — which is exactly what this device
   already emits. MDS submission is a vendor/business certification process,
   not firmware work.

---

## 3. Linux: real today, narrower than this doc previously claimed

The product-owner belief — "Linux already has a compatible way to log in via
passkeys" — **is true**, but it is the FIDO/U2F path (`pam_u2f`), not the
PIV/PKCS#11 path this document previously conflated it with. Keep the two
separate; they have different statuses.

### 3.1 `pam_u2f` (FIDO/U2F) — real and working

`run_linux_login_setup` in `crates/daemon/src/login.rs` is genuine, working
code, not a stub:

1. Creates `~/.config/cryptick/u2f_keys` (and, purely for interop with
   existing `pam_u2f` setups, the tool's own documented default path
   `~/.config/Yubico/u2f_keys` as a fallback).
2. Shells out to the real external tool `pamu2fcfg -u <user>` (from
   `libpam-u2f`), which performs an actual CTAP1/U2F registration against the
   device — confirmed real in firmware: `core/fido2/u2f.c` implements
   `U2F_REGISTER`/`U2F_AUTHENTICATE` (not a stub either).
3. Writes `pamu2fcfg`'s output (the key-handle mapping) to both paths above.
4. Prints the PAM line the user needs to add themselves:
   `auth sufficient pam_u2f.so cue`.

Set up today with:

```bash
sudo apt install pcscd libpam-u2f
sudo cp packaging/udev/70-cryptick.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
cryptick-daemon login setup           # registers the key, prints the PAM line
sudo nano /etc/pam.d/sudo             # add the printed line yourself
```

**What's missing relative to the "1-click wizard" framing:**
- It only prints a suggested line for `/etc/pam.d/sudo`. It never touches
  `/etc/pam.d/common-auth` (GDM/LightDM/SDDM desktop lock screen), despite
  this doc's §4.2 previously showing a lock-screen PAM block — that
  automation does not exist; a user has to add it to `common-auth` by hand,
  using the same `pam_u2f.so` line, not the `pam_pkcs11.so` line this
  document previously showed (that line belongs to the unimplemented PIV
  path below, and pasting it into `common-auth` with no PIV card provisioned
  would just fail closed).
- It never edits any system file automatically — by design, to avoid locking
  a user out of `sudo` or the desktop; this is a reasonable safety choice but
  is not what "1-click" implies.
- Depends on `libpam-u2f`/`pamu2fcfg` being installed; the daemon does not
  install it.

### 3.2 `pam_pkcs11` (PIV) — aspirational, not implemented

`PROJECT.md` marks Linux PIV login as "✅ PIV → `pam_pkcs11`" in its BLE
feasibility table, but that line describes architectural feasibility (PC/SC
can reach `pam_pkcs11` once a PIV card is present), not a finished feature.
There is no PKCS#11 module in this repo — no `crates/*pkcs11*`, no built
`.so`. Making this real means installing a generic third-party PKCS#11
provider (e.g. OpenSC) against this device's PIV applet over PC/SC
(`vpcd`/`ifd-vpcd.bundle` for BLE, direct CCID for USB), which hits the exact
same hardware-verification gap documented in `MAC_LOGIN.md`: the PIV applet
is host-tested only, nothing has run against a real reader, and certificate
issuance tooling doesn't exist. Don't advertise this path as done until that
work lands — it is tracked by the same checklist as the macOS PIV work in
§1, since it is the same applet and the same missing certificate-issuance
step, just reached through `opensc-pkcs11.so` + `pam_pkcs11.conf` instead of
`sc_auth`.

---

## 4. Security & Emergency Recovery Policy

> [!IMPORTANT]
> **Emergency Recovery**: Never lock yourself out of your system. Always keep
> a secondary administrator account with a long password, or store an
> emergency recovery key in a secure vault, before enforcing mandatory smart
> card or security-key policies.

### PIN Lockout Counter

This is about the **PIV PIN** (Slot 9A/9D), confirmed against firmware
(`core/piv/piv.h`): `PIV_PIN_MAX_RETRIES` is **3**. After 3 consecutive failed
PIN attempts the PIV applet locks (`PIV_SW_AUTH_BLOCKED`). The default PIV PIN
is the NIST SP 800-73 default `123456` until changed. This is unrelated to the
CTAP2 `clientPIN` used by the FIDO2/WebAuthn and `pam_u2f` paths — the two PINs
are gating two different applets and are not interchangeable.

### Loss or Depleted Battery

- A depleted battery still allows wired USB CCID/CTAPHID operation — plug in
  directly.
- If the token is unavailable, macOS and Linux both fall back to a
  password-login option (this is an OS fallback, not something Cryptick
  implements).

---

## Sources

- [Intro to smart card integration – Apple Support](https://support.apple.com/guide/deployment/intro-to-smart-card-integration-depd0b888248/web)
- [Supported smart card functions on Mac – Apple Support](https://support.apple.com/guide/deployment/supported-smart-card-functions-on-mac-depc47f60521/web)
- [Advanced smart card options on Mac – Apple Support](https://support.apple.com/guide/deployment/advanced-smart-card-options-dep7b2ede1e3/web)
- [FileVault and smart card usage in macOS – Apple Support](https://support.apple.com/guide/deployment/filevault-and-smart-card-usage-dep806850525/web)
- [Microsoft Entra ID attestation for FIDO2 security key vendors](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor)
- [Sign in with a FIDO2 security key – Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-security-key-sign-in)
- [FIDO2 Security Key Sign-in to Windows – Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-windows)
