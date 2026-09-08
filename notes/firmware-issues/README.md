# Firmware issue drafts

Findings from reading [`alphaseneca/cryptick-token-code`](https://github.com/alphaseneca/cryptick-token-code)
at commit `d3b4701`, written up as issue bodies. **Nothing here has been posted.**

| Draft | Subject | Why it matters |
|---|---|---|
| [01](01-ble-transport-is-not-ctaphid.md) | `ble_fido` scaffold targets CTAPHID-over-BLE | Wrong wire format. Cheap to fix now, a rewrite later. Includes the GATT table, framing rules, buffer bounds and the LESC+MITM pairing config. |
| [02](02-transport-coupling-keepalive.md) | Presence keepalive hardwired to CTAPHID | Blocks BLE keepalive. Clean seam, ~10 lines. |
| [03](03-piv-select-truncated-aid.md) | PIV SELECT rejects the truncated AID | Would break both the Linux and macOS login paths. Needs verifying against OpenSC first. |
| [04](04-scaffolds-not-compiled.md) | Three scaffolds excluded from `build_src_filter` | CI never compiles the files the roadmap says are next. |
| [05](05-docs-say-ble-is-out-of-scope.md) | Docs still say BLE is out of scope | Next agent reading `AGENTS.md` starts from the wrong premise. |
| [06](06-dual-transport-arbitration.md) | USB + BLE must arbitrate for a single-threaded CTAP core | **Security.** `ctap_request()` has no lock; one shared `_user_confirmed` flag means a fingerprint meant for a USB operation could satisfy a BLE one. |

**File 1 and 6 together, and implement them together** — 6 corrects a threading
implication in 1, and neither is complete alone. They are the two where the cost
of delay compounds.

Project goal these assume: the device is FIDO2 **and** PIV, over **both** USB and
BLE. USB works natively on every OS with no host software; the daemon in this repo
exists only to make the BLE transport look like the USB one.

Delete this directory once the issues are filed.
