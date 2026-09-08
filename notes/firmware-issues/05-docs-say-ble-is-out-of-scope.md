# Issue draft 5 — docs still say BLE is out of scope

**Repo:** `alphaseneca/cryptick-token-code`
**Labels:** `docs`

BLE is the direction, but three documents currently tell an agent or contributor the opposite:

| File | Line | Says |
|---|---|---|
| `AGENTS.md` | 158 | "Do not do by default: BLE (stubs removed; not in product MVP)" |
| `AGENTS.md` | 64 | "Do not reintroduce full product BLE without enabling scaffold deliberately" |
| `docs/MAC_LOGIN.md` | 13 | Mac login is "PIV over USB CCID … not FIDO HID and **not BLE**" |

`README.md:80` and `core/FEATURES_TODO.md:13` are already consistent with BLE being on the roadmap,
so it is only these three that contradict.

The `MAC_LOGIN.md` line is worth keeping in spirit — macOS login really is PIV, not FIDO — but the
"not BLE" half is about the transport underneath PIV, and BLE-backed PIV via a host-side virtual
reader is a real path. Reword rather than delete.

Suggested: move BLE from "Do not do by default" into the P2/P3 backlog with a pointer to issue
draft 1, so the next agent that opens `AGENTS.md` starts from the right wire format instead of
re-deriving CTAPHID-over-BLE from the current scaffold comment.

While editing `AGENTS.md`, the "Removed:" table row listing `ble` as removed is also now stale.
