# Issue draft 3 — PIV SELECT rejects the truncated AID that real clients send

**Repo:** `alphaseneca/cryptick-token-code`
**Labels:** `piv`, `bug`
**File:** `core/piv/piv.c:47`

## Current behaviour

```c
if (p1 == 0x04 && lc == PIV_AID_LEN &&
    memcmp(cmd + 5, PIV_AID, PIV_AID_LEN) == 0) {
    put_sw(out, &len, 0x9000);
```

This requires `Lc` to be exactly 11 and the AID to match all 11 bytes of
`A0 00 00 03 08 00 00 10 00 01 00`.

## Why it will reject real clients

The trailing `01 00` is the PIV application **version**, not part of the identity. SP 800-73 provides
for selecting the PIV Card Application by a right-truncated AID, and ISO 7816-4 SELECT with
`P1=0x04` is defined as a DF-name **prefix** match. In practice clients send the 9-byte
`A0 00 00 03 08 00 00 10 00`.

If OpenSC's PIV driver and Apple's `com.apple.CryptoTokenKit.pivtoken` both do that, the stub answers
`6A82` (file or application not found) and neither the Linux `pam_pkcs11` path nor the macOS
`sc_auth` path in `docs/MAC_LOGIN.md` can get off the ground.

**Verify before changing:** check the AID length used in `opensc/src/libopensc/card-piv.c`, and
capture what `pivtoken` actually sends. I have not confirmed either against a live client — the
spec argument is solid, the client behaviour should be observed rather than assumed.

## Suggested fix

Accept any `Lc` between 9 and 11 that prefix-matches:

```c
#define PIV_AID_MIN_LEN 9   /* RID + PIX; SP 800-73 allows right-truncated SELECT */

if (p1 == 0x04 && lc >= PIV_AID_MIN_LEN && lc <= PIV_AID_LEN &&
    memcmp(cmd + 5, PIV_AID, lc) == 0) {
    put_sw(out, &len, 0x9000);
    return (int)len;
}
```

A conformant SELECT response should eventually return the application property template (tag `61`)
rather than a bare `9000`, but that belongs with the real applet, not the stub.

## Also worth extending the host test

`tests/host/test_piv_apdu.py` currently asserts against a Python re-implementation of the APDU
*builder* and never exercises `core/piv/piv.c`. A case for the 9-byte SELECT would have caught this,
if the test drove the C. See issue draft 4.

## Checked and fine

The bounds arithmetic in `piv_handle_apdu` is sound — `lc` is capped at 255 by its `uint8_t` source
so `5 + lc` cannot overflow, and the `memcmp` is guarded by both the length check and `cmd_len`.
Short `cmd_len` returns `6700`, unknown INS returns `6D00`. No memory-safety problem here.
