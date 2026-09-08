# Issue draft 2 — user-presence keepalive is hardwired to CTAPHID

**Repo:** `alphaseneca/cryptick-token-code`
**Labels:** `ble`, `fido2`, `refactor`
**Blocks:** issue draft 1 (BLE keepalive)

## The coupling

`core/fido2/ctap.c` is transport-agnostic and signals presence through the HAL:

```c
device_set_status(CTAPHID_STATUS_UPNEEDED);        /* ctap.c:635 */
int ret = ctap_user_presence_test(CTAP2_UP_DELAY_MS);
```

But the ESP32 HAL reaches straight back into the USB transport
(`core/fido2/hal_esp32.cpp:154-158`):

```c
if (now - last_keepalive >= 100) {
    extern void ctaphid_update_status(int8_t status);
    ctaphid_update_status(CTAPHID_STATUS_UPNEEDED);
    last_keepalive = now;
}
```

So while the fingerprint is being waited on, the keepalive is emitted as a **CTAPHID** frame on USB
regardless of which transport actually opened the transaction. Over BLE that byte stream goes
nowhere, and the host sees a silent authenticator until it times out.

Two smaller things in the same spot: the `extern` declaration is inline in the function body rather
than from `ctaphid.h`, and the 100 ms cadence is a bare literal (`AGENTS.md` convention #1 puts
product timeouts in `board_config.h`).

## Suggested shape

Give the HAL a notion of which transport owns the current transaction, and dispatch:

```c
typedef enum { FIDO_TRANSPORT_NONE = 0, FIDO_TRANSPORT_USB, FIDO_TRANSPORT_BLE } fido_transport_t;

void fido_transport_set_active(fido_transport_t t);   /* set on request arrival, clear on completion */

static void fido_send_keepalive(int8_t status)
{
    switch (_active_transport) {
    case FIDO_TRANSPORT_USB: ctaphid_update_status(status); break;
    case FIDO_TRANSPORT_BLE: ble_fido_send_keepalive(status); break;   /* CMD_KEEPALIVE 0x82 */
    default: break;
    }
}
```

`ctap_user_presence_test()` then calls `fido_send_keepalive()` and knows nothing about either
transport. On BLE this becomes a `0x82` notification on fidoStatus with a one-byte body —
`0x01` PROCESSING or `0x02` TUP_NEEDED — which is what the 100 ms tick already means.

The existing 100 ms interval is comfortably inside the BLE transport's expectations, so no timing
change is needed; only the destination.

## Not a bug, checked

`device_disable_up()` (`hal_esp32.cpp:257`) auto-confirms presence, but it is only ever set from
`ctap.c:1954` (`GA.up == 0`) and the U2F register path — the spec-defined silent-assertion case.
That is correct behaviour, not a bypass.
