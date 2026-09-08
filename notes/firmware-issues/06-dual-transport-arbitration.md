# Issue draft 6 — USB and BLE must arbitrate for a single-threaded CTAP core

**Repo:** `alphaseneca/cryptick-token-code`
**Labels:** `ble`, `fido2`, `security`, `design`
**Refines:** issue draft 1 — read that first, then this.

Now that both USB **and** BLE are product transports, this is the constraint that
decides whether the BLE work is safe or subtly broken.

## What protects `ctap_request()` today

Nothing, explicitly. There is no mutex, no re-entrancy guard, no critical section
anywhere near it. What makes it safe is a structural accident:

```c
/* core/fido2/hal_esp32.cpp:174 */
void _fido_task_loop(void *pvParameters) {
    ctap_init();
    uint8_t pkt[64];
    while (true) {
        if (_hid_queue && xQueueReceive(_hid_queue, pkt, pdMS_TO_TICKS(10)) == pdTRUE) {
            ctaphid_handle_packet(pkt);          /* → ctap_request() */
        }
        ctaphid_check_timeouts();
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
```

**One task** (`fido2_task`, pinned to core 0, priority 4) drains **one queue** and
is the only caller of `ctap_request()`. The USB ISR path just posts 64-byte
reports into `_hid_queue` (`hal_esp32.cpp:56`). Single producer, single consumer,
single transaction — so the CTAP state machine never re-enters.

## How BLE breaks it, if done the obvious way

The obvious NimBLE integration is to reassemble fragments in the GATT write
callback and call the CTAP layer from there. That runs on the **NimBLE host
task**, not `fido2_task`. Two tasks then enter `ctap_request()` concurrently and
the authenticator's state machine — PIN token state, RK iteration, the response
buffer — is shared mutable state with no lock.

Draft 1 says BLE should call `ctap_request()` as a sibling of `ctaphid.c`. That is
right about *layering* and wrong if taken as a threading instruction. Corrected:
**BLE is a sibling producer feeding the same consumer task.** It must never call
`ctap_request()` from a NimBLE callback.

## The security half, which is worse than the corruption half

`ctap_user_presence_test()` waits on process-global state:

```c
/* core/fido2/hal_esp32.cpp:16, 138-140 */
static bool _up_disabled;
_fido_ui_request = 1;
_user_confirmed  = false;
```

There is one `_user_confirmed` flag for the whole device. If a USB transaction and
a BLE transaction are both waiting for presence, **one fingerprint touch satisfies
whichever check reads the flag first** — which may not be the one the user meant
to approve. An attacker with a bonded BLE link could open an assertion and wait
for the user to touch the sensor for their own unrelated USB operation.

Serializing through the one task removes this by construction: a second
transaction cannot start until the first has finished. That is the real reason the
single-task design must be preserved, not just tidiness.

## Suggested shape

Keep one consumer task. Give it a second producer and a request that can describe
either transport:

```c
typedef enum { FIDO_TRANSPORT_USB = 1, FIDO_TRANSPORT_BLE } fido_transport_t;

typedef struct {
    fido_transport_t transport;
    uint16_t len;                        /* ≤ CTAP_MAX_MESSAGE_SIZE */
    uint8_t  data[CTAP_MAX_MESSAGE_SIZE];
} fido_request_t;                        /* queue by pointer, not by value */
```

- USB keeps posting 64-byte reports; `ctaphid.c` reassembles them as it does now.
- BLE reassembles fragments **in the NimBLE task** (that part is pure byte work and
  safe there), then posts one complete `MSG` payload to the FIDO task.
- The task sets the active transport before dispatch and clears it after, which is
  exactly the hook issue draft 2 needs for keepalive routing.
- While a transaction is in flight, the other transport gets a busy response —
  `CTAP2_ERR_CHANNEL_BUSY` over USB, `ERR_OTHER` (`0x7f`) over BLE — rather than
  being queued behind it. Queueing a second transaction that will demand its own
  fingerprint minutes later is worse UX than a clean refusal.

`fido_request_t` is ~1.2 KB, so queue pointers to pool-allocated buffers rather
than copying by value; two buffers is enough given only one is ever in flight.

## Separately: the queue reset on overflow

```c
/* core/fido2/hal_esp32.cpp:56-60 */
if (xQueueSend(_hid_queue, report, 0) != pdTRUE) {
    xQueueReset(_hid_queue);
    xQueueSend(_hid_queue, report, 0);
}
```

Dropping the whole queue mid-transaction discards CONT packets that a partially
reassembled CTAPHID message still needs. `ctaphid.c` will catch the resulting
sequence gap and error, so this is not memory-unsafe — but it turns transient
backpressure into a failed operation with a confusing host-side error. Prefer
dropping the single new packet and letting the host time out, or grow
`HID_QUEUE_LEN`.

## PIV over both transports has the same shape

Once PIV is reachable over USB CCID *and* BLE, `piv_handle_apdu()` inherits this
problem exactly. Route it through the same single-consumer arbitration rather than
inventing a second scheme.
