# Issue draft 4 — three scaffolds are excluded from the build, so CI never compiles them

**Repo:** `alphaseneca/cryptick-token-code`
**Labels:** `ci`, `build`

## What is missing

`platformio.ini:18-28` `build_src_filter` for `esp32-s3-n16r8`:

```ini
build_src_filter =
	+<main.cpp>
	+<systems/>
	+<host/>
	+<../core/totp.cpp>
	+<../core/crypto_esp32.cpp>
	+<../core/fido2/>
	-<../core/fido2/test_power.c>
	-<../core/fido2/stubs.c>
	+<../drivers/fingerprint_r558s.cpp>
	+<../drivers/usb_device.cpp>
```

Not listed, therefore never compiled by `pio run` or by `.github/workflows/ci.yml`:

- `core/ble_fido/ble_fido.c`
- `core/piv/piv.c`
- `drivers/usb_ccid.cpp`

`AGENTS.md` coding convention #2 says "New sources must be listed in `platformio.ini`
`build_src_filter`", so this is already against the repo's own rule.

## Why it matters

These three are exactly the files the roadmap says are next (`core/FEATURES_TODO.md`, last two
lines). They can accumulate syntax errors, signature drift against `ctap.h`/`device.h`, and stale
includes with nothing to catch it. `tests/host/test_piv_apdu.py` gives a false sense of coverage: it
tests a Python copy of the APDU builder, not the C that the docstring says it matches.

## Two options

**A — compile-only host job (preferred).** Keeps dead code out of the product image and out of the
flash budget. These files are freestanding C with no Arduino dependencies:

```yaml
      - name: Scaffold syntax check
        run: |
          gcc -fsyntax-only -Icore -Icore/fido2 -Iinclude core/ble_fido/ble_fido.c core/piv/piv.c
```

`usb_ccid.cpp` needs `g++` and the TinyUSB headers, so it may be easier to fold in under option B.

**B — add them to `build_src_filter`.** Total cost is under 90 lines of side-effect-free code, and
`ble_fido_init()` / `usb_ccid_init()` are no-ops that nothing calls. Straightforward, but it does put
unused code in the shipped image, and `AGENTS.md:64` asks that BLE not be enabled in the product
build casually.

Either way, once `core/piv/piv.c` compiles on the host, `tests/host/test_piv_apdu.py` can drive the
real `piv_handle_apdu()` through `ctypes` instead of re-implementing it.
