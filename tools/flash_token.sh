#!/bin/bash
set -e

PIO="/Users/aurelius/.platformio/penv/bin/pio"
ESPTOOL="/Users/aurelius/.platformio/penv/bin/python3 /Users/aurelius/.platformio/packages/tool-esptoolpy/esptool.py"
FW_DIR="/Users/aurelius/Projects/cryptick-token-code"

echo "=== Cryptick Token ESP32-S3 Firmware Flasher ==="

# Find USB modem device
PORT=$(ls /dev/cu.usbmodem* 2>/dev/null | head -n 1 || true)
if [ -z "$PORT" ]; then
    echo "ERROR: No USB modem device found under /dev/cu.usbmodem*"
    echo "Please plug the Cryptick Token into a USB port."
    exit 1
fi

echo "Detected port: $PORT"
echo ""
echo "---------------------------------------------------------"
echo "ACTION REQUIRED: Enter ESP32-S3 Bootloader Mode"
echo "  1. Press and HOLD the BOOT button (GPIO 0)"
echo "  2. Press and RELEASE the RESET (EN) button"
echo "  3. RELEASE the BOOT button"
echo "---------------------------------------------------------"
echo "Waiting for device to enter ROM download mode..."

# Continuous loop until esptool detects the bootloader
while true; do
    if $ESPTOOL --port "$PORT" --chip esp32s3 --connect-attempts 1 chip_id >/dev/null 2>&1; then
        echo ""
        echo "✓ Connected to ESP32-S3 ROM Bootloader!"
        break
    fi
    sleep 0.8
    echo -n "."
done

echo ""
echo "--> Uploading Cryptick Token firmware via PlatformIO..."
$PIO run -d "$FW_DIR" -e esp32-s3-n16r8-install -t upload --upload-port "$PORT"

echo ""
echo "=== Firmware Flash Succeeded! ==="
echo "The token will now boot with native TinyUSB CTAPHID (0x1209:0xBEEE)."
