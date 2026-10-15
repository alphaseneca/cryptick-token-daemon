#!/bin/bash
set -e

PYTHON="/Users/aurelius/.platformio/penv/bin/python3"
PIO="/Users/aurelius/.platformio/penv/bin/pio"
FW_DIR="/Users/aurelius/Projects/cryptick-token-code"

echo "=== Cryptick Token USB Flasher (Zero-Button 1200bps Touch) ==="

$PYTHON -c "
import serial, time, glob, subprocess, sys

ports = glob.glob('/dev/cu.usbmodem*')
if not ports:
    print('ERROR: No /dev/cu.usbmodem* device detected. Plug in your Cryptick Token.')
    sys.exit(1)

port = ports[0]
print(f'Detected token on port: {port}')
print('Sending 1200bps touch reboot to enter ROM download mode...')

try:
    s = serial.Serial(port, 1200)
    time.sleep(0.05)
    s.close()
    print('1200bps touch completed.')
except Exception as e:
    print('Notice: Serial disconnected on reboot (expected):', e)

time.sleep(1.8)
ports_after = glob.glob('/dev/cu.usbmodem*')
if not ports_after:
    print('ERROR: No port detected after 1200bps touch!')
    sys.exit(1)

rom_port = ports_after[0]
print(f'ROM Bootloader active on: {rom_port}')
print('--> Uploading Cryptick Token firmware via PlatformIO...')

cmd = [
    '$PIO',
    'run',
    '-d', '$FW_DIR',
    '-e', 'esp32-s3-n16r8-install',
    '-t', 'upload',
    '--upload-port', rom_port
]
res = subprocess.run(cmd)
if res.returncode == 0:
    print('\n=== Firmware Flash Succeeded! ===')
    print('The token is now running native TinyUSB CTAPHID (0x1209:0xBEEE).')
else:
    print('\nERROR: Firmware flash failed.')
    sys.exit(res.returncode)
"
