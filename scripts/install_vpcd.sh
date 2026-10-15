#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUNDLE_SRC="$REPO_ROOT/drivers/ifd-vpcd.bundle"
TARGET_DIR="/usr/local/libexec/SmartCardServices/drivers"

echo "=== Installing Cryptick Virtual PCD Driver (ifd-vpcd) for macOS ==="

if [ ! -d "$BUNDLE_SRC" ]; then
    echo "Building ifd-vpcd.bundle..."
    mkdir -p /tmp/ifd-vpcd-build
    clang -dynamiclib -O2 -Wall \
      -I/tmp/vsmartcard/virtualsmartcard/src/pcsclite-vpcd/PCSC \
      -I/tmp/vsmartcard/virtualsmartcard/src/vpcd \
      -I/tmp/vsmartcard/virtualsmartcard/src/ifd-vpcd \
      -I/tmp/vsmartcard/virtualsmartcard/MacOSX \
      -DVPCDPORT=35963 \
      -DVPCDSLOTS=2 \
      /tmp/vsmartcard/virtualsmartcard/src/ifd-vpcd/ifd-vpcd.c \
      /tmp/vsmartcard/virtualsmartcard/src/vpcd/vpcd.c \
      /tmp/vsmartcard/virtualsmartcard/src/vpcd/lock.c \
      -o /tmp/ifd-vpcd-build/libifd-vpcd.dylib
    
    install_name_tool -id @rpath/libifd-vpcd.dylib /tmp/ifd-vpcd-build/libifd-vpcd.dylib
    codesign -s - -f /tmp/ifd-vpcd-build/libifd-vpcd.dylib
    
    mkdir -p "$BUNDLE_SRC/Contents/MacOS"
    cp /tmp/ifd-vpcd-build/libifd-vpcd.dylib "$BUNDLE_SRC/Contents/MacOS/libifd-vpcd.dylib"
    cp "$REPO_ROOT/drivers/ifd-vpcd.bundle/Contents/Info.plist" "$BUNDLE_SRC/Contents/Info.plist"
    codesign -s - -f "$BUNDLE_SRC"
fi

echo "Copying bundle to $TARGET_DIR..."
sudo mkdir -p "$TARGET_DIR"
sudo cp -R "$BUNDLE_SRC" "$TARGET_DIR/"
sudo chown -R root:wheel "$TARGET_DIR/ifd-vpcd.bundle"
sudo chmod -R 755 "$TARGET_DIR/ifd-vpcd.bundle"

echo "Configuring /etc/reader.conf for macOS com.apple.ifdreader..."
cat << 'EOF' | sudo tee /etc/reader.conf > /dev/null
FRIENDLYNAME    Virtual PCD
DEVICENAME      /dev/null:35963
LIBPATH         /usr/local/libexec/SmartCardServices/drivers/ifd-vpcd.bundle
CHANNELID       0x8C7B
EOF
sudo chmod 644 /etc/reader.conf

echo "Restarting smartcard and ifdreader subsystems..."
sudo killall -HUP ctkd 2>/dev/null || true
sudo killall -HUP pcscd 2>/dev/null || true
sudo killall -9 com.apple.ifdreader 2>/dev/null || true
sudo launchctl kickstart -k system/com.apple.ifdreader 2>/dev/null || true

echo "[SUCCESS] ifd-vpcd.bundle and /etc/reader.conf are configured!"
echo "Verifying driver and reader status..."
system_profiler SPSmartCardsDataType

