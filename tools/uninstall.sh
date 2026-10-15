#!/usr/bin/env bash
# Cryptick Token Daemon & Tooling Uninstaller
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="${DESTDIR:-}$PREFIX/bin"
LIB_DIR="${DESTDIR:-}$PREFIX/lib"

echo "=== Uninstalling Cryptick Token Daemon ==="

# 1. Stop and remove background service
if [ -x "$BIN_DIR/cryptick-daemon" ]; then
    echo "--> Stopping and removing background service via $BIN_DIR/cryptick-daemon..."
    "$BIN_DIR/cryptick-daemon" service uninstall || true
elif [ -x "$ROOT/target/release/cryptick-daemon" ]; then
    echo "--> Stopping and removing background service via target/release/cryptick-daemon..."
    "$ROOT/target/release/cryptick-daemon" service uninstall || true
fi

# 2. Remove installed executables
echo "--> Removing binaries from $BIN_DIR..."
rm -f "$BIN_DIR/cryptick-daemon" "$BIN_DIR/cryptick-piv" "$BIN_DIR/ble-probe" "$BIN_DIR/ble-ctap"

# 3. Remove middleware
echo "--> Removing middleware from $LIB_DIR..."
rm -f "$LIB_DIR/libsk_blebridge.dylib" "$LIB_DIR/libsk_blebridge.so"

# 4. Clean up IPC sockets if remaining
SOCKET="${XDG_RUNTIME_DIR:-$HOME/Library/Application Support}/cryptick/daemon.sock"
if [ -S "$SOCKET" ] || [ -f "$SOCKET" ]; then
    echo "--> Removing socket $SOCKET..."
    rm -f "$SOCKET"
fi

echo "=== Uninstallation Complete ==="
