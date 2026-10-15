#!/usr/bin/env bash
# macOS Installer Package (.pkg) Builder for Cryptick Token Daemon
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_DIR="$REPO_ROOT/target/packages"
PKG_ROOT="$REPO_ROOT/target/pkg_root"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

mkdir -p "$TARGET_DIR"

if ! command -v pkgbuild >/dev/null 2>&1; then
    echo "Error: 'pkgbuild' is only available on macOS systems." >&2
    exit 1
fi

echo "=== Building Cryptick Token macOS Installer Package (.pkg) ==="

# 1. Compile release binaries if needed
echo "--> Compiling release binaries and libraries..."
cargo build --release -p daemon -p piv -p transport-ble -p sk-middleware -p webauthn-host

VERSION=$(cargo metadata --no-deps --format-version 1 2>/dev/null | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "0.1.0")
ARCH=$(uname -m)
OUT_PKG="$TARGET_DIR/CryptickTokenDaemon-${VERSION}-${ARCH}.pkg"

echo "--> Target Package: $OUT_PKG"
echo "--> Staging root payload..."
rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT/usr/local/bin"
mkdir -p "$PKG_ROOT/usr/local/lib"
mkdir -p "$PKG_ROOT/Library/LaunchAgents"
mkdir -p "$PKG_ROOT/Library/Application Support/Google/Chrome/NativeMessagingHosts"
mkdir -p "$PKG_ROOT/Library/Application Support/Mozilla/NativeMessagingHosts"
mkdir -p "$PKG_ROOT/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
mkdir -p "$PKG_ROOT/Library/Application Support/Chromium/NativeMessagingHosts"

# Copy binaries
cp -f "$REPO_ROOT/target/release/cryptick-daemon" "$PKG_ROOT/usr/local/bin/"
cp -f "$REPO_ROOT/target/release/cryptick-piv" "$PKG_ROOT/usr/local/bin/"
cp -f "$REPO_ROOT/target/release/ble-probe" "$PKG_ROOT/usr/local/bin/"
cp -f "$REPO_ROOT/target/release/ble-ctap" "$PKG_ROOT/usr/local/bin/"
cp -f "$REPO_ROOT/target/release/cryptick-webauthn-host" "$PKG_ROOT/usr/local/bin/"
cp -f "$REPO_ROOT/tools/cryptick" "$PKG_ROOT/usr/local/bin/"
chmod 755 "$PKG_ROOT/usr/local/bin/"*

# Copy OpenSSH SK middleware library
if [ -f "$REPO_ROOT/target/release/libsk_blebridge.dylib" ]; then
    cp -f "$REPO_ROOT/target/release/libsk_blebridge.dylib" "$PKG_ROOT/usr/local/lib/"
    chmod 755 "$PKG_ROOT/usr/local/lib/libsk_blebridge.dylib"
fi

# Copy LaunchAgent plist
cp -f "$REPO_ROOT/packaging/launchd/com.cryptick.daemon.plist" "$PKG_ROOT/Library/LaunchAgents/"

# Copy VPCD smart card bundle if built
if [ -d "$REPO_ROOT/drivers/ifd-vpcd.bundle" ]; then
    mkdir -p "$PKG_ROOT/usr/local/libexec/SmartCardServices/drivers"
    cp -R "$REPO_ROOT/drivers/ifd-vpcd.bundle" "$PKG_ROOT/usr/local/libexec/SmartCardServices/drivers/"
fi

# Generate native messaging manifest for system-wide /usr/local/bin path
MANIFEST_TMP="$REPO_ROOT/target/com.cryptick.webauthn.json"
cat << 'EOF' > "$MANIFEST_TMP"
{
  "name": "com.cryptick.webauthn",
  "description": "Cryptick Token WebAuthn Native Messaging Host",
  "path": "/usr/local/bin/cryptick-webauthn-host",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://jbggkoakhockpdblbiohpdfjcpolbfha/"
  ]
}
EOF

cp "$MANIFEST_TMP" "$PKG_ROOT/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.cryptick.webauthn.json"
cp "$MANIFEST_TMP" "$PKG_ROOT/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.cryptick.webauthn.json"
cp "$MANIFEST_TMP" "$PKG_ROOT/Library/Application Support/Chromium/NativeMessagingHosts/com.cryptick.webauthn.json"

# Firefox requires allowed_extensions instead of allowed_origins
cat << 'EOF' > "$MANIFEST_TMP"
{
  "name": "com.cryptick.webauthn",
  "description": "Cryptick Token WebAuthn Native Messaging Host",
  "path": "/usr/local/bin/cryptick-webauthn-host",
  "type": "stdio",
  "allowed_extensions": [
    "cryptick@alphaseneca.com"
  ]
}
EOF
cp "$MANIFEST_TMP" "$PKG_ROOT/Library/Application Support/Mozilla/NativeMessagingHosts/com.cryptick.webauthn.json"
rm -f "$MANIFEST_TMP"

# 2. Build Component Package
echo "--> Invoking pkgbuild..."
pkgbuild \
    --root "$PKG_ROOT" \
    --scripts "$SCRIPTS_DIR" \
    --identifier "com.cryptick.daemon" \
    --version "$VERSION" \
    --install-location "/" \
    "$OUT_PKG"

echo ""
echo "=== macOS Package Created Successfully ==="
echo "Package File: $OUT_PKG"
ls -lh "$OUT_PKG"
