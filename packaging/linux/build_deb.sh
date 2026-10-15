#!/usr/bin/env bash
# Linux Debian (.deb) Package Builder for Cryptick Token Daemon
# Works on Debian/Ubuntu (via dpkg-deb) or cross-builds via standard ar + tar.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_DIR="$REPO_ROOT/target/packages"
DEB_ROOT="$REPO_ROOT/target/deb_root"

mkdir -p "$TARGET_DIR"

echo "=== Building Cryptick Token Debian Package (.deb) ==="

VERSION=$(cargo metadata --no-deps --format-version 1 2>/dev/null | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "0.1.0")

# Architecture detection (translates uname to debian arch)
case "$(uname -m)" in
    x86_64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l)  ARCH="armhf" ;;
    *)       ARCH="amd64" ;;
esac

OUT_DEB="$TARGET_DIR/cryptick-token-daemon_${VERSION}_${ARCH}.deb"
echo "--> Target Package: $OUT_DEB"

# Staging filesystem
rm -rf "$DEB_ROOT"
mkdir -p "$DEB_ROOT/DEBIAN"
mkdir -p "$DEB_ROOT/usr/bin"
mkdir -p "$DEB_ROOT/usr/lib"
mkdir -p "$DEB_ROOT/usr/lib/systemd/user"
mkdir -p "$DEB_ROOT/usr/lib/udev/rules.d"
mkdir -p "$DEB_ROOT/etc/opt/chrome/native-messaging-hosts"
mkdir -p "$DEB_ROOT/usr/lib/mozilla/native-messaging-hosts"

# 1. Prepare control file
sed -e "s/^Version:.*/Version: ${VERSION}/" \
    -e "s/^Architecture:.*/Architecture: ${ARCH}/" \
    "$SCRIPT_DIR/debian/control" > "$DEB_ROOT/DEBIAN/control"

cp "$SCRIPT_DIR/debian/postinst" "$DEB_ROOT/DEBIAN/postinst"
cp "$SCRIPT_DIR/debian/prerm" "$DEB_ROOT/DEBIAN/prerm"
chmod 755 "$DEB_ROOT/DEBIAN/postinst" "$DEB_ROOT/DEBIAN/prerm"

# 2. Copy binaries and tools
for bin in cryptick-daemon cryptick-piv ble-probe ble-ctap cryptick-webauthn-host; do
    if [ -f "$REPO_ROOT/target/release/$bin" ]; then
        cp -f "$REPO_ROOT/target/release/$bin" "$DEB_ROOT/usr/bin/"
        chmod 755 "$DEB_ROOT/usr/bin/$bin"
    fi
done

cp -f "$REPO_ROOT/tools/cryptick" "$DEB_ROOT/usr/bin/cryptick"
chmod 755 "$DEB_ROOT/usr/bin/cryptick"

# 3. Middleware library
if [ -f "$REPO_ROOT/target/release/libsk_blebridge.so" ]; then
    cp -f "$REPO_ROOT/target/release/libsk_blebridge.so" "$DEB_ROOT/usr/lib/"
    chmod 755 "$DEB_ROOT/usr/lib/libsk_blebridge.so"
fi

# 4. Systemd service & udev rules
cp -f "$REPO_ROOT/packaging/systemd/cryptick-daemon.service" "$DEB_ROOT/usr/lib/systemd/user/"
chmod 644 "$DEB_ROOT/usr/lib/systemd/user/cryptick-daemon.service"

cp -f "$REPO_ROOT/packaging/udev/70-cryptick.rules" "$DEB_ROOT/usr/lib/udev/rules.d/"
chmod 644 "$DEB_ROOT/usr/lib/udev/rules.d/70-cryptick.rules"

# 5. Native messaging manifests
cat << 'EOF' > "$DEB_ROOT/etc/opt/chrome/native-messaging-hosts/com.cryptick.webauthn.json"
{
  "name": "com.cryptick.webauthn",
  "description": "Cryptick Token WebAuthn Native Messaging Host",
  "path": "/usr/bin/cryptick-webauthn-host",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://jbggkoakhockpdblbiohpdfjcpolbfha/"
  ]
}
EOF
chmod 644 "$DEB_ROOT/etc/opt/chrome/native-messaging-hosts/com.cryptick.webauthn.json"

cat << 'EOF' > "$DEB_ROOT/usr/lib/mozilla/native-messaging-hosts/com.cryptick.webauthn.json"
{
  "name": "com.cryptick.webauthn",
  "description": "Cryptick Token WebAuthn Native Messaging Host",
  "path": "/usr/bin/cryptick-webauthn-host",
  "type": "stdio",
  "allowed_extensions": [
    "cryptick@alphaseneca.com"
  ]
}
EOF
chmod 644 "$DEB_ROOT/usr/lib/mozilla/native-messaging-hosts/com.cryptick.webauthn.json"

# 6. Build .deb package
if command -v dpkg-deb >/dev/null 2>&1; then
    echo "--> Invoking dpkg-deb..."
    dpkg-deb --build "$DEB_ROOT" "$OUT_DEB"
else
    echo "--> dpkg-deb not found; using standard tar + ar assembler..."
    TMP_BUILD="$REPO_ROOT/target/deb_build"
    rm -rf "$TMP_BUILD"
    mkdir -p "$TMP_BUILD"

    echo "2.0" > "$TMP_BUILD/debian-binary"

    (cd "$DEB_ROOT/DEBIAN" && tar --numeric-owner -czf "$TMP_BUILD/control.tar.gz" .)
    (cd "$DEB_ROOT" && tar --exclude='./DEBIAN*' --numeric-owner -czf "$TMP_BUILD/data.tar.gz" .)

    python3 -c "
import os, time

out_path = '$OUT_DEB'
parts = [
    ('debian-binary', open('$TMP_BUILD/debian-binary', 'rb').read()),
    ('control.tar.gz', open('$TMP_BUILD/control.tar.gz', 'rb').read()),
    ('data.tar.gz', open('$TMP_BUILD/data.tar.gz', 'rb').read()),
]

with open(out_path, 'wb') as out:
    out.write(b'!<arch>\n')
    for name, data in parts:
        hdr = f'{name:<16}{int(time.time()):<12}0     0     100644  {len(data):<10}\x60\n'.encode('ascii')
        out.write(hdr)
        out.write(data)
        if len(data) % 2 != 0:
            out.write(b'\n')
"
    rm -rf "$TMP_BUILD"
fi

echo ""
echo "=== Debian Package Created Successfully ==="
echo "Package File: $OUT_DEB"
ls -lh "$OUT_DEB"
