#!/usr/bin/env bash
# Cryptick Token Daemon & Tooling Installer
# Supports macOS (launchd) and Linux (systemd --user)
set -euo pipefail

# Ensure Cargo/Rust is in PATH
if ! command -v cargo >/dev/null 2>&1; then
    for rust_bin in "$HOME/.cargo/bin" "$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin" "$HOME/.rustup/toolchains/stable-x86_64-apple-darwin/bin" "$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin"; do
        if [ -x "$rust_bin/cargo" ]; then
            export PATH="$rust_bin:$PATH"
            break
        fi
    done
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: 'cargo' was not found in PATH. Please install Rust or add cargo to PATH." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="${DESTDIR:-}$PREFIX/bin"
LIB_DIR="${DESTDIR:-}$PREFIX/lib"

echo "=== Installing Cryptick Token Daemon ==="
echo "Version : $(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)"
echo "Prefix  : $PREFIX"
echo "Bin dir : $BIN_DIR"
echo "Lib dir : $LIB_DIR"
echo ""

# 1. Build release binaries
echo "--> Compiling release binaries and middleware..."
cargo build --release -p daemon -p piv -p transport-ble -p sk-middleware -p webauthn-host -p cryptick-manager

mkdir -p "$BIN_DIR" "$LIB_DIR"

# Stop running service prior to replacing executables on disk (prevents macOS SIGKILL from text busy)
if command -v launchctl >/dev/null 2>&1; then
    launchctl stop com.cryptick.daemon 2>/dev/null || true
    launchctl unload "$HOME/Library/LaunchAgents/com.cryptick.daemon.plist" 2>/dev/null || true
elif command -v systemctl >/dev/null 2>&1; then
    systemctl --user stop cryptick-daemon 2>/dev/null || true
fi

# 2. Copy binaries (remove existing first to allocate fresh inodes on macOS)
echo "--> Installing executables to $BIN_DIR..."
rm -f "$BIN_DIR/cryptick-daemon" "$BIN_DIR/cryptick-piv" "$BIN_DIR/cryptick-manager" "$BIN_DIR/ble-probe" "$BIN_DIR/ble-ctap" "$BIN_DIR/cryptick-webauthn-host" "$BIN_DIR/cryptick"
cp -f "$ROOT/target/release/cryptick-daemon" "$BIN_DIR/"
cp -f "$ROOT/target/release/cryptick-piv" "$BIN_DIR/"
if [ -f "$ROOT/target/release/cryptick-manager" ]; then
    cp -f "$ROOT/target/release/cryptick-manager" "$BIN_DIR/"
fi
cp -f "$ROOT/target/release/ble-probe" "$BIN_DIR/"
cp -f "$ROOT/target/release/ble-ctap" "$BIN_DIR/"
if [ -f "$ROOT/target/release/cryptick-webauthn-host" ]; then
    cp -f "$ROOT/target/release/cryptick-webauthn-host" "$BIN_DIR/"
fi
cp -f "$ROOT/tools/cryptick" "$BIN_DIR/cryptick"
chmod +x "$BIN_DIR/cryptick-daemon" "$BIN_DIR/cryptick-piv" "$BIN_DIR/ble-probe" "$BIN_DIR/ble-ctap" "$BIN_DIR/cryptick"
[ -f "$BIN_DIR/cryptick-manager" ] && chmod +x "$BIN_DIR/cryptick-manager"
[ -f "$BIN_DIR/cryptick-webauthn-host" ] && chmod +x "$BIN_DIR/cryptick-webauthn-host"

if [ "$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then
    codesign -s - -f "$BIN_DIR/cryptick-daemon" "$BIN_DIR/cryptick-piv" "$BIN_DIR/cryptick-manager" "$BIN_DIR/ble-probe" "$BIN_DIR/ble-ctap" "$BIN_DIR/cryptick-webauthn-host" 2>/dev/null || true
fi

# 3. Copy middleware library
case "$(uname -s)" in
    Darwin)
        MW_SRC="$ROOT/target/release/libsk_blebridge.dylib"
        MW_DEST="$LIB_DIR/libsk_blebridge.dylib"
        ;;
    *)
        MW_SRC="$ROOT/target/release/libsk_blebridge.so"
        MW_DEST="$LIB_DIR/libsk_blebridge.so"
        ;;
esac

if [ -f "$MW_SRC" ]; then
    echo "--> Installing OpenSSH SK middleware to $LIB_DIR..."
    cp -f "$MW_SRC" "$MW_DEST"
fi

# 4. Install background user service
echo "--> Registering and starting background service..."
"$BIN_DIR/cryptick-daemon" service install

echo ""
# 5. Run health check
"$BIN_DIR/cryptick-daemon" check || true

# 6. Configure shell environment in ~/.zshrc or ~/.bashrc
for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -f "$rc" ] || [ "$(basename "$SHELL" 2>/dev/null || echo "")" = "$(basename "${rc%.*}")" ]; then
        if ! grep -q "$BIN_DIR" "$rc" 2>/dev/null; then
            echo "--> Adding $BIN_DIR to $rc..."
            echo "" >> "$rc"
            echo "# Cryptick Token Daemon & tools" >> "$rc"
            echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$rc"
        fi
        if ! grep -q "SSH_SK_PROVIDER" "$rc" 2>/dev/null && [ -f "$MW_DEST" ]; then
            echo "export SSH_SK_PROVIDER=\"$MW_DEST\"" >> "$rc"
        fi
    fi
done

if [ "$(uname -s)" = "Darwin" ]; then
    if [ -d "/usr/local/libexec/SmartCardServices/drivers/ifd-vpcd.bundle" ]; then
        echo "Virtual Smart Card Driver: Installed (/usr/local/libexec/SmartCardServices/drivers/ifd-vpcd.bundle)"
    else
        echo "Virtual Smart Card Driver: Not installed yet."
        echo "  To enable wireless PIV login over BLE, run: ./scripts/install_vpcd.sh"
    fi
fi

echo ""
echo "=== Installation Complete ==="
echo "Binaries are installed to: $BIN_DIR"
echo "OpenSSH SK Provider path: $MW_DEST"
echo "If this terminal window does not find the command yet, run:"
echo "  source ~/.zshrc"
echo ""

