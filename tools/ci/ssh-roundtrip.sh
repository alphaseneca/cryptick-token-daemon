#!/usr/bin/env bash
# Drives the real ssh-keygen through the SK middleware, the IPC socket, the
# daemon and a device — enrolling a key and signing with it.
#
# Against the fake device this is the L2 end of PROJECT.md §14; on the
# self-hosted runner with --features hardware-ble it is the L4 SSH round trip.
# Same script either way, which is the point: the thing under test is the whole
# path, and only the transport differs.
set -euo pipefail

FEATURES="${FEATURES:-fake-transport}"
ROOT="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
DAEMON_PID=""

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        # Reap it, so job control does not print "Terminated" and make a
        # successful run look like a failure.
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

case "$(uname -s)" in
    Darwin) LIB="libsk_blebridge.dylib" ;;
    *)      LIB="libsk_blebridge.so" ;;
esac

echo "building (features: $FEATURES)"
cargo build --manifest-path "$ROOT/Cargo.toml" -p daemon --features "$FEATURES" --bin cryptick-daemon
cargo build --manifest-path "$ROOT/Cargo.toml" -p sk-middleware

PROVIDER="$ROOT/target/debug/$LIB"
test -f "$PROVIDER" || { echo "no middleware at $PROVIDER"; exit 1; }

if [ "$(uname -s)" = "Darwin" ]; then
    SOCKET="${HOME}/Library/Application Support/cryptick/daemon.sock"
else
    SOCKET="${XDG_RUNTIME_DIR:-$HOME/.cryptick}/daemon.sock"
fi

# A daemon killed by a signal never runs its Drop, so a dead socket file can be
# left behind. Existence therefore proves nothing — the wait below connects.
rm -f "$SOCKET"

echo "starting daemon"
"$ROOT/target/debug/cryptick-daemon" &
DAEMON_PID=$!

connectable() {
    python3 - "$1" <<'EOF' 2>/dev/null
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1)
s.connect(sys.argv[1])
s.close()
EOF
}

for _ in $(seq 1 100); do
    connectable "$SOCKET" && break
    kill -0 "$DAEMON_PID" 2>/dev/null || { echo "daemon exited during startup"; exit 1; }
    sleep 0.1
done
connectable "$SOCKET" || { echo "daemon never became connectable"; exit 1; }
echo "socket: $SOCKET"

ASKPASS="$WORK/askpass.sh"
cat << 'EOF' > "$ASKPASS"
#!/bin/sh
exit 0
EOF
chmod +x "$ASKPASS"

echo "enrolling"
SSH_ASKPASS_REQUIRE=force SSH_ASKPASS="$ASKPASS" SSH_SK_PROVIDER="$PROVIDER" ssh-keygen -t ed25519-sk \
    -f "$WORK/id_sk" -N '' -C ssh-roundtrip </dev/null

grep -q '^sk-ssh-ed25519@openssh.com ' "$WORK/id_sk.pub" \
    || { echo "enrolled key is not an sk key"; cat "$WORK/id_sk.pub"; exit 1; }
echo "enrolled: $(cut -d' ' -f1 <"$WORK/id_sk.pub")"

echo "signing"
echo "ssh-roundtrip" > "$WORK/msg"
SSH_ASKPASS_REQUIRE=force SSH_ASKPASS="$ASKPASS" SSH_SK_PROVIDER="$PROVIDER" ssh-keygen -Y sign \
    -f "$WORK/id_sk" -n roundtrip "$WORK/msg" </dev/null

grep -q 'BEGIN SSH SIGNATURE' "$WORK/msg.sig" \
    || { echo "no signature produced"; exit 1; }

echo "OK: enrolled and signed through the full path"
