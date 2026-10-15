#!/usr/bin/env bash
# Browser Extension (.zip) Packager for Cryptick WebAuthn & Hardware TOTP
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXT_DIR="$REPO_ROOT/extensions/cryptick-webauthn"
TARGET_DIR="$REPO_ROOT/target/packages"

mkdir -p "$TARGET_DIR"

if [ ! -d "$EXT_DIR" ]; then
    echo "Error: Extension directory '$EXT_DIR' does not exist." >&2
    exit 1
fi

echo "=== Building Cryptick Token Browser Extension Packages (.zip) ==="

# 1. Parse version from manifest.json
VERSION=$(python3 -c "import json; print(json.load(open('$EXT_DIR/manifest.json'))['version'])" 2>/dev/null || echo "1.0.0")
echo "--> Extension Version: $VERSION"

CHROME_ZIP="$TARGET_DIR/cryptick-webauthn-chrome-v${VERSION}.zip"
FIREFOX_ZIP="$TARGET_DIR/cryptick-webauthn-firefox-v${VERSION}.zip"

STAGING="$REPO_ROOT/target/ext_staging"
rm -rf "$STAGING"
mkdir -p "$STAGING/chrome" "$STAGING/firefox"

# 2. Package for Chrome / Chromium / Edge / Brave (Manifest V3)
echo "--> Packaging Chrome / Chromium / Edge / Brave edition..."
cp -R "$EXT_DIR"/* "$STAGING/chrome/"
rm -f "$CHROME_ZIP"
(cd "$STAGING/chrome" && zip -r -9 "$CHROME_ZIP" . -x "*.DS_Store" "*__MACOSX*")

# 3. Package for Firefox (Manifest V3 with gecko ID)
echo "--> Packaging Mozilla Firefox edition..."
cp -R "$EXT_DIR"/* "$STAGING/firefox/"
python3 -c "
import json
with open('$STAGING/firefox/manifest.json', 'r+') as f:
    data = json.load(f)
    if 'browser_specific_settings' not in data:
        data['browser_specific_settings'] = {
            'gecko': {
                'id': 'cryptick@alphaseneca.com',
                'strict_min_version': '109.0'
            }
        }
    f.seek(0)
    json.dump(data, f, indent=2)
    f.truncate()
"
rm -f "$FIREFOX_ZIP"
(cd "$STAGING/firefox" && zip -r -9 "$FIREFOX_ZIP" . -x "*.DS_Store" "*__MACOSX*")

rm -rf "$STAGING"

echo ""
echo "=== Extension Packages Created Successfully ==="
echo "Chrome ZIP  : $CHROME_ZIP"
ls -lh "$CHROME_ZIP"
echo "Firefox ZIP : $FIREFOX_ZIP"
ls -lh "$FIREFOX_ZIP"
