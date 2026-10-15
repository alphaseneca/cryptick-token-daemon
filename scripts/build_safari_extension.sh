#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="/tmp/cryptick_safari_build"
APP_DIR="/Applications/CryptickPasskey.app"
PLUGINS_DIR="$APP_DIR/Contents/PlugIns"
APPEX_DIR="$PLUGINS_DIR/CryptickExtension.appex"

echo "=== Building Cryptick Token Safari Extension ==="

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# 1. Compile Main Companion App
cat << 'EOF' > "$BUILD_DIR/SafariApp.swift"
import Cocoa

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let alert = NSAlert()
        alert.messageText = "Cryptick Token Safari Extension"
        alert.informativeText = "The Cryptick Token passkey bridge is installed.\n\nTo enable in Safari:\n1. Open Safari -> Settings -> Advanced and check 'Show features for web developers'.\n2. Open Develop menu and check 'Allow Unsigned Extensions'.\n3. Open Safari -> Settings -> Extensions and check 'Cryptick Token Passkey Bridge'."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
        NSApp.terminate(nil)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
EOF

swiftc -target arm64-apple-macos14.0 -framework Cocoa "$BUILD_DIR/SafariApp.swift" -o "$BUILD_DIR/CryptickPasskey"

# 2. Compile Safari Web Extension Handler
cat << 'EOF' > "$BUILD_DIR/SafariHandler.swift"
import Foundation
import SafariServices

@objc(SafariWebExtensionHandler)
class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        guard let item = context.inputItems.first as? NSExtensionItem,
              let message = item.userInfo?[SFExtensionMessageKey] as? [String: Any] else {
            let errorItem = NSExtensionItem()
            errorItem.userInfo = [SFExtensionMessageKey: ["status": "error", "message": "No input received"]]
            context.completeRequest(returningItems: [errorItem], completionHandler: nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let jsonData = try JSONSerialization.data(withJSONObject: message, options: [])
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/Users/aurelius/.local/bin/cryptick-webauthn-host")
                let stdinPipe = Pipe()
                let stdoutPipe = Pipe()
                process.standardInput = stdinPipe
                process.standardOutput = stdoutPipe

                try process.run()

                var len = UInt32(jsonData.count)
                let lenData = Data(bytes: &len, count: 4)
                stdinPipe.fileHandleForWriting.write(lenData)
                stdinPipe.fileHandleForWriting.write(jsonData)
                stdinPipe.fileHandleForWriting.closeFile()

                let outData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()

                if outData.count >= 4 {
                    let respLen = Int(outData.subdata(in: 0..<4).withUnsafeBytes { $0.load(as: UInt32.self) })
                    if outData.count >= 4 + respLen {
                        let jsonResp = outData.subdata(in: 4..<4+respLen)
                        if let respDict = try? JSONSerialization.jsonObject(with: jsonResp, options: []) as? [String: Any] {
                            let respItem = NSExtensionItem()
                            respItem.userInfo = [SFExtensionMessageKey: respDict]
                            context.completeRequest(returningItems: [respItem], completionHandler: nil)
                            return
                        }
                    }
                }

                let errorItem = NSExtensionItem()
                errorItem.userInfo = [SFExtensionMessageKey: ["status": "error", "message": "Host process returned invalid data"]]
                context.completeRequest(returningItems: [errorItem], completionHandler: nil)
            } catch {
                let errorItem = NSExtensionItem()
                errorItem.userInfo = [SFExtensionMessageKey: ["status": "error", "message": error.localizedDescription]]
                context.completeRequest(returningItems: [errorItem], completionHandler: nil)
            }
        }
    }
}
EOF

swiftc -emit-library -target arm64-apple-macos14.0 -framework Foundation -framework SafariServices "$BUILD_DIR/SafariHandler.swift" -o "$BUILD_DIR/CryptickExtension"

# 3. Assemble App Bundle
echo "Assembling $APP_DIR..."
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APPEX_DIR/Contents/MacOS"
mkdir -p "$APPEX_DIR/Contents/Resources"

cp "$BUILD_DIR/CryptickPasskey" "$APP_DIR/Contents/MacOS/CryptickPasskey"
cp "$BUILD_DIR/CryptickExtension" "$APPEX_DIR/Contents/MacOS/CryptickExtension"

# Plists
cat << 'EOF' > "$APP_DIR/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.cryptick.CryptickPasskey</string>
    <key>CFBundleName</key>
    <string>CryptickPasskey</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleExecutable</key>
    <string>CryptickPasskey</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
</dict>
</plist>
EOF

cat << 'EOF' > "$APPEX_DIR/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.cryptick.CryptickPasskey.Extension</string>
    <key>CFBundleName</key>
    <string>CryptickExtension</string>
    <key>CFBundlePackageType</key>
    <string>XPC!</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleExecutable</key>
    <string>CryptickExtension</string>
    <key>NSExtension</key>
    <dict>
        <key>NSExtensionPointIdentifier</key>
        <string>com.apple.Safari.web-extension</string>
        <key>NSExtensionPrincipalClass</key>
        <string>SafariWebExtensionHandler</string>
    </dict>
</dict>
</plist>
EOF

# Copy Extension resources
cp -R "$DIR/extensions/cryptick-webauthn/"* "$APPEX_DIR/Contents/Resources/"

# Code sign ad-hoc
codesign --force --deep --sign - "$APP_DIR"

echo "=== Safari Extension successfully installed to $APP_DIR ==="
