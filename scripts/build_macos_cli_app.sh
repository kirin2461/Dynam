#!/usr/bin/env bash
# Wrap the portable CLI build into a clickable Dynam-CLI.app bundle.
#
# Layout:
#   Dynam-CLI.app/
#   ├── Contents/
#   │   ├── Info.plist
#   │   ├── PkgInfo
#   │   ├── MacOS/
#   │   │   └── Dynam              ← shell launcher (opens Terminal, runs ncp)
#   │   └── Resources/
#   │       ├── bin/ncp            ← real binary (RPATH @loader_path/../lib)
#   │       └── lib/*.dylib        ← bundled deps
#
# Run scripts/build_macos_portable.sh first (this script depends on its output).

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_ROOT="${PROJECT_ROOT}/dist"
ARCH="$(uname -m)"
VERSION="$(sed -n '/^project(/,/)/p' "${PROJECT_ROOT}/CMakeLists.txt" \
    | sed -n 's/.*VERSION[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' \
    | head -1)"
VERSION="${VERSION:-0.0.0}"

PORTABLE_DIR="${DIST_ROOT}/Dynam-${VERSION}-macos-${ARCH}"
APP_DIR="${DIST_ROOT}/Dynam-CLI.app"

if [[ ! -x "${PORTABLE_DIR}/bin/ncp" ]]; then
    echo "error: ${PORTABLE_DIR}/bin/ncp not found." >&2
    echo "       Run scripts/build_macos_portable.sh first." >&2
    exit 1
fi

echo "==> Building ${APP_DIR}"
rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS" "${APP_DIR}/Contents/Resources/bin" "${APP_DIR}/Contents/Resources/lib"

cp "${PORTABLE_DIR}/bin/ncp" "${APP_DIR}/Contents/Resources/bin/"
cp "${PORTABLE_DIR}/lib/"*.dylib "${APP_DIR}/Contents/Resources/lib/"

cat > "${APP_DIR}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>Dynam</string>
    <key>CFBundleDisplayName</key>     <string>Dynam (CLI)</string>
    <key>CFBundleIdentifier</key>      <string>org.ncp-project.dynam-cli</string>
    <key>CFBundleVersion</key>         <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key> <string>${VERSION}</string>
    <key>CFBundleExecutable</key>      <string>Dynam</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>CFBundleSignature</key>       <string>????</string>
    <key>LSMinimumSystemVersion</key>  <string>11.0</string>
    <key>NSHighResolutionCapable</key> <true/>
    <!-- LSUIElement keeps the Dock icon hidden; comment out if you want one -->
    <key>LSUIElement</key>             <false/>
</dict>
</plist>
EOF

echo "APPL????" > "${APP_DIR}/Contents/PkgInfo"

# The launcher opens Terminal with `ncp` so users get an interactive shell.
# Double-click → Terminal window → ncp's help/status → prompt awaits next command.
cat > "${APP_DIR}/Contents/MacOS/Dynam" <<'EOF'
#!/usr/bin/env bash
# Resolve the .app bundle path even through symlinks.
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NCP="${APP_DIR}/Resources/bin/ncp"

# osascript opens a new Terminal window and runs an interactive shell with
# ncp on PATH. The trailing `exec bash` keeps the window open after ncp exits
# so users can re-run commands or read output.
/usr/bin/osascript <<APPLESCRIPT
tell application "Terminal"
    activate
    do script "clear; export PATH=\"$(dirname "${NCP}"):\$PATH\"; ncp help; echo; echo '── ncp is on your PATH. Try: ncp status, ncp run, ncp rotate ──'; exec bash -l"
end tell
APPLESCRIPT
EOF
chmod +x "${APP_DIR}/Contents/MacOS/Dynam"

echo "==> Ad-hoc signing the bundle"
codesign --force --deep --sign - "${APP_DIR}"

echo "==> Packaging .zip (DragNDrop-friendly)"
( cd "${DIST_ROOT}" && zip -qry "Dynam-CLI-${VERSION}-macos-${ARCH}.zip" "Dynam-CLI.app" )

echo
echo "Done."
echo "  Bundle: ${APP_DIR}"
echo "  Zip:    ${DIST_ROOT}/Dynam-CLI-${VERSION}-macos-${ARCH}.zip"
echo
echo "Double-click Dynam-CLI.app in Finder to launch."
