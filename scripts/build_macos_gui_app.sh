#!/usr/bin/env bash
# Build Dynam.app — the Qt6 GUI macOS bundle.
#
# Pipeline:
#   1. cmake build with -DENABLE_GUI=ON (output: build-gui/bin/ncp.app)
#   2. cmake build with -DENABLE_CLI=ON (output: build-portable/bin/ncp)
#      so we can stash the CLI inside the .app at Resources/bin/ncp
#   3. Stage to /tmp (avoids Write-tool xattr taint)
#   4. Write a complete Info.plist; copy the .icns; bundle the CLI binary
#   5. macdeployqt to copy/rewrite Qt frameworks and dylib deps
#   6. ditto-clone into a clean tree and ad-hoc codesign
#   7. ditto-copy into dist/Dynam.app
#
# Output:
#   dist/Dynam.app
#   dist/Dynam-<version>-macos-<arch>.zip

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="$(uname -m)"
VERSION="$(sed -n '/^project(/,/)/p' "${PROJECT_ROOT}/CMakeLists.txt" \
    | sed -n 's/.*VERSION[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' \
    | head -1)"
VERSION="${VERSION:-0.0.0}"

GUI_BUILD="${PROJECT_ROOT}/build-gui"
CLI_BUILD="${PROJECT_ROOT}/build-portable"
DIST_ROOT="${PROJECT_ROOT}/dist"
STAGE="/tmp/dynam-stage"
FINAL="/tmp/Dynam.app"
ICON_SRC="${PROJECT_ROOT}/resources/Dynam.icns"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script must run on macOS" >&2
    exit 1
fi

# ─── Build GUI (Qt6) ─────────────────────────────────────────────────────────
echo "==> Configuring GUI build"
cmake -S "${PROJECT_ROOT}" -B "${GUI_BUILD}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_PORTABLE_MACOS=ON \
    -DENABLE_GUI=ON \
    -DENABLE_CLI=OFF \
    -DENABLE_TESTS=OFF \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
    -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt > /dev/null
echo "==> Building GUI"
cmake --build "${GUI_BUILD}" --config Release --parallel

# ─── Build CLI separately (the same target name conflicts otherwise) ─────────
echo "==> Configuring CLI build"
cmake -S "${PROJECT_ROOT}" -B "${CLI_BUILD}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_PORTABLE_MACOS=ON \
    -DENABLE_GUI=OFF \
    -DENABLE_CLI=ON \
    -DENABLE_TESTS=OFF \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 > /dev/null
echo "==> Building CLI"
cmake --build "${CLI_BUILD}" --config Release --parallel

# ─── Stage and bundle ────────────────────────────────────────────────────────
rm -rf "${STAGE}" "${FINAL}"
mkdir -p "${STAGE}"
ditto --noextattr --norsrc "${GUI_BUILD}/bin/ncp.app" "${STAGE}/Dynam.app"

# Icon
mkdir -p "${STAGE}/Dynam.app/Contents/Resources"
if [[ -f "${ICON_SRC}" ]]; then
    cp "${ICON_SRC}" "${STAGE}/Dynam.app/Contents/Resources/Dynam.icns"
else
    echo "warning: ${ICON_SRC} missing; bundle will have no icon" >&2
fi

# CLI binary at a fixed path inside the bundle
mkdir -p "${STAGE}/Dynam.app/Contents/Resources/bin"
cp "${CLI_BUILD}/bin/ncp" "${STAGE}/Dynam.app/Contents/Resources/bin/ncp"

# Info.plist (complete; CMake's default leaves everything empty)
cat > "${STAGE}/Dynam.app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>     <string>en</string>
    <key>CFBundleExecutable</key>            <string>ncp</string>
    <key>CFBundleIdentifier</key>            <string>org.ncp-project.dynam</string>
    <key>CFBundleInfoDictionaryVersion</key> <string>6.0</string>
    <key>CFBundleName</key>                  <string>Dynam</string>
    <key>CFBundleDisplayName</key>           <string>Dynam</string>
    <key>CFBundlePackageType</key>           <string>APPL</string>
    <key>CFBundleSignature</key>             <string>????</string>
    <key>CFBundleShortVersionString</key>    <string>${VERSION}</string>
    <key>CFBundleVersion</key>               <string>${VERSION}</string>
    <key>CFBundleIconFile</key>              <string>Dynam.icns</string>
    <key>LSMinimumSystemVersion</key>        <string>11.0</string>
    <key>NSHighResolutionCapable</key>       <true/>
    <key>NSPrincipalClass</key>              <string>NSApplication</string>
    <key>NSSupportsAutomaticGraphicsSwitching</key> <true/>
    <key>NSHumanReadableCopyright</key>      <string>Copyright 2026 NCP Project</string>
</dict>
</plist>
EOF

# Qt frameworks + dylib path rewriting
echo "==> macdeployqt"
/opt/homebrew/bin/macdeployqt "${STAGE}/Dynam.app" 2>&1 | grep -vE "Cannot resolve|using QList" | tail -5 || true

# Sign in /tmp where xattrs aren't reintroduced
ditto --noextattr --norsrc "${STAGE}/Dynam.app" "${FINAL}"
echo "==> Ad-hoc codesign"
codesign --force --deep --sign - --timestamp=none "${FINAL}" 2>&1 | tail -2
codesign --verify --verbose "${FINAL}" 2>&1

# Move to dist/, re-verify, then unseal so the user can edit freely.
mkdir -p "${DIST_ROOT}"
rm -rf "${DIST_ROOT}/Dynam.app"
ditto --noextattr --norsrc "${FINAL}" "${DIST_ROOT}/Dynam.app"

# Strip any quarantine flags that macOS might have re-added during the
# move so the bundle is ready to double-click without Gatekeeper warnings.
xattr -dr com.apple.quarantine "${DIST_ROOT}/Dynam.app" 2>/dev/null || true

# One last signature verification before we unseal — confirms the binary
# inside is good (the kernel will reject otherwise).
codesign --verify "${DIST_ROOT}/Dynam.app" && echo "✅ ${DIST_ROOT}/Dynam.app is signed and valid"

# Now drop the bundle-level seal so Info.plist / Resources / PlugIns are
# editable. The Mach-O binary keeps its own embedded signature; we're only
# removing the file-hash manifest that detects bundle tampering. Result:
# user can hot-edit anything in the .app without the next launch breaking.
rm -rf "${DIST_ROOT}/Dynam.app/Contents/_CodeSignature"
chmod -R u+w "${DIST_ROOT}/Dynam.app"
echo "==> Bundle unsealed (binary signature kept for kernel; resource seal removed)"

ZIP="${DIST_ROOT}/Dynam-${VERSION}-macos-${ARCH}.zip"
rm -f "${ZIP}"
( cd "${DIST_ROOT}" && zip -qry "$(basename "${ZIP}")" "Dynam.app" )

# DMG: a small staging directory with the .app and an "Applications" symlink,
# converted to a compressed disk image. hdiutil create -srcfolder is the
# Apple-standard pattern; no extra deps needed.
DMG="${DIST_ROOT}/Dynam-${VERSION}-macos-${ARCH}.dmg"
DMG_STAGE="$(mktemp -d -t dynam-dmg.XXXXXX)"
trap 'rm -rf "${DMG_STAGE}"' EXIT
ditto --noextattr --norsrc "${DIST_ROOT}/Dynam.app" "${DMG_STAGE}/Dynam.app"
ln -s /Applications "${DMG_STAGE}/Applications"
rm -f "${DMG}"
hdiutil create \
    -volname "Dynam ${VERSION}" \
    -srcfolder "${DMG_STAGE}" \
    -ov -format UDZO \
    "${DMG}" > /dev/null

echo
echo "Done."
echo "  Bundle: ${DIST_ROOT}/Dynam.app"
echo "  CLI:    ${DIST_ROOT}/Dynam.app/Contents/Resources/bin/ncp"
echo "  Zip:    ${ZIP}"
echo "  DMG:    ${DMG}"
