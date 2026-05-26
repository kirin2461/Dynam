#!/usr/bin/env bash
# One-shot installer: builds dist/Dynam.app (if needed), strips xattrs,
# deploys it to ~/Desktop, ad-hoc re-signs, and verifies double-click
# launch via LaunchServices. Run from anywhere.
#
# Usage:
#   ./scripts/install_to_desktop.sh

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_BUNDLE="${PROJECT_ROOT}/dist/Dynam.app"
DEST="${HOME}/Desktop/Dynam.app"

if [[ ! -d "${SRC_BUNDLE}" ]]; then
    echo "==> dist/Dynam.app missing — building it"
    "${PROJECT_ROOT}/scripts/build_macos_gui_app.sh"
fi

echo "==> Deploying to ${DEST}"
rm -rf "${DEST}"
ditto --noextattr --norsrc "${SRC_BUNDLE}" "${DEST}"

echo "==> Ad-hoc re-signing (ditto strips signatures)"
codesign --force --deep --sign - --timestamp=none "${DEST}" 2>&1 | tail -2

echo "==> Verifying signature"
codesign --verify "${DEST}" && echo "✅ signature valid"

# Strip Gatekeeper / quarantine xattrs so macOS never prompts on first
# launch. ditto already skipped xattrs on the original copy, but some
# OS code paths re-stamp com.apple.quarantine after Finder sees the
# new bundle — explicitly removing both keeps double-click silent.
echo "==> Stripping Gatekeeper / quarantine flags"
xattr -dr com.apple.quarantine "${DEST}" 2>/dev/null || true
xattr -dr com.apple.provenance  "${DEST}" 2>/dev/null || true

# Remove the bundle-level resource sealing (Contents/_CodeSignature/) so
# the user can edit Info.plist / Resources / PlugIns without invalidating
# anything. The Mach-O binary's *own* signature stays — required for the
# Apple Silicon kernel to load its code pages — but the bundle is
# otherwise unprotected and freely editable.
echo "==> Removing bundle resource sealing (keeping binary signature)"
rm -rf "${DEST}/Contents/_CodeSignature"

# Make every file under the bundle writable. ditto can preserve read-only
# bits from the source tree; chmod -R u+w lifts them so any modification
# (Info.plist, Resources/Dynam.icns, anything in Resources/bin/) Just Works.
echo "==> Making every file writable"
chmod -R u+w "${DEST}"

echo "==> Launching via LaunchServices (same path Finder double-click uses)"
open "${DEST}"
sleep 3
if pgrep -f "${DEST}/Contents/MacOS/ncp" > /dev/null; then
    echo "✅ Dynam.app launched — process is alive"
    echo
    echo "App is on your Desktop. Double-click it any time to open."
else
    echo "❌ App did not stay open — check ~/Library/Logs/DiagnosticReports/ncp*.ips"
    exit 1
fi
