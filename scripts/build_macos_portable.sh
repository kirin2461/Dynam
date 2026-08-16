#!/usr/bin/env bash
# Build a portable macOS distribution of Dynam.
#
# Output: dist/Dynam-<version>-macos-<arch>/
#   bin/ncp
#   lib/<bundled dylibs>
#   LICENSE
#   README.md
#
# Also produces dist/Dynam-<version>-macos-<arch>.tar.gz

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build-portable"
DIST_ROOT="${PROJECT_ROOT}/dist"
ARCH="$(uname -m)"
VERSION="$(sed -n '/^project(/,/)/p' "${PROJECT_ROOT}/CMakeLists.txt" \
    | sed -n 's/.*VERSION[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' \
    | head -1)"
VERSION="${VERSION:-0.0.0}"
STAGE_NAME="Dynam-${VERSION}-macos-${ARCH}"
STAGE_DIR="${DIST_ROOT}/${STAGE_NAME}"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script must run on macOS" >&2
    exit 1
fi

echo "==> Configuring (BUILD_PORTABLE_MACOS=ON)"
cmake -S "${PROJECT_ROOT}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_PORTABLE_MACOS=ON \
    -DENABLE_GUI=OFF \
    -DENABLE_TESTS=OFF \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0

echo "==> Building"
cmake --build "${BUILD_DIR}" --config Release --parallel

echo "==> Staging ${STAGE_DIR}"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}/bin" "${STAGE_DIR}/lib"
cp "${BUILD_DIR}/bin/ncp" "${STAGE_DIR}/bin/"
cp "${PROJECT_ROOT}/LICENSE" "${PROJECT_ROOT}/README.md" "${STAGE_DIR}/"

# ─────────────────────────────────────────────────────────────────────────
# bundle_dylibs: copy every non-system dylib the binary depends on into
# STAGE_DIR/lib and rewrite install names so the loader resolves them via
# @rpath. The binary's RPATH is already @loader_path/../lib (set in CMake).
#
# TODO(you): implement this. See the prompt in chat for the design choices
# you need to make — this is the heart of "portable" on macOS.
# ─────────────────────────────────────────────────────────────────────────
# macOS stock bash is 3.2 — no associative arrays. Use a `:`-delimited
# sentinel string instead. Names contain only characters safe for this.
BUNDLED_DYLIBS=":"

bundle_dylibs() {
    local target="$1"
    local libdir="$2"

    chmod u+w "${target}"

    while IFS= read -r line; do
        local dep
        dep="$(echo "${line}" | awk '{print $1}')"
        [[ -z "${dep}" ]] && continue
        [[ "${dep}" == "${target}" ]] && continue
        [[ "${dep}" == /usr/lib/* ]] && continue
        [[ "${dep}" == /System/* ]] && continue
        [[ "${dep}" == @* ]] && continue

        local name
        name="$(basename "${dep}")"
        local rpath_name="@rpath/${name}"
        local dest="${libdir}/${name}"

        install_name_tool -change "${dep}" "${rpath_name}" "${target}" 2>/dev/null || true

        case "${BUNDLED_DYLIBS}" in
            *":${name}:"*) ;;
            *)
                BUNDLED_DYLIBS="${BUNDLED_DYLIBS}${name}:"
                cp "${dep}" "${dest}"
                chmod u+w "${dest}"
                install_name_tool -id "${rpath_name}" "${dest}"
                bundle_dylibs "${dest}" "${libdir}"
                ;;
        esac
    done < <(otool -L "${target}" | tail -n +2)
}

bundle_dylibs "${STAGE_DIR}/bin/ncp" "${STAGE_DIR}/lib"

echo "==> Re-signing (ad-hoc) so Apple Silicon will load rewritten dylibs"
find "${STAGE_DIR}/lib" -name '*.dylib' -exec codesign --force --sign - {} \;
codesign --force --sign - "${STAGE_DIR}/bin/ncp"

echo "==> Packaging tarball"
tar -czf "${DIST_ROOT}/${STAGE_NAME}.tar.gz" -C "${DIST_ROOT}" "${STAGE_NAME}"

echo
echo "Done."
echo "  Folder:  ${STAGE_DIR}"
echo "  Tarball: ${DIST_ROOT}/${STAGE_NAME}.tar.gz"
