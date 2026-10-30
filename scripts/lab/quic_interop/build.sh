#!/usr/bin/env bash
# Builds the ncp_quic_cli interop harness (G4 real QUIC transport).
# Requires: g++ (C++17), libmsquic runtime (libmsquic.so.2) installed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
OUT="${1:-$HERE/ncp_quic_cli}"

MSQUIC_LIB_FLAG="-l:libmsquic.so.2"
MSQUIC_SO=""
for d in /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu /usr/local/lib /usr/lib; do
    if [ -e "$d/libmsquic.so.2" ]; then MSQUIC_SO="$d/libmsquic.so.2"; break; fi
done
if [ -z "$MSQUIC_SO" ]; then
    echo "ERROR: libmsquic.so.2 not found in standard library paths" >&2
    exit 1
fi

g++ -std=c++17 -O2 -Wall -Wextra \
    -I"$HERE/include" \
    -I"$REPO_ROOT/src/core/include" \
    -I"$REPO_ROOT/third_party/msquic/include" \
    "$HERE/ncp_quic_cli.cpp" \
    "$REPO_ROOT/src/core/src/ncp_real_quic.cpp" \
    $MSQUIC_LIB_FLAG -lpthread \
    -o "$OUT"

echo "built: $OUT"
