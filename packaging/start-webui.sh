#!/bin/sh
# Dynam NCP - Web UI launcher (Linux/macOS)
cd "$(dirname "$0")" || exit 1
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "[Dynam] Python 3 not found. Install python3 and re-run."
    exit 1
fi
echo "[Dynam] Installing web UI dependencies (first run only)..."
"$PY" -m pip install -q -r web/requirements.txt || \
    "$PY" -m pip install -q --user -r web/requirements.txt || {
        echo "[Dynam] pip install failed. Check your internet connection and re-run."
        exit 1
    }
export NCP_OPEN_BROWSER=1
echo "[Dynam] Starting Web UI on http://127.0.0.1:8080 ..."
exec "$PY" web/server.py
