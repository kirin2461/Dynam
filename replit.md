# NCP - Network Control Protocol

## Overview
NCP (Network Control Protocol) is a multi-layered network anonymization and privacy platform. It provides advanced tools for bypassing Deep Packet Inspection (DPI), traffic obfuscation, and enhancing network security through a "Master Orchestrator" pipeline.

## Architecture
- **Web Interface**: Flask-based web backend (`web/server.py`) with a static frontend (`web/static/`)
- **Core Library**: C++17 library (`src/core/`) — not compiled in Replit (simulation mode used)
- **CLI**: C++ command-line tool (`src/cli/`) — not compiled in Replit
- **GUI**: Qt6-based GUI (`src/gui/`) — not available in Replit

## Tech Stack
- **Backend**: Python 3 + Flask + Flask-SocketIO
- **Frontend**: Vanilla JavaScript + Chart.js + WebSockets
- **Core (native)**: C++17 with libsodium, OpenSSL, libnetfilter_queue (Linux)
- **Database**: SQLite3 (via ncp_db.hpp in native code)

## Running the Application
The web server runs on port 5000 using the "Start application" workflow:
```
cd web && python server.py
```

The server runs in "simulation mode" since the native NCP binary is not compiled in this environment. All dashboard UI and API endpoints work correctly.

## Key Files
- `web/server.py` — Main Flask server (REST API + WebSocket)
- `web/static/` — Frontend HTML, CSS, JavaScript
- `web/ncp_license.py` — License verification module
- `web/requirements.txt` — Python dependencies

## Configuration
- Server port: 5000 (default, overridable via `NCP_WEB_PORT` env var)
- Host: 0.0.0.0 (accepts all connections, required for Replit proxy)
- CORS: All origins allowed

## Dependencies
Python packages installed:
- flask, flask-cors, flask-socketio
- psutil, eventlet, cryptography
- gunicorn (for production deployment)

## Changes Made for Replit
1. Changed host from `127.0.0.1` to `0.0.0.0` for Replit proxy compatibility
2. Changed default port from `8085` to `5000`
3. Set CORS to allow all origins (`*`)
4. Fixed `state_lock` → `stats_lock` bug in `/api/config` route
