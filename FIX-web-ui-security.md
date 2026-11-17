# Fix: web control panel security and correctness defects (W-03 … W-08)

**Date**: 2026-11-16
**Files changed**: `web/server.py`, `web/bypass_routes.py`,
`web/static/js/websocket.js`, `web/requirements.txt`
**Source**: `plan.md` §7
**Status**: Fixed. **Checked by reading and syntax inspection only** — there is
no Python on the build machine, so none of this was executed.

> The companion XSS work (W-01, W-02) is in `FIX-web-ui-xss.md`.

---

## W-03 — CORS / Socket.IO origins hardcoded to port 8085

**Problem.** `CORS(app, …)` and `cors_allowed_origins` were both pinned to
`127.0.0.1:8085` / `localhost:8085`, but the listening port comes from
`NCP_WEB_PORT`. On any other port the panel's own Socket.IO connection was
rejected as cross-origin, so live stats, logs and the AutoPilot badge silently
stopped updating — with no visible error.

**Fix.** Derive the allowed origins from the actual port once, at startup:

```python
def _web_port() -> int:
    try:
        p = int(os.environ.get("NCP_WEB_PORT", "8085"))
    except (TypeError, ValueError):
        p = 8085
    return p if 1 <= p <= 65535 else 8085

WEB_PORT = _web_port()
_ALLOWED_ORIGINS = [
    f"http://127.0.0.1:{WEB_PORT}",
    f"http://localhost:{WEB_PORT}",
    f"http://[::1]:{WEB_PORT}",
]
CORS(app, origins=_ALLOWED_ORIGINS)
socketio = SocketIO(app, cors_allowed_origins=_ALLOWED_ORIGINS, async_mode="threading")
```

`WEB_PORT` is reused as the bind port in `main()`, so the two can no longer
disagree. The port is range-checked so a malformed `NCP_WEB_PORT` falls back to
8085 instead of raising.

## W-04 — Socket.IO connections were not token-checked

**Problem.** `_api_guard` only covers `/api/*`. The `/ws` stream carries log
lines and stats (hostnames, learned strategies) and was protected only by the
CORS origin list — which any local non-browser process bypasses trivially.

**Fix.** The connect handler now requires the same per-start token as the REST
API, sent in the Socket.IO `auth` payload:

```python
def _ws_auth_ok(auth) -> bool:
    token = ""
    if isinstance(auth, dict):
        token = auth.get("token") or ""
    elif isinstance(auth, str):
        token = auth
    if not isinstance(token, str) or not token:
        return False
    return hmac.compare_digest(token, _API_TOKEN)
```

The handler rejects on failure with `ConnectionRefusedError("forbidden_token")`.
`hmac.compare_digest` is used rather than `==` so the check is constant-time.
The client (`websocket.js`) reads the token from `<meta name="ncp-token">`
lazily on each connect, so a rotated token is picked up on reconnect.

## W-05 — argument injection in `/api/monitor/autopilot/learn`

**Problem.** The domain was only checked for spaces and `/`. A value starting
with `-` reached `ncp autopilot learn <domain>` and was parsed as a CLI option —
`{"domain": "--help"}` was the documented repro.

**Fix.** Validate as a hostname with the existing `_valid_domain()` (which wraps
`_HOST_RE`, already used by `/api/hostlist/add`), rejecting with 400 before any
process is spawned.

Note recorded in the code comment: inserting `--` would not have been sufficient
here, because the CLI's own option parser skips every `-`-prefixed token — so
hostname validation is the correct fix, not argument shielding.

## W-07 — corrupt `autopilot.json` silently rendered as "no records"

**Problem.** `_read_autopilot_db()` returned an empty result for a corrupt or
half-written file, so the panel showed "Нет выученных хостов" instead of an
error. This happens naturally when the C++ writer is mid-write.

**Fix.** The reader now returns `(db, records, error)`:
- file missing → no error (genuinely "nothing learned yet")
- file present but unparseable → explicit error string

The error is surfaced as `autopilot_db_error` in `/api/monitor/autopilot`. The
per-record loop also skips a record whose value is not an object instead of
500-ing the whole endpoint, so one bad record cannot blank the table.

## W-08 — update install blocked a request thread for up to 120 s

**Problem.** `/api/update/install` ran the download and install synchronously
inside the request, with no progress reported.

**Fix.** Runs in a background thread (`_run_update_install`) like the other
long operations, with a `…/status` route for progress.

## W-06 — Werkzeug development server used in production

**Problem.** `socketio.run(..., allow_unsafe_werkzeug=True)` served the control
panel with the Werkzeug *development* server — single-threaded, not hardened,
and explicitly flagged unsafe by the library itself.

**Fix.** Prefer `waitress`, a real WSGI server, when importable; otherwise fall
back to Werkzeug but **log a loud warning** instead of hiding it behind the
unsafe flag:

```python
_use_dev_server = os.environ.get("NCP_WEB_DEV_SERVER") == "1"
_waitress_serve = None
if not _use_dev_server:
    try:
        from waitress import serve as _waitress_serve
    except ImportError:
        _waitress_serve = None

if _waitress_serve is not None:
    logger.info("Serving with waitress (production WSGI server)")
    _waitress_serve(app, host="127.0.0.1", port=port, threads=8)
else:
    if not _use_dev_server:
        logger.warning("waitress is not installed - falling back to the "
                       "Werkzeug development server. …")
    socketio.run(app, host="127.0.0.1", port=port, debug=False,
                 allow_unsafe_werkzeug=True)
```

`waitress>=3.0.0` added to `web/requirements.txt`.

**Behaviour change worth knowing:** waitress does not upgrade HTTP to WebSocket,
so Socket.IO negotiates down to long-polling. The client already lists
`['websocket', 'polling']`, so live updates keep working — over polling instead
of a socket. If WebSocket transport matters, use `eventlet` (already a
dependency) or keep `NCP_WEB_DEV_SERVER=1`.

The graceful fallback is deliberate: this change alters how the server starts,
which is the one thing that, if wrong, prevents the panel from starting at all.

## Verification — and its limits

**No Python or Node exists on this machine.** `python`, `python3`, `py` are
absent or Store stubs; `node` is absent. Therefore:

| Item | How it was verified |
|---|---|
| W-01/W-02 | grep audit of every `${…}` in an `innerHTML` (see `FIX-web-ui-xss.md`) |
| W-03 | read: origins and bind port now derive from one `WEB_PORT` |
| W-04 | read: `hmac` imported (line 11), `_ws_auth_ok` defined (2229), called in the connect handler (2242), `ConnectionRefusedError` imported (28), `_API_TOKEN` defined (290), client sends `auth` |
| W-05 | read: `_valid_domain` defined (line 54), called in the route, 400 returned |
| W-06 | read: balanced try/except, 4-space indent inside `main()`, fallback path preserved |
| W-07 | read: 3-tuple return, error surfaced in the API payload |
| W-08 | read: background thread + status route present |

**Nothing was executed.** No file was run through `py_compile`, no panel was
started, no request was made. Static cross-reference only (grep the symbol is
defined, grep the symbol is called).

Before merging, someone with a Python environment should run:

```bash
python -m py_compile web/server.py web/bypass_routes.py
pip install waitress
python web/server.py
# then: open the panel, confirm live stats update, and confirm
# /api/monitor/autopilot/learn {"domain": "--help"} returns 400
```

## Not done

- **W-06 at runtime** — the waitress path has never been executed.
- **No test added** for any of these. `plan.md` §7.4 specifies checks for
  W-03/W-04/W-05; none were written.
- **`requirements.txt` upper bounds** (a §7.3 item) were not added.
- **The C++ side's atomic JSON write** (referenced by W-07) was not touched —
  out of scope for this file set.
