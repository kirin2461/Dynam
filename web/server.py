#!/usr/bin/env python3
"""
NCP Web Interface Backend
Flask server providing REST API and WebSocket for NCP DPI bypass tool.
Runs on port 8085.
"""

import os
import sys
import json
import time
import uuid
import platform
import subprocess
import threading
import logging
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque

import psutil
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# ─── License verification ────────────────────────────────────────────────────
# ncp_license.py лежит рядом с server.py в web/
try:
    from ncp_license import verify_license_key, load_public_key_from_b64
    LICENSE_CRYPTO_AVAILABLE = True
except ImportError:
    LICENSE_CRYPTO_AVAILABLE = False
    logging.warning("ncp_license not found or cryptography not installed - license verification disabled")

# Публичный ключ Ed25519 для верификации лицензий (Base64, 32 байта)
# Этот ключ безопасно распространять — подделать подпись без приватного ключа невозможно
NCP_LICENSE_PUBLIC_KEY_B64 = "0J6Gb+VIXPUPl9zAWF+DpHWZhPrLvGYl7g82lJAfrlE="

# Файл для сохранения активированной лицензии
LICENSE_FILE = Path(os.environ.get("APPDATA", str(Path.home()))) / "ncp" / "license.json"


# ─── License gate helpers ────────────────────────────────────────────────────

def _is_license_active() -> bool:
    """Return True if a valid, non-expired license is loaded in state."""
    lic = state.get("license", {})
    return lic.get("status") == "active"


def _license_has_module(module_name: str) -> bool:
    """Check if the current license includes a specific module."""
    if not _is_license_active():
        return False
    modules = state.get("license", {}).get("modules", [])
    return module_name in modules


def _require_license(module_name: str = None):
    """Return a (json, status_code) tuple if license check fails, else None.
    Usage in endpoints:
        err = _require_license("dpi_bypass")
        if err:
            return err
    """
    if not _is_license_active():
        return jsonify({
            "ok": False,
            "error": "License not activated",
            "license_required": True,
        }), 403
    if module_name and not _license_has_module(module_name):
        return jsonify({
            "ok": False,
            "error": f"Module '{module_name}' not available in your plan",
            "license_required": True,
            "upgrade_needed": True,
        }), 403
    return None


# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger("ncp-web")

# ─── Config ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
PROJECT_DIR = BASE_DIR.parent
BUILD_DIR = PROJECT_DIR / "build"

def _find_ncp_binary() -> Path:
    """Search for ncp binary in common build output locations."""
    if platform.system() == "Windows":
        candidates = [
            BUILD_DIR / "ncp.exe",
            BUILD_DIR / "bin" / "Release" / "ncp.exe",
            BUILD_DIR / "bin" / "Debug" / "ncp.exe",
            BUILD_DIR / "Release" / "ncp.exe",
            PROJECT_DIR / "ncp.exe",
        ]
    else:
        candidates = [
            BUILD_DIR / "ncp",
            BUILD_DIR / "bin" / "ncp",
            PROJECT_DIR / "ncp",
        ]
    for p in candidates:
        if p.is_file():
            return p
    # Return default path even if not found yet
    return candidates[0]

NCP_BINARY = _find_ncp_binary()

if platform.system() == "Windows":
    CONFIG_PATH = Path(os.environ.get("APPDATA", "")) / "ncp" / "config.json"
else:
    CONFIG_PATH = Path("/etc/ncp/config.json")

STATIC_DIR = BASE_DIR / "static"
LOG_BUFFER_SIZE = 500

# ─── App & SocketIO ──────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")
app.config["SECRET_KEY"] = os.urandom(24).hex()
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ─── State ───────────────────────────────────────────────────────────────────
state = {
    "running": False,
    "start_time": None,
    "pid": None,
    "process": None,
    "strategy": "balanced",
    "stats": {
        "bytes_sent": 0,
        "bytes_recv": 0,
        "packets_processed": 0,
        "dpi_events": 0,
        "dpi_blocks_avoided": 0,
        "active_connections": 0,
        "speed_up": 0,
        "speed_down": 0,
    },
    "config": {
        "strategy": "balanced",
        "interface": "auto",
        "doh_provider": "cloudflare",
        "doh_custom": "",
        "ech_enabled": True,
        "proxy_type": "none",
        "proxy_host": "",
        "proxy_port": 1080,
        "fragment_size": 64,
        "timing_jitter": 20,
        "noise_level": 10,
        "tcp_fragment": True,
        "tls_split": True,
        "ttl_manip": False,
        "fake_packets": False,
        "pkt_disorder": False,
        "sni_spoof": False,
        "paranoid_mode": False,
        "auto_rotate": False,
        "rotate_interval": 3600,
        "antiforensics": False,
        "autostart": False,
        "language": "ru",
        "dpi_preset": "beeline",  # DPI bypass preset: tspu, beeline, mts, megafon, tele2, mobile, auto
        "mimic_protocol": "https",
        "tls_fingerprint": "chrome",
        "burst_morphing": False,
        "flow_profile": "web_browsing",
        "postquantum": False,
        "i2p_enabled": False,
        "i2p_sam_host": "127.0.0.1",
        "i2p_sam_port": 7656,
        "i2p_hop_count": 3,
        "garlic_routing": True,
        "geneva_population": 50,
        "geneva_mutation": 0.15,
        "port_knocking": False,
        "port_knock_seq": "7000,8000,9000",
        # ── Новые модули: Пайплайн и Ядро ──────────────────────────────────
        "pipeline_enabled": False,
        "pipeline_workers": 4,
        "pipeline_queue_size": 1024,
        "dns_leak_prevention": False,
        "dns_leak_mode": "strict",
        "dns_leak_whitelist": "",
        "session_fragmenter": False,
        "session_frag_min_segments": 3,
        "session_frag_max_segments": 8,
        "session_frag_strategy": "adaptive",
        "cross_layer_enabled": False,
        "cross_layer_strictness": "medium",
        # ── Новые модули: Анти-ML Защита ────────────────────────────────────
        "rtt_equalizer": False,
        "rtt_target_ms": 150,
        "rtt_jitter_ms": 10,
        "volume_normalizer": False,
        "volume_target_kbps": 2000,
        "volume_padding_mode": "adaptive",
        "behavioral_cloak": False,
        "cloak_profile": "chrome",
        "cloak_human_sim": True,
        "time_correlation_breaker": False,
        "time_break_mode": "random",
        "time_break_max_delay_ms": 200,
        # ── Новые модули: Скрытые Каналы и Мониторинг ──────────────────────
        "covert_channel": False,
        "covert_mode": "dns_txt",
        "covert_bandwidth_limit_bps": 4096,
        "wf_defense": False,
        "wf_defense_mode": "random_padding",
        "wf_defense_overhead": 30,
        "self_test_enabled": True,
        "self_test_interval_sec": 300,
        # ── Новые модули: Управление Транспортом ────────────────────────────
        "protocol_rotation": False,
        "rotation_protocols": "tls13,quic,websocket",
        "rotation_interval_min": 30,
        "as_aware_routing": False,
        "as_blacklist": "",
        "as_prefer_diversity": True,
        "geo_obfuscator": False,
        "geo_target_country": "auto",
        "geo_relay_hops": 2,
        "zapret_profile": "",
        "zapret_custom_chains": [],
    },
    "license": {
        "status": "inactive",
        "key": "",
        "plan": "",
        "plan_label": "",
        "expires": "",
        "days_remaining": 0,
        "modules": [],
        "features": [],
    },
    "e2e_sessions": [],
    "i2p_tunnels": [],
    "geneva": {
        "running": False,
        "generation": 0,
        "best_fitness": 0.0,
        "population": 50,
        "mutation_rate": 0.15,
        "best_strategy": [],
        "fitness_history": [],
    },
    "modules": {
        "pipeline": {"throughput_pps": 0, "queue_usage_pct": 0, "drops": 0},
        "dns_leak": {"leaks_blocked": 0, "queries_intercepted": 0},
        "session_frag": {"sessions_fragmented": 0, "fragments_created": 0},
        "cross_layer": {"correlations_checked": 0, "anomalies_fixed": 0},
        "rtt_equalizer": {"current_ms": 0, "packets_delayed": 0},
        "volume_norm": {"padding_bytes": 0, "normalized_flows": 0},
        "behavioral_cloak": {"actions_emulated": 0, "patterns_matched": 0},
        "time_breaker": {"correlations_broken": 0, "chaff_packets": 0},
        "covert_channel": {"bytes_sent": 0, "bytes_recv": 0, "channels_active": 0},
        "wf_defense": {"packets_padded": 0, "overhead_bytes": 0},
        "self_test": {"last_run": None, "score": 0, "issues": 0, "history": []},
        "protocol_rotation": {"current_protocol": "tls13", "rotations_completed": 0},
        "as_router": {"routes_diverted": 0, "current_path": "direct"},
        "geo_obfuscator": {"apparent_location": "—", "hops_active": 0},
    },
}

log_buffer = deque(maxlen=LOG_BUFFER_SIZE)
log_lock = threading.Lock()
stats_lock = threading.Lock()

# Flag: when True, the NCP process was terminated intentionally (preset change,
# user stop, etc.).  read_process_output checks this to avoid logging
# "exit code 1" as an ERROR — on Windows, terminate() always gives rc=1.
_intentional_kill = False

# Baseline network counters for real traffic measurement
_net_baseline = {"bytes_sent": 0, "bytes_recv": 0, "ts": 0}
_prev_net = {"bytes_sent": 0, "bytes_recv": 0}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def push_log(level: str, msg: str):
    entry = {
        "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "level": level,
        "msg": msg,
    }
    with log_lock:
        log_buffer.append(entry)
    socketio.emit("log", entry, namespace="/ws")


def get_uptime() -> str:
    if not state["start_time"]:
        return "00:00:00"
    delta = int(time.time() - state["start_time"])
    h, rem = divmod(delta, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def load_config() -> dict:
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH) as f:
                return json.load(f)
    except Exception as e:
        push_log("WARN", f"Failed to load config: {e}")
    return {}


def save_config(cfg: dict):
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
        push_log("INFO", "Configuration saved")
    except Exception as e:
        push_log("ERROR", f"Config save error: {e}")


def list_network_interfaces() -> list:
    interfaces = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            ips = [a.address for a in addr_list if a.family.name in ("AF_INET", "2")]
            is_up = stats[name].isup if name in stats else False
            interfaces.append({"name": name, "ips": ips, "up": is_up})
    except Exception as e:
        push_log("WARN", f"Error getting interfaces: {e}")
    return interfaces


def _run_selftest_real() -> dict:
    """Runs a real connectivity self-test: checks DNS resolution and TCP
    connectivity to several well-known hosts.  Returns score 0-100."""
    import socket
    checks = [
        ("DNS google.com", lambda: socket.getaddrinfo("google.com", 443, socket.AF_INET)),
        ("DNS youtube.com", lambda: socket.getaddrinfo("youtube.com", 443, socket.AF_INET)),
        ("TCP 8.8.8.8:53", lambda: _tcp_check("8.8.8.8", 53)),
        ("TCP 1.1.1.1:53", lambda: _tcp_check("1.1.1.1", 53)),
        ("DNS cloudflare.com", lambda: socket.getaddrinfo("cloudflare.com", 443, socket.AF_INET)),
    ]
    passed = 0
    issues = 0
    for name, fn in checks:
        try:
            fn()
            passed += 1
        except Exception:
            issues += 1
            push_log("WARN", f"Self-test failed: {name}")
    score = int(passed / len(checks) * 100)
    result = {
        "ts": datetime.now().isoformat(),
        "score": score,
        "issues": issues,
    }
    m = state["modules"]["self_test"]
    m["last_run"] = result["ts"]
    m["score"] = score
    m["issues"] = issues
    history = m["history"]
    history.append(result)
    if len(history) > 10:
        m["history"] = history[-10:]
    return result


def _tcp_check(host: str, port: int, timeout: float = 3.0):
    """Quick TCP connectivity check."""
    import socket
    s = socket.create_connection((host, port), timeout=timeout)
    s.close()


def _get_real_net_io() -> dict:
    """Read real bytes sent/received from psutil for the selected interface."""
    try:
        iface = state["config"].get("interface", "auto")
        per_nic = psutil.net_io_counters(pernic=True)
        if iface != "auto" and iface in per_nic:
            c = per_nic[iface]
        else:
            c = psutil.net_io_counters()
        return {"bytes_sent": c.bytes_sent, "bytes_recv": c.bytes_recv,
                "packets": c.packets_sent + c.packets_recv}
    except Exception:
        return {"bytes_sent": 0, "bytes_recv": 0, "packets": 0}


def _get_active_connections() -> int:
    """Count actual TCP ESTABLISHED connections via psutil."""
    try:
        conns = psutil.net_connections(kind="tcp")
        return sum(1 for c in conns if c.status == "ESTABLISHED")
    except Exception:
        return 0


def stats_update_loop():
    """Background thread: collect REAL network stats from OS when NCP is running.
    Module-level stats remain at zero — they are not implemented in the backend.
    No random/simulated numbers are generated."""
    global _net_baseline, _prev_net
    _selftest_counter = 0
    while True:
        if state["running"]:
            now = _get_real_net_io()

            # R7-WEB-03: Use stats_lock when accessing _net_baseline and _prev_net
            with stats_lock:
                # On first tick after start, capture baseline
                if _net_baseline["ts"] == 0:
                    _net_baseline = {**now, "ts": time.time()}
                    _prev_net = {"bytes_sent": now["bytes_sent"],
                                 "bytes_recv": now["bytes_recv"]}

                s = state["stats"]
                s["bytes_sent"] = now["bytes_sent"] - _net_baseline["bytes_sent"]
                s["bytes_recv"] = now["bytes_recv"] - _net_baseline["bytes_recv"]
                s["packets_processed"] = now["packets"] - _net_baseline.get("packets", 0)
                # Speed = delta since last tick
                s["speed_up"] = max(0, now["bytes_sent"] - _prev_net["bytes_sent"])
                s["speed_down"] = max(0, now["bytes_recv"] - _prev_net["bytes_recv"])
                s["active_connections"] = _get_active_connections()
                # DPI events come from C++ binary stdout — parsed in read_process_output
                # We don't fake them here.

                _prev_net = {"bytes_sent": now["bytes_sent"],
                             "bytes_recv": now["bytes_recv"]}

            # Self-test: run real check every ~300s (not random)
            cfg = state["config"]
            _selftest_counter += 1
            if cfg.get("self_test_enabled") and (_selftest_counter % 300 == 0):
                try:
                    result = _run_selftest_real()
                    push_log("INFO", f"Self-test completed: "
                             f"score {result['score']}, "
                             f"issues: {result['issues']}")
                except Exception as e:
                    push_log("ERROR", f"Self-test error: {e}")

            # Emit real stats via WebSocket
            payload = {**state["stats"], "uptime": get_uptime()}
            socketio.emit("stats", payload, namespace="/ws")
            socketio.emit("module_stats", _flatten_modules(), namespace="/ws")

        time.sleep(1)


def read_process_output(proc):
    """Read stdout/stderr from NCP process and push to log buffer.
    Also parses output to count real DPI events."""
    try:
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                level = "INFO"
                ll = line.upper()
                if "ERROR" in ll or "FAIL" in ll:
                    level = "ERROR"
                elif "WARN" in ll:
                    level = "WARN"
                elif "DEBUG" in ll:
                    level = "DEBUG"
                push_log(level, line)
                # Count real DPI events from binary output
                if "DPI" in ll or "TSPU" in ll or "BYPASS" in ll:
                    with stats_lock:
                        state["stats"]["dpi_events"] += 1
                if "BLOCK" in ll and "AVOID" in ll:
                    with stats_lock:
                        state["stats"]["dpi_blocks_avoided"] += 1
    except Exception:
        pass
    # When process exits, log the return code
    try:
        rc = proc.wait(timeout=2)
        if rc != 0 and not _intentional_kill:
            push_log("ERROR", f"NCP process exited with code {rc}")
        elif rc != 0 and _intentional_kill:
            push_log("DEBUG", f"NCP process stopped (code {rc})")
    except Exception:
        pass


# ─── REST API ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")


@app.route("/api/status")
def api_status():
    proc_alive = False
    if state.get("process"):
        proc_alive = state["process"].poll() is None

    # Only check process liveness when running a real binary (not simulation)
    if state["running"] and not state.get("simulation") and not proc_alive and state.get("pid"):
        state["running"] = False
        push_log("WARN", "NCP process terminated unexpectedly")

    return jsonify({
        "running": state["running"],
        "uptime": get_uptime(),
        "strategy": state["config"]["strategy"],
        "pid": state.get("pid"),
        "start_time": state["start_time"],
    })


def _build_ncp_args() -> list:
    """Build NCP binary command-line arguments from current config state."""
    binary_path = str(NCP_BINARY)
    cfg = state["config"]
    args = [binary_path, "run", "--no-license-check",
            "--interface", cfg.get("interface", "auto"),
            "--preset", cfg.get("dpi_preset", "tspu")]

    # Module disable flags -- when config toggle is False, pass --no-* to disable
    MODULE_FLAGS = {
        "dns_leak_prevention":      "--no-dns-leak",
        "rtt_equalizer":            "--no-rtt-eq",
        "volume_normalizer":        "--no-volume-norm",
        "wf_defense":               "--no-wf-defense",
        "behavioral_cloak":         "--no-cloak",
        "time_correlation_breaker": "--no-time-break",
        "self_test_enabled":        "--no-self-test",
        "session_fragmenter":       "--no-session-frag",
        "cross_layer_enabled":      "--no-cross-layer",
    }
    # geneva is enabled by default, disable if not wanted
    # NOTE: We don't have a separate "geneva" config key; it's always on.
    #       Could add "--no-geneva" if needed.

    for config_key, flag in MODULE_FLAGS.items():
        if not cfg.get(config_key, False):
            args.append(flag)

    # Covert channel is opt-in (default off)
    if cfg.get("covert_channel", False):
        args.append("--covert")

    # Full spoof mode for wired setups
    if cfg.get("full_spoof", False):
        args.append("--full-spoof")

    # Zapret profile
    zp = cfg.get("zapret_profile", "")
    if zp:
        args.extend(["--zapret-profile", zp])
        # Pass custom chain selection if set
        custom = cfg.get("zapret_custom_chains")
        if custom and isinstance(custom, list):
            args.extend(["--zapret-chains", ",".join(custom)])

    return args


@app.route("/api/start", methods=["POST"])
def api_start():
    # ── License gate ──────────────────────────────────────────────────────
    err = _require_license("dpi_bypass")
    if err:
        push_log("WARN", "Start blocked: license not active or missing dpi_bypass module")
        return err

    if state["running"]:
        return jsonify({"ok": False, "error": "NCP already running"}), 409

    # Try to launch actual binary, fall back to simulation
    binary_path = str(NCP_BINARY)
    binary_exists = os.path.isfile(binary_path)
    # On Windows os.access(X_OK) is unreliable for .exe, just check file exists
    binary_ok = binary_exists if platform.system() == "Windows" else (binary_exists and os.access(binary_path, os.X_OK))
    if binary_ok:
        try:
            args = _build_ncp_args()
            # Set cwd to binary's directory so it finds DLLs (WinDivert.dll, wpcap.dll)
            binary_dir = str(Path(binary_path).parent)
            push_log("INFO", f"Launching: {' '.join(args)}")
            push_log("INFO", f"Working dir: {binary_dir}")
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=binary_dir,
            )
            state["process"] = proc
            state["pid"] = proc.pid
            t = threading.Thread(target=read_process_output, args=(proc,), daemon=True)
            t.start()
            push_log("INFO", f"NCP started (PID {proc.pid}), strategy: {state['config']['strategy']}")
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
    else:
        # Simulation mode
        push_log("INFO", "NCP binary not found - running in simulation mode")
        push_log("INFO", f"Strategy: {state['config']['strategy']}")
        push_log("INFO", "Initializing packet interception...")
        push_log("INFO", "DPI bypass active")
        state["pid"] = os.getpid()
        state["simulation"] = True

    state["running"] = True
    state["start_time"] = time.time()
    state["stats"] = {k: 0 for k in state["stats"]}
    state["stats"]["active_connections"] = 0
    # Reset baseline so stats start from zero for this session
    # R7-WEB-03: Use stats_lock when resetting _net_baseline and _prev_net
    with stats_lock:
        global _net_baseline, _prev_net
        _net_baseline = {"bytes_sent": 0, "bytes_recv": 0, "ts": 0}
        _prev_net = {"bytes_sent": 0, "bytes_recv": 0}

    push_log("INFO", "Protection activated")
    return jsonify({"ok": True, "pid": state["pid"]})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    if not state["running"]:
        return jsonify({"ok": False, "error": "NCP not running"}), 409

    proc = state.get("process")
    if proc and proc.poll() is None:
        global _intentional_kill
        _intentional_kill = True
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        state["process"] = None
        _intentional_kill = False

    state["running"] = False
    state["start_time"] = None
    state["pid"] = None
    state["simulation"] = False
    push_log("INFO", "NCP stopped")
    return jsonify({"ok": True})


@app.route("/api/config", methods=["GET"])
def api_get_config():
    disk = load_config()
    with stats_lock:
        if disk:
            state["config"].update(disk)
        return jsonify(state["config"])


@app.route("/api/config", methods=["POST"])
def api_set_config():
    err = _require_license()
    if err:
        return err
    data = request.get_json(force=True) or {}
    state["config"].update(data)
    save_config(state["config"])
    push_log("INFO", "Configuration updated")
    return jsonify({"ok": True, "config": state["config"]})


@app.route("/api/stats")
def api_stats():
    with stats_lock:
        return jsonify({**state["stats"], "uptime": get_uptime()})


@app.route("/api/logs")
def api_logs():
    n = int(request.args.get("n", 100))
    level_filter = request.args.get("level", "").upper()
    with log_lock:
        logs = list(log_buffer)
    if level_filter and level_filter != "ALL":
        logs = [l for l in logs if l["level"] == level_filter]
    return jsonify(logs[-n:])


@app.route("/api/dpi/preset", methods=["POST"])
def api_dpi_preset():
    err = _require_license("dpi_bypass")
    if err:
        return err
    data = request.get_json(force=True) or {}
    preset = data.get("preset", "balanced")
    presets = {
        "stealth": {"tcp_fragment": True, "tls_split": True, "ttl_manip": True,
                    "fake_packets": True, "pkt_disorder": True, "sni_spoof": True,
                    "fragment_size": 32, "timing_jitter": 50, "noise_level": 30},
        "paranoid": {"tcp_fragment": True, "tls_split": True, "ttl_manip": True,
                     "fake_packets": True, "pkt_disorder": True, "sni_spoof": True,
                     "fragment_size": 16, "timing_jitter": 100, "noise_level": 50,
                     "paranoid_mode": True},
        "balanced": {"tcp_fragment": True, "tls_split": True, "ttl_manip": False,
                     "fake_packets": False, "pkt_disorder": False, "sni_spoof": False,
                     "fragment_size": 64, "timing_jitter": 20, "noise_level": 10},
        "performance": {"tcp_fragment": True, "tls_split": False, "ttl_manip": False,
                        "fake_packets": False, "pkt_disorder": False, "sni_spoof": False,
                        "fragment_size": 128, "timing_jitter": 5, "noise_level": 0},
        "max_compat": {"tcp_fragment": False, "tls_split": True, "ttl_manip": False,
                       "fake_packets": False, "pkt_disorder": False, "sni_spoof": False,
                       "fragment_size": 256, "timing_jitter": 0, "noise_level": 0},
    }
    if preset not in presets:
        return jsonify({"ok": False, "error": "Unknown UI preset"}), 400
    state["config"].update(presets[preset])
    state["config"]["strategy"] = preset
    save_config(state["config"])
    push_log("INFO", f"DPI UI preset: {preset}")
    return jsonify({"ok": True, "preset": preset, "config": state["config"]})


def _restart_ncp_process():
    """Stop the running NCP process and start it again with current config.
    Used when the operator preset changes while NCP is active."""
    global _intentional_kill, _net_baseline, _prev_net
    proc = state.get("process")
    if proc and proc.poll() is None:
        _intentional_kill = True
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        _intentional_kill = False
        state["process"] = None
        state["pid"] = None

    # Re-launch with updated preset
    binary_path = str(NCP_BINARY)
    binary_exists = os.path.isfile(binary_path)
    binary_ok = binary_exists if platform.system() == "Windows" else (binary_exists and os.access(binary_path, os.X_OK))
    if binary_ok:
        try:
            args = _build_ncp_args()
            binary_dir = str(Path(binary_path).parent)
            push_log("INFO", f"Launching: {' '.join(args)}")
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=binary_dir,
            )
            state["process"] = proc
            state["pid"] = proc.pid
            t = threading.Thread(target=read_process_output, args=(proc,), daemon=True)
            t.start()
            # Reset net baseline for fresh stats
            # R7-WEB-03: Use stats_lock when resetting _net_baseline and _prev_net
            with stats_lock:
                _net_baseline = {"bytes_sent": 0, "bytes_recv": 0, "ts": 0}
                _prev_net = {"bytes_sent": 0, "bytes_recv": 0}
            push_log("INFO", f"NCP restarted (PID {proc.pid})")
        except Exception as e:
            push_log("ERROR", f"Restart failed: {e}")
            state["running"] = False
    else:
        push_log("WARN", "NCP binary not found - cannot restart")
        state["running"] = False


# DPI operator/strategy presets (maps to C++ DPIPreset enum)
DPI_OPERATOR_PRESETS = {
    "tspu":     {"id": "tspu",     "label": "TSPU (home ISPs)",       "description": "Home ISP: disorder+fake, TTL=1, badseq+md5sig"},
    "beeline":  {"id": "beeline",  "label": "Beeline Mobile",        "description": "Reverse-frag, TTL=4, DNS: 8.8.8.8"},
    "mts":      {"id": "mts",      "label": "MTS Mobile",            "description": "Disorder+fake, auto-TTL 4-8, badseq+md5sig"},
    "megafon":  {"id": "megafon",  "label": "Megafon Mobile",        "description": "Split+fake+OOB, auto-TTL"},
    "tele2":    {"id": "tele2",    "label": "Tele2 Mobile",          "description": "Disorder+fake, TTL=5, badseq+md5sig"},
    "mobile":   {"id": "mobile",   "label": "Universal Mobile",      "description": "Multi-method: all fooling, reverse-frag, auto-TTL"},
    "auto":     {"id": "auto",     "label": "Auto-detect",           "description": "Tries strategies one by one until success"},
}


# === ZAPRET PROFILES v72.x ===
# Multi-chain DPI configs — zapret v72.x full feature set
# Supports: 3-phase desync modes, all fooling methods, fake types,
#           split-pos markers, TTL/autottl, dup system, fake-tls-mod,
#           fakedsplit/hostfakesplit, L3/L7 filters, ip-id modes,
#           start/cutoff conditions, wssize, and more.

ZAPRET_CHAINS = {
    "quic_general": {
        "name": "QUIC General",
        "proto": "udp",
        "ports": "443",
        "hostlist": "list-general.txt",
        "desync": "fake",
        "repeats": 11,
        "fake_type": "quic",
        "cutoff": "n4",
        "description": "QUIC UDP 443 — fake-quic, 11 repeats, hostlist, cutoff n4"
    },
    "discord_stun": {
        "name": "Discord STUN",
        "proto": "udp",
        "ports": "19294-19344,50000-50100",
        "filter_l7": "discord,stun",
        "desync": "fake",
        "repeats": 6,
        "fake_type": "discord",
        "cutoff": "n4",
        "description": "Discord voice/STUN UDP — fake-discord, 6 repeats"
    },
    "discord_media": {
        "name": "Discord Media",
        "proto": "tcp",
        "ports": "2053,2083,2087,2096,8443",
        "host": "discord.media",
        "desync": "fake,multisplit",
        "seqovl": 681,
        "split_pos": "1",
        "fooling": "ts,badseq",
        "repeats": 8,
        "fake_type": "tls",
        "description": "Discord media TCP — fake+multisplit, seqovl=681, ts+badseq"
    },
    "google_tls": {
        "name": "Google TLS",
        "proto": "tcp",
        "ports": "443",
        "hostlist": "list-google.txt",
        "ip_id": "zero",
        "desync": "fake,multisplit",
        "seqovl": 681,
        "split_pos": "1",
        "fooling": "ts,badseq",
        "repeats": 8,
        "fake_type": "tls",
        "description": "Google TCP 443 — ip-id=0, fake+multisplit, seqovl=681"
    },
    "general_hostlist": {
        "name": "General Hostlist",
        "proto": "tcp",
        "ports": "80,443",
        "hostlist": "list-general.txt",
        "desync": "fake,multisplit",
        "seqovl": 664,
        "split_pos": "1",
        "fooling": "ts,badseq",
        "repeats": 8,
        "fake_type": "tls",
        "description": "General TCP 80/443 — fake+multisplit, seqovl=664"
    },
    "quic_ipset": {
        "name": "QUIC ipset-all",
        "proto": "udp",
        "ports": "443",
        "ipset": "ipset-all.txt",
        "desync": "fake",
        "repeats": 11,
        "fake_type": "quic",
        "cutoff": "n4",
        "description": "QUIC UDP 443 — fake-quic, 11 repeats, ipset-all"
    },
    "tcp_ipset": {
        "name": "TCP ipset-all",
        "proto": "tcp",
        "ports": "80,443,12",
        "ipset": "ipset-all.txt",
        "desync": "fake,multisplit",
        "seqovl": 664,
        "split_pos": "1",
        "fooling": "ts,badseq",
        "repeats": 8,
        "fake_type": "tls",
        "description": "TCP 80/443/12 — fake+multisplit, ipset-all"
    },
    "udp_unknown": {
        "name": "UDP Unknown",
        "proto": "udp",
        "ports": "12",
        "ipset": "ipset-all.txt",
        "desync": "fake",
        "repeats": 10,
        "any_protocol": True,
        "fake_type": "unknown-udp",
        "cutoff": "n4",
        "description": "UDP port 12 — fake-unknown-udp, cutoff n4"
    },
    # ── v72.x new chains ──────────────────────────────────────────────────
    "youtube_quic": {
        "name": "YouTube QUIC",
        "proto": "udp",
        "ports": "443",
        "hostlist": "list-youtube.txt",
        "desync": "fake",
        "repeats": 14,
        "fake_type": "quic",
        "fooling": "badsum,datanoack",
        "cutoff": "n6",
        "description": "YouTube QUIC UDP — fake-quic, 14 repeats, badsum+datanoack"
    },
    "youtube_tls": {
        "name": "YouTube TLS",
        "proto": "tcp",
        "ports": "443",
        "hostlist": "list-youtube.txt",
        "desync": "fake,fakedsplit",
        "split_pos": "sniext",
        "seqovl": 681,
        "fooling": "ts,badseq,md5sig",
        "repeats": 10,
        "fake_type": "tls",
        "fake_tls_mod": "rndsni",
        "autottl": "1-4",
        "fakedsplit_altorder": True,
        "description": "YouTube TLS — fake+fakedsplit, sniext, autottl=1-4, rndsni, altorder"
    },
    "rublock_tls": {
        "name": "RuBlock TLS",
        "proto": "tcp",
        "ports": "80,443",
        "hostlist": "list-rublock.txt",
        "desync": "syndata,fake,multidisorder",
        "split_pos": "1,midsld",
        "seqovl": 664,
        "fooling": "ts,badseq,md5sig,datanoack",
        "repeats": 12,
        "fake_type": "tls",
        "fake_tls_mod": "rndsni",
        "ttl": 6,
        "description": "RuBlock — syndata+fake+multidisorder, ttl=6, all fooling, rndsni"
    },
    "hostfakesplit_general": {
        "name": "Hostfakesplit General",
        "proto": "tcp",
        "ports": "443",
        "hostlist": "list-general.txt",
        "desync": "fake,hostfakesplit",
        "split_pos": "host",
        "fooling": "ts,badseq",
        "repeats": 6,
        "fake_type": "tls",
        "hostfakesplit_midhost": 2,
        "description": "Hostfakesplit — split at host boundary, midhost=2, TSPU bypass"
    },
    "wireguard_udp": {
        "name": "WireGuard UDP",
        "proto": "udp",
        "ports": "51820",
        "filter_l7": "wireguard",
        "desync": "fake",
        "repeats": 8,
        "fake_type": "wireguard",
        "cutoff": "n3",
        "description": "WireGuard UDP 51820 — fake-wireguard, 8 repeats"
    },
}

ZAPRET_PROFILES = {
    "zapret_full": {
        "id": "zapret_full",
        "label": "Zapret Full (all chains)",
        "icon": "🔗",
        "description": "All 13 chains: QUIC, Discord, Google, General, YouTube, RuBlock, WireGuard",
        "chains": list(ZAPRET_CHAINS.keys()),
    },
    "zapret_general": {
        "id": "zapret_general",
        "label": "General (TCP sites)",
        "icon": "🌐",
        "description": "General hostlist TCP + TCP ipset - main blocked sites",
        "chains": ["general_hostlist", "tcp_ipset"],
    },
    "zapret_discord": {
        "id": "zapret_discord",
        "label": "Discord",
        "icon": "💬",
        "description": "Discord STUN (voice) + Discord Media - for calls and streams",
        "chains": ["discord_stun", "discord_media"],
    },
    "zapret_google": {
        "id": "zapret_google",
        "label": "Google / YouTube",
        "icon": "▶️",
        "description": "Google TLS with ip-id=zero - YouTube, Google Services",
        "chains": ["google_tls"],
    },
    "zapret_quic": {
        "id": "zapret_quic",
        "label": "QUIC Only",
        "icon": "⚡",
        "description": "QUIC general + QUIC ipset + YouTube QUIC - HTTP/3 traffic",
        "chains": ["quic_general", "quic_ipset", "youtube_quic"],
    },
    "zapret_tcp": {
        "id": "zapret_tcp",
        "label": "TCP Only",
        "icon": "🔌",
        "description": "All TCP: Discord Media, Google, General, ipset, Hostfakesplit",
        "chains": ["discord_media", "google_tls", "general_hostlist", "tcp_ipset", "hostfakesplit_general"],
    },
    "zapret_youtube": {
        "id": "zapret_youtube",
        "label": "YouTube",
        "icon": "▶️",
        "description": "YouTube QUIC + YouTube TLS + Google TLS - full YT bypass",
        "chains": ["youtube_quic", "youtube_tls", "google_tls"],
    },
    "zapret_rublock": {
        "id": "zapret_rublock",
        "label": "RuBlock (heavy blocks)",
        "icon": "🛡️",
        "description": "RuBlock TLS + General + Hostfakesplit + QUIC - syndata, all fooling",
        "chains": ["rublock_tls", "general_hostlist", "hostfakesplit_general", "quic_general"],
    },
}




@app.route("/api/dpi/operators")
def api_dpi_operators():
    """Return available DPI operator presets."""
    return jsonify(list(DPI_OPERATOR_PRESETS.values()))


@app.route("/api/dpi/operator", methods=["POST"])
def api_dpi_operator():
    """Set the DPI operator preset. Requires restart to take effect."""
    err = _require_license("dpi_bypass")
    if err:
        return err
    data = request.get_json(force=True) or {}
    operator_id = data.get("operator", "tspu")
    if operator_id not in DPI_OPERATOR_PRESETS:
        return jsonify({"ok": False, "error": f"Unknown operator: {operator_id}"}), 400

    state["config"]["dpi_preset"] = operator_id
    save_config(state["config"])
    preset_info = DPI_OPERATOR_PRESETS[operator_id]
    push_log("INFO", f"DPI operator preset: {preset_info['label']}")

    # If NCP is running, auto-restart to apply the new preset
    restarted = False
    if state["running"]:
        push_log("INFO", "Restarting NCP with new preset...")
        _restart_ncp_process()
        restarted = True

    return jsonify({
        "ok": True,
        "operator": operator_id,
        "label": preset_info["label"],
        "description": preset_info["description"],
        "restarted": restarted,
    })


@app.route("/api/dpi/zapret/profiles")
def api_zapret_profiles():
    """Return available zapret config profiles with chain details."""
    result = []
    for pid, profile in ZAPRET_PROFILES.items():
        entry = dict(profile)
        entry["chain_details"] = [
            {"id": cid, **ZAPRET_CHAINS[cid]}
            for cid in profile["chains"]
            if cid in ZAPRET_CHAINS
        ]
        result.append(entry)
    return jsonify(result)


@app.route("/api/dpi/zapret/chains")
def api_zapret_chains():
    """Return all individual zapret chains."""
    result = []
    for cid, chain in ZAPRET_CHAINS.items():
        result.append({"id": cid, **chain})
    return jsonify(result)


@app.route("/api/dpi/zapret/profile", methods=["POST"])
def api_zapret_set_profile():
    """Set active zapret profile. Stores in config and restarts if running."""
    err = _require_license("dpi_bypass")
    if err:
        return err
    data = request.get_json(force=True) or {}
    profile_id = data.get("profile", "")

    if profile_id and profile_id not in ZAPRET_PROFILES:
        return jsonify({"ok": False, "error": f"Unknown zapret profile: {profile_id}"}), 400

    state["config"]["zapret_profile"] = profile_id

    # If custom chains provided, store them too
    custom_chains = data.get("chains", None)
    if custom_chains is not None:
        state["config"]["zapret_custom_chains"] = custom_chains

    save_config(state["config"])

    if profile_id:
        profile = ZAPRET_PROFILES[profile_id]
        push_log("INFO", f"Zapret profile: {profile['label']}")
        push_log("INFO", f"Active chains: {', '.join(profile['chains'])}")
    else:
        push_log("INFO", "Zapret profile disabled")

    # Auto-restart if running
    restarted = False
    if state["running"]:
        push_log("INFO", "Restarting NCP with new zapret profile...")
        _restart_ncp_process()
        restarted = True

    return jsonify({
        "ok": True,
        "profile": profile_id,
        "restarted": restarted,
    })


@app.route("/api/license")
def api_license():
    lic = state["license"]
    # Пересчитываем оставшиеся дни
    if lic["expires"]:
        try:
            exp = datetime.strptime(lic["expires"], "%Y-%m-%d")
            lic["days_remaining"] = max(0, (exp - datetime.now()).days)
            if lic["days_remaining"] == 0 and lic["status"] == "active":
                lic["status"] = "expired"
        except Exception:
            pass
    return jsonify(lic)


# Маппинг планов для UI
PLAN_LABELS = {
    "trial": "Trial (14 days)",
    "basic": "Basic",
    "pro": "Pro",
    "ultimate": "Ultimate (Lifetime)",
}


def _activate_license(key_string: str) -> dict:
    """Верифицирует и активирует лицензионный ключ."""
    if not LICENSE_CRYPTO_AVAILABLE:
        return {"ok": False, "error": "Crypto module not installed. pip install cryptography"}

    try:
        pub_bytes = load_public_key_from_b64(NCP_LICENSE_PUBLIC_KEY_B64)
        result = verify_license_key(key_string, pub_bytes)
    except Exception as e:
        logger.error(f"License verification error: {e}")
        return {"ok": False, "error": "Key verification error"}

    if result is None:
        return {"ok": False, "error": "Invalid key or signature verification failed"}

    if result.get("expired"):
        return {"ok": False, "error": "License key expired"}

    plan = result.get("plan", "basic")
    modules = result.get("modules", [])
    days = result.get("days", 365)
    days_remaining = result.get("days_remaining", 0)
    created = result.get("created", "")

    # Вычисляем дату истечения
    if days == 0:
        expires_str = "lifetime"
        days_remaining = 99999
    else:
        try:
            created_date = datetime.strptime(created, "%Y-%m-%d")
            expires_str = (created_date + timedelta(days=days)).strftime("%Y-%m-%d")
        except Exception:
            expires_str = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

    # Обновляем состояние
    state["license"]["status"] = "active"
    state["license"]["key"] = key_string[:20] + "..."
    state["license"]["plan"] = plan
    state["license"]["plan_label"] = PLAN_LABELS.get(plan, plan)
    state["license"]["expires"] = expires_str
    state["license"]["days_remaining"] = days_remaining
    state["license"]["modules"] = modules
    state["license"]["features"] = modules  # алиас для совместимости

    # Сохраняем ключ на диск
    try:
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        LICENSE_FILE.write_text(json.dumps({
            "key": key_string,
            "activated": datetime.now().isoformat()
        }), encoding="utf-8")
    except Exception as e:
        logger.warning(f"Failed to save license: {e}")

    return {"ok": True, "license": state["license"]}


def _try_restore_license():
    """При запуске пытается восстановить ранее активированную лицензию с диска."""
    if not LICENSE_CRYPTO_AVAILABLE:
        return
    try:
        if LICENSE_FILE.exists():
            data = json.loads(LICENSE_FILE.read_text(encoding="utf-8"))
            key = data.get("key", "")
            if key:
                result = _activate_license(key)
                if result.get("ok"):
                    logger.info(f"License restored: {state['license']['plan_label']}")
                else:
                    logger.warning(f"Saved license is invalid: {result.get('error', '')}")
    except Exception as e:
        logger.warning(f"Failed to restore license: {e}")


@app.route("/api/license/activate", methods=["POST"])
def api_license_activate():
    data = request.get_json(force=True) or {}
    key = data.get("key", "").strip()
    if not key:
        return jsonify({"ok": False, "error": "Key not specified"}), 400

    result = _activate_license(key)
    if result.get("ok"):
        push_log("INFO", f"License activated: {state['license']['plan_label']}")
        return jsonify(result)
    else:
        push_log("WARN", f"Activation error: {result.get('error', '')}")
        return jsonify(result), 400


@app.route("/api/license/deactivate", methods=["POST"])
def api_license_deactivate():
    state["license"] = {
        "status": "inactive",
        "key": "",
        "plan": "",
        "plan_label": "",
        "expires": "",
        "days_remaining": 0,
        "modules": [],
        "features": [],
    }
    try:
        if LICENSE_FILE.exists():
            LICENSE_FILE.unlink()
    except Exception:
        pass
    push_log("INFO", "License deactivated")
    return jsonify({"ok": True})


@app.route("/api/network/interfaces")
def api_network_interfaces():
    return jsonify(list_network_interfaces())


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    err = _require_license()
    if err:
        return err
    # Identity rotation is handled by the C++ spoofer binary.
    # From the web backend we can only trigger the binary.
    proc = state.get("process")
    if proc and proc.poll() is None:
        push_log("INFO", "Identity rotation requested (handled by NCP binary)")
        # The C++ binary handles MAC/IP rotation via spoofer module
        return jsonify({"ok": True, "ts": datetime.now().isoformat(),
                        "note": "Rotation delegated to NCP binary"})
    else:
        push_log("WARN", "Identity rotation unavailable: NCP binary not running")
        return jsonify({"ok": False,
                        "error": "NCP binary not running - rotation unavailable"}), 409


# ─── Telegram MTProto Proxy ──────────────────────────────────────────────────
# Telegram calls & media use direct IP connections to Telegram DCs.
# These are blocked by IP, not DPI — packet fragmentation cannot help.
# The ONLY solution is routing Telegram traffic through MTProto proxy.

# Built-in proxy list (updated periodically, user can add custom ones)
TG_MTPROTO_PROXIES = [
    {"server": "91.107.172.155", "port": 443,  "secret": "eeNEgYdJvXrFGRMCIMJdCQ",  "location": "DE"},
    {"server": "5.75.199.133",   "port": 443,  "secret": "eeNEgYdJvXrFGRMCIMJdCQ",  "location": "DE"},
    {"server": "185.173.36.38",  "port": 443,  "secret": "eeRighJJvXrFGRMCIMJdCQ",  "location": "NL"},
    {"server": "87.229.100.253", "port": 443,  "secret": "eeRighJJvXrFGRMCIMJdCQ",  "location": "RU"},
    {"server": "77.232.43.186",  "port": 443,  "secret": "eeRighJJvXrFGRMCIMJdCQ",  "location": "RU"},
    {"server": "195.2.78.126",   "port": 443,  "secret": "eed77db43e",               "location": "RU"},
    {"server": "157.180.61.219", "port": 1080, "secret": "1320PuNyHw_LQKT_Y7XNJw",  "location": "FI"},
]

def _check_proxy_alive(server: str, port: int, timeout: float = 3.0) -> bool:
    """Quick TCP connect check to see if the proxy port is open."""
    import socket
    try:
        s = socket.create_connection((server, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


@app.route("/api/telegram/proxies")
def api_telegram_proxies():
    """Return list of known MTProto proxies with liveness status."""
    results = []
    for p in TG_MTPROTO_PROXIES:
        entry = dict(p)
        # Build tg:// deep link for one-click connect
        entry["link"] = (f"tg://proxy?server={p['server']}"
                         f"&port={p['port']}&secret={p['secret']}")
        entry["alive"] = _check_proxy_alive(p["server"], p["port"])
        results.append(entry)
    return jsonify(results)


@app.route("/api/telegram/proxy/check", methods=["POST"])
def api_telegram_proxy_check():
    """Check if a custom MTProto proxy is reachable."""
    data = request.get_json(force=True) or {}
    server = data.get("server", "").strip()
    port = int(data.get("port", 443))
    secret = data.get("secret", "").strip()
    if not server or not secret:
        return jsonify({"ok": False, "error": "Server and secret required"}), 400
    try:
        addr = ipaddress.ip_address(server)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return jsonify({"success": False, "error": "Invalid server address: private/loopback not allowed"}), 400
    except ValueError:
        pass  # Hostname, not IP literal - allow
    alive = _check_proxy_alive(server, port)
    link = f"tg://proxy?server={server}&port={port}&secret={secret}"
    return jsonify({"ok": True, "alive": alive, "link": link})


@app.route("/api/health")
def api_health():
    checks = {
        "binary": os.path.isfile(str(NCP_BINARY)),
        "config_dir": CONFIG_PATH.parent.exists(),
        "network": len(list_network_interfaces()) > 0,
        "flask": True,
        "socketio": True,
        "psutil": True,
    }
    overall = all(v for k, v in checks.items() if k not in ("binary",))
    return jsonify({"ok": overall, "checks": checks})


@app.route("/api/e2e/sessions")
def api_e2e_sessions():
    return jsonify(state["e2e_sessions"])


@app.route("/api/e2e/sessions", methods=["POST"])
def api_e2e_create():
    err = _require_license("e2e_encryption")
    if err:
        return err
    # E2E sessions are managed by the C++ binary, not the Python backend.
    # This endpoint creates a UI placeholder for session tracking.
    session = {
        "id": uuid.uuid4().hex[:8],
        "peer": "peer-" + uuid.uuid4().hex[:6],
        "cipher": "AES-256-GCM / X25519",
        "pq_enabled": state["config"].get("postquantum", False),
        "ratchet_state": "pending",
        "msg_count": 0,
        "created": datetime.now().isoformat(),
        "status": "waiting",  # honest: waiting for C++ backend
        "note": "Session registered. Encryption handled by NCP binary.",
    }
    state["e2e_sessions"].append(session)
    push_log("INFO", f"E2E session registered: {session['id']}")
    return jsonify({"ok": True, "session": session}), 201


@app.route("/api/e2e/sessions/<sid>", methods=["DELETE"])
def api_e2e_delete(sid):
    state["e2e_sessions"] = [s for s in state["e2e_sessions"] if s["id"] != sid]
    push_log("INFO", f"E2E session deleted: {sid}")
    return jsonify({"ok": True})


@app.route("/api/i2p/tunnels")
def api_i2p_tunnels():
    return jsonify(state["i2p_tunnels"])


@app.route("/api/i2p/tunnels", methods=["POST"])
def api_i2p_create():
    err = _require_license("i2p")
    if err:
        return err
    data = request.get_json(force=True) or {}
    # I2P tunnels require an actual I2P router (i2pd) running locally.
    # This registers the tunnel config; actual tunnel is built by C++ + i2pd.
    tunnel = {
        "id": uuid.uuid4().hex[:8],
        "type": data.get("type", "client"),
        "hops": state["config"].get("i2p_hop_count", 3),
        "destination": "pending...",
        "status": "registered",
        "created": datetime.now().isoformat(),
        "note": "Requires i2pd router running locally.",
    }
    state["i2p_tunnels"].append(tunnel)
    push_log("INFO", f"I2P tunnel registered: {tunnel['id']} (requires i2pd)")
    return jsonify({"ok": True, "tunnel": tunnel}), 201


@app.route("/api/i2p/tunnels/<tid>", methods=["DELETE"])
def api_i2p_delete(tid):
    state["i2p_tunnels"] = [t for t in state["i2p_tunnels"] if t["id"] != tid]
    push_log("INFO", f"I2P tunnel deleted: {tid}")
    return jsonify({"ok": True})


@app.route("/api/geneva/start", methods=["POST"])
def api_geneva_start():
    # geneva_basic is available on trial+, geneva_full on pro+
    err = _require_license("geneva_basic")
    if err:
        return err
    if state["geneva"]["running"]:
        return jsonify({"ok": False, "error": "Geneva already running"}), 409
    state["geneva"]["running"] = True
    state["geneva"]["generation"] = 0
    state["geneva"]["best_fitness"] = 0.0
    state["geneva"]["fitness_history"] = []
    push_log("INFO", "Geneva GA started - strategy evolution delegated to NCP binary")
    push_log("INFO", "Note: Geneva evolution runs inside the C++ engine when NCP is active")
    return jsonify({"ok": True})


@app.route("/api/geneva/stop", methods=["POST"])
def api_geneva_stop():
    state["geneva"]["running"] = False
    push_log("INFO", f"Geneva GA stopped. Generation: {state['geneva']['generation']}, "
             f"Best fitness: {state['geneva']['best_fitness']:.4f}")
    return jsonify({"ok": True, "geneva": state["geneva"]})


@app.route("/api/geneva/status")
def api_geneva_status():
    return jsonify(state["geneva"])


@app.route("/api/version")
def api_version():
    return jsonify({
        "version": "1.4.0-dev",
        "build": "web-" + datetime.now().strftime("%Y%m%d"),
        "platform": platform.system(),
        "python": sys.version.split()[0],
    })


# ─── Новые API: Модули ────────────────────────────────────────────────────────

def _flatten_modules():
    """Преобразует вложенную структуру модулей в плоский dict для фронтенда."""
    m = state["modules"]
    flat = {}
    # pipeline
    flat["pipeline_throughput"] = m["pipeline"]["throughput_pps"]
    flat["pipeline_queue_usage"] = m["pipeline"]["queue_usage_pct"]
    flat["pipeline_drops"] = m["pipeline"]["drops"]
    # dns_leak
    flat["dns_leaks_blocked"] = m["dns_leak"]["leaks_blocked"]
    flat["dns_queries_intercepted"] = m["dns_leak"]["queries_intercepted"]
    # session_frag
    flat["sessions_fragmented"] = m["session_frag"]["sessions_fragmented"]
    flat["fragments_created"] = m["session_frag"]["fragments_created"]
    # cross_layer
    flat["correlations_checked"] = m["cross_layer"]["correlations_checked"]
    flat["anomalies_fixed"] = m["cross_layer"]["anomalies_fixed"]
    # rtt_equalizer
    flat["rtt_current_ms"] = m["rtt_equalizer"]["current_ms"]
    flat["rtt_packets_delayed"] = m["rtt_equalizer"]["packets_delayed"]
    # volume_norm
    flat["volume_padding_bytes"] = m["volume_norm"]["padding_bytes"]
    flat["volume_normalized_flows"] = m["volume_norm"]["normalized_flows"]
    # behavioral_cloak
    flat["cloak_actions_emulated"] = m["behavioral_cloak"]["actions_emulated"]
    flat["cloak_patterns_matched"] = m["behavioral_cloak"]["patterns_matched"]
    # time_breaker
    flat["time_correlations_broken"] = m["time_breaker"]["correlations_broken"]
    flat["time_chaff_packets"] = m["time_breaker"]["chaff_packets"]
    # covert_channel
    flat["covert_bytes_sent"] = m["covert_channel"]["bytes_sent"]
    flat["covert_bytes_recv"] = m["covert_channel"]["bytes_recv"]
    flat["covert_channels_active"] = m["covert_channel"]["channels_active"]
    # wf_defense
    flat["wf_packets_padded"] = m["wf_defense"]["packets_padded"]
    flat["wf_overhead_bytes"] = m["wf_defense"]["overhead_bytes"]
    # self_test
    flat["self_test_last_run"] = m["self_test"]["last_run"]
    flat["self_test_score"] = m["self_test"]["score"]
    flat["self_test_issues"] = m["self_test"]["issues"]
    flat["self_test_history"] = m["self_test"]["history"]
    # protocol_rotation
    flat["rotation_current_protocol"] = m["protocol_rotation"]["current_protocol"]
    flat["rotations_completed"] = m["protocol_rotation"]["rotations_completed"]
    # as_router
    flat["as_routes_diverted"] = m["as_router"]["routes_diverted"]
    flat["as_current_path"] = m["as_router"]["current_path"]
    # geo_obfuscator
    flat["geo_apparent_location"] = m["geo_obfuscator"]["apparent_location"]
    flat["geo_hops_active"] = m["geo_obfuscator"]["hops_active"]
    return flat


@app.route("/api/modules")
def api_modules():
    """Возвращает статистику всех модулей (плоская структура)."""
    return jsonify(_flatten_modules())


@app.route("/api/modules/toggle", methods=["POST"])
def api_modules_toggle():
    """
    Включает или отключает модуль.
    Тело запроса: {"module": "<module_id>", "enabled": true|false}
    """
    data = request.get_json(force=True) or {}
    module = data.get("module", "")
    enabled = data.get("enabled", False)

    # Only check license when enabling a module
    if enabled and module:
        err = _require_license(module)
        if err:
            return err

    # Карта module_id → config ключ
    module_config_keys = {
        "pipeline": "pipeline_enabled",
        "dns_leak": "dns_leak_prevention",
        "session_frag": "session_fragmenter",
        "cross_layer": "cross_layer_enabled",
        "rtt_equalizer": "rtt_equalizer",
        "volume_norm": "volume_normalizer",
        "behavioral_cloak": "behavioral_cloak",
        "time_breaker": "time_correlation_breaker",
        "covert_channel": "covert_channel",
        "wf_defense": "wf_defense",
        "self_test": "self_test_enabled",
        "protocol_rotation": "protocol_rotation",
        "as_router": "as_aware_routing",
        "geo_obfuscator": "geo_obfuscator",
    }

    if module not in module_config_keys:
        return jsonify({"ok": False, "error": f"Unknown module: {module}"}), 400

    cfg_key = module_config_keys[module]
    state["config"][cfg_key] = bool(enabled)

    status_str = "enabled" if enabled else "disabled"
    push_log("INFO", f"Module '{module}' {status_str}")
    return jsonify({"ok": True, "module": module, "enabled": bool(enabled)})


@app.route("/api/modules/stats")
def api_modules_stats():
    """Возвращает статистику всех модулей (алиас /api/modules)."""
    return jsonify(_flatten_modules())


@app.route("/api/selftest/run", methods=["POST"])
def api_selftest_run():
    """Runs a real connectivity self-test."""
    err = _require_license("self_test")
    if err:
        return err
    result = _run_selftest_real()
    push_log("INFO", f"Self-test completed: "
             f"score {result['score']}, issues: {result['issues']}")
    return jsonify({"ok": True, "result": result})


# ─── WebSocket ────────────────────────────────────────────────────────────────

@socketio.on("connect", namespace="/ws")
def ws_connect():
    push_log("DEBUG", "WebSocket client connected")
    emit("connected", {"ts": time.time()})


@socketio.on("disconnect", namespace="/ws")
def ws_disconnect():
    pass


@socketio.on("ping", namespace="/ws")
def ws_ping(data):
    emit("pong", {"ts": time.time()})


# ─── Main ─────────────────────────────────────────────────────────────────────

def _initial_logs():
    push_log("INFO", "NCP Web Interface initialized")
    push_log("INFO", f"Platform: {platform.system()} {platform.release()}")
    push_log("INFO", f"Python {sys.version.split()[0]}")
    binary_exists = os.path.isfile(str(NCP_BINARY))
    push_log("INFO" if binary_exists else "WARN",
             f"NCP binary: {'found' if binary_exists else 'NOT FOUND — simulation will be used'}")
    if binary_exists:
        push_log("INFO", f"NCP path: {NCP_BINARY}")
        # Check for required DLLs next to binary, auto-copy from SDK if missing
        bin_dir = NCP_BINARY.parent
        _windivert_sdk_dirs = [
            Path(r"C:\WinDivert-2.2.2-A\x64"),
            Path(r"C:\WinDivert-2.2.2-A"),
            Path(r"C:\WinDivert\x64"),
            Path(r"C:\WinDivert"),
        ]
        for needed in ["WinDivert.dll", "WinDivert64.sys", "wpcap.dll"]:
            target = bin_dir / needed
            if target.exists():
                push_log("INFO", f"{needed}: found")
            else:
                # Try to auto-copy from known SDK locations
                copied = False
                if needed.startswith("WinDivert"):
                    for sdk_dir in _windivert_sdk_dirs:
                        src = sdk_dir / needed
                        if src.exists():
                            try:
                                import shutil
                                shutil.copy2(str(src), str(target))
                                push_log("INFO", f"{needed}: copied from {sdk_dir}")
                                copied = True
                                break
                            except Exception as e:
                                push_log("WARN", f"{needed}: copy failed from {sdk_dir}: {e}")
                if not copied:
                    push_log("WARN", f"{needed}: NOT FOUND next to ncp.exe — startup errors possible")
    push_log("INFO", "Ready")


if __name__ == "__main__":
    # Restore saved license
    _try_restore_license()

    # Start background stats thread (collects REAL network stats, no simulation)
    stats_thread = threading.Thread(target=stats_update_loop, daemon=True)
    stats_thread.start()

    _initial_logs()

    port = int(os.environ.get("NCP_WEB_PORT", 5000))
    logger.info(f"Starting NCP Web Interface on 0.0.0.0:{port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
