# -*- coding: utf-8 -*-
"""
NCP Bypass routes — proxy mode, blockcheck, hostlists, zapret import,
DPI detector events, availability checker, autostart, auto-update.

Registered from server.py via register_bypass_routes(app, ctx).
ctx keys:
    state          – global state dict (with "config")
    push_log       – fn(level, msg)
    save_config    – fn(cfg)
    ncp_binary     – str path to ncp binary
    config_dir     – Path to config directory
    exe_dir        – Path to the executable directory (frozen) or web dir
"""

import json
import os
import platform
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

from flask import jsonify, request

# ─────────────────────────────────────────────────────────────────────────────
# Module-level state
# ─────────────────────────────────────────────────────────────────────────────

_proxy_proc = None
_proxy_lock = threading.Lock()

_blockcheck = {
    "running": False,
    "started": 0.0,
    "report": None,
    "error": None,
}
_blockcheck_lock = threading.Lock()

CHECK_SITES = [
    ("YouTube", "www.youtube.com"),
    ("Discord", "discord.com"),
    ("Instagram", "www.instagram.com"),
    ("X (Twitter)", "x.com"),
    ("WhatsApp", "web.whatsapp.com"),
    ("Google", "www.google.com"),
]


# ─────────────────────────────────────────────────────────────────────────────
# TLS probe helpers (pure Python, no external deps)
# ─────────────────────────────────────────────────────────────────────────────

def _build_client_hello(sni: str) -> bytes:
    """Minimal TLS ClientHello with SNI (enough to elicit ServerHello)."""
    hs = bytearray()
    hs += b"\x03\x03"                      # TLS 1.2
    hs += bytes(range(0xA0, 0xC0))         # random (32)
    hs += b"\x00"                          # session id
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xCCA9, 0xCCA8]
    hs += struct.pack(">H", 2 * len(ciphers))
    for c in ciphers:
        hs += struct.pack(">H", c)
    hs += b"\x01\x00"                      # null compression

    ext = bytearray()
    sni_b = sni.encode()
    ext += struct.pack(">HHH", 0x0000, len(sni_b) + 5, len(sni_b) + 3)
    ext += b"\x00" + struct.pack(">H", len(sni_b)) + sni_b
    ext += struct.pack(">HH", 0x002B, 5) + b"\x04" + struct.pack(">HH", 0x0304, 0x0303)
    ext += struct.pack(">HHH", 0x000A, 6, 0x001D) + struct.pack(">H", 0x0017)
    ext += struct.pack(">HH", 0x000B, 2) + b"\x01\x00"
    ext += struct.pack(">HH", 0x000D, 8) + struct.pack(">HHHH", 0x0403, 0x0804, 0x0401, 0x0501)
    ext += struct.pack(">HH", 0x0033, 36) + struct.pack(">HHH", 34, 0x001D, 32) + bytes(range(1, 33))

    hs += struct.pack(">H", len(ext)) + ext

    rec = bytearray(b"\x16\x03\x01")
    rec += struct.pack(">H", len(hs) + 4)
    rec += b"\x01" + len(hs).to_bytes(3, "big") + hs
    return bytes(rec)


def _tls_probe(sock: socket.socket, domain: str, timeout: float) -> dict:
    """Send ClientHello over an established connection, await any TLS reply."""
    t0 = time.time()
    try:
        sock.settimeout(timeout)
        sock.sendall(_build_client_hello(domain))
        data = sock.recv(8)
        if data:
            return {"ok": True, "latency_ms": int((time.time() - t0) * 1000)}
        return {"ok": False, "fail": "timeout"}
    except socket.timeout:
        return {"ok": False, "fail": "timeout"}
    except ConnectionResetError:
        return {"ok": False, "fail": "rst"}
    except OSError:
        return {"ok": False, "fail": "connect"}


def _probe_direct(domain: str, timeout: float) -> dict:
    try:
        sock = socket.create_connection((domain, 443), timeout=timeout)
    except (socket.timeout, socket.gaierror, OSError) as e:
        reason = "dns" if isinstance(e, socket.gaierror) else "timeout"
        return {"ok": False, "fail": reason}
    try:
        return _tls_probe(sock, domain, timeout)
    finally:
        sock.close()


def _probe_via_socks5(domain: str, proxy_port: int, timeout: float) -> dict:
    try:
        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    except OSError:
        return {"ok": False, "fail": "proxy_down"}
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        if len(resp) != 2 or resp[1] != 0:
            return {"ok": False, "fail": "proxy"}
        d = domain.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + struct.pack(">H", 443))
        rep = sock.recv(10)
        if len(rep) < 2:
            return {"ok": False, "fail": "proxy"}
        if rep[1] != 0:
            return {"ok": False, "fail": "connect"}
        return _tls_probe(sock, domain, timeout)
    except (socket.timeout, ConnectionResetError, OSError):
        return {"ok": False, "fail": "timeout"}
    finally:
        sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Route registration
# ─────────────────────────────────────────────────────────────────────────────

def register_bypass_routes(app, ctx):
    state = ctx["state"]
    push_log = ctx["push_log"]
    save_config = ctx["save_config"]
    ncp_binary = ctx["ncp_binary"]
    config_dir = Path(ctx["config_dir"])

    autohl_path = config_dir / "autohostlist.txt"
    detector_log = config_dir / "detector_events.jsonl"

    # ── proxy control ────────────────────────────────────────────────────

    def _proxy_args(cfg):
        args = [ncp_binary, "proxy",
                "--port", str(cfg.get("proxy_port", 1080)),
                "--bind", "127.0.0.1",
                "--autohostlist", str(autohl_path),
                "--detector-log", str(detector_log)]
        if cfg.get("proxy_doh", True):
            args.append("--doh")
        if cfg.get("proxy_block_quic", False):
            args.append("--block-quic")
        fq = int(cfg.get("proxy_fake_quic", 0) or 0)
        if fq > 0:
            args += ["--fake-quic", str(fq)]
        strat = cfg.get("proxy_strategy") or {}
        stype = strat.get("type")
        if stype == "dpi_config":
            if strat.get("enable_multi_layer_split") and strat.get("split_positions"):
                args += ["--multisplit", ",".join(str(p) for p in strat["split_positions"])]
                if strat.get("split_at_sni"):
                    args.append("--split-sni")
            elif strat.get("split_at_sni") and not strat.get("enable_tcp_split"):
                args.append("--split-sni")
            elif strat.get("enable_tcp_split") and strat.get("split_position"):
                args += ["--split-pos", str(strat["split_position"])]
                if strat.get("split_at_sni"):
                    args.append("--split-sni")
        elif stype == "zapret_chain" and strat.get("chain_cmdline"):
            args += ["--chain", strat["chain_cmdline"]]
        return args

    @app.route("/api/proxy/start", methods=["POST"])
    def api_proxy_start():
        global _proxy_proc
        with _proxy_lock:
            if _proxy_proc and _proxy_proc.poll() is None:
                return jsonify({"ok": False, "error": "Прокси уже запущен"}), 409
            cfg = state["config"]
            args = _proxy_args(cfg)
            try:
                _proxy_proc = subprocess.Popen(
                    args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    cwd=str(Path(ncp_binary).parent))
            except Exception as e:
                push_log("ERROR", f"Proxy start failed: {e}")
                return jsonify({"ok": False, "error": str(e)}), 500
            push_log("INFO", f"Desync proxy started on 127.0.0.1:{cfg.get('proxy_port', 1080)} (PID {_proxy_proc.pid})")
        return jsonify({"ok": True, "pid": _proxy_proc.pid,
                        "port": state["config"].get("proxy_port", 1080)})

    @app.route("/api/proxy/stop", methods=["POST"])
    def api_proxy_stop():
        global _proxy_proc
        with _proxy_lock:
            if not _proxy_proc or _proxy_proc.poll() is not None:
                return jsonify({"ok": False, "error": "Прокси не запущен"}), 409
            _proxy_proc.terminate()
            try:
                _proxy_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _proxy_proc.kill()
            push_log("INFO", "Desync proxy stopped")
        return jsonify({"ok": True})

    @app.route("/api/proxy/status")
    def api_proxy_status():
        running = bool(_proxy_proc and _proxy_proc.poll() is None)
        cfg = state["config"]
        autohl_size = 0
        if autohl_path.exists():
            try:
                autohl_size = sum(1 for line in autohl_path.read_text().splitlines()
                                  if line.strip() and not line.startswith("#"))
            except Exception:
                pass
        return jsonify({
            "running": running,
            "port": cfg.get("proxy_port", 1080),
            "doh": cfg.get("proxy_doh", True),
            "block_quic": cfg.get("proxy_block_quic", False),
            "fake_quic": cfg.get("proxy_fake_quic", 0),
            "strategy": cfg.get("proxy_strategy"),
            "autohostlist_size": autohl_size,
        })

    @app.route("/api/proxy/config", methods=["POST"])
    def api_proxy_config():
        body = request.get_json(force=True) or {}
        cfg = state["config"]
        for key in ("proxy_port", "proxy_doh", "proxy_block_quic", "proxy_fake_quic"):
            if key in body:
                cfg[key] = body[key]
        save_config(cfg)
        return jsonify({"ok": True})

    # ── blockcheck ───────────────────────────────────────────────────────

    def _run_blockcheck(domains, timeout_ms):
        global _blockcheck
        out_path = config_dir / "blockcheck_report.json"
        args = [ncp_binary, "blockcheck", "--json",
                "--timeout", str(timeout_ms),
                "--out", str(out_path)]
        if domains:
            args += ["--domains", ",".join(domains)]
        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  timeout=max(180, timeout_ms * 40 // 1000))
            report = None
            if out_path.exists():
                try:
                    report = json.loads(out_path.read_text())
                except Exception:
                    pass
            if report is None and proc.stdout.strip().startswith("{"):
                report = json.loads(proc.stdout)
            with _blockcheck_lock:
                _blockcheck["report"] = report
                _blockcheck["error"] = None if report else (proc.stderr or proc.stdout)[-500:]
        except Exception as e:
            with _blockcheck_lock:
                _blockcheck["error"] = str(e)
        finally:
            with _blockcheck_lock:
                _blockcheck["running"] = False

    @app.route("/api/blockcheck/start", methods=["POST"])
    def api_blockcheck_start():
        with _blockcheck_lock:
            if _blockcheck["running"]:
                return jsonify({"ok": False, "error": "Подбор уже выполняется"}), 409
            body = request.get_json(force=True) or {}
            domains = body.get("domains") or []
            timeout_ms = int(body.get("timeout_ms", 4000))
            _blockcheck["running"] = True
            _blockcheck["started"] = time.time()
            _blockcheck["report"] = None
            _blockcheck["error"] = None
        push_log("INFO", "Blockcheck started (auto strategy selection)")
        threading.Thread(target=_run_blockcheck, args=(domains, timeout_ms),
                         daemon=True).start()
        return jsonify({"ok": True})

    @app.route("/api/blockcheck/status")
    def api_blockcheck_status():
        with _blockcheck_lock:
            return jsonify({
                "running": _blockcheck["running"],
                "elapsed": round(time.time() - _blockcheck["started"], 1)
                           if _blockcheck["started"] else 0,
                "report": _blockcheck["report"],
                "error": _blockcheck["error"],
            })

    @app.route("/api/blockcheck/apply", methods=["POST"])
    def api_blockcheck_apply():
        body = request.get_json(force=True) or {}
        strategy = body.get("strategy")
        if not strategy:
            return jsonify({"ok": False, "error": "no strategy"}), 400
        state["config"]["proxy_strategy"] = strategy
        save_config(state["config"])
        push_log("INFO", f"Strategy applied: {strategy.get('strategy', '?')}")
        return jsonify({"ok": True, "strategy": strategy})

    # ── availability checker ─────────────────────────────────────────────

    @app.route("/api/availability")
    def api_availability():
        timeout = float(request.args.get("timeout", 5))
        proxy_running = bool(_proxy_proc and _proxy_proc.poll() is None)
        proxy_port = int(state["config"].get("proxy_port", 1080))
        results = []

        def check(name, domain):
            direct = _probe_direct(domain, timeout)
            entry = {"name": name, "domain": domain, "direct": direct}
            if proxy_running:
                entry["via_proxy"] = _probe_via_socks5(domain, proxy_port, timeout)
            results.append(entry)

        threads = [threading.Thread(target=check, args=(n, d)) for n, d in CHECK_SITES]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout * 2 + 2)
        return jsonify({"sites": results, "proxy_running": proxy_running})

    # ── hostlists ────────────────────────────────────────────────────────

    @app.route("/api/hostlist")
    def api_hostlist_get():
        entries = []
        if autohl_path.exists():
            entries = [l.strip() for l in autohl_path.read_text().splitlines()
                       if l.strip() and not l.startswith("#")]
        return jsonify({"entries": entries, "path": str(autohl_path)})

    @app.route("/api/hostlist/add", methods=["POST"])
    def api_hostlist_add():
        body = request.get_json(force=True) or {}
        host = (body.get("host") or "").strip().lower()
        if not host:
            return jsonify({"ok": False, "error": "empty host"}), 400
        existing = set()
        if autohl_path.exists():
            existing = {l.strip() for l in autohl_path.read_text().splitlines()}
        if host in existing:
            return jsonify({"ok": True, "added": False})
        with open(autohl_path, "a") as f:
            f.write(host + "\n")
        return jsonify({"ok": True, "added": True})

    @app.route("/api/hostlist/remove", methods=["POST"])
    def api_hostlist_remove():
        body = request.get_json(force=True) or {}
        host = (body.get("host") or "").strip().lower()
        if not autohl_path.exists():
            return jsonify({"ok": True, "removed": False})
        lines = [l for l in autohl_path.read_text().splitlines()
                 if l.strip() and l.strip() != host]
        autohl_path.write_text("\n".join(lines) + ("\n" if lines else ""))
        return jsonify({"ok": True, "removed": True})

    @app.route("/api/hostlist/clear", methods=["POST"])
    def api_hostlist_clear():
        autohl_path.write_text("")
        push_log("INFO", "Auto-hostlist cleared")
        return jsonify({"ok": True})

    # ── zapret import ────────────────────────────────────────────────────

    @app.route("/api/zapret/import", methods=["POST"])
    def api_zapret_import():
        body = request.get_json(force=True) or {}
        zargs = (body.get("args") or "").strip()
        if not zargs:
            return jsonify({"ok": False, "error": "empty args"}), 400
        try:
            proc = subprocess.run([ncp_binary, "import-zapret", "--args", zargs],
                                  capture_output=True, text=True, timeout=15)
            out = proc.stdout
            # JSON is printed first; trailing status line follows
            depth = 0
            end = -1
            start = out.find("{")
            for i in range(start, len(out)):
                if out[i] == "{":
                    depth += 1
                elif out[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if start < 0 or end < 0:
                return jsonify({"ok": False, "error": "parse failed",
                                "raw": out[-300:]}), 500
            parsed = json.loads(out[start:end + 1])
            return jsonify({"ok": True, "profile": parsed})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.route("/api/zapret/apply", methods=["POST"])
    def api_zapret_apply():
        body = request.get_json(force=True) or {}
        chain_cmdline = (body.get("chain_cmdline") or "").strip()
        if not chain_cmdline:
            return jsonify({"ok": False, "error": "empty chain"}), 400
        state["config"]["proxy_strategy"] = {
            "type": "zapret_chain",
            "strategy": body.get("name", "zapret-import"),
            "chain_cmdline": chain_cmdline,
        }
        save_config(state["config"])
        push_log("INFO", "Imported zapret strategy applied to proxy")
        return jsonify({"ok": True})

    # ── DPI detector events ──────────────────────────────────────────────

    @app.route("/api/detector/events")
    def api_detector_events():
        limit = int(request.args.get("limit", 50))
        events = []
        if detector_log.exists():
            try:
                lines = detector_log.read_text().splitlines()[-limit:]
                for line in lines:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        pass
            except Exception:
                pass
        return jsonify({"events": events})

    # ── autostart ────────────────────────────────────────────────────────

    def _autostart_get():
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     r"Software\Microsoft\Windows\CurrentVersion\Run")
                try:
                    val, _ = winreg.QueryValueEx(key, "NCP")
                    return True, val
                except FileNotFoundError:
                    return False, ""
                finally:
                    winreg.CloseKey(key)
            except Exception:
                return False, ""
        else:
            desktop = Path.home() / ".config" / "autostart" / "ncp.desktop"
            return desktop.exists(), str(desktop)

    @app.route("/api/autostart", methods=["GET", "POST"])
    def api_autostart():
        if request.method == "GET":
            enabled, val = _autostart_get()
            return jsonify({"enabled": enabled, "value": val})
        body = request.get_json(force=True) or {}
        enable = bool(body.get("enabled"))
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     r"Software\Microsoft\Windows\CurrentVersion\Run",
                                     0, winreg.KEY_SET_VALUE)
                try:
                    if enable:
                        import sys
                        winreg.SetValueEx(key, "NCP", 0, winreg.REG_SZ,
                                          f'"{sys.executable}"')
                    else:
                        try:
                            winreg.DeleteValue(key, "NCP")
                        except FileNotFoundError:
                            pass
                finally:
                    winreg.CloseKey(key)
                return jsonify({"ok": True, "enabled": enable})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500
        else:
            desktop = Path.home() / ".config" / "autostart" / "ncp.desktop"
            try:
                if enable:
                    import sys
                    desktop.parent.mkdir(parents=True, exist_ok=True)
                    desktop.write_text(
                        "[Desktop Entry]\nType=Application\nName=NCP\n"
                        f"Exec={sys.executable} {Path(__file__).parent / 'server.py'}\n"
                        "X-GNOME-Autostart-enabled=true\n")
                elif desktop.exists():
                    desktop.unlink()
                return jsonify({"ok": True, "enabled": enable})
            except Exception as e:
                return jsonify({"ok": False, "error": str(e)}), 500

    # ── auto-update ──────────────────────────────────────────────────────

    @app.route("/api/update/check")
    def api_update_check():
        try:
            import ncp_update
            info = ncp_update.check_for_update()
            return jsonify({"ok": True, **info})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.route("/api/update/install", methods=["POST"])
    def api_update_install():
        try:
            import ncp_update
            result = ncp_update.download_and_install()
            return jsonify(result)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
