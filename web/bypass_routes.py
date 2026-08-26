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
import re
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

# ─────────────────────────────────────────────────────────────────────────────
# System-proxy safety net (v1.5.5)
#
# The engine restores Windows system-proxy settings only on GRACEFUL exit.
# The web layer kills the engine/proxy with TerminateProcess (proc.terminate()),
# so that cleanup never ran: ProxyEnable=1 stayed pointing at a dead
# 127.0.0.1:<port> and the user lost internet every time NCP was stopped.
# These helpers restore the settings from the web side no matter how the
# engine died, and refuse to enable the system proxy when it cannot work.
# ─────────────────────────────────────────────────────────────────────────────

def _win_inet_notify():
    """Tell Windows the proxy settings changed (same as engine's win_inet_notify)."""
    if os.name != "nt":
        return
    try:
        import ctypes
        wininet = ctypes.windll.wininet
        # INTERNET_OPTION_SETTINGS_CHANGED = 39, INTERNET_OPTION_REFRESH = 37
        wininet.InternetSetOptionW(0, 39, 0, 0)
        wininet.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


def _read_win_proxy():
    """Return (ProxyEnable, ProxyServer) from HKCU Internet Settings."""
    if os.name != "nt":
        return None, None
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        try:
            enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
        except OSError:
            enabled = 0
        try:
            server = winreg.QueryValueEx(key, "ProxyServer")[0]
        except OSError:
            server = ""
        winreg.CloseKey(key)
        return enabled, server or ""
    except Exception:
        return None, None


def _winreg_clear_proxy(port: int) -> bool:
    """Fallback: clear ProxyEnable when it points at OUR local proxy port.

    Never touches settings that point anywhere else."""
    if os.name != "nt":
        return False
    try:
        enabled, server = _read_win_proxy()
        if not enabled:
            return False
        m = re.fullmatch(r"127\.0\.0\.1:(\d+)", (server or "").strip())
        if not m or int(m.group(1)) != int(port):
            return False
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        _win_inet_notify()
        return True
    except Exception:
        return False


def restore_system_proxy(ncp_binary: str, port: int = 1080, log=None) -> bool:
    """Restore Windows system proxy after the desync proxy stops.

    Preferred path: `ncp sysproxy off` (the engine keeps a saved-settings state
    file and restores ProxyServer/ProxyOverride exactly). Fallback: clear
    ProxyEnable via winreg when it points at our own 127.0.0.1:<port>.
    No-op on non-Windows or when the current proxy settings are not ours.
    """
    if os.name != "nt":
        return False
    restored = False
    try:
        enabled, server = _read_win_proxy()
        ours = bool(enabled) and bool(
            re.fullmatch(r"127\.0\.0\.1:(\d+)", (server or "").strip()))
        if not ours:
            return False
        if ncp_binary and Path(ncp_binary).exists():
            try:
                subprocess.run([ncp_binary, "sysproxy", "off"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=10, cwd=str(Path(ncp_binary).parent))
                enabled2, _srv = _read_win_proxy()
                restored = not enabled2
            except Exception:
                restored = False
        if not restored:
            restored = _winreg_clear_proxy(port)
        if restored and log:
            log("INFO", "Системный прокси Windows восстановлен — интернет снова работает напрямую")
        elif not restored and log:
            log("WARN", "Не удалось автоматически отключить системный прокси Windows. "
                        "Откройте Параметры → Сеть и интернет → Прокси и выключите "
                        "«Использовать прокси-сервер».")
    except Exception:
        pass
    return restored


def ensure_proxy_stopped(ncp_binary: str, port: int = 1080, log=None):
    """Kill the desync proxy if it is running, then restore the system proxy.

    Called from /api/stop and via atexit — the app must never leave Windows
    pointing at a dead local proxy."""
    global _proxy_proc
    try:
        with _proxy_lock:
            proc = _proxy_proc
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            _proxy_proc = None
    except Exception:
        pass
    restore_system_proxy(ncp_binary, port, log=log)


def heal_stale_system_proxy(ncp_binary: str, port: int = 1080, log=None) -> bool:
    """Startup heal: a previous crash/kill may have left ProxyEnable=1 pointing
    at our dead local proxy. Restore it before the user notices dead internet."""
    if os.name != "nt":
        return False
    try:
        enabled, server = _read_win_proxy()
        m = re.fullmatch(r"127\.0\.0\.1:(\d+)", (server or "").strip())
        if not enabled or not m:
            return False
        with _proxy_lock:
            alive = bool(_proxy_proc and _proxy_proc.poll() is None)
        if alive:
            return False  # proxy is actually running — leave the settings alone
        if log:
            log("WARN", "Обнаружен «застывший» системный прокси от прошлого запуска "
                        f"(127.0.0.1:{m.group(1)}) — восстанавливаю настройки Windows…")
        return restore_system_proxy(ncp_binary, port, log=log)
    except Exception:
        return False


def _doh_preflight(timeout: float = 2.5) -> bool:
    """True if any major DoH endpoint answers a real DNS wire query.

    Enabling the Windows system proxy while every DoH endpoint is blocked would
    instantly kill the user's internet (all browser traffic routed into a proxy
    that cannot resolve anything). Hand-built DNS wire query — stdlib only."""
    import base64
    import ssl
    import urllib.request
    # DNS query: example.com IN A (12-byte header + qname + qtype/qclass)
    query = (bytes.fromhex("000001000001000000000000")
             + b"\x07example\x03com\x00" + bytes.fromhex("00010001"))
    b64 = base64.urlsafe_b64encode(query).rstrip(b"=").decode("ascii")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # connectivity preflight, not identity check
    for host in ("1.1.1.1", "1.0.0.1", "9.9.9.9", "77.88.8.8"):
        try:
            req = urllib.request.Request(
                f"https://{host}/dns-query?dns={b64}",
                headers={"accept": "application/dns-message"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200 and len(resp.read(64)) > 12:
                    return True
        except Exception:
            continue
    return False


_blockcheck = {
    "running": False,
    "started": 0.0,
    "report": None,
    "error": None,
}
_blockcheck_lock = threading.Lock()

_ap_learn = {
    "running": False,
    "domain": None,
    "result": None,
    "error": None,
}
_ap_learn_lock = threading.Lock()

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
    def _engine_ok():
        try:
            return bool(ncp_binary) and Path(ncp_binary).exists()
        except Exception:
            return False

    def _engine_missing_response():
        return jsonify({"ok": False, "engine_missing": True,
                        "error": "Движок ncp не найден. Веб-интерфейс работает, "
                                 "но для этой функции нужен собранный бинарник ncp "
                                 "(ncp.exe рядом с ncp-gui.exe или build/ncp)."}), 503

    config_dir = Path(ctx["config_dir"])

    autohl_path = config_dir / "autohostlist.txt"
    detector_log = config_dir / "detector_events.jsonl"
    events_log = config_dir / "proxy_events.jsonl"
    stats_file = config_dir / "proxy_stats.json"

    def _autopilot_db_path() -> Path:
        """Mirror AutoPilot::default_db_path() from the C++ core."""
        if platform.system() == "Windows":
            appdata = os.environ.get("APPDATA")
            if appdata:
                return Path(appdata) / "ncp" / "autopilot.json"
            return Path("autopilot.json")
        home = os.environ.get("HOME")
        if home:
            return Path(home) / ".ncp" / "autopilot.json"
        return Path("autopilot.json")

    # ── proxy control ────────────────────────────────────────────────────

    def _proxy_args(cfg):
        args = [ncp_binary, "proxy",
                "--port", str(cfg.get("proxy_port", 1080)),
                "--bind", "127.0.0.1",
                "--autohostlist", str(autohl_path),
                "--detector-log", str(detector_log),
                "--events-log", str(events_log),
                "--stats-file", str(stats_file)]
        if cfg.get("proxy_doh", True):
            args.append("--doh")
        if cfg.get("proxy_autopilot", True):
            args.append("--autopilot")
        if cfg.get("proxy_system_wide"):
            args.append("--system-proxy")
        tb = (cfg.get("tor_binary") or "").strip()
        if tb:
            args += ["--tor-exec", tb]
            for line in (cfg.get("tor_bridges") or "").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    args += ["--tor-bridge", line]
            if (cfg.get("pt_obfs4") or "").strip():
                args += ["--pt-obfs4", cfg["pt_obfs4"].strip()]
            if (cfg.get("pt_snowflake") or "").strip():
                args += ["--pt-snowflake", cfg["pt_snowflake"].strip()]
        up = (cfg.get("proxy_upstream") or "").strip()
        if up and not tb:
            args += ["--upstream", up]
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
        if not _engine_ok():
            return _engine_missing_response()
        global _proxy_proc
        with _proxy_lock:
            if _proxy_proc and _proxy_proc.poll() is None:
                return jsonify({"ok": False, "error": "Прокси уже запущен"}), 409
            cfg = state["config"]
            # v1.5.5: never enable the Windows system proxy when every DoH
            # endpoint is unreachable — the proxy would be unable to resolve
            # anything and all browser traffic would die (the exact
            # "proxy breaks my internet" scenario users reported).
            if cfg.get("proxy_system_wide") and os.name == "nt" and cfg.get("proxy_doh", True):
                if not _doh_preflight():
                    push_log("WARN", "Системный прокси НЕ включён: DoH недоступен "
                                     "(DNS/TLS заблокированы) — прокси сломал бы интернет. "
                                     "Сначала подберите рабочую стратегию (Автопилот/Blockcheck).")
                    return jsonify({"ok": False, "doh_blocked": True,
                                    "error": "Системный прокси не включён: DoH (запасной DNS) "
                                             "недоступен — прокси сломал бы вам интернет. Сначала "
                                             "подберите рабочую стратегию в разделе «Автопилот» или "
                                             "«Blockcheck», затем запускайте прокси."}), 503
            args = _proxy_args(cfg)
            # fresh event stream per proxy run (bounded growth)
            try:
                events_log.write_text("")
            except Exception:
                pass
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
        restore_system_proxy(ncp_binary,
                             int(state["config"].get("proxy_port", 1080) or 1080),
                             log=push_log)
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
            "system_wide": cfg.get("proxy_system_wide", False),
            "upstream": cfg.get("proxy_upstream", ""),
            "tor_binary": cfg.get("tor_binary", ""),
            "tor_bridges": cfg.get("tor_bridges", ""),
            "pt_obfs4": cfg.get("pt_obfs4", ""),
            "pt_snowflake": cfg.get("pt_snowflake", ""),
            "fake_quic": cfg.get("proxy_fake_quic", 0),
            "strategy": cfg.get("proxy_strategy"),
            "autohostlist_size": autohl_size,
        })

    @app.route("/api/proxy/config", methods=["POST"])
    def api_proxy_config():
        body = request.get_json(force=True) or {}
        cfg = state["config"]
        for key in ("proxy_port", "proxy_doh", "proxy_block_quic", "proxy_fake_quic",
                    "proxy_system_wide",
                    "proxy_upstream",
                    "tor_binary", "tor_bridges", "pt_obfs4", "pt_snowflake",
                    "proxy_autopilot"):
            if key in body:
                cfg[key] = body[key]
        save_config(cfg)
        return jsonify({"ok": True})

    def _leak_fetch(eh, ep, epth, socks_port=0, timeout=6):
        # Minimal HTTP GET, optionally via local SOCKS5 (domain-form CONNECT,
        # so the proxy/upstream resolves — mirroring real proxied DNS path).
        if socks_port:
            s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
            s.sendall(b"\x05\x01\x00")
            r = s.recv(2)
            if len(r) != 2 or r[0] != 5 or r[1] != 0:
                s.close(); raise IOError("socks5_greeting")
            hb = eh.encode()
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", ep))
            hdr = s.recv(4)
            if len(hdr) < 4 or hdr[1] != 0:
                s.close(); raise IOError("socks5_connect_%d" % (hdr[1] if len(hdr) > 1 else -1))
            atyp = hdr[3]
            if atyp == 1: s.recv(4)
            elif atyp == 3:
                ln = s.recv(1)[0]; s.recv(ln)
            elif atyp == 4: s.recv(16)
            s.recv(2)
        else:
            s = socket.create_connection((eh, ep), timeout=timeout)
        try:
            req = ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                   % (epth, eh)).encode()
            s.sendall(req)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
        body = data.split(b"\r\n\r\n", 1)[-1]
        return body.decode(errors="replace").strip()

    @app.route("/api/proxy/leak-test", methods=["POST"])
    def api_proxy_leak_test():
        # Compares the IP seen directly vs through the proxy — visible proof
        # that the chain actually hides the user (or an honest leak verdict).
        body = request.get_json(force=True) or {}
        cfg = state["config"]
        echo_url = body.get("echo_url") or "http://api.ipify.org/"
        m = re.match(r"^http://([^:/]+)(?::(\d+))?(/\S*)?$", echo_url)
        if not m:
            return jsonify({"ok": False, "error": "bad_echo_url"})
        eh, ep, epth = m.group(1), int(m.group(2) or 80), m.group(3) or "/"
        running = bool(_proxy_proc and _proxy_proc.poll() is None)
        res = {"ok": True, "proxy_running": running,
               "doh": bool(cfg.get("proxy_doh", True)),
               "upstream": cfg.get("proxy_upstream", ""),
               "tor_managed": bool((cfg.get("tor_binary") or "").strip())}
        try:
            res["direct_ip"] = _leak_fetch(eh, ep, epth)
        except Exception as e:
            res["direct_ip"] = None
            res["direct_error"] = str(e) or type(e).__name__
        if running:
            try:
                res["proxied_ip"] = _leak_fetch(
                    eh, ep, epth, socks_port=int(cfg.get("proxy_port", 1080)))
            except Exception as e:
                res["proxied_ip"] = None
                res["proxied_error"] = str(e) or type(e).__name__
        else:
            res["proxied_ip"] = None
        d, p = res.get("direct_ip"), res.get("proxied_ip")
        if p and d and p != d:
            res["verdict"] = "hidden"
        elif p and d and p == d:
            res["verdict"] = "leak"
        elif p and not d:
            res["verdict"] = "proxied_only"
        elif running and not p:
            res["verdict"] = "proxy_error"
        else:
            res["verdict"] = "proxy_off"
        return jsonify(res)

    @app.route("/api/proxy/upstream-probe", methods=["POST"])
    def api_proxy_upstream_probe():
        # TCP-probe the upstream proxy (Tor etc.) - no system changes.
        body = request.get_json(force=True) or {}
        url = (body.get("upstream") or state["config"].get("proxy_upstream") or "").strip()
        m = re.match(r"^(socks5|socks|http)://([^:/]+):(\d+)$", url)
        if not m:
            return jsonify({"ok": False, "error": "no_upstream"})
        host, port = m.group(2), int(m.group(3))
        t0 = time.time()
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                latency = int((time.time() - t0) * 1000)
                if m.group(1) in ("socks5", "socks"):
                    s.sendall(b"\x05\x01\x00")
                    resp = s.recv(2)
                    ok = len(resp) == 2 and resp[0] == 5
                else:
                    ok = True
            return jsonify({"ok": bool(ok), "latency_ms": latency,
                            "tor": port in (9050, 9150)})
        except Exception as e:
            return jsonify({"ok": False, "error": type(e).__name__})

    # ── live monitor (events JSONL + stats file emitted by the proxy) ────

    @app.route("/api/monitor/stats")
    def api_monitor_stats():
        running = bool(_proxy_proc and _proxy_proc.poll() is None)
        stats = None
        try:
            if stats_file.exists():
                stats = json.loads(stats_file.read_text().strip())
        except Exception:
            stats = None
        return jsonify({
            "running": running,
            "stats": stats,
            "autopilot_enabled": _read_autopilot_db()[0].get("enabled", False),
        })

    def _read_autopilot_db():
        """Returns (db_dict, records_list). Missing/corrupt → empty."""
        try:
            p = _autopilot_db_path()
            if p.exists():
                db = json.loads(p.read_text())
                recs = db.get("records", {}) or {}
                return db, recs
        except Exception:
            pass
        return {}, {}

    @app.route("/api/monitor/events")
    def api_monitor_events():
        # Incremental tail: ?since=<byte offset>. Resets when the file shrank
        # (proxy restart truncates the log).
        try:
            since = int(request.args.get("since", "0"))
        except ValueError:
            since = 0
        events = []
        offset = 0
        try:
            size = events_log.stat().st_size if events_log.exists() else 0
            if since < 0 or since > size:
                since = 0
            offset = since
            if events_log.exists() and size > since:
                with open(events_log, "rb") as f:
                    f.seek(since)
                    chunk = f.read()
                offset = size
                for raw in chunk.decode("utf-8", errors="replace").splitlines():
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        events.append(json.loads(raw))
                    except Exception:
                        continue
        except Exception:
            pass
        # cap payload: newest 200 events
        if len(events) > 200:
            events = events[-200:]
        return jsonify({"events": events, "offset": offset})

    @app.route("/api/monitor/autopilot")
    def api_monitor_autopilot():
        db, recs = _read_autopilot_db()
        out = []
        for host, r in recs.items():
            out.append({
                "host": host,
                "strategy": r.get("strategy", "?"),
                "successes": r.get("successes", 0),
                "failures": r.get("failures", 0),
                "consec_failures": r.get("consec_failures", 0),
                "ewma_latency_ms": r.get("ewma_latency_ms", 0),
                "degraded": bool(r.get("degraded", False)),
                "last_outcome": r.get("last_outcome", 0),
            })
        out.sort(key=lambda x: x["last_outcome"], reverse=True)
        return jsonify({
            "enabled": db.get("enabled", False),
            "records": out,
            "db_path": str(_autopilot_db_path()),
            "learn": dict(_ap_learn),
        })

    def _run_ap_learn(domain, use_doh):
        global _ap_learn
        args = [ncp_binary, "autopilot", "learn", domain, "--timeout", "6000"]
        if use_doh:
            args.append("--doh")
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=180)
            ok = "[+]" in (proc.stdout or "")
            with _ap_learn_lock:
                _ap_learn["running"] = False
                _ap_learn["result"] = (proc.stdout or proc.stderr or "").strip()[-500:]
                _ap_learn["error"] = None if ok else "no working strategy"
        except Exception as e:
            with _ap_learn_lock:
                _ap_learn["running"] = False
                _ap_learn["error"] = str(e)

    _ap_preset = {"running": False, "preset": "", "done": 0, "total": 0,
                  "line": "", "ok": None}
    _ap_preset_lock = threading.Lock()

    def _run_ap_preset(preset):
        args = [ncp_binary, "autopilot", "learn-preset", preset,
                "--doh", "--timeout", "4000"]
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            for ln in proc.stdout:
                ln = ln.strip()
                if not ln:
                    continue
                with _ap_preset_lock:
                    _ap_preset["line"] = ln
                    m = re.match(r"\[(\d+)/(\d+)\]", ln)
                    if m:
                        _ap_preset["done"] = int(m.group(1))
                        _ap_preset["total"] = int(m.group(2))
            proc.wait(timeout=1800)
            with _ap_preset_lock:
                _ap_preset["ok"] = proc.returncode == 0
        except Exception:
            with _ap_preset_lock:
                _ap_preset["ok"] = False
        finally:
            with _ap_preset_lock:
                _ap_preset["running"] = False

    @app.route("/api/monitor/autopilot/learn-preset", methods=["GET", "POST"])
    def api_monitor_autopilot_learn_preset():
        if not _engine_ok():
            return _engine_missing_response()
        if request.method == "GET":
            with _ap_preset_lock:
                return jsonify(dict(_ap_preset))
        body = request.get_json(force=True) or {}
        preset = (body.get("preset") or "").strip().lower()
        if preset not in ("discord", "youtube", "x"):
            return jsonify({"ok": False, "error": "unknown preset"}), 400
        with _ap_preset_lock:
            if _ap_preset["running"]:
                return jsonify({"ok": False, "error": "busy"}), 409
            _ap_preset.update({"running": True, "preset": preset, "done": 0,
                               "total": 0, "line": "", "ok": None})
        threading.Thread(target=_run_ap_preset, args=(preset,),
                         daemon=True).start()
        return jsonify({"ok": True, "preset": preset})

    @app.route("/api/monitor/autopilot/learn", methods=["POST"])
    def api_monitor_autopilot_learn():
        if not _engine_ok():
            return _engine_missing_response()
        body = request.get_json(force=True) or {}
        domain = (body.get("domain") or "").strip().lower()
        if not domain or " " in domain or "/" in domain:
            return jsonify({"ok": False, "error": "Некорректный домен"}), 400
        with _ap_learn_lock:
            if _ap_learn["running"]:
                return jsonify({"ok": False, "error": "Обучение уже идёт"}), 409
            _ap_learn.update({"running": True, "domain": domain,
                              "result": None, "error": None})
        use_doh = bool(state["config"].get("proxy_doh", True))
        threading.Thread(target=_run_ap_learn, args=(domain, use_doh),
                         daemon=True).start()
        push_log("INFO", f"AutoPilot: learning {domain}…")
        return jsonify({"ok": True})

    @app.route("/api/monitor/autopilot/reset", methods=["POST"])
    def api_monitor_autopilot_reset():
        if not _engine_ok():
            return _engine_missing_response()
        body = request.get_json(force=True) or {}
        domain = (body.get("domain") or "").strip().lower()
        args = [ncp_binary, "autopilot", "reset"] + ([domain] if domain else [])
        try:
            subprocess.run(args, capture_output=True, timeout=15)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
        push_log("INFO", f"AutoPilot DB reset: {domain or 'all'}")
        return jsonify({"ok": True})

    @app.route("/api/monitor/autopilot/enabled", methods=["POST"])
    def api_monitor_autopilot_enabled():
        if not _engine_ok():
            return _engine_missing_response()
        body = request.get_json(force=True) or {}
        enabled = bool(body.get("enabled"))
        try:
            subprocess.run([ncp_binary, "autopilot",
                            "enable" if enabled else "disable"],
                           capture_output=True, timeout=15)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500
        # also persist as proxy default
        cfg = state["config"]
        cfg["proxy_autopilot"] = enabled
        save_config(cfg)
        return jsonify({"ok": True, "enabled": enabled})

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
                                  timeout=max(600, timeout_ms * 150 // 1000))
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
        except subprocess.TimeoutExpired:
            with _blockcheck_lock:
                _blockcheck["error"] = ("blockcheck не уложился во время - обычно это значит, "
                                        "что сейчас не работает DNS или интернет. "
                                        "Запустите самотест и проверьте DNS.")
        except Exception as e:
            with _blockcheck_lock:
                _blockcheck["error"] = str(e)
        finally:
            with _blockcheck_lock:
                _blockcheck["running"] = False

    @app.route("/api/blockcheck/start", methods=["POST"])
    def api_blockcheck_start():
        if not _engine_ok():
            return _engine_missing_response()
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
        if not _engine_ok():
            return _engine_missing_response()
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
        if not _engine_ok():
            return _engine_missing_response()
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
