# -*- coding: utf-8 -*-
"""
NCP Enterprise routes — SPA, Reality fallback, Stego-DNS, Port-Hopping,
Fog mesh, XDP/eBPF diagnostics.

Registered from server.py via register_enterprise_routes(app, ctx).
ctx keys (same as bypass_routes):
    state          – global state dict (with "config")
    push_log       – fn(level, msg)
    save_config    – fn(cfg)
    ncp_binary     – str path to ncp binary
    config_dir     – Path to config directory
    require_license – fn(module_name) -> (response, code) | None

Security notes:
    * All input is validated with strict regexes before reaching subprocess.
    * subprocess is always called with an argument list — never a shell.
    * Secrets (passphrases, private keys, porthop secret) are never logged,
      never written to config.json and never returned by status endpoints.
      Key material that the CLI requires as a file is written to a dedicated
      file under config_dir with 0600 permissions.
"""

import re
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

from flask import jsonify, request

# ─────────────────────────────────────────────────────────────────────────────
# Input validation
# ─────────────────────────────────────────────────────────────────────────────

_RE_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_RE_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9_]([a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9_])?"
    r"(\.[a-zA-Z0-9_]([a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9_])?)*\.?$")
_RE_B64 = re.compile(r"^[A-Za-z0-9+/]{1,512}={0,2}$")
_RE_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_RE_SESSION_ID = re.compile(r"^(0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$")


def _valid_ipv4(s):
    m = _RE_IPV4.match(s or "")
    return bool(m) and all(int(g) <= 255 for g in m.groups())


def _valid_host(s):
    """Hostname or IPv4 address."""
    return bool(s) and (_valid_ipv4(s) or bool(_RE_HOSTNAME.match(s)))


def _valid_port(v, lo=1, hi=65535):
    try:
        p = int(v)
    except (TypeError, ValueError):
        return False
    return lo <= p <= hi


def _split_host_port(s):
    """'host:port' -> (host, port) or None. Strictly validated."""
    if not s or not isinstance(s, str) or s.count(":") != 1:
        return None
    host, _, port_s = s.rpartition(":")
    if not _valid_host(host) or not _valid_port(port_s):
        return None
    return host, int(port_s)


def _bad(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


# ─────────────────────────────────────────────────────────────────────────────
# Long-running daemon management (reality serve / spa serve / porthop serve /
# fog node) — same Popen + terminate pattern as api_proxy_start, plus a
# bounded log tail captured from stdout/stderr.
# ─────────────────────────────────────────────────────────────────────────────

_daemons = {}
_daemons_lock = threading.Lock()
_LOG_TAIL = 60


class _Daemon:
    __slots__ = ("proc", "log", "params", "started")

    def __init__(self, proc, params):
        self.proc = proc
        self.log = deque(maxlen=_LOG_TAIL)
        self.params = params          # non-secret description for status UI
        self.started = time.time()

    def alive(self):
        return self.proc is not None and self.proc.poll() is None


def _log_reader(daemon):
    try:
        for line in daemon.proc.stdout:
            line = line.rstrip()
            if line:
                daemon.log.append(line[-500:])
    except Exception:
        pass


def _daemon_start(name, args, cwd, params):
    with _daemons_lock:
        cur = _daemons.get(name)
        if cur and cur.alive():
            return None, _bad("Демон уже запущен", 409)
        try:
            proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=cwd)
        except Exception as e:
            return None, _bad(f"Не удалось запустить: {e}", 500)
        d = _Daemon(proc, params)
        _daemons[name] = d
    threading.Thread(target=_log_reader, args=(d,), daemon=True).start()
    # Give the process a moment to fail fast (bad args, bind error)
    time.sleep(0.6)
    if not d.alive():
        tail = list(d.log)
        return None, _bad("Процесс завершился сразу после запуска: "
                          + (" | ".join(tail[-3:]) if tail else "нет вывода"), 500)
    return d, None


def _daemon_stop(name):
    with _daemons_lock:
        d = _daemons.get(name)
        if not d or not d.alive():
            return _bad("Демон не запущен", 409)
        d.proc.terminate()
        try:
            d.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.proc.kill()
    return None


def _daemon_status(name):
    with _daemons_lock:
        d = _daemons.get(name)
        if not d:
            return {"running": False, "pid": None, "params": {}, "log": []}
        return {
            "running": d.alive(),
            "pid": d.proc.pid if d.alive() else None,
            "uptime": int(time.time() - d.started) if d.alive() else 0,
            "params": d.params,
            "log": list(d.log)[-20:],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Route registration
# ─────────────────────────────────────────────────────────────────────────────

def register_enterprise_routes(app, ctx):
    state = ctx["state"]
    push_log = ctx["push_log"]
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
    require_license = ctx["require_license"]
    bin_dir = str(Path(ncp_binary).parent)

    def _run_once(args, timeout=20):
        """Run a short-lived CLI command, return (rc, combined_output)."""
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout, cwd=bin_dir)
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()

    def _write_secret_file(filename, content):
        """Key material required by the CLI as a file: 0600, config_dir only."""
        path = config_dir / filename
        path.write_text(content, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path

    # ═══════════════════════════════════════════════════════════════════
    # SPA — Single Packet Authorization
    # ═══════════════════════════════════════════════════════════════════

    @app.route("/api/spa/keygen", methods=["POST"])
    def api_spa_keygen():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("spa")
        if err:
            return err
        prefix = f"spa_{int(time.time())}"
        try:
            rc, out = _run_once([ncp_binary, "spa", "keygen", "--out",
                                 str(config_dir / prefix)])
        except Exception as e:
            return _bad(f"keygen failed: {e}", 500)
        key_path = config_dir / (prefix + ".key")
        if not key_path.exists():
            return _bad("keygen не создал ключевой файл: " + out[-300:], 500)
        key_id = ""
        pubkey_line = ""
        lines = out.splitlines()
        for i, ln in enumerate(lines):
            if "key_id:" in ln:
                key_id = ln.split("key_id:", 1)[1].strip()
            if "authorized_keys" in ln and i + 1 < len(lines):
                pubkey_line = lines[i + 1].strip()
        key_content = ""
        try:
            key_content = key_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass
        push_log("INFO", f"SPA keypair generated (key_id {key_id or '?'})")
        return jsonify({
            "ok": True,
            "key_id": key_id,
            "authorized_keys_line": pubkey_line,
            "key_path": str(key_path),
            "key_content": key_content,
            "output": out[-1000:],
        })

    @app.route("/api/spa/knock", methods=["POST"])
    def api_spa_knock():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("spa")
        if err:
            return err
        body = request.get_json(force=True) or {}
        host = (body.get("host") or "").strip()
        if not _valid_host(host):
            return _bad("Некорректный host")
        allow_port = body.get("allow_port")
        if not _valid_port(allow_port):
            return _bad("Некорректный allow-port (1–65535)")
        udp_port = body.get("port", 54117)
        if not _valid_port(udp_port):
            return _bad("Некорректный порт SPA (1–65535)")
        proto = (body.get("proto") or "tcp").strip().lower()
        if proto not in ("tcp", "udp"):
            return _bad("proto должен быть tcp или udp")
        ttl = body.get("ttl", 0)
        try:
            ttl = int(ttl or 0)
        except (TypeError, ValueError):
            return _bad("Некорректный ttl")
        if ttl < 0 or ttl > 86400:
            return _bad("ttl вне диапазона (0–86400)")

        # Key material: either a server-side path from a previous keygen or
        # inline key content (written to a 0600 file, reused by knocks).
        key_path = (body.get("key_path") or "").strip()
        key_content = (body.get("key_content") or "").strip()
        if key_path:
            p = Path(key_path)
            if not p.is_file() or p.suffix != ".key":
                return _bad("Некорректный путь к ключу (.key)")
        elif key_content:
            if len(key_content) > 512 or not re.match(r"^[A-Za-z0-9+/=\s]+$", key_content):
                return _bad("Некорректное содержимое ключа")
            p = _write_secret_file("spa_client.key", key_content)
        else:
            return _bad("Укажите key_path или key_content")

        args = [ncp_binary, "spa", "knock", host, "--key", str(p),
                "--allow-port", str(int(allow_port)),
                "--port", str(int(udp_port)), "--proto", proto]
        if ttl:
            args += ["--ttl", str(ttl)]
        try:
            rc, out = _run_once(args, timeout=15)
        except subprocess.TimeoutExpired:
            return _bad("Таймаут отправки knock", 504)
        except Exception as e:
            return _bad(f"knock failed: {e}", 500)
        ok = "[+]" in out
        if ok:
            push_log("INFO", f"SPA knock sent to {host} (open {proto}/{int(allow_port)})")
        return jsonify({"ok": ok, "output": out[-1000:]}), (200 if ok else 500)

    @app.route("/api/spa/serve/start", methods=["POST"])
    def api_spa_serve_start():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("spa")
        if err:
            return err
        body = request.get_json(force=True) or {}
        keys_text = (body.get("authorized_keys") or "").strip()
        if not keys_text:
            return _bad("Вставьте authorized_keys (по одному ключу на строку)")
        if len(keys_text) > 65536:
            return _bad("Слишком большой список ключей")
        for ln in keys_text.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#") and not re.match(r"^[A-Za-z0-9+/=\s]+$", ln):
                return _bad("Недопустимые символы в authorized_keys")
        port = body.get("port", 54117)
        if not _valid_port(port):
            return _bad("Некорректный порт (1–65535)")
        bind = (body.get("bind") or "0.0.0.0").strip()
        if not _valid_ipv4(bind):
            return _bad("bind должен быть IPv4-адресом")
        default_ttl = body.get("default_ttl", 300)
        max_ttl = body.get("max_ttl", 86400)
        if not _valid_port(default_ttl, 1, 86400) or not _valid_port(max_ttl, 1, 86400 * 30):
            return _bad("Некорректный TTL")
        dry_run = bool(body.get("dry_run"))

        keys_path = config_dir / "spa_authorized_keys.txt"
        keys_path.write_text(keys_text + "\n", encoding="utf-8")

        args = [ncp_binary, "spa", "serve",
                "--authorized-keys", str(keys_path),
                "--port", str(int(port)), "--bind", bind,
                "--default-ttl", str(int(default_ttl)),
                "--max-ttl", str(int(max_ttl))]
        if dry_run:
            args.append("--dry-run")
        d, resp = _daemon_start("spa", args, bin_dir, {
            "port": int(port), "bind": bind, "dry_run": dry_run,
        })
        if resp:
            return resp
        push_log("INFO", f"SPA server started on UDP {bind}:{int(port)}"
                         + (" (dry-run)" if dry_run else ""))
        return jsonify({"ok": True, "pid": d.proc.pid})

    @app.route("/api/spa/serve/stop", methods=["POST"])
    def api_spa_serve_stop():
        err = require_license("spa")
        if err:
            return err
        resp = _daemon_stop("spa")
        if resp:
            return resp
        push_log("INFO", "SPA server stopped")
        return jsonify({"ok": True})

    @app.route("/api/spa/serve/status")
    def api_spa_serve_status():
        err = require_license("spa")
        if err:
            return err
        return jsonify(_daemon_status("spa"))

    # ═══════════════════════════════════════════════════════════════════
    # Reality — XTLS-Reality-style fallback server
    # ═══════════════════════════════════════════════════════════════════

    def _reality_args(body, dry_run):
        listen = body.get("listen", 443)
        if not _valid_port(listen):
            return None, _bad("Некорректный listen-порт (1–65535)")
        fb = _split_host_port((body.get("fallback") or "").strip())
        if not fb:
            return None, _bad("fallback должен быть в форме host:port")
        internal = _split_host_port((body.get("internal") or "").strip())
        if not internal:
            return None, _bad("internal должен быть в форме host:port")
        key_text = (body.get("key_file") or "").strip()
        if not key_text:
            return None, _bad("Вставьте содержимое key-file (key_id + base64 ключи)")
        if len(key_text) > 65536:
            return None, _bad("Слишком большой key-file")
        for ln in key_text.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#") and not re.match(r"^[A-Za-z0-9+/=\s]+$", ln):
                return None, _bad("Недопустимые символы в key-file")
        key_path = _write_secret_file("reality_clients.key", key_text)
        args = [ncp_binary, "reality", "serve",
                "--listen", str(int(listen)),
                "--fallback", f"{fb[0]}:{fb[1]}",
                "--internal", f"{internal[0]}:{internal[1]}",
                "--key-file", str(key_path)]
        if dry_run:
            args.append("--dry-run")
        return args, None

    @app.route("/api/reality/dry-run", methods=["POST"])
    def api_reality_dry_run():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("reality")
        if err:
            return err
        body = request.get_json(force=True) or {}
        args, resp = _reality_args(body, dry_run=True)
        if resp:
            return resp
        try:
            rc, out = _run_once(args)
        except Exception as e:
            return _bad(f"dry-run failed: {e}", 500)
        ok = "Dry run" in out and rc == 0
        return jsonify({"ok": ok, "output": out[-1500:]}), (200 if ok else 400)

    @app.route("/api/reality/start", methods=["POST"])
    def api_reality_start():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("reality")
        if err:
            return err
        body = request.get_json(force=True) or {}
        args, resp = _reality_args(body, dry_run=False)
        if resp:
            return resp
        d, resp = _daemon_start("reality", args, bin_dir, {
            "listen": int(body.get("listen", 443)),
            "fallback": body.get("fallback"),
            "internal": body.get("internal"),
        })
        if resp:
            return resp
        push_log("INFO", f"Reality server started on TCP :{int(body.get('listen', 443))}")
        return jsonify({"ok": True, "pid": d.proc.pid})

    @app.route("/api/reality/stop", methods=["POST"])
    def api_reality_stop():
        err = require_license("reality")
        if err:
            return err
        resp = _daemon_stop("reality")
        if resp:
            return resp
        push_log("INFO", "Reality server stopped")
        return jsonify({"ok": True})

    @app.route("/api/reality/status")
    def api_reality_status():
        err = require_license("reality")
        if err:
            return err
        return jsonify(_daemon_status("reality"))

    # ═══════════════════════════════════════════════════════════════════
    # Stego-DNS — zero-knowledge steganographic DNS records
    # ═══════════════════════════════════════════════════════════════════

    @app.route("/api/stegodns/encode", methods=["POST"])
    def api_stegodns_encode():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("stegodns")
        if err:
            return err
        body = request.get_json(force=True) or {}
        ip = (body.get("ip") or "").strip()
        if not _valid_ipv4(ip):
            return _bad("Некорректный IPv4-адрес")
        port = body.get("port")
        if not _valid_port(port):
            return _bad("Некорректный порт (1–65535)")
        spa_pub = (body.get("spa_pubkey") or "").strip()
        if not _RE_B64.match(spa_pub):
            return _bad("spa-pubkey должен быть base64 (32 байта)")
        passphrase = body.get("passphrase") or ""
        if not passphrase or len(passphrase) > 256:
            return _bad("Пустая или слишком длинная passphrase")
        domain = (body.get("domain") or "").strip().lower()
        if not _RE_HOSTNAME.match(domain):
            return _bad("Некорректный домен")
        expires = body.get("expires", 0)
        try:
            expires = int(expires or 0)
        except (TypeError, ValueError):
            return _bad("Некорректный expires")
        if expires < 0 or expires > 4102444800:
            return _bad("expires вне диапазона (unix time)")

        sk_path = (body.get("signing_key_path") or "").strip()
        sk_b64 = (body.get("signing_key") or "").strip()
        if sk_path:
            p = Path(sk_path)
            if not p.is_file():
                return _bad("Файл signing-key не найден")
        elif sk_b64:
            if not _RE_B64.match(sk_b64):
                return _bad("signing-key должен быть base64")
            p = _write_secret_file("stegodns_signing.key", sk_b64)
        else:
            return _bad("Укажите signing_key (base64) или signing_key_path")

        args = [ncp_binary, "stegodns", "encode",
                "--ip", ip, "--port", str(int(port)),
                "--spa-pubkey", spa_pub, "--passphrase", passphrase,
                "--signing-key", str(p), "--domain", domain]
        if expires:
            args += ["--expires", str(expires)]
        try:
            rc, out = _run_once(args)
        except Exception as e:
            return _bad(f"encode failed: {e}", 500)
        # First line is the TXT record, then "[*] verify-pubkey: <b64>"
        txt = ""
        verify_pubkey = ""
        for ln in out.splitlines():
            ln = ln.strip()
            if ln.startswith("[*] verify-pubkey:"):
                verify_pubkey = ln.split(":", 1)[1].strip()
            elif ln and not ln.startswith("[") and not txt:
                txt = ln
        if not txt:
            return _bad("encode не удался: " + out[-400:], 500)
        push_log("INFO", f"Stego-DNS record encoded for {domain}")
        return jsonify({"ok": True, "txt": txt, "verify_pubkey": verify_pubkey})

    @app.route("/api/stegodns/decode", methods=["POST"])
    def api_stegodns_decode():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("stegodns")
        if err:
            return err
        body = request.get_json(force=True) or {}
        txt = (body.get("txt") or "").strip()
        # Printable ASCII only — the value is passed as a single argv element
        # (no shell), and real records contain spaces/colons ("v=spf1 ip4:..").
        if not txt or len(txt) > 4096 or not re.match(r"^[\x20-\x7e]+$", txt):
            return _bad("Некорректная TXT-запись")
        passphrase = body.get("passphrase") or ""
        if not passphrase or len(passphrase) > 256:
            return _bad("Пустая или слишком длинная passphrase")
        vpk = (body.get("verify_pubkey") or "").strip()
        if not _RE_B64.match(vpk):
            return _bad("verify-pubkey должен быть base64 (32 байта)")
        try:
            rc, out = _run_once([ncp_binary, "stegodns", "decode",
                                 "--txt", txt, "--passphrase", passphrase,
                                 "--verify-pubkey", vpk])
        except Exception as e:
            return _bad(f"decode failed: {e}", 500)
        if "NodeParams" not in out:
            return jsonify({"ok": False, "error": "Запись не расшифрована "
                            "(неверная запись, подпись, passphrase или истекла)",
                            "output": out[-400:]}), 400
        params = {}
        for ln in out.splitlines():
            ln = ln.strip()
            for key in ("ip", "port", "spa_pubkey", "expires"):
                if ln.startswith(key + ":"):
                    params[key] = ln.split(":", 1)[1].strip()
        return jsonify({"ok": True, "params": params, "output": out[-1000:]})

    # ═══════════════════════════════════════════════════════════════════
    # Port-Hopping — UDP port-hopping transport
    # ═══════════════════════════════════════════════════════════════════

    def _porthop_common(body):
        """Returns (base_port, range, secret, interval, error_response)."""
        base_port = body.get("base_port")
        rng = body.get("range")
        if not _valid_port(base_port):
            return None, None, None, None, _bad("Некорректный base-port")
        try:
            rng = int(rng)
        except (TypeError, ValueError):
            return None, None, None, None, _bad("Некорректный range")
        if rng <= 0 or rng > 1000 or int(base_port) + rng > 65536:
            return None, None, None, None, _bad("range вне допустимого диапазона")
        secret = body.get("secret") or ""
        if not secret or len(secret) > 256:
            return None, None, None, None, _bad("Пустой или слишком длинный secret")
        interval = body.get("hop_interval", 60)
        try:
            interval = int(interval)
        except (TypeError, ValueError):
            return None, None, None, None, _bad("Некорректный hop-interval")
        if interval < 1 or interval > 86400:
            return None, None, None, None, _bad("hop-interval вне диапазона (1–86400)")
        return int(base_port), rng, secret, interval, None

    @app.route("/api/porthop/serve/start", methods=["POST"])
    def api_porthop_serve_start():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("porthop")
        if err:
            return err
        body = request.get_json(force=True) or {}
        base_port, rng, secret, interval, resp = _porthop_common(body)
        if resp:
            return resp
        args = [ncp_binary, "porthop", "serve",
                "--base-port", str(base_port), "--range", str(rng),
                "--secret", secret, "--hop-interval", str(interval)]
        sids = body.get("session_ids") or []
        if isinstance(sids, str):
            sids = [s.strip() for s in sids.splitlines() if s.strip()]
        for sid in sids[:16]:
            if not _RE_SESSION_ID.match(str(sid)):
                return _bad(f"Некорректный session-id: {sid}")
            args += ["--session-id", str(sid)]
        d, resp = _daemon_start("porthop", args, bin_dir, {
            "base_port": base_port, "range": rng, "hop_interval": interval,
            "sessions": len(sids) if sids else 1,
        })
        if resp:
            return resp
        push_log("INFO", f"PortHop server started on UDP [{base_port}, {base_port + rng})")
        return jsonify({"ok": True, "pid": d.proc.pid})

    @app.route("/api/porthop/serve/stop", methods=["POST"])
    def api_porthop_serve_stop():
        err = require_license("porthop")
        if err:
            return err
        resp = _daemon_stop("porthop")
        if resp:
            return resp
        push_log("INFO", "PortHop server stopped")
        return jsonify({"ok": True})

    @app.route("/api/porthop/serve/status")
    def api_porthop_serve_status():
        err = require_license("porthop")
        if err:
            return err
        return jsonify(_daemon_status("porthop"))

    @app.route("/api/porthop/client", methods=["POST"])
    def api_porthop_client():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("porthop")
        if err:
            return err
        body = request.get_json(force=True) or {}
        base_port, rng, secret, interval, resp = _porthop_common(body)
        if resp:
            return resp
        host = (body.get("host") or "").strip()
        if not _valid_ipv4(host):
            return _bad("host должен быть IPv4-адресом")
        message = body.get("message") or ""
        if not message or len(message) > 1000:
            return _bad("Пустое или слишком длинное сообщение (макс. 1000)")
        args = [ncp_binary, "porthop", "client",
                "--host", host, "--base-port", str(base_port),
                "--range", str(rng), "--secret", secret,
                "--message", message, "--hop-interval", str(interval)]
        sid = (body.get("session_id") or "").strip()
        if sid:
            if not _RE_SESSION_ID.match(sid):
                return _bad("Некорректный session-id")
            args += ["--session-id", sid]
        try:
            rc, out = _run_once(args, timeout=15)
        except subprocess.TimeoutExpired:
            return _bad("Таймаут клиента port-hop", 504)
        except Exception as e:
            return _bad(f"client failed: {e}", 500)
        echoed = "[+] Echo" in out
        return jsonify({"ok": echoed, "echoed": echoed, "output": out[-1500:]})

    # ═══════════════════════════════════════════════════════════════════
    # Fog — cooperative fog mesh overlay node
    # ═══════════════════════════════════════════════════════════════════

    @app.route("/api/fog/start", methods=["POST"])
    def api_fog_start():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("fog")
        if err:
            return err
        body = request.get_json(force=True) or {}
        node_id = (body.get("id") or "").strip().lower()
        if not _RE_HEX32.match(node_id):
            return _bad("id должен быть 32 hex-символа (16 байт)")
        port = body.get("port")
        if not _valid_port(port):
            return _bad("Некорректный порт (1–65535)")
        args = [ncp_binary, "fog", "node", "--id", node_id, "--port", str(int(port))]
        peers = body.get("peers") or []
        if isinstance(peers, str):
            peers = [p.strip() for p in peers.splitlines() if p.strip()]
        for peer in peers[:32]:
            hp = _split_host_port(peer)
            if not hp or not _valid_ipv4(hp[0]):
                return _bad(f"Некорректный peer (ожидается ip:port): {peer}")
            args += ["--peer", f"{hp[0]}:{hp[1]}"]
        d, resp = _daemon_start("fog", args, bin_dir, {
            "id": node_id, "port": int(port), "peers": len(peers),
        })
        if resp:
            return resp
        push_log("INFO", f"Fog node {node_id[:8]}… started on UDP :{int(port)}")
        return jsonify({"ok": True, "pid": d.proc.pid})

    @app.route("/api/fog/stop", methods=["POST"])
    def api_fog_stop():
        err = require_license("fog")
        if err:
            return err
        resp = _daemon_stop("fog")
        if resp:
            return resp
        push_log("INFO", "Fog node stopped")
        return jsonify({"ok": True})

    @app.route("/api/fog/status")
    def api_fog_status():
        err = require_license("fog")
        if err:
            return err
        return jsonify(_daemon_status("fog"))

    # ═══════════════════════════════════════════════════════════════════
    # XDP — eBPF/XDP diagnostics (Linux only; compile/attach/detach are
    # intentionally NOT exposed — they require root and raw interface access)
    # ═══════════════════════════════════════════════════════════════════

    def _xdp_linux_only():
        import platform
        if platform.system() != "Linux":
            return _bad("XDP/eBPF доступен только на Linux", 400)
        return None

    @app.route("/api/xdp/probe")
    def api_xdp_probe():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("xdp")
        if err:
            return err
        resp = _xdp_linux_only()
        if resp:
            return jsonify({"ok": True, "supported": False,
                            "output": "Только Linux"})
        try:
            rc, out = _run_once([ncp_binary, "xdp", "probe"])
        except Exception as e:
            return _bad(f"probe failed: {e}", 500)
        supported = "[+]" in out
        return jsonify({"ok": True, "supported": supported, "output": out[-500:]})

    @app.route("/api/xdp/stats", methods=["POST"])
    def api_xdp_stats():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("xdp")
        if err:
            return err
        resp = _xdp_linux_only()
        if resp:
            return resp
        body = request.get_json(force=True) or {}
        port = body.get("port")
        if not _valid_port(port, 0, 65535):
            return _bad("Некорректный порт (0–65535)")
        try:
            rc, out = _run_once([ncp_binary, "xdp", "stats", str(int(port))])
        except Exception as e:
            return _bad(f"stats failed: {e}", 500)
        m = re.search(r"(\d+) packets,\s*(\d+) bytes", out)
        if not m:
            return jsonify({"ok": False, "error": "Счётчики недоступны "
                            "(программа не привязана или нет прав)",
                            "output": out[-400:]}), 400
        return jsonify({"ok": True, "port": int(port),
                        "packets": int(m.group(1)), "bytes": int(m.group(2)),
                        "output": out[-500:]})

    @app.route("/api/xdp/drop", methods=["POST"])
    def api_xdp_drop():
        if not _engine_ok():
            return _engine_missing_response()
        err = require_license("xdp")
        if err:
            return err
        resp = _xdp_linux_only()
        if resp:
            return resp
        body = request.get_json(force=True) or {}
        port = body.get("port")
        if not _valid_port(port, 0, 65535):
            return _bad("Некорректный порт (0 = отключить drop)")
        try:
            rc, out = _run_once([ncp_binary, "xdp", "drop", str(int(port))])
        except Exception as e:
            return _bad(f"drop failed: {e}", 500)
        ok = "[+]" in out
        if ok:
            push_log("INFO", f"XDP selective drop: port {int(port) or 'off'}")
        return jsonify({"ok": ok, "output": out[-500:]}), (200 if ok else 400)
