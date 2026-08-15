# -*- coding: utf-8 -*-
"""
ncp_update.py — автоматическое обновление NCP с проверкой подписи Ed25519.

Схема:
  1. GitHub release (kirin2461/Dynam) содержит ассет manifest.json:
       {
         "version": "1.6.0",
         "notes": "...",
         "assets": {
           "windows-x64": {
             "name": "ncp-gui-v1.6.0-windows-x64.exe",
             "url":  "https://github.com/.../ncp-gui-v1.6.0-windows-x64.exe",
             "sha256": "<hex>",
             "signature": "<base64 Ed25519 over ascii sha256-hex>"
           },
           "linux-x64": { ... }
         }
       }
  2. Подпись проверяется тем же публичным ключом, что и лицензии.
  3. Скачанный файл сверяется по sha256, затем атомарно подменяется
     (на Windows — через .bat с отложенной заменой).
"""

import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO = "kirin2461/Dynam"
RELEASES_API = f"https://api.github.com/repos/{REPO}/releases/latest"

NCP_UPDATE_PUBLIC_KEY_B64 = "FT2FWdlm6rGldWix5fDJBuZmrHIR+73CuRpWszs/Hog="

CURRENT_VERSION = "1.5.0"

_UA = {"User-Agent": "NCP-Updater/1.5"}


def _platform_key() -> str:
    if platform.system() == "Windows":
        return "windows-x64"
    return "linux-x64"


def _version_tuple(v: str):
    parts = []
    for tok in v.replace("-", ".").split("."):
        digits = "".join(ch for ch in tok if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _fetch_json(url: str, timeout: int = 15) -> dict:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _verify_signature(sha256_hex: str, signature_b64: str) -> bool:
    """Ed25519-подпись поверх ASCII-строки с hex-хешем файла."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(NCP_UPDATE_PUBLIC_KEY_B64))
        try:
            pub.verify(base64.b64decode(signature_b64), sha256_hex.encode("ascii"))
            return True
        except InvalidSignature:
            return False
    except Exception:
        return False


def check_for_update() -> dict:
    """Проверяет наличие новой версии. Не скачивает сам бинарь."""
    try:
        rel = _fetch_json(RELEASES_API)
    except Exception as e:
        return {"update_available": False, "error": f"release check failed: {e}",
                "current": CURRENT_VERSION}

    manifest = None
    for asset in rel.get("assets", []):
        if asset.get("name") == "manifest.json":
            manifest = _fetch_json(asset["browser_download_url"])
            break

    if not manifest:
        return {"update_available": False,
                "error": "manifest.json не найден в релизе",
                "current": CURRENT_VERSION,
                "latest": rel.get("tag_name", "")}

    latest = str(manifest.get("version", "0"))
    key = _platform_key()
    asset_info = (manifest.get("assets") or {}).get(key)

    available = _version_tuple(latest) > _version_tuple(CURRENT_VERSION)
    result = {
        "update_available": bool(available and asset_info),
        "current": CURRENT_VERSION,
        "latest": latest,
        "notes": manifest.get("notes", ""),
        "platform": key,
    }
    if available and not asset_info:
        result["error"] = f"нет сборки для {key} в манифесте"
    if asset_info:
        result["asset"] = {"name": asset_info.get("name"),
                           "size_hint": asset_info.get("size_hint", 0)}
    return result


def download_and_install() -> dict:
    """Скачивает, проверяет и устанавливает обновление."""
    info = check_for_update()
    if not info.get("update_available"):
        return {"ok": False, "error": info.get("error", "обновление недоступно"),
                **{k: v for k, v in info.items() if k in ("current", "latest")}}

    try:
        rel = _fetch_json(RELEASES_API)
        manifest_url = next(a["browser_download_url"]
                            for a in rel.get("assets", [])
                            if a.get("name") == "manifest.json")
        manifest = _fetch_json(manifest_url)
        asset = manifest["assets"][_platform_key()]
    except Exception as e:
        return {"ok": False, "error": f"manifest error: {e}"}

    url = asset["url"]
    expected_sha = asset["sha256"].lower()
    signature = asset.get("signature", "")

    tmp_dir = Path(tempfile.mkdtemp(prefix="ncp_update_"))
    tmp_file = tmp_dir / asset["name"]
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=120) as r, open(tmp_file, "wb") as f:
            shutil.copyfileobj(r, f)

        actual_sha = hashlib.sha256(tmp_file.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            return {"ok": False,
                    "error": f"sha256 mismatch: {actual_sha[:16]}… != {expected_sha[:16]}…"}

        if not _verify_signature(actual_sha, signature):
            return {"ok": False, "error": "подпись обновления недействительна"}

        # ── install ──
        if getattr(sys, "frozen", False):
            target = Path(sys.executable)
            if platform.system() == "Windows":
                new_file = target.with_suffix(".new.exe")
                shutil.copyfile(tmp_file, new_file)
                bat = target.parent / "ncp_update.bat"
                bat.write_text(
                    "@echo off\r\n"
                    "timeout /t 2 /nobreak >nul\r\n"
                    f'move /y "{new_file}" "{target}"\r\n'
                    f'start "" "{target}"\r\n'
                    'del "%~f0"\r\n')
                subprocess.Popen(["cmd", "/c", str(bat)],
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                return {"ok": True, "restart_required": True,
                        "message": "Обновление установлено, приложение перезапустится"}
            else:
                backup = target.with_suffix(".bak")
                shutil.copyfile(target, backup)
                shutil.copyfile(tmp_file, target)
                target.chmod(0o755)
                return {"ok": True, "restart_required": True,
                        "message": "Обновление установлено, перезапустите приложение"}
        else:
            # dev-режим: складываем рядом
            out = Path(__file__).parent / asset["name"]
            shutil.copyfile(tmp_file, out)
            return {"ok": True, "restart_required": False,
                    "message": f"Обновление скачано: {out}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ── утилита для подписи манифеста (используется при выпуске релиза) ──

def sign_asset_sha256(sha256_hex: str, private_key_b64: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    return base64.b64encode(priv.sign(sha256_hex.encode("ascii"))).decode("ascii")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        print(json.dumps(check_for_update(), indent=2, ensure_ascii=False))
    else:
        print("usage: ncp_update.py check")
