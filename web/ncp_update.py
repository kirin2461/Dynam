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
# Signed manifest committed in the repo — fallback when a release was
# published without manifest.json (works without CI signing secrets).
MANIFEST_RAW_URL = f"https://raw.githubusercontent.com/{REPO}/master/update-manifest.json"

NCP_UPDATE_PUBLIC_KEY_B64 = "FT2FWdlm6rGldWix5fDJBuZmrHIR+73CuRpWszs/Hog="

CURRENT_VERSION = "1.5.5"

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
        try:
            manifest = _fetch_json(MANIFEST_RAW_URL)
        except Exception:
            manifest = None

    if not manifest:
        return {"update_available": False,
                "error": "manifest.json не найден ни в релизе, ни в репозитории",
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
        manifest_url = next((a["browser_download_url"]
                             for a in rel.get("assets", [])
                             if a.get("name") == "manifest.json"),
                            MANIFEST_RAW_URL)
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
        if asset["name"].lower().endswith((".zip", ".tar.gz", ".tgz")):
            return _install_archive(tmp_file, asset["name"], tmp_dir)
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


def _extract_archive(archive: Path, dest: Path) -> Path:
    """Extract a release archive; return the directory holding app files."""
    dest.mkdir(parents=True, exist_ok=True)
    if archive.name.lower().endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(archive) as z:
            z.extractall(dest)
    else:
        import tarfile
        with tarfile.open(archive) as t:
            t.extractall(dest)
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def _install_archive(archive: Path, name: str, tmp_dir: Path) -> dict:
    """Install a multi-file release archive (zip/tar.gz) over the app dir."""
    inner = _extract_archive(archive, tmp_dir / "extracted")
    if getattr(sys, "frozen", False):
        appdir = Path(sys.executable).parent
        exe_name = Path(sys.executable).name
        if platform.system() == "Windows":
            bat = appdir / "ncp_update.bat"
            bat.write_text(
                "@echo off\r\n"
                f"taskkill /IM {exe_name} /F >nul 2>&1\r\n"
                "taskkill /IM ncp.exe /F >nul 2>&1\r\n"
                "timeout /t 2 /nobreak >nul\r\n"
                f'robocopy "{inner}" "{appdir}" /E /IS /IT /R:3 /W:1 '
                "/NFL /NDL /NJH /NJS >nul\r\n"
                f'start "" "{appdir / exe_name}"\r\n'
                'del "%~f0"\r\n')
            subprocess.Popen(["cmd", "/c", str(bat)],
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return {"ok": True, "restart_required": True,
                    "message": "Обновление установлено, приложение перезапустится"}
        shutil.copytree(str(inner), str(appdir), dirs_exist_ok=True)
        try:
            os.chmod(appdir / exe_name, 0o755)
        except Exception:
            pass
        return {"ok": True, "restart_required": True,
                "message": "Обновление установлено, перезапустите приложение"}
    # dev-режим: складываем архив рядом
    out = Path(__file__).parent / name
    shutil.copyfile(archive, out)
    return {"ok": True, "restart_required": False,
            "message": f"Обновление скачано: {out}"}


def make_manifest(version: str, tag: str, private_key_b64: str, files: list) -> dict:
    """Build a signed update manifest for the given release asset files."""
    assets = {}
    for f in files:
        p = Path(f)
        lname = p.name.lower()
        if "windows" in lname:
            key = "windows-x64"
        elif "linux" in lname:
            key = "linux-x64"
        else:
            continue  # macOS и прочие — пока не поддерживаются апдейтером
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        assets[key] = {
            "name": p.name,
            "url": f"https://github.com/{REPO}/releases/download/{tag}/{p.name}",
            "sha256": sha,
            "signature": sign_asset_sha256(sha, private_key_b64),
            "size_hint": p.stat().st_size,
        }
    return {"version": version, "notes": f"NCP {tag}", "assets": assets}


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "check":
        print(json.dumps(check_for_update(), indent=2, ensure_ascii=False))
    elif args and args[0] == "manifest":
        # ncp_update.py manifest <version> <tag> (--key-env VAR | --key-file PATH) <files...>
        version, tag = args[1], args[2]
        rest = args[3:]
        if rest[0] == "--key-env":
            key_b64 = os.environ[rest[1]].strip()
            files = rest[2:]
        elif rest[0] == "--key-file":
            key_b64 = Path(rest[1]).read_text().strip()
            files = rest[2:]
        else:
            raise SystemExit("need --key-env VAR or --key-file PATH")
        print(json.dumps(make_manifest(version, tag, key_b64, files),
                         indent=2, ensure_ascii=False))
    else:
        print("usage: ncp_update.py check | manifest ...")
