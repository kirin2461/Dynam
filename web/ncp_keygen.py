#!/usr/bin/env python3
"""
ncp_keygen.py — Генератор лицензионных ключей NCP.

Выполняет две задачи:
  1. generate-keypair — создаёт пару ключей Ed25519 (приватный сохраняется
     в файл с правами 0600, публичный печатается в Base64 для встраивания
     в server.py как NCP_LICENSE_PUBLIC_KEY_B64)
  2. issue — выпускает лицензионный ключ NCP-XXXXX-... подписанный
     приватным ключом

Формат ключа соответствует web/ncp_license.py:
  raw = json_payload_bytes + ed25519_signature(64 байта)
  строка = "NCP-" + base32(raw) блоками по 5 символов через дефис

Примеры:
  python3 ncp_keygen.py generate-keypair --out ncp_private_key.b64
  python3 ncp_keygen.py issue --key ncp_private_key.b64 --plan ultimate --days 0 --modules all
  python3 ncp_keygen.py issue --key ncp_private_key.b64 --plan trial --days 14 \
      --modules dpi_bypass,self_test
"""

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from datetime import date

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from ncp_license import format_key, parse_key, verify_license_key

# Все модули, известные web-серверу (см. _require_license(...) в server.py)
ALL_MODULES = [
    "dpi_bypass",
    "e2e_encryption",
    "i2p",
    "geneva_basic",
    "self_test",
    "pipeline",
    "dns_leak",
    "session_frag",
    "cross_layer",
    "rtt_equalizer",
    "volume_norm",
    "behavioral_cloak",
    "time_breaker",
    "covert_channel",
    "wf_defense",
    "protocol_rotation",
    "as_router",
    "geo_obfuscator",
]

VALID_PLANS = ["trial", "basic", "pro", "ultimate"]


def cmd_generate_keypair(args):
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    out_path = args.out
    with open(out_path, "w") as f:
        f.write(base64.b64encode(priv_raw).decode("ascii") + "\n")
    os.chmod(out_path, 0o600)

    print(f"Приватный ключ сохранён: {out_path} (права 0600 — НЕ публикуйте его)")
    print(f"Публичный ключ (Base64, для server.py NCP_LICENSE_PUBLIC_KEY_B64):")
    print(base64.b64encode(pub_raw).decode("ascii"))


def _default_key_file() -> str:
    """ncp_private_key.b64 рядом с exe (frozen) или со скриптом."""
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).parent / "ncp_private_key.b64")
    return str(Path(__file__).parent / "ncp_private_key.b64")


def _load_private_key(path: str) -> Ed25519PrivateKey:
    if not os.path.isfile(path):
        print(f"ОШИБКА: файл приватного ключа не найден: {path}", file=sys.stderr)
        print("Положите ncp_private_key.b64 рядом с ncp-keygen.exe "
              "или укажите --key <путь>.", file=sys.stderr)
        sys.exit(2)
    with open(path) as f:
        b64 = f.read().strip()
    raw = base64.b64decode(b64)
    return Ed25519PrivateKey.from_private_bytes(raw)


def cmd_issue(args):
    priv = _load_private_key(args.key or _default_key_file())

    if args.modules == "all":
        modules = list(ALL_MODULES)
    else:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        unknown = [m for m in modules if m not in ALL_MODULES]
        if unknown:
            print(f"ПРЕДУПРЕЖДЕНИЕ: неизвестные модули: {unknown}", file=sys.stderr)

    payload = {
        "plan": args.plan,
        "modules": modules,
        "days": args.days,
        "created": args.created or date.today().strftime("%Y-%m-%d"),
    }
    if args.hwid:
        payload["hwid"] = args.hwid

    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = priv.sign(payload_bytes)
    key_string = format_key(payload_bytes + signature)

    # Самопроверка: ключ должен верифицироваться публичным ключом
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    check = verify_license_key(key_string, pub_raw)
    if check is None:
        print("ОШИБКА: выпущенный ключ не прошёл самопроверку", file=sys.stderr)
        sys.exit(1)

    print("Лицензионный ключ NCP:")
    print(key_string)
    print()
    print(f"  plan={payload['plan']}  days={payload['days']} "
          f"({'lifetime' if args.days == 0 else str(args.days) + ' дн.'})  "
          f"created={payload['created']}")
    print(f"  modules ({len(modules)}): {', '.join(modules)}")
    print()
    print("Публичный ключ для верификации (Base64):")
    print(base64.b64encode(pub_raw).decode("ascii"))


def _fix_console_encoding():
    # Windows console may be cp1251/cp1252 - switch stdout/stderr to UTF-8
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    _fix_console_encoding()
    ap = argparse.ArgumentParser(description="NCP license key generator")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate-keypair", help="Создать пару ключей Ed25519")
    g.add_argument("--out", default="ncp_private_key.b64",
                   help="Файл для приватного ключа (права 0600)")
    g.set_defaults(func=cmd_generate_keypair)

    i = sub.add_parser("issue", help="Выпустить лицензионный ключ")
    i.add_argument("--key", default=None,
                   help="Файл приватного ключа (Base64); по умолч. ncp_private_key.b64 рядом с exe")
    i.add_argument("--plan", default="ultimate", choices=VALID_PLANS)
    i.add_argument("--days", type=int, default=0,
                   help="Срок действия в днях (0 = пожизненная)")
    i.add_argument("--modules", default="all",
                   help="'all' или список через запятую")
    i.add_argument("--created", default=None, help="Дата YYYY-MM-DD (по умолч. сегодня)")
    i.add_argument("--hwid", default=None, help="Привязка к HWID (опционально)")
    i.set_defaults(func=cmd_issue)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
