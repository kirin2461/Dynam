"""
ncp_license.py — Общая библиотека для работы с лицензионными ключами NCP.

Используется как генератором ключей (ncp_keygen.py), так и сервером (server.py)
для верификации лицензий.

Зависимости: cryptography>=41.0.0
"""

import base64
import json
from datetime import date, datetime
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


# ─────────────────────────────────────────────
# Константы формата
# ─────────────────────────────────────────────

KEY_PREFIX = "NCP-"
CHUNK_SIZE = 5          # Размер каждого блока в отформатированном ключе
SIGNATURE_SIZE = 64     # Размер подписи Ed25519 в байтах


# ─────────────────────────────────────────────
# Вспомогательные функции форматирования
# ─────────────────────────────────────────────

def format_key(raw_bytes: bytes) -> str:
    """
    Форматирует сырые байты в строку лицензионного ключа вида:
    NCP-XXXXX-XXXXX-XXXXX-...

    Параметры:
        raw_bytes: Бинарные данные (payload + подпись)

    Возвращает:
        Отформатированная строка ключа
    """
    # Base32 без паддинга, верхний регистр
    encoded = base64.b32encode(raw_bytes).decode("ascii").rstrip("=")
    # Разбиваем на блоки по CHUNK_SIZE символов
    chunks = [encoded[i:i + CHUNK_SIZE] for i in range(0, len(encoded), CHUNK_SIZE)]
    return KEY_PREFIX + "-".join(chunks)


def parse_key(key_string: str) -> bytes:
    """
    Убирает префикс 'NCP-' и дефисы, возвращает сырые байты.

    Параметры:
        key_string: Строка ключа в формате NCP-XXXXX-XXXXX-...

    Возвращает:
        Декодированные байты

    Исключения:
        ValueError: Если ключ имеет неверный формат
    """
    # Убираем префикс
    s = key_string.strip()
    if s.upper().startswith(KEY_PREFIX):
        s = s[len(KEY_PREFIX):]

    # Убираем дефисы и переводим в верхний регистр
    s = s.replace("-", "").upper()

    # Восстанавливаем паддинг Base32 (кратно 8)
    padding = (8 - len(s) % 8) % 8
    s += "=" * padding

    try:
        return base64.b32decode(s)
    except Exception as e:
        raise ValueError(f"Неверный формат ключа: {e}") from e


# ─────────────────────────────────────────────
# Основная функция верификации
# ─────────────────────────────────────────────

def verify_license_key(
    key_string: str,
    public_key_bytes: bytes
) -> Optional[dict]:
    """
    Верифицирует лицензионный ключ NCP.

    Алгоритм:
        1. Разбирает строку ключа → сырые байты
        2. Разделяет на payload и подпись (последние 64 байта)
        3. Проверяет подпись Ed25519
        4. Парсит JSON-payload
        5. Проверяет срок действия

    Параметры:
        key_string:       Строка ключа в формате NCP-XXXXX-...
        public_key_bytes: Публичный ключ Ed25519 (32 байта, raw)

    Возвращает:
        Словарь с полями payload + {valid, expired, days_remaining}
        или None при неверной подписи/формате
    """
    # 1. Разбираем ключ
    try:
        raw = parse_key(key_string)
    except ValueError as e:
        return None

    # Проверяем минимальную длину (хотя бы подпись + 1 байт payload)
    if len(raw) <= SIGNATURE_SIZE:
        return None

    # 2. Разделяем payload и подпись
    payload_bytes = raw[:-SIGNATURE_SIZE]
    signature = raw[-SIGNATURE_SIZE:]

    # 3. Верифицируем подпись Ed25519
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(signature, payload_bytes)
    except InvalidSignature:
        return None
    except Exception:
        return None

    # 4. Парсим JSON
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    # 5. Проверяем срок действия
    today = date.today()
    days = payload.get("days", 365)
    created_str = payload.get("created", "")

    expired = False
    days_remaining = -1

    if days == 0:
        # Пожизненная лицензия
        expired = False
        days_remaining = 99999
    else:
        try:
            created_date = datetime.strptime(created_str, "%Y-%m-%d").date()
            from datetime import timedelta
            expiry_date = created_date + timedelta(days=days)
            expired = today > expiry_date
            days_remaining = max(0, (expiry_date - today).days)
        except ValueError:
            # Не можем распарсить дату — считаем истёкшей
            expired = True
            days_remaining = 0

    # Возвращаем обогащённый payload
    result = dict(payload)
    result["valid"] = True
    result["expired"] = expired
    result["days_remaining"] = days_remaining

    return result


# ─────────────────────────────────────────────
# Утилиты для работы с публичным ключом
# ─────────────────────────────────────────────

def load_public_key_from_b64(b64_string: str) -> bytes:
    """
    Загружает публичный ключ из Base64-строки.

    Параметры:
        b64_string: Base64-строка публичного ключа

    Возвращает:
        Байты публичного ключа (32 байта)
    """
    return base64.b64decode(b64_string.strip())


def load_public_key_from_file(path: str) -> bytes:
    """
    Загружает публичный ключ из файла (raw 32-байтовый формат).

    Параметры:
        path: Путь к файлу ключа

    Возвращает:
        Байты публичного ключа (32 байта)
    """
    with open(path, "rb") as f:
        return f.read()
