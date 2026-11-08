"""Бібліотечне хешування через hashlib; власних криптопримітивів немає.

whole — один update усього повідомлення; chunked — послідовні update
заздалегідь нарізаними блоками до CHUNK_BYTES. Кожен виклик підготовленої
операції створює НОВИЙ стан хеш-функції; змінних глобальних об'єктів немає.
"""
from app.security.hashing.profiles import CHUNK_BYTES, PROFILES, make_hasher

MODES = ("whole", "chunked")


def _validate(algorithm: object, data: object, mode: object) -> bytes:
    if not isinstance(algorithm, str) or algorithm not in PROFILES:
        raise ValueError("unknown hash profile")
    if not isinstance(mode, str) or mode not in MODES:
        raise ValueError("unknown hashing mode")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("bytes input required")
    return bytes(data)  # незмінна копія: подальші зміни bytearray не впливають


def prepare_operation(algorithm: str, data: bytes, mode: str = "whole"):
    """Готує незмінні блоки ПОЗА таймером і повертає операцію без аргументів.

    Кожен виклик операції: новий об'єкт → update (один або по блоках) → digest().
    """
    payload = _validate(algorithm, data, mode)
    if mode == "whole":
        def operation() -> bytes:
            hasher = make_hasher(algorithm)
            hasher.update(payload)
            return hasher.digest()
        return operation

    chunks = tuple(payload[offset:offset + CHUNK_BYTES]
                   for offset in range(0, len(payload), CHUNK_BYTES))

    def operation() -> bytes:
        hasher = make_hasher(algorithm)
        for chunk in chunks:
            hasher.update(chunk)
        return hasher.digest()
    return operation


def hash_bytes(algorithm: str, data: bytes, mode: str = "whole") -> bytes:
    """Хеш у вигляді bytes; новий стан на кожен виклик."""
    return prepare_operation(algorithm, data, mode)()


def hamming_bits(left: bytes, right: bytes) -> int:
    """Кількість відмінних БІТІВ двох непорожніх хешів однакової довжини."""
    if not isinstance(left, (bytes, bytearray)) or not isinstance(right, (bytes, bytearray)):
        raise TypeError("bytes required")
    if not left or len(left) != len(right):
        raise ValueError("equal nonzero lengths required")
    return sum((a ^ b).bit_count() for a, b in zip(left, right))
