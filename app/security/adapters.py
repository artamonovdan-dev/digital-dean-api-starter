"""Спільний контракт для cryptography та PyCryptodome без відкритого fallback.

Обидві функції приймають однакові аргументи і працюють з однаковим форматом:
шифротекст і 16-байтовий тег зберігаються окремо. cryptography приєднує тег
до кінця результату, PyCryptodome повертає його окремо — адаптер вирівнює це.
Новий об'єкт бібліотеки створюється для кожної операції; ключі та nonce
генеруються зовні (keys.py, nonce.py).
"""

from Crypto.Cipher import AES, ChaCha20_Poly1305
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from app.security.profiles import TAG_BYTES, validate_backend, validate_profile


class CiphertextError(Exception):
    """Повідомлення не пройшло перевірку автентичності."""


def _pycryptodome_cipher(algorithm: str, key: bytes, nonce: bytes):
    if algorithm.startswith("AES-"):
        return AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
    return ChaCha20_Poly1305.new(key=key, nonce=nonce)


def seal_bytes(backend, algorithm, key, nonce, data, aad):
    """Шифрує data і повертає пару (ciphertext, tag)."""
    validate_backend(backend)
    validate_profile(algorithm, key, nonce)
    is_aes = algorithm.startswith("AES-")
    if backend == "cryptography":
        factory = AESGCM if is_aes else ChaCha20Poly1305
        combined = factory(key).encrypt(nonce, data, aad)
        return combined[:-TAG_BYTES], combined[-TAG_BYTES:]
    cipher = _pycryptodome_cipher(algorithm, key, nonce)
    cipher.update(aad)
    return cipher.encrypt_and_digest(data)


def open_bytes(backend, algorithm, key, nonce, ct, tag, aad):
    """Повертає початкові байти тільки після успішної перевірки повного тега.

    Будь-яка невдача перевірки (змінені ct, tag, aad, ключ чи nonce)
    перетворюється на CiphertextError; частково розшифровані байти не видаються.
    """
    validate_backend(backend)
    validate_profile(algorithm, key, nonce)
    if not isinstance(tag, (bytes, bytearray)) or len(tag) != TAG_BYTES:
        raise CiphertextError("Verification failed")
    is_aes = algorithm.startswith("AES-")
    try:
        if backend == "cryptography":
            factory = AESGCM if is_aes else ChaCha20Poly1305
            return factory(key).decrypt(nonce, bytes(ct) + bytes(tag), aad)
        cipher = _pycryptodome_cipher(algorithm, key, nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)
    except (InvalidTag, ValueError) as exc:
        raise CiphertextError("Verification failed") from exc
