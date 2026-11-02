"""Параметри визначеного навчального профілю, не універсальні межі схем."""

KEY_BYTES = {
    "AES-128-GCM": 16,
    "AES-256-GCM": 32,
    "ChaCha20-Poly1305": 32,
}
BACKENDS = ("cryptography", "pycryptodome")
NONCE_BYTES = 12
TAG_BYTES = 16


def validate_backend(backend: str) -> None:
    """Дозволені лише дві бібліотеки навчального профілю."""
    if not isinstance(backend, str) or backend not in BACKENDS:
        raise ValueError("Unsupported backend")


def validate_profile(algorithm: str, key: bytes, nonce: bytes) -> None:
    """Відхиляє невідомий алгоритм і неправильні довжини ключа та nonce.

    Перевірка довжин не доводить випадковість ключа чи унікальність nonce:
    ці властивості забезпечують keys.py і nonce.py.
    """
    if not isinstance(algorithm, str) or algorithm not in KEY_BYTES:
        raise ValueError("Unsupported algorithm")
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES[algorithm]:
        raise ValueError("Invalid key length")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_BYTES:
        raise ValueError("Invalid nonce length")
