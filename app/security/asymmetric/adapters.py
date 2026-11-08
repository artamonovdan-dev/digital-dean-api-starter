"""Бібліотечні адаптери асиметричного та гібридного шифрування.

generate_keypair повертає (private, public). encrypt/decrypt приймають
profile, об'єкт відповідного ключа, bytes і keyword-only context.
Контекст: label для OAEP, label та AAD для RSA/AES, info для HPKE.
RSA/AES envelope: wrapped_key[384] || nonce[12] || ct_with_tag.
HPKE envelope: повернений Suite.encrypt enc || ct без перекодування.

Власних криптографічних примітивів немає: RSA-OAEP, AES-GCM і HPKE
виконує бібліотека cryptography.
"""
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

from app.security.asymmetric.profiles import (
    CONTEXT, KEY_PROFILES, PROFILES, expected_ciphertext_bytes, oaep_max_bytes,
)

AES_KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
WRAPPED_KEY_BYTES = 384  # RSA-3072
HPKE_ENC_BYTES = {"x25519": 32, "p256": 65}
RSA_BITS = {"rsa-2048": 2048, "rsa-3072": 3072}
_HPKE_KEM = {"x25519": KEM.X25519, "p256": KEM.P256}


class DecryptionError(ValueError):
    """Єдина безпечна помилка відхилення криптографічного повідомлення."""


# --- ключі --------------------------------------------------------------------


def generate_keypair(key_profile: str) -> tuple[object, object]:
    """Нова пара ключів бібліотечним генератором; повертає (private, public)."""
    if key_profile not in KEY_PROFILES:
        raise ValueError("unsupported key profile")
    if key_profile in RSA_BITS:
        private = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS[key_profile])
    elif key_profile == "x25519":
        private = x25519.X25519PrivateKey.generate()
    else:
        private = ec.generate_private_key(ec.SECP256R1())
    return private, private.public_key()


def _require_key(key_profile: str, key: object, *, private: bool) -> None:
    """Тип і розмір ключа мають відповідати профілю."""
    if key_profile in RSA_BITS:
        kind = rsa.RSAPrivateKey if private else rsa.RSAPublicKey
        ok = isinstance(key, kind) and key.key_size == RSA_BITS[key_profile]
    elif key_profile == "x25519":
        kind = x25519.X25519PrivateKey if private else x25519.X25519PublicKey
        ok = isinstance(key, kind)
    else:
        kind = ec.EllipticCurvePrivateKey if private else ec.EllipticCurvePublicKey
        ok = isinstance(key, kind) and isinstance(key.curve, ec.SECP256R1)
    if not ok:
        raise ValueError("key does not match profile")


def _oaep(context: bytes) -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=context,
    )


def _suite(key_profile: str) -> Suite:
    return Suite(_HPKE_KEM[key_profile], KDF.HKDF_SHA256, AEAD.AES_256_GCM)


def _check_bytes(value: object, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError(f"{name} must be bytes")
    return bytes(value)


# --- шифрування ---------------------------------------------------------------


def encrypt(profile: str, public: object, message: bytes,
            *, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")
    spec = PROFILES[profile]
    _require_key(spec.key_profile, public, private=False)
    message = _check_bytes(message, "message")
    context = _check_bytes(context, "context")

    if spec.group == "direct":
        # Пряме RSA-OAEP лише для коротких повідомлень до межі формули 1.
        if len(message) > oaep_max_bytes(RSA_BITS[spec.key_profile]):
            raise ValueError("message exceeds OAEP limit")
        return public.encrypt(message, _oaep(context))

    if spec.key_profile == "rsa-3072":
        # Навчальний гібрид: нові ключ AES і nonce для кожного повідомлення.
        key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(NONCE_BYTES)
        wrapped = public.encrypt(key, _oaep(context))
        return wrapped + nonce + AESGCM(key).encrypt(nonce, message, context)

    # HPKE Base: Suite сам створює ефемерний ключ, виконує KEM, KDF і AEAD.
    return _suite(spec.key_profile).encrypt(message, public, info=context)


# --- розшифрування ------------------------------------------------------------


def _decrypt(profile: str, private: object, envelope: bytes, context: bytes) -> bytes:
    spec = PROFILES[profile]
    _require_key(spec.key_profile, private, private=True)
    envelope = _check_bytes(envelope, "envelope")
    context = _check_bytes(context, "context")

    if spec.group == "direct":
        if len(envelope) != expected_ciphertext_bytes(profile, 0):
            raise ValueError("invalid envelope length")
        return private.decrypt(envelope, _oaep(context))

    if spec.key_profile == "rsa-3072":
        if len(envelope) < WRAPPED_KEY_BYTES + NONCE_BYTES + TAG_BYTES:
            raise ValueError("invalid envelope length")
        wrapped = envelope[:WRAPPED_KEY_BYTES]
        nonce = envelope[WRAPPED_KEY_BYTES:WRAPPED_KEY_BYTES + NONCE_BYTES]
        ciphertext = envelope[WRAPPED_KEY_BYTES + NONCE_BYTES:]
        key = private.decrypt(wrapped, _oaep(context))
        if len(key) != AES_KEY_BYTES:
            raise ValueError("invalid wrapped key")
        return AESGCM(key).decrypt(nonce, ciphertext, context)

    if len(envelope) < HPKE_ENC_BYTES[spec.key_profile] + TAG_BYTES:
        raise ValueError("invalid envelope length")
    try:
        return _suite(spec.key_profile).decrypt(envelope, private, info=context)
    except (InvalidTag, ValueError):
        raise
    except Exception as exc:  # noqa: BLE001 — будь-яка відмова HPKE є відхиленням
        raise ValueError("hpke decryption failed") from exc


def decrypt(profile: str, private: object, envelope: bytes,
            *, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")
    try:
        return _decrypt(profile, private, envelope, context)
    except (InvalidTag, ValueError) as exc:
        raise DecryptionError("decryption rejected") from exc
