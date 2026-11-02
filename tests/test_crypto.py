"""Початкові тести приймання падають до реалізації; не пропускайте їх."""

from concurrent.futures import ThreadPoolExecutor
from secrets import token_bytes

import pytest

from app.security.adapters import CiphertextError, open_bytes, seal_bytes
from app.security.context import note_aad
from app.security.keys import create_process_key
from app.security.nonce import NonceSequence
from app.security.profiles import BACKENDS, KEY_BYTES, validate_profile

PROFILES = tuple(KEY_BYTES.items())


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
@pytest.mark.parametrize("message", (b"", b"demo", "Навчальна примітка  ".encode()))
def test_round_trip(backend, algorithm, key_size, message):
    # Новий незалежний ключ на тест; лише одне шифрування з nonce=0.
    key, nonce, aad = token_bytes(key_size), bytes(12), b"synthetic-context"
    ct, tag = seal_bytes(backend, algorithm, key, nonce, message, aad)
    assert len(ct) == len(message)
    assert len(tag) == 16
    assert open_bytes(backend, algorithm, key, nonce, ct, tag, aad) == message


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
@pytest.mark.parametrize("changed_part", ("ct", "tag", "aad", "key", "nonce"))
def test_tampering_is_rejected(backend, algorithm, key_size, changed_part):
    key, nonce, aad = token_bytes(key_size), bytes(12), b"synthetic-context"
    ct, tag = seal_bytes(backend, algorithm, key, nonce, b"demo", aad)
    if changed_part == "ct":
        ct = bytes([ct[0] ^ 1]) + ct[1:]
    elif changed_part == "tag":
        tag = bytes([tag[0] ^ 1]) + tag[1:]
    elif changed_part == "aad":
        aad = b"different-context"
    elif changed_part == "key":
        key = token_bytes(key_size)
    else:
        nonce = bytes([1]) + nonce[1:]
    with pytest.raises(CiphertextError):
        open_bytes(backend, algorithm, key, nonce, ct, tag, aad)


@pytest.mark.parametrize("algorithm,key_size", PROFILES)
@pytest.mark.parametrize("writer,reader", (BACKENDS, tuple(reversed(BACKENDS))))
def test_cross_library(algorithm, key_size, writer, reader):
    key, nonce, aad = token_bytes(key_size), bytes(12), b"synthetic-context"
    ct, tag = seal_bytes(writer, algorithm, key, nonce, b"demo", aad)
    assert open_bytes(reader, algorithm, key, nonce, ct, tag, aad) == b"demo"


@pytest.mark.parametrize("args", (
    ("unknown", bytes(32), bytes(12)),
    ("AES-256-GCM", bytes(16), bytes(12)),
    ("AES-128-GCM", bytes(16), bytes(11)),
))
def test_invalid_profile(args):
    with pytest.raises(ValueError):
        validate_profile(*args)


def test_counter_limit_and_concurrency():
    seq = NonceSequence(limit=1000)
    with ThreadPoolExecutor(max_workers=8) as executor:
        values = list(executor.map(lambda _: seq.next(), range(1000)))
    assert len(set(values)) == 1000
    assert all(len(value) == 12 for value in values)
    with pytest.raises(RuntimeError):
        seq.next()


def test_context_is_bound_to_expected_student():
    assert note_aad("a", "n", "AES-256-GCM", "k") != note_aad(
        "b", "n", "AES-256-GCM", "k"
    )


def test_process_key_has_no_secret_in_repr():
    value = create_process_key()
    assert len(value.key) == 32
    assert "key=" not in repr(value)
    assert "nonces=" not in repr(value)


# --- додаткові перевірки ------------------------------------------------------


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
@pytest.mark.parametrize("size", (1024, 65536, 1048576))
def test_round_trip_large_binary(backend, algorithm, key_size, size):
    key, nonce, aad = token_bytes(key_size), bytes(12), b"x" * 64
    message = token_bytes(size)
    ct, tag = seal_bytes(backend, algorithm, key, nonce, message, aad)
    assert len(ct) + len(tag) == size + 16
    assert open_bytes(backend, algorithm, key, nonce, ct, tag, aad) == message


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
def test_truncated_tag_is_rejected(backend, algorithm, key_size):
    key, nonce, aad = token_bytes(key_size), bytes(12), b"ctx"
    ct, tag = seal_bytes(backend, algorithm, key, nonce, b"demo", aad)
    with pytest.raises(CiphertextError):
        open_bytes(backend, algorithm, key, nonce, ct, tag[:12], aad)


@pytest.mark.parametrize("algorithm,key_size", PROFILES)
def test_unknown_backend_is_rejected(algorithm, key_size):
    key, nonce = token_bytes(key_size), bytes(12)
    with pytest.raises(ValueError):
        seal_bytes("openssl-cli", algorithm, key, nonce, b"demo", b"")
    with pytest.raises(ValueError):
        open_bytes("openssl-cli", algorithm, key, nonce, b"demo", bytes(16), b"")


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("algorithm,key_size", PROFILES)
def test_wrong_key_length_is_rejected_separately(backend, algorithm, key_size):
    with pytest.raises(ValueError):
        seal_bytes(backend, algorithm, token_bytes(key_size - 1), bytes(12), b"demo", b"")


def test_nonce_sequence_is_monotonic_without_repeats():
    seq = NonceSequence(limit=5000)
    values = [seq.next() for _ in range(5000)]
    assert len(set(values)) == 5000
    assert values[0] == bytes(12)
    assert int.from_bytes(values[-1], "big") == 4999


@pytest.mark.parametrize("limit", (0, -1, 1_000_001, 2.0, "10"))
def test_invalid_counter_limit(limit):
    with pytest.raises(ValueError):
        NonceSequence(limit=limit)


def test_context_is_canonical_and_bound_to_all_fields():
    base = note_aad("s", "n", "AES-256-GCM", "k")
    assert base == note_aad("s", "n", "AES-256-GCM", "k")
    assert base != note_aad("s", "other", "AES-256-GCM", "k")
    assert base != note_aad("s", "n", "AES-128-GCM", "k")
    assert base != note_aad("s", "n", "AES-256-GCM", "other")
    assert b" " not in base


def test_process_keys_are_independent():
    first, second = create_process_key(), create_process_key()
    assert first.key != second.key
    assert first.key_id != second.key_id
