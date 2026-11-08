"""Початкові критерії приймання: TODO повинні стати реалізацією."""
import pytest
from app.security.asymmetric.adapters import DecryptionError, decrypt, encrypt, generate_keypair
from app.security.asymmetric.profiles import PROFILES, expected_ciphertext_bytes, oaep_max_bytes


@pytest.fixture(scope="module", params=list(PROFILES))
def profile(request):
    return request.param


def test_roundtrip_and_length(profile):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    for size in PROFILES[profile].sizes:
        message = b"d" * size
        envelope = encrypt(profile, public, message)
        assert len(envelope) == expected_ciphertext_bytes(profile, size)
        assert decrypt(profile, private, envelope) == message


@pytest.mark.parametrize("failure", ["wrong_key", "tamper", "wrong_context"])
def test_decryption_rejects(profile, failure):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    envelope = encrypt(profile, public, b"synthetic-record")
    context = b"digital-dean:practice-03:report-v1"
    if failure == "wrong_key":
        private, _ = generate_keypair(PROFILES[profile].key_profile)
    elif failure == "tamper":
        envelope = envelope[:-1] + bytes([envelope[-1] ^ 1])
    else:
        context = b"wrong-context"
    with pytest.raises(DecryptionError):
        decrypt(profile, private, envelope, context=context)


@pytest.mark.parametrize("bits", [2048, 3072])
def test_oaep_boundary(bits):
    private, public = generate_keypair(f"rsa-{bits}")
    profile = f"rsa{bits}-oaep"
    limit = oaep_max_bytes(bits)
    message = b"d" * limit
    assert decrypt(profile, private, encrypt(profile, public, message)) == message
    with pytest.raises(ValueError):
        encrypt(profile, public, b"d" * (limit + 1))


def test_unknown_profile_rejected():
    with pytest.raises(ValueError):
        encrypt("unknown", None, b"synthetic")


# --- власні перевірки -----------------------------------------------------------

from cryptography.hazmat.primitives import serialization  # noqa: E402

from app.schemas.asymmetric_report import PUBLIC_KEY_DER_BYTES  # noqa: E402
from app.security.asymmetric.profiles import CONTEXT, KEY_PROFILES  # noqa: E402


@pytest.mark.parametrize("key_profile", KEY_PROFILES)
def test_generate_keypair_public_der_size(key_profile):
    private, public = generate_keypair(key_profile)
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert len(der) == PUBLIC_KEY_DER_BYTES[key_profile]
    assert private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == der


def test_unknown_key_profile_rejected():
    with pytest.raises(ValueError):
        generate_keypair("rsa-1024")


def test_unknown_profile_rejected_on_decrypt():
    with pytest.raises(ValueError):
        decrypt("unknown", None, b"x")


@pytest.mark.parametrize("profile,wrong_key_profile", [
    ("rsa2048-oaep", "rsa-3072"),
    ("rsa3072-oaep", "rsa-2048"),
    ("rsa3072-oaep-aes256gcm", "x25519"),
    ("hpke-x25519-aes256gcm", "p256"),
    ("hpke-p256-aes256gcm", "x25519"),
])
def test_mismatched_key_rejected(profile, wrong_key_profile):
    wrong_private, wrong_public = generate_keypair(wrong_key_profile)
    with pytest.raises(ValueError):
        encrypt(profile, wrong_public, b"synthetic")
    private, public = generate_keypair(PROFILES[profile].key_profile)
    envelope = encrypt(profile, public, b"synthetic")
    with pytest.raises(DecryptionError):
        decrypt(profile, wrong_private, envelope)


def test_truncated_envelope_rejected(profile):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    envelope = encrypt(profile, public, b"synthetic-record")
    for cut in (envelope[:-1], envelope[:20], b""):
        with pytest.raises(DecryptionError):
            decrypt(profile, private, cut)


def test_fresh_material_per_message(profile):
    # Нові ключ AES/nonce (гібрид), ефемерний ключ (HPKE), випадкове доповнення OAEP.
    _, public = generate_keypair(PROFILES[profile].key_profile)
    message = b"d" * PROFILES[profile].sizes[0]
    assert encrypt(profile, public, message) != encrypt(profile, public, message)


def test_hybrid_envelope_layout():
    private, public = generate_keypair("rsa-3072")
    envelope = encrypt("rsa3072-oaep-aes256gcm", public, b"d" * 1024)
    assert len(envelope) == 384 + 12 + 1024 + 16
    # Змінений nonce (байти 384..395) теж відхиляється.
    changed = envelope[:384] + bytes([envelope[384] ^ 1]) + envelope[385:]
    with pytest.raises(DecryptionError):
        decrypt("rsa3072-oaep-aes256gcm", private, changed)


def test_context_parameter_is_used(profile):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    custom = b"digital-dean:practice-03:custom"
    envelope = encrypt(profile, public, b"synthetic", context=custom)
    assert decrypt(profile, private, envelope, context=custom) == b"synthetic"
    with pytest.raises(DecryptionError):
        decrypt(profile, private, envelope, context=CONTEXT)


def test_non_bytes_message_rejected():
    _, public = generate_keypair("x25519")
    with pytest.raises(ValueError):
        encrypt("hpke-x25519-aes256gcm", public, "text")


def test_benchmark_correctness_checks_all_pass():
    from benchmarks.asymmetric_benchmark import run_correctness_checks
    from app.schemas.asymmetric_report import EXPECTED_CHECKS

    checks = run_correctness_checks()
    assert len(checks) == 22
    assert {(c["profile"], c["name"]) for c in checks} == EXPECTED_CHECKS
    assert all(c["passed"] is True for c in checks)


def test_benchmark_statistics_helpers():
    from benchmarks.asymmetric_benchmark import measure_batch, rotated, summarize

    calls = []
    elapsed, per_operation = measure_batch(lambda: calls.append(1), 20)
    assert len(calls) == 20 and elapsed > 0 and per_operation == elapsed / 20
    assert summarize([5.0, 1.0, 3.0, 2.0, 4.0]) == (3.0, 2.0)
    with pytest.raises(ValueError):
        summarize([1.0, 2.0])
    with pytest.raises(ValueError):
        measure_batch(lambda: None, 0)
    assert rotated(("a", "b", "c"), 1) == ("b", "c", "a")
