"""Структура базового звіту; допишіть семантичний валідатор."""
import math
from datetime import datetime, timedelta
from typing import Annotated, Literal
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def _exact_integer(value: object) -> int:
    # Numeric Literal comparisons alone can accept True or 5.0 as integers.
    if type(value) is not int:
        raise ValueError("an exact integer is required")
    return value


One = Annotated[Literal[1], BeforeValidator(_exact_integer)]
Five = Annotated[Literal[5], BeforeValidator(_exact_integer)]
Ten = Annotated[Literal[10], BeforeValidator(_exact_integer)]
Twenty = Annotated[Literal[20], BeforeValidator(_exact_integer)]
SixtyFour = Annotated[Literal[64], BeforeValidator(_exact_integer)]

ProfileId = Literal[
    "rsa2048-oaep", "rsa3072-oaep", "rsa3072-oaep-aes256gcm",
    "hpke-x25519-aes256gcm", "hpke-p256-aes256gcm",
]
KeyId = Literal["rsa-2048", "rsa-3072", "x25519", "p256"]
PositiveFloat = Annotated[float, Field(gt=0, allow_inf_nan=False)]
NonNegativeFloat = Annotated[float, Field(ge=0, allow_inf_nan=False)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Experiment(StrictModel):
    series: Five
    operations_per_series: Twenty
    warmup: Ten
    keygen_runs: Five
    direct_payload_bytes: SixtyFour
    hybrid_sizes_bytes: list[int]
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    created_at_utc: str = Field(min_length=20, max_length=40)


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=100)
    cryptography: Literal["48.0.1"]
    openssl: str = Field(min_length=1, max_length=150)
    os: str = Field(min_length=1, max_length=150)
    cpu: str = Field(min_length=1, max_length=200)


class KeyGeneration(StrictModel):
    key_profile: KeyId
    runs: Five
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    public_key_der_bytes: int = Field(gt=0, le=4096)


class Result(StrictModel):
    profile: ProfileId
    group: Literal["direct", "hybrid"]
    operation: Literal["encrypt", "decrypt"]
    payload_bytes: int = Field(gt=0, le=1048576)
    series: Five
    operations_per_series: Twenty
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    ciphertext_bytes: int = Field(gt=0, le=1048988)
    throughput_mib_s: PositiveFloat | None


class Check(StrictModel):
    profile: ProfileId
    name: Literal["roundtrip", "wrong_key", "tamper", "wrong_context", "oaep_boundary"]
    passed: bool


class BenchmarkReport(StrictModel):
    schema_version: One
    experiment: Experiment
    environment: Environment
    key_generation: list[KeyGeneration] = Field(min_length=4, max_length=4)
    results: list[Result] = Field(min_length=22, max_length=22)
    checks: list[Check] = Field(min_length=22, max_length=22)


class BenchmarkResponse(BenchmarkReport):
    """Відповідь API: спочатку перевіряється повний збережений звіт,
    потім фільтрується тільки results (варіант 1: payload_bytes).
    key_generation і checks залишаються повними; порожній results допустимий."""

    results: list[Result] = Field(max_length=22)


PROFILE_SPECS = {
    # profile: (group, key_profile, sizes)
    "rsa2048-oaep": ("direct", "rsa-2048", (64,)),
    "rsa3072-oaep": ("direct", "rsa-3072", (64,)),
    "rsa3072-oaep-aes256gcm": ("hybrid", "rsa-3072", (1024, 65536, 1048576)),
    "hpke-x25519-aes256gcm": ("hybrid", "x25519", (1024, 65536, 1048576)),
    "hpke-p256-aes256gcm": ("hybrid", "p256", (1024, 65536, 1048576)),
}
HYBRID_OVERHEAD = {"rsa3072-oaep-aes256gcm": 412, "hpke-x25519-aes256gcm": 48, "hpke-p256-aes256gcm": 81}
DIRECT_CIPHERTEXT = {"rsa2048-oaep": 256, "rsa3072-oaep": 384}
PUBLIC_KEY_DER_BYTES = {"rsa-2048": 294, "rsa-3072": 422, "x25519": 44, "p256": 91}
KEY_PROFILE_IDS = ("rsa-2048", "rsa-3072", "x25519", "p256")
OPERATIONS = ("encrypt", "decrypt")
CHECK_NAMES = ("roundtrip", "wrong_key", "tamper", "wrong_context")
ALLOWED_PAYLOAD_BYTES = (64, 1024, 65536, 1048576)

EXPECTED_RESULTS = frozenset(
    (profile, operation, size)
    for profile, (_, _, sizes) in PROFILE_SPECS.items()
    for size in sizes
    for operation in OPERATIONS
)  # 22
EXPECTED_CHECKS = frozenset(
    [(profile, name) for profile in PROFILE_SPECS for name in CHECK_NAMES]
    + [("rsa2048-oaep", "oaep_boundary"), ("rsa3072-oaep", "oaep_boundary")]
)  # 22


def expected_ciphertext(profile: str, payload_bytes: int) -> int:
    if profile in DIRECT_CIPHERTEXT:
        return DIRECT_CIPHERTEXT[profile]
    return payload_bytes + HYBRID_OVERHEAD[profile]


def throughput_mib_s(payload_bytes: int, median_ns: float) -> float:
    """Формула 3: S * 10^9 / (2^20 * t_m)."""
    return payload_bytes * 1e9 / (2**20 * median_ns)


def _is_utc_timestamp(value: str) -> bool:
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return False
    return moment.tzinfo is not None and moment.utcoffset() == timedelta(0)


def validate_complete_report(data: object) -> BenchmarkReport:
    """Структурна (Pydantic) і семантична перевірка повного збереженого звіту.

    Піднімає ValueError за будь-якої невідповідності. Значення passed=false
    не приховуються: звіт із невдалою перевіркою залишається валідним
    і чесно показує цю невдачу.
    """
    report = BenchmarkReport.model_validate(data)

    experiment = report.experiment
    if experiment.hybrid_sizes_bytes != [1024, 65536, 1048576]:
        raise ValueError("unexpected hybrid sizes")
    if not _is_utc_timestamp(experiment.created_at_utc):
        raise ValueError("created_at_utc must be ISO 8601 UTC")

    key_profiles = [item.key_profile for item in report.key_generation]
    if len(set(key_profiles)) != len(key_profiles) or set(key_profiles) != set(KEY_PROFILE_IDS):
        raise ValueError("key generation coverage")
    for item in report.key_generation:
        if item.public_key_der_bytes != PUBLIC_KEY_DER_BYTES[item.key_profile]:
            raise ValueError("unexpected public key size")

    combos = [(r.profile, r.operation, r.payload_bytes) for r in report.results]
    if len(set(combos)) != len(combos):
        raise ValueError("duplicate result")
    if set(combos) != EXPECTED_RESULTS:
        raise ValueError("result coverage")
    for result in report.results:
        group = PROFILE_SPECS[result.profile][0]
        if result.group != group:
            raise ValueError("group mismatch")
        if result.ciphertext_bytes != expected_ciphertext(result.profile, result.payload_bytes):
            raise ValueError("unexpected ciphertext length")
        if group == "direct":
            if result.throughput_mib_s is not None:
                raise ValueError("direct RSA throughput must be null")
        else:
            if result.throughput_mib_s is None:
                raise ValueError("hybrid throughput required")
            expected = throughput_mib_s(result.payload_bytes, result.median_ns)
            if not math.isclose(result.throughput_mib_s, expected, rel_tol=1e-9):
                raise ValueError("throughput formula")

    checks = [(c.profile, c.name) for c in report.checks]
    if len(set(checks)) != len(checks) or set(checks) != EXPECTED_CHECKS:
        raise ValueError("check coverage")
    return report
