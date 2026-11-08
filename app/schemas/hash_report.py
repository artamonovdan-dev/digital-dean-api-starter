"""Структура звіту; змістову перевірку validate_report реалізує студент."""
import math
from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictInt

from app.security.hashing.profiles import (
    CHECK_NAMES, PAYLOAD_SIZES, PROFILES, AlgorithmID, Mode, repeat_count,
)

MODES = ("whole", "chunked")


def _exact_int(value):
    if type(value) is not int:
        raise ValueError("integer required; bool/float/string is not an integer")
    return value


Version = Annotated[Literal[1], BeforeValidator(_exact_int)]
Int5 = Annotated[Literal[5], BeforeValidator(_exact_int)]
Int10 = Annotated[Literal[10], BeforeValidator(_exact_int)]
Int100 = Annotated[Literal[100], BeforeValidator(_exact_int)]
Int1000 = Annotated[Literal[1000], BeforeValidator(_exact_int)]
Int1024 = Annotated[Literal[1024], BeforeValidator(_exact_int)]
Int16384 = Annotated[Literal[16384], BeforeValidator(_exact_int)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonnegativeInt = Annotated[StrictInt, Field(ge=0)]
Positive = Annotated[float, Field(gt=0)]
Nonnegative = Annotated[float, Field(ge=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", allow_inf_nan=False)


class Parameters(StrictModel):
    sizes: list[PositiveInt] = Field(min_length=4, max_length=4)
    chunk_bytes: Int16384
    warmup: Int10
    series: Int5
    repeats_small: Int1000
    repeats_large: Int100
    avalanche_trials: Int100
    avalanche_bytes: Int1024


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=160)
    openssl_ssl: str = Field(min_length=1, max_length=160)
    os: str = Field(min_length=1, max_length=240)
    cpu: str = Field(min_length=1, max_length=160)
    architecture: str = Field(min_length=1, max_length=80)


class AlgorithmStatus(StrictModel):
    algorithm: AlgorithmID
    available: bool
    reason: Literal["not_available_in_environment"] | None
    implementation: str | None = Field(max_length=160)


class PerformanceResult(StrictModel):
    algorithm: AlgorithmID
    mode: Mode
    payload_bytes: PositiveInt
    digest_bytes: PositiveInt
    repeats: PositiveInt
    median_ns: Positive
    iqr_ns: Nonnegative
    throughput_mib_s: Positive


class AvalancheResult(StrictModel):
    algorithm: AlgorithmID
    input_bytes: Int1024
    trials: Int100
    digest_bits: PositiveInt
    min_flipped_bits: NonnegativeInt
    max_flipped_bits: NonnegativeInt
    mean_flipped_bits: Nonnegative
    mean_fraction: float = Field(ge=0, le=1)


class CorrectnessCheck(StrictModel):
    algorithm: AlgorithmID
    name: Literal["known-abc", "known-empty", "unicode-utf8", "determinism",
                  "digest-length", "stream-equivalence"]
    passed: bool


class Summary(StrictModel):
    algorithms_count: PositiveInt
    available_count: PositiveInt
    results_count: NonnegativeInt
    checks_count: NonnegativeInt
    all_checks_passed: bool


class HashReport(StrictModel):
    schema_version: Version
    created_at: str = Field(min_length=20, max_length=40)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    parameters: Parameters
    environment: Environment
    algorithms: list[AlgorithmStatus] = Field(min_length=7, max_length=7)
    results: list[PerformanceResult] = Field(min_length=40, max_length=56)
    avalanche: list[AvalancheResult] = Field(min_length=5, max_length=7)
    checks: list[CorrectnessCheck] = Field(min_length=30, max_length=42)


class HashResponse(HashReport):
    """Відповідь API. Повний файл спочатку проходить validate_report; потім
    варіант 1 (payload_bytes) фільтрує лише results. algorithms, avalanche
    і checks залишаються повними; summary для варіанта 1 — null."""

    results: list[PerformanceResult] = Field(max_length=56)
    summary: Summary | None = None


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _is_utc_moment(value: str) -> bool:
    """Чинний момент UTC із Z або +00:00; дата перевіряється розбором."""
    if not (value.endswith("Z") or value.endswith("+00:00")):
        return False
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return moment.utcoffset() == timedelta(0)


def validate_report(data: object) -> HashReport:
    """Структура (Pydantic) + повне змістове покриття звіту.

    Піднімає ValueError (ValidationError — його підклас). Перевірки з
    passed=False є допустимими діагностичними даними й не вилучаються.
    """
    report = HashReport.model_validate(data)

    _require(_is_utc_moment(report.created_at), "created_at must be a valid UTC moment")
    params = report.parameters
    _require(params.sizes == list(PAYLOAD_SIZES), "unexpected payload sizes")

    # Статуси: рівно сім унікальних; недоступними можуть бути лише md5/sha1.
    names = [row.algorithm for row in report.algorithms]
    _require(len(set(names)) == len(names) and set(names) == set(PROFILES), "algorithm coverage")
    available = set()
    for row in report.algorithms:
        if row.available:
            _require(row.reason is None and bool(row.implementation), "available status")
            available.add(row.algorithm)
        else:
            _require(PROFILES[row.algorithm].legacy, "required profile unavailable")
            _require(row.reason == "not_available_in_environment" and row.implementation is None,
                     "unavailable status")

    # Швидкодія: повна матриця доступних профілів × 4 розміри × 2 способи.
    keys = [(r.algorithm, r.mode, r.payload_bytes) for r in report.results]
    expected = {(a, m, s) for a in available for m in MODES for s in PAYLOAD_SIZES}
    _require(len(set(keys)) == len(keys), "duplicate result")
    _require(set(keys) == expected, "result coverage")
    for r in report.results:
        _require(r.digest_bytes == PROFILES[r.algorithm].digest_bytes, "digest length")
        _require(r.repeats == repeat_count(r.payload_bytes), "repeat count")
        _require(math.isfinite(r.median_ns) and math.isfinite(r.iqr_ns), "finite timing")
        formula = r.payload_bytes * 1e9 / (2**20 * r.median_ns)
        _require(math.isclose(r.throughput_mib_s, formula, rel_tol=1e-9), "throughput formula")

    # Лавинний ефект: один агрегат на кожен доступний профіль.
    algs = [a.algorithm for a in report.avalanche]
    _require(len(set(algs)) == len(algs) and set(algs) == available, "avalanche coverage")
    for a in report.avalanche:
        bits = 8 * PROFILES[a.algorithm].digest_bytes
        _require(a.digest_bits == bits, "avalanche digest bits")
        _require(a.min_flipped_bits <= a.mean_flipped_bits <= a.max_flipped_bits <= bits,
                 "avalanche bounds")
        _require(math.isclose(a.mean_fraction, a.mean_flipped_bits / bits, rel_tol=1e-9, abs_tol=1e-12),
                 "avalanche fraction")

    # Перевірки: шість назв рівно один раз для кожного доступного профілю.
    pairs = [(c.algorithm, c.name) for c in report.checks]
    _require(len(set(pairs)) == len(pairs), "duplicate check")
    _require(set(pairs) == {(a, n) for a in available for n in CHECK_NAMES}, "check coverage")
    return report
