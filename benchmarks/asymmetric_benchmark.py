"""Окремий експеримент практичної 3, не виклик з HTTP.

Запуск з кореня проєкту:
    python -m benchmarks.asymmetric_benchmark

Створює results/practice-03/raw.csv (130 рядків) і report.json
(4 генерації + 22 результати + 22 перевірки) лише після структурної
та семантичної перевірки; файли замінюються атомарно (os.replace).

Межі таймера:
- ключі одержувача, повідомлення, конверти для decrypt — поза таймером;
- у таймері encrypt гібриду: новий ключ AES, nonce, OAEP і AES-GCM;
  у HPKE — весь Suite.encrypt (ефемерний ключ, KEM, KDF, AEAD);
- у таймері decrypt — лише 20 викликів decrypt; перевірка — після таймера;
- прогрів, перевірки, DER, CSV/JSON і запис файлів — поза таймером.
"""
import csv
import io
import json
import os
import platform
import statistics
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns

from cryptography.hazmat.primitives import serialization

from app.schemas.asymmetric_report import (
    KEY_PROFILE_IDS,
    expected_ciphertext,
    throughput_mib_s,
    validate_complete_report,
)
from app.security.asymmetric.adapters import (
    DecryptionError, decrypt, encrypt, generate_keypair,
)
from app.security.asymmetric.profiles import (
    CONTEXT, DIRECT_SIZE, HYBRID_SIZES, PROFILES, oaep_max_bytes,
)

SERIES = 5
OPERATIONS = 20
WARMUP = 10
KEYGEN_RUNS = 5
CSV_COLUMNS = (
    "group", "profile", "operation", "payload_bytes", "series_index",
    "operations", "elapsed_ns", "ns_per_operation", "ciphertext_bytes",
)
ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "results" / "practice-03"
WRONG_CONTEXT = b"digital-dean:practice-03:wrong-context"
DIRECT_PROFILES = tuple(p for p, s in PROFILES.items() if s.group == "direct")
HYBRID_PROFILES = tuple(p for p, s in PROFILES.items() if s.group == "hybrid")


def measure_batch(operation, count: int = OPERATIONS) -> tuple[int, float]:
    if count < 1:
        raise ValueError("count must be positive")
    started = perf_counter_ns()
    for _ in range(count):
        operation()
    elapsed = perf_counter_ns() - started
    return elapsed, elapsed / count


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != SERIES:
        raise ValueError("five series required")
    q1, _, q3 = statistics.quantiles(samples, n=4, method="inclusive")
    return float(statistics.median(samples)), float(q3 - q1)


def synthetic_message(size: int) -> bytes:
    """Синтетичні байти потрібної довжини (не реальні дані)."""
    pattern = b"synthetic-digital-dean-record|"
    return (pattern * (size // len(pattern) + 1))[:size]


def rotated(items: tuple, shift: int) -> tuple:
    """Циклічна зміна порядку профілів перед кожною серією."""
    shift %= len(items)
    return items[shift:] + items[:shift]


# --- 22 перевірки коректності -------------------------------------------------


def _rejects(action) -> bool:
    try:
        action()
    except DecryptionError:
        return True
    return False


def run_correctness_checks() -> list[dict]:
    """Незалежний стан на кожну перевірку; реальні криптографічні операції."""
    checks = []
    for profile, spec in PROFILES.items():
        private, public = generate_keypair(spec.key_profile)
        other_private, _ = generate_keypair(spec.key_profile)
        message = synthetic_message(spec.sizes[0])

        def roundtrip() -> bool:
            for size in spec.sizes:
                data = synthetic_message(size)
                envelope = encrypt(profile, public, data)
                if len(envelope) != expected_ciphertext(profile, size):
                    return False
                if decrypt(profile, private, envelope) != data:
                    return False
            return True

        def wrong_key() -> bool:
            envelope = encrypt(profile, public, message)
            return _rejects(lambda: decrypt(profile, other_private, envelope))

        def tamper() -> bool:
            envelope = encrypt(profile, public, message)
            changed = envelope[:-1] + bytes([envelope[-1] ^ 1])
            return _rejects(lambda: decrypt(profile, private, changed))

        def wrong_context() -> bool:
            envelope = encrypt(profile, public, message)
            return _rejects(lambda: decrypt(profile, private, envelope, context=WRONG_CONTEXT))

        named = [("roundtrip", roundtrip), ("wrong_key", wrong_key),
                 ("tamper", tamper), ("wrong_context", wrong_context)]
        if spec.group == "direct":
            bits = 2048 if spec.key_profile == "rsa-2048" else 3072

            def oaep_boundary(bits=bits) -> bool:
                limit = oaep_max_bytes(bits)
                data = synthetic_message(limit)
                if decrypt(profile, private, encrypt(profile, public, data)) != data:
                    return False
                try:
                    encrypt(profile, public, synthetic_message(limit + 1))
                except ValueError:
                    return True
                return False

            named.append(("oaep_boundary", oaep_boundary))

        for name, check in named:
            try:
                passed = bool(check())
            except Exception:  # noqa: BLE001 — невдача фіксується як passed=false
                passed = False
            checks.append({"profile": profile, "name": name, "passed": passed})
    return checks


# --- середовище ---------------------------------------------------------------


def _cpu_model() -> str:
    try:
        from benchmarks.crypto_benchmark import _cpu_model as practice2_cpu

        return practice2_cpu()[:200] or "unknown"
    except Exception:  # noqa: BLE001
        return platform.processor()[:200] or "unknown"


def _openssl_version() -> str:
    """Версія OpenSSL, яку використовує саме cryptography (не системний openssl)."""
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.openssl_version_text()
    except Exception:  # noqa: BLE001
        from cryptography.hazmat.bindings._rust import openssl as rust_openssl

        return rust_openssl.openssl_version_text()


def collect_environment() -> dict:
    import cryptography

    return {
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": _openssl_version()[:150],
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})"[:150],
        "cpu": _cpu_model(),
    }


def source_commit() -> str:
    """SHA коду перед запуском; без нього звіт не створюється."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


# --- вимірювання --------------------------------------------------------------


def measure_key_generation(raw_rows: list[dict]) -> list[dict]:
    for key_profile in KEY_PROFILE_IDS:  # прогрівальна пара кожного типу
        generate_keypair(key_profile)
    samples = {key_profile: [] for key_profile in KEY_PROFILE_IDS}
    der_sizes = {}
    for run in range(1, KEYGEN_RUNS + 1):
        for key_profile in rotated(KEY_PROFILE_IDS, run - 1):
            created = []
            elapsed, _ = measure_batch(lambda: created.append(generate_keypair(key_profile)), 1)
            samples[key_profile].append(float(elapsed))
            _, public = created[0]
            der_sizes[key_profile] = len(public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            raw_rows.append({
                "group": "key_generation", "profile": key_profile, "operation": "keygen",
                "payload_bytes": 0, "series_index": run, "operations": 1,
                "elapsed_ns": elapsed, "ns_per_operation": float(elapsed), "ciphertext_bytes": 0,
            })
    rows = []
    for key_profile in KEY_PROFILE_IDS:
        median_ns, iqr_ns = summarize(samples[key_profile])
        rows.append({
            "key_profile": key_profile, "runs": KEYGEN_RUNS, "median_ns": median_ns,
            "iqr_ns": iqr_ns, "public_key_der_bytes": der_sizes[key_profile],
        })
    return rows


def _run_series(operation: str, profile: str, keys: dict, message: bytes, count: int) -> tuple[int, float]:
    """Одна серія: підготовка поза таймером, перевірка після таймера."""
    private, public = keys[profile]
    outputs = []
    if operation == "encrypt":
        def call():
            outputs.append(encrypt(profile, public, message))
    else:
        prepared = iter([encrypt(profile, public, message) for _ in range(count)])

        def call():
            outputs.append(decrypt(profile, private, next(prepared)))
    elapsed, per_operation = measure_batch(call, count)
    expected_length = expected_ciphertext(profile, len(message))
    for item in outputs:
        if operation == "encrypt" and len(item) != expected_length:
            raise RuntimeError(f"unexpected envelope length for {profile}")
        if operation == "decrypt" and item != message:
            raise RuntimeError(f"roundtrip failed for {profile}")
    return elapsed, per_operation


def measure_operations(raw_rows: list[dict], series_order: list[dict]) -> list[dict]:
    # Ключі одержувача створюються поза таймером, окремо для кожного профілю.
    keys = {profile: generate_keypair(spec.key_profile) for profile, spec in PROFILES.items()}
    groups = [("direct", DIRECT_PROFILES, DIRECT_SIZE)] + [
        ("hybrid", HYBRID_PROFILES, size) for size in HYBRID_SIZES
    ]
    samples: dict[tuple, list[float]] = {}
    for operation in ("encrypt", "decrypt"):
        for group, profiles, size in groups:
            message = synthetic_message(size)
            for profile in profiles:  # прогрів 10 операцій, не записується
                _run_series(operation, profile, keys, message, WARMUP)
            for series_index in range(1, SERIES + 1):
                order = rotated(profiles, series_index - 1)
                series_order.append({
                    "operation": operation, "payload_bytes": size,
                    "series_index": series_index, "order": list(order),
                })
                for profile in order:
                    elapsed, per_operation = _run_series(operation, profile, keys, message, OPERATIONS)
                    samples.setdefault((profile, operation, size), []).append(per_operation)
                    raw_rows.append({
                        "group": group, "profile": profile, "operation": operation,
                        "payload_bytes": size, "series_index": series_index,
                        "operations": OPERATIONS, "elapsed_ns": elapsed,
                        "ns_per_operation": per_operation,
                        "ciphertext_bytes": expected_ciphertext(profile, size),
                    })
            print(f"done: {operation} {group} {size} B", flush=True)

    results = []
    for profile, spec in PROFILES.items():
        for size in spec.sizes:
            for operation in ("encrypt", "decrypt"):
                median_ns, iqr_ns = summarize(samples[(profile, operation, size)])
                results.append({
                    "profile": profile, "group": spec.group, "operation": operation,
                    "payload_bytes": size, "series": SERIES, "operations_per_series": OPERATIONS,
                    "median_ns": median_ns, "iqr_ns": iqr_ns,
                    "ciphertext_bytes": expected_ciphertext(profile, size),
                    "throughput_mib_s": None if spec.group == "direct" else throughput_mib_s(size, median_ns),
                })
    return results


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8", newline="")
    os.replace(temporary, path)


def run_experiment(output_dir: Path = OUTPUT_DIR) -> dict:
    commit = source_commit()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    environment = collect_environment()

    raw_rows: list[dict] = []
    series_order: list[dict] = []
    key_generation = measure_key_generation(raw_rows)
    results = measure_operations(raw_rows, series_order)
    checks = run_correctness_checks()

    report = {
        "schema_version": 1,
        "experiment": {
            "series": SERIES, "operations_per_series": OPERATIONS, "warmup": WARMUP,
            "keygen_runs": KEYGEN_RUNS, "direct_payload_bytes": DIRECT_SIZE,
            "hybrid_sizes_bytes": list(HYBRID_SIZES),
            "source_commit": commit, "created_at_utc": created_at,
        },
        "environment": environment,
        "key_generation": key_generation,
        "results": results,
        "checks": checks,
    }
    if len(raw_rows) != 130:
        raise RuntimeError("expected 130 raw rows")
    validate_complete_report(report)  # запис лише після повної перевірки

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(raw_rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write(output_dir / "raw.csv", buffer.getvalue())
    _atomic_write(output_dir / "report.json", json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    _atomic_write(output_dir / "series_order.json", json.dumps(series_order, indent=2) + "\n")

    failed = [c for c in checks if not c["passed"]]
    print(f"raw.csv: {len(raw_rows)} rows; report.json: 4 + {len(results)} + {len(checks)}; "
          f"failed checks: {len(failed)}")
    return report


def main() -> int:
    try:
        run_experiment()
    except NotImplementedError as exc:
        print(str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
