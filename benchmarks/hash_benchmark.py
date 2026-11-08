"""Локальний відтворюваний експеримент практичної 4 (не викликається з HTTP).

Запуск з кореня проєкту, після коміту коду і з чистим робочим каталогом:
    python -m benchmarks.hash_benchmark

Створює results/practice-04/raw.csv (40A рядків), avalanche.csv (100A рядків)
і report.json; JSON записується лише після повної перевірки validate_report.
Якщо хоча б одна перевірка коректності має passed=False, звіт усе одно
зберігається (діагностика), а процес завершується ненульовим кодом.

Межі таймера: новий об'єкт, update, digest і цикл. Поза таймером: генерація
байтів, нарізання блоків (prepare_operation), прогрів, перевірки, hex, CSV/JSON.
"""
import csv
import io
import json
import os
import platform
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import median, quantiles
from time import perf_counter_ns

from app.schemas.hash_report import validate_report
from app.security.hashing.adapters import MODES, hamming_bits, hash_bytes, prepare_operation
from app.security.hashing.profiles import (
    AVALANCHE_BYTES, AVALANCHE_TRIALS, CHECK_NAMES, CHUNK_BYTES, PAYLOAD_SIZES, PROFILES,
    SERIES, WARMUP, make_hasher, probe_profiles, repeat_count, synthetic_payload,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "results" / "practice-04"
RAW_COLUMNS = ("algorithm", "mode", "payload_bytes", "series", "repeats", "elapsed_ns", "ns_per_op")
AVALANCHE_COLUMNS = ("algorithm", "trial", "bit_index", "digest_bits", "flipped_bits", "fraction")

# Публічні контрольні значення (порожній рядок, "abc") — не результати вимірювань.
KNOWN_VECTORS = {
    "sha256": ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    "sha512": ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
               "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
               "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192"
               "992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    "sha3-256": ("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                 "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    "blake2b-256": ("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
                    "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
    "blake2s-256": ("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
                    "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
    "md5": ("d41d8cd98f00b204e9800998ecf8427e", "900150983cd24fb0d6963f7d28e17f72"),
    "sha1": ("da39a3ee5e6b4b0d3255bfef95601890afd80709",
             "a9993e364706816aba3e25717850c26c9cd0d89d"),
}
UNICODE_SAMPLE = "Синтетична відомість Цифрового деканату: ґ, є, ї, ’".encode("utf-8")


def measure_batch(operation, repeats: int) -> float:
    """Середній час однієї операції в серії (формула 1), нс."""
    return time_series(operation, repeats) / repeats


def time_series(operation, repeats: int) -> int:
    """Загальний час серії elapsed_ns (додатне ціле)."""
    if type(repeats) is not int or repeats <= 0:
        raise ValueError("positive repeat count required")
    start = perf_counter_ns()
    for _ in range(repeats):
        operation()
    elapsed_ns = perf_counter_ns() - start
    if elapsed_ns <= 0:
        raise RuntimeError("non-positive timer interval")
    return elapsed_ns


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != 5:
        raise ValueError("five series required")
    q1, _, q3 = quantiles(samples, n=4, method="inclusive")
    return median(samples), q3 - q1


def throughput_mib_s(size: int, median_ns: float) -> float:
    """Формула 2: S * 10^9 / (2^20 * t_m)."""
    return size * 1e9 / (2**20 * median_ns)


def aggregate_raw(rows: list[dict]) -> list[dict]:
    """Агрегати з сирих серій; той самий шлях для JSON і для перевірки узгодженості."""
    grouped: dict[tuple, list[float]] = {}
    for row in rows:
        key = (row["algorithm"], row["mode"], int(row["payload_bytes"]))
        grouped.setdefault(key, []).append(int(row["elapsed_ns"]) / int(row["repeats"]))
    results = []
    for (algorithm, mode, size), samples in grouped.items():
        median_ns, iqr_ns = summarize(samples)
        results.append({
            "algorithm": algorithm, "mode": mode, "payload_bytes": size,
            "digest_bytes": PROFILES[algorithm].digest_bytes, "repeats": repeat_count(size),
            "median_ns": float(median_ns), "iqr_ns": float(iqr_ns),
            "throughput_mib_s": throughput_mib_s(size, median_ns),
        })
    return results


# --- перевірки коректності ------------------------------------------------------


def run_checks(algorithm: str) -> list[dict]:
    """Шість іменованих перевірок для одного доступного профілю."""
    digest_bytes = PROFILES[algorithm].digest_bytes

    def known(index: int, payload: bytes) -> bool:
        return hash_bytes(algorithm, payload).hex() == KNOWN_VECTORS[algorithm][index]

    def unicode_utf8() -> bool:
        reference = make_hasher(algorithm)
        reference.update(UNICODE_SAMPLE)
        return (hash_bytes(algorithm, UNICODE_SAMPLE) == reference.digest()
                and hash_bytes(algorithm, UNICODE_SAMPLE) != hash_bytes(
                    algorithm, UNICODE_SAMPLE.decode("utf-8").encode("utf-16-le")))

    def determinism() -> bool:
        data = synthetic_payload(65536)
        first = hash_bytes(algorithm, data)
        hash_bytes(algorithm, b"other message between calls")
        return all(hash_bytes(algorithm, data, mode) == first for mode in MODES) and \
            first == hash_bytes(algorithm, data)

    def digest_length() -> bool:
        return all(len(hash_bytes(algorithm, synthetic_payload(size), mode)) == digest_bytes
                   for size in (0, *PAYLOAD_SIZES) for mode in MODES)

    def stream_equivalence() -> bool:
        sizes = (0, 1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1, *PAYLOAD_SIZES)
        return all(hash_bytes(algorithm, synthetic_payload(size)) ==
                   hash_bytes(algorithm, synthetic_payload(size), "chunked") for size in sizes)

    tests = {
        "known-abc": lambda: known(1, b"abc"),
        "known-empty": lambda: known(0, b""),
        "unicode-utf8": unicode_utf8,
        "determinism": determinism,
        "digest-length": digest_length,
        "stream-equivalence": stream_equivalence,
    }
    checks = []
    for name in CHECK_NAMES:
        try:
            passed = bool(tests[name]())
        except Exception:  # noqa: BLE001 — невдача зберігається як passed=False
            passed = False
        checks.append({"algorithm": algorithm, "name": name, "passed": passed})
    return checks


# --- лавинний ефект -------------------------------------------------------------


def avalanche_trials(algorithm: str) -> list[dict]:
    """100 окремих змін одного біта початкових 1024 байтів (кожна від оригіналу)."""
    original = synthetic_payload(AVALANCHE_BYTES)
    base = hash_bytes(algorithm, original)
    bits = 8 * len(base)
    rows = []
    for index in range(AVALANCHE_TRIALS):
        changed = bytearray(original)
        changed[index // 8] ^= 1 << (index % 8)
        flipped = hamming_bits(base, hash_bytes(algorithm, bytes(changed)))
        rows.append({"algorithm": algorithm, "trial": index + 1, "bit_index": index,
                     "digest_bits": bits, "flipped_bits": flipped, "fraction": flipped / bits})
    return rows


def aggregate_avalanche(algorithm: str, rows: list[dict]) -> dict:
    bits = rows[0]["digest_bits"]
    flipped = [row["flipped_bits"] for row in rows]
    mean_bits = sum(flipped) / len(flipped)
    return {"algorithm": algorithm, "input_bytes": AVALANCHE_BYTES, "trials": len(rows),
            "digest_bits": bits, "min_flipped_bits": min(flipped),
            "max_flipped_bits": max(flipped), "mean_flipped_bits": mean_bits,
            "mean_fraction": mean_bits / bits}


# --- середовище та Git ----------------------------------------------------------


def _cpu_model() -> str:
    try:
        from benchmarks.crypto_benchmark import _cpu_model as cpu

        return (cpu() or "unknown")[:160]
    except Exception:  # noqa: BLE001
        return (platform.processor() or "unknown")[:160]


def collect_environment() -> dict:
    return {
        "python": platform.python_version(),
        "openssl_ssl": ssl.OPENSSL_VERSION[:160],
        "os": f"{platform.system()} {platform.release()}"[:240],
        "cpu": _cpu_model(),
        "architecture": (platform.machine() or "unknown")[:80],
    }


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True, check=True).stdout.strip()


def clean_source_commit() -> str:
    """Чистий робочий каталог обов'язковий: source_commit має ідентифікувати код запуску."""
    if _git("status", "--porcelain"):
        raise SystemExit("Working tree is not clean: commit your code before the experiment.")
    return _git("rev-parse", "HEAD")


# --- експеримент ----------------------------------------------------------------


def measure_performance(available: list[str]) -> list[dict]:
    raw_rows = []
    for size in PAYLOAD_SIZES:
        payload = synthetic_payload(size)  # однакові байти для всіх профілів
        repeats = repeat_count(size)
        for mode in MODES:
            operations = {a: prepare_operation(a, payload, mode) for a in available}
            for algorithm in available:  # прогрів 10 операцій, не записується
                for _ in range(WARMUP):
                    operations[algorithm]()
            for series in range(1, SERIES + 1):
                shift = (series - 1) % len(available)
                for algorithm in available[shift:] + available[:shift]:  # зсув порядку
                    elapsed = time_series(operations[algorithm], repeats)
                    raw_rows.append({"algorithm": algorithm, "mode": mode, "payload_bytes": size,
                                     "series": series, "repeats": repeats, "elapsed_ns": elapsed,
                                     "ns_per_op": elapsed / repeats})
            print(f"done: {size} B {mode}", flush=True)
    return raw_rows


def _csv(rows: list[dict], columns: tuple) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8", newline="")
    os.replace(temporary, path)


def run_experiment(output_dir: Path = OUTPUT_DIR, source_commit: str | None = None) -> dict:
    commit = source_commit or clean_source_commit()
    statuses = probe_profiles()
    available = [row["algorithm"] for row in statuses if row["available"]]

    raw_rows = measure_performance(available)
    results = aggregate_raw(raw_rows)
    order = {(a, m, s): i for i, (a, m, s) in enumerate(
        (a, m, s) for a in PROFILES for s in PAYLOAD_SIZES for m in MODES)}
    results.sort(key=lambda r: order[(r["algorithm"], r["mode"], r["payload_bytes"])])

    avalanche_rows, avalanche, checks = [], [], []
    for algorithm in available:
        rows = avalanche_trials(algorithm)
        avalanche_rows.extend(rows)
        avalanche.append(aggregate_avalanche(algorithm, rows))
        checks.extend(run_checks(algorithm))

    report = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_commit": commit,
        "parameters": {
            "sizes": list(PAYLOAD_SIZES), "chunk_bytes": CHUNK_BYTES, "warmup": WARMUP,
            "series": SERIES, "repeats_small": 1000, "repeats_large": 100,
            "avalanche_trials": AVALANCHE_TRIALS, "avalanche_bytes": AVALANCHE_BYTES,
        },
        "environment": collect_environment(),
        "algorithms": statuses,
        "results": results,
        "avalanche": avalanche,
        "checks": checks,
    }
    validate_report(report)  # JSON записується лише після повної перевірки

    output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write(output_dir / "raw.csv", _csv(raw_rows, RAW_COLUMNS))
    _atomic_write(output_dir / "avalanche.csv", _csv(avalanche_rows, AVALANCHE_COLUMNS))
    _atomic_write(output_dir / "report.json", json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    failed = [c for c in checks if not c["passed"]]
    print(f"available: {len(available)}/7; raw.csv: {len(raw_rows)}; avalanche.csv: "
          f"{len(avalanche_rows)}; results: {len(results)}; checks: {len(checks)}; failed: {len(failed)}")
    return report


def main() -> int:
    report = run_experiment()
    return 1 if any(not c["passed"] for c in report["checks"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except NotImplementedError as exc:
        raise SystemExit(str(exc)) from None
