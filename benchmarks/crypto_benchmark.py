"""Відтворюване вимірювання шести комбінацій симетричного шифрування.

Запуск з кореня проєкту:
    python -m benchmarks.crypto_benchmark --output-dir results/practice-02

Методика (документ практичної роботи 2, розділ 6):
- 6 комбінацій (2 бібліотеки × 3 алгоритми), розміри 1, 64, 1024 КіБ, 2 операції;
- однакові випадкові байти й однаковий 64-байтовий контекст для всіх реалізацій;
- прогрівання 10 операцій, потім 5 серій по 100 операцій;
- окремий випадковий ключ і власний NonceSequence на кожну комбінацію;
- нові nonce для кожного шифрування, також під час прогрівання;
- усередині таймера: створення об'єкта бібліотеки + операція + обгортка адаптера;
- поза таймером: генерація ключів, даних, nonce, запис файлів, друк;
- порядок комбінацій перемішується між серіями (зафіксоване seed, не для ключів).
"""

import argparse
import csv
import json
import platform
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_bytes
from statistics import median, quantiles
from time import perf_counter_ns
from uuid import uuid4

from app.security.adapters import open_bytes, seal_bytes
from app.security.nonce import NonceSequence
from app.security.profiles import BACKENDS, KEY_BYTES

SIZES_BYTES = (1024, 65536, 1048576)
WARMUP = 10
SERIES = 5
OPERATIONS_PER_SERIES = 100
BENCHMARK_AAD = b"digital-dean-practice-02-benchmark".ljust(64, b".")
SHUFFLE_SEED = 20261102
OPERATIONS = ("encrypt", "decrypt")
COMBINATIONS = tuple((backend, algorithm) for algorithm in KEY_BYTES for backend in BACKENDS)
RAW_FIELDS = (
    "run_id", "backend", "algorithm", "size_bytes", "operation",
    "series_index", "operations", "total_ns", "mean_ns",
)


def measure_batch(operation, arguments) -> float:
    """Середній час однієї операції в серії, нс; аргументи вже підготовлені."""
    if not arguments:
        raise ValueError("Empty batch")
    started = perf_counter_ns()
    for item in arguments:
        operation(*item)
    elapsed = perf_counter_ns() - started
    if elapsed <= 0:
        raise RuntimeError("Invalid elapsed time")
    return elapsed / len(arguments)


def summarize(series_mean_ns, size_bytes) -> dict:
    """Медіана 5 середніх, inclusive IQR і МіБ/с за початковими байтами."""
    if len(series_mean_ns) != SERIES:
        raise ValueError("Five series required")
    q1, _, q3 = quantiles(series_mean_ns, n=4, method="inclusive")
    typical = median(series_mean_ns)
    if typical <= 0:
        raise ValueError("Time must be positive")
    return {
        "median_ns": typical,
        "iqr_ns": q3 - q1,
        "throughput_mib_s": size_bytes * 1e9 / (2**20 * typical),
    }


# --- середовище -------------------------------------------------------------


def _cpu_model() -> str:
    if sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            ) as key:
                return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        except OSError:
            pass
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    if sys.platform == "darwin":
        try:
            return subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, check=True
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            pass
    return platform.processor() or "unknown"


def _cryptography_info() -> dict:
    import cryptography

    info = {"version": cryptography.__version__, "openssl": "unknown"}
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        info["openssl"] = backend.openssl_version_text()
    except Exception:  # noqa: BLE001 — відомості необов'язкові
        try:
            from cryptography.hazmat.bindings._rust import openssl as rust_openssl

            info["openssl"] = rust_openssl.openssl_version_text()
        except Exception:  # noqa: BLE001
            pass
    return info


def _pycryptodome_info() -> dict:
    import Crypto

    info = {"version": Crypto.__version__, "aes_ni": "unknown", "clmul": "unknown"}
    try:
        from Crypto.Util import _cpu_features

        info["aes_ni"] = bool(_cpu_features.have_aes_ni())
        info["clmul"] = bool(_cpu_features.have_clmul())
    except Exception:  # noqa: BLE001
        pass
    return info


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def collect_environment() -> dict:
    clock = time.get_clock_info("perf_counter")
    pycryptodome = _pycryptodome_info()
    return {
        "cpu_model": _cpu_model(),
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "cryptography": _cryptography_info(),
        "pycryptodome": pycryptodome,
        # Відомості про апаратне прискорення беруться з виявлення PyCryptodome,
        # а не виводяться з того, який алгоритм виявився швидшим.
        "hardware_acceleration": {
            "aes_ni": pycryptodome["aes_ni"],
            "clmul": pycryptodome["clmul"],
            "source": "Crypto.Util._cpu_features",
        },
        "timer": {
            "function": "time.perf_counter_ns",
            "implementation": clock.implementation,
            "resolution_s": clock.resolution,
            "monotonic": clock.monotonic,
        },
    }


# --- експеримент ------------------------------------------------------------


def _verify_round_trips(states: dict, messages: dict) -> dict:
    """Перед вимірюванням перевіряє точне відновлення і готує конверти для decrypt."""
    envelopes = {}
    for (backend, algorithm), (key, nonces) in states.items():
        for size, message in messages.items():
            nonce = nonces.next()
            ct, tag = seal_bytes(backend, algorithm, key, nonce, message, BENCHMARK_AAD)
            if open_bytes(backend, algorithm, key, nonce, ct, tag, BENCHMARK_AAD) != message:
                raise RuntimeError(f"Round trip failed: {backend} {algorithm} {size}")
            envelopes[(backend, algorithm, size)] = (nonce, ct, tag)
    return envelopes


def _arguments(operation, backend, algorithm, key, nonces, message, envelope, count):
    """Готує кортежі аргументів поза таймером; для encrypt кожен nonce новий."""
    if operation == "encrypt":
        return [
            (backend, algorithm, key, nonces.next(), message, BENCHMARK_AAD) for _ in range(count)
        ]
    nonce, ct, tag = envelope  # повторне розшифрування коректного конверта допустиме
    item = (backend, algorithm, key, nonce, ct, tag, BENCHMARK_AAD)
    return [item] * count


def run_benchmark(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    started_at = datetime.now(timezone.utc).isoformat()
    git_commit = _git("rev-parse", "HEAD")
    git_dirty = _git("status", "--porcelain") not in ("", "unknown")
    environment = collect_environment()

    # Незалежні від API ключі: окремий ключ і лічильник на кожну комбінацію.
    states = {
        combo: (token_bytes(KEY_BYTES[combo[1]]), NonceSequence())
        for combo in COMBINATIONS
    }
    messages = {size: token_bytes(size) for size in SIZES_BYTES}
    envelopes = _verify_round_trips(states, messages)
    functions = {"encrypt": seal_bytes, "decrypt": open_bytes}
    shuffler = random.Random(SHUFFLE_SEED)  # лише для порядку, не для криптографії

    series: dict[tuple, list[float]] = {}
    raw_rows = []
    for size in SIZES_BYTES:
        message = messages[size]
        for operation in OPERATIONS:
            function = functions[operation]
            # Прогрівання: не входить до статистики, nonce теж нові.
            for backend, algorithm in COMBINATIONS:
                key, nonces = states[(backend, algorithm)]
                for item in _arguments(
                    operation, backend, algorithm, key, nonces, message,
                    envelopes[(backend, algorithm, size)], WARMUP,
                ):
                    function(*item)
            for index in range(1, SERIES + 1):
                order = list(COMBINATIONS)
                shuffler.shuffle(order)
                for backend, algorithm in order:
                    key, nonces = states[(backend, algorithm)]
                    arguments = _arguments(
                        operation, backend, algorithm, key, nonces, message,
                        envelopes[(backend, algorithm, size)], OPERATIONS_PER_SERIES,
                    )
                    mean_ns = measure_batch(function, arguments)
                    series.setdefault((backend, algorithm, size, operation), []).append(mean_ns)
                    raw_rows.append({
                        "run_id": run_id,
                        "backend": backend,
                        "algorithm": algorithm,
                        "size_bytes": size,
                        "operation": operation,
                        "series_index": index,
                        "operations": OPERATIONS_PER_SERIES,
                        "total_ns": round(mean_ns * OPERATIONS_PER_SERIES),
                        "mean_ns": mean_ns,
                    })
            print(f"done: {size} B {operation}", flush=True)

    results = []
    for algorithm in KEY_BYTES:
        for backend in BACKENDS:
            for size in SIZES_BYTES:
                for operation in OPERATIONS:
                    values = series[(backend, algorithm, size, operation)]
                    results.append({
                        "backend": backend,
                        "algorithm": algorithm,
                        "size_bytes": size,
                        "operation": operation,
                        "series_mean_ns": values,
                        **summarize(values, size),
                    })

    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "code_state": {"git_commit": git_commit, "uncommitted_changes": git_dirty},
        "environment": environment,
        "parameters": {
            "sizes_bytes": list(SIZES_BYTES),
            "warmup": WARMUP,
            "series": SERIES,
            "operations_per_series": OPERATIONS_PER_SERIES,
            "aad_bytes": len(BENCHMARK_AAD),
            "nonce_bytes": 12,
            "tag_bytes": 16,
            "includes_cipher_object_creation": True,
            "aggregation": "median of 5 series means; IQR via statistics.quantiles(method='inclusive')",
            "throughput_unit": "MiB/s of original message bytes (tag excluded)",
            "series_order": f"shuffled per series, random.Random({SHUFFLE_SEED})",
        },
        "results": results,
    }

    with (output_dir / "raw.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS)
        writer.writeheader()
        writer.writerows(raw_rows)
    (output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"raw.csv: {len(raw_rows)} series, report.json: {len(results)} results -> {output_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Practice 2 symmetric benchmark")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        run_benchmark(args.output_dir)
    except NotImplementedError as exc:
        parser.exit(2, f"Практична 2: модуль вимірювань ще не реалізовано: {exc}\n")


if __name__ == "__main__":
    main()
