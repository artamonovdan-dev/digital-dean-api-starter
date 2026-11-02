"""Маршрут тільки читає звіт; не запускає вимірювання через HTTP."""

import json
import math
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.security.profiles import BACKENDS, KEY_BYTES

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["crypto-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-02/report.json"

UNAVAILABLE = "Benchmark results unavailable"
SIZES_BYTES = (1024, 65536, 1048576)
OPERATIONS = ("encrypt", "decrypt")
EXPECTED_ROWS = len(BACKENDS) * len(KEY_BYTES) * len(SIZES_BYTES) * len(OPERATIONS)  # 36


class ReportFormatError(ValueError):
    """Файл звіту не відповідає визначеній структурі."""


def _number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _check_row(row) -> tuple:
    if not isinstance(row, dict):
        raise ReportFormatError("row")
    if row.get("backend") not in BACKENDS or row.get("algorithm") not in KEY_BYTES:
        raise ReportFormatError("combination")
    if row.get("size_bytes") not in SIZES_BYTES or row.get("operation") not in OPERATIONS:
        raise ReportFormatError("size or operation")
    series = row.get("series_mean_ns")
    if not isinstance(series, list) or len(series) != 5 or not all(_number(v) and v > 0 for v in series):
        raise ReportFormatError("series")
    for name in ("median_ns", "iqr_ns", "throughput_mib_s"):
        if not _number(row.get(name)) or row[name] < 0:
            raise ReportFormatError(name)
    return row["backend"], row["algorithm"], row["size_bytes"], row["operation"]


def load_benchmark_report(path: Path) -> dict:
    """Читає й перевіряє report.json; шлях задає конфігурація, не клієнт.

    FileNotFoundError — файлу немає; ReportFormatError — структура некоректна.
    """
    if not path.is_file():
        raise FileNotFoundError(path)
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportFormatError("json") from exc
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ReportFormatError("schema_version")
    if not isinstance(report.get("run_id"), str):
        raise ReportFormatError("run_id")
    for name in ("environment", "parameters"):
        if not isinstance(report.get(name), dict):
            raise ReportFormatError(name)
    results = report.get("results")
    if not isinstance(results, list) or len(results) != EXPECTED_ROWS:
        raise ReportFormatError("results")
    keys = {_check_row(row) for row in results}
    if len(keys) != EXPECTED_ROWS:
        raise ReportFormatError("duplicate rows")
    return report


def get_report_path() -> Path:
    """Конфігурація шляху; тести підміняють цю залежність, а не HTTP-вхід."""
    return REPORT_PATH


@router.get(
    "/benchmark-results",
    summary="Прочитати підсумковий звіт вимірювань",
    responses={404: {"description": "Звіт ще не створено"}, 500: {"description": "Звіт пошкоджено"}},
)
def benchmark_results(path: Annotated[Path, Depends(get_report_path)]) -> dict:
    try:
        return load_benchmark_report(path)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=UNAVAILABLE) from None
    except (ReportFormatError, OSError):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=UNAVAILABLE) from None
