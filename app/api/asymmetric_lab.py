"""Новий маршрут практичної 3: лише читає й перевіряє збережений звіт.

Маршрут не імпортує і не запускає benchmarks, не приймає шлях файлу,
алгоритм чи розмір експерименту від клієнта.
"""
import json
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from app.schemas.asymmetric_report import (
    ALLOWED_PAYLOAD_BYTES,
    BenchmarkReport,
    BenchmarkResponse,
    validate_complete_report,
)

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["asymmetric-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-03/report.json"
MAX_REPORT_BYTES = 1048576  # Local teaching limit, not a universal JSON limit.


def _reject_constant(value: str):
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def load_report() -> BenchmarkReport:
    try:
        with REPORT_PATH.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report too large")
        data = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
        return validate_complete_report(data)
    except FileNotFoundError as exc:
        raise HTTPException(404, "benchmark report not found") from exc
    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(500, "benchmark report invalid") from exc


@router.get(
    "/asymmetric-benchmark-results",
    response_model=BenchmarkResponse,
    summary="Результати власного експерименту асиметричного шифрування",
    responses={
        404: {"description": "Звіт ще не створено"},
        422: {"description": "Неприйнятне значення payload_bytes"},
        500: {"description": "Звіт некоректний"},
    },
)
def get_asymmetric_benchmark_results(
    payload_bytes: Annotated[
        int | None,
        Query(
            description="Варіант 1: фільтр results за розміром повідомлення "
                        "(64, 1024, 65536 або 1048576 байтів)",
            examples=[1024],
        ),
    ] = None,
) -> BenchmarkResponse:
    # Варіант 1: int + явна серверна перевірка дозволеного переліку.
    if payload_bytes is not None and payload_bytes not in ALLOWED_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=422,
            detail=[{
                "type": "enum",
                "loc": ["query", "payload_bytes"],
                "msg": "payload_bytes must be one of 64, 1024, 65536, 1048576",
                "input": payload_bytes,
            }],
        )
    # Спочатку повний файл проходить BenchmarkReport і семантичну перевірку.
    report = load_report()
    data = report.model_dump()
    if payload_bytes is not None:
        data["results"] = [r for r in data["results"] if r["payload_bytes"] == payload_bytes]
    return BenchmarkResponse.model_validate(data)
