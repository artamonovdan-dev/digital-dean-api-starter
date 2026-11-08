"""Новий маршрут практичної 4: лише читає й перевіряє збережений звіт.

Не запускає вимірювань, не імпортує модулі експерименту, не приймає
шлях файлу, документи чи паролі від клієнта.
"""
import json
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from app.schemas.hash_report import HashReport, HashResponse, validate_report
from app.security.hashing.profiles import PAYLOAD_SIZES

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["hash-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-04/report.json"
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


def load_report() -> HashReport:
    try:
        with REPORT_PATH.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report too large")
        data = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
        return validate_report(data)
    except FileNotFoundError as exc:
        raise HTTPException(404, "hash report not found") from exc
    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(500, "hash report invalid") from exc


@router.get(
    "/hash-benchmark-results",
    response_model=HashResponse,
    summary="Результати власного експерименту хешування",
    responses={
        404: {"description": "Звіт ще не створено"},
        422: {"description": "Неприйнятне значення payload_bytes"},
        500: {"description": "Звіт некоректний"},
    },
)
def get_hash_benchmark_results(
    payload_bytes: Annotated[
        int | None,
        Query(description="Варіант 1: фільтр results за розміром повідомлення "
                          "(64, 1024, 65536 або 1048576 байтів)", examples=[1024]),
    ] = None,
) -> HashResponse:
    # Варіант 1: int + явна серверна перевірка переліку; неприйнятне значення не ігнорується.
    if payload_bytes is not None and payload_bytes not in PAYLOAD_SIZES:
        raise HTTPException(422, detail=[{
            "type": "enum",
            "loc": ["query", "payload_bytes"],
            "msg": "payload_bytes must be one of 64, 1024, 65536, 1048576",
            "input": payload_bytes,
        }])
    report = load_report()  # повна перевірка HashReport ДО фільтрації
    data = report.model_dump()
    if payload_bytes is not None:
        data["results"] = [r for r in data["results"] if r["payload_bytes"] == payload_bytes]
    data["summary"] = None
    return HashResponse.model_validate(data)
