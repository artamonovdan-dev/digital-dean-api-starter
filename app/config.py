"""Конфігурація закладу освіти.

Межі навчальних значень читаються зі змінних середовища, а не ховаються в коді.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class InstitutionConfig:
    enrollment_year_min: int
    enrollment_year_max: int


def _read_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"Змінна {name} має бути цілим числом") from exc


def load_institution_config() -> InstitutionConfig:
    config = InstitutionConfig(
        enrollment_year_min=_read_int("DEAN_ENROLLMENT_YEAR_MIN", 2018),
        enrollment_year_max=_read_int("DEAN_ENROLLMENT_YEAR_MAX", 2026),
    )
    if config.enrollment_year_min > config.enrollment_year_max:
        raise RuntimeError("DEAN_ENROLLMENT_YEAR_MIN не може бути більшим за DEAN_ENROLLMENT_YEAR_MAX")
    return config


institution_config = load_institution_config()
