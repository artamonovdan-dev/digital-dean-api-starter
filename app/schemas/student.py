"""Схеми даних запису студента — машинна частина контракту API."""

from typing import Annotated, Self
from uuid import UUID

from annotated_types import Interval
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    Strict,
    StringConstraints,
    model_validator,
)

from app.config import institution_config


class StrictModel(BaseModel):
    """Спільна сувора конфігурація: невідомі поля заборонені, крайні пробіли вилучаються."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


# Великі латинські або українські літери чи цифри, дефіс і дві цифри: КН-31, CS-21, ПІ2-11.
GROUP_CODE_PATTERN = r"^[A-ZА-ЩЬЮЯҐЄІЇ0-9]{1,10}-[0-9]{2}$"

FullName = Annotated[str, StringConstraints(min_length=5, max_length=120)]
GroupCode = Annotated[str, StringConstraints(pattern=GROUP_CODE_PATTERN)]
# Межі задає конфігурація закладу (app/config.py, змінні середовища), а не прихована константа.
# Strict(): приймається лише справжнє ціле число (не "2024", не 2024.5, не true).
EnrollmentYear = Annotated[
    int,
    Strict(),
    Interval(
        ge=institution_config.enrollment_year_min,
        le=institution_config.enrollment_year_max,
    ),
]


class StudentCreate(StrictModel):
    """Тіло POST /api/v1/students. Поля id тут немає: його генерує сервер."""

    full_name: FullName = Field(examples=["Олена Коваль"])
    email: EmailStr = Field(examples=["olena.koval@example.com"])
    group_code: GroupCode = Field(examples=["КН-31"])
    enrollment_year: EnrollmentYear = Field(examples=[2024])


class StudentRead(StudentCreate):
    """Вихідна модель: повне представлення запису, яке повертає сервер."""

    model_config = ConfigDict(frozen=True)

    id: UUID


class StudentUpdate(StrictModel):
    """Тіло PATCH: дозвільний список полів, кожне з яких необов'язкове."""

    full_name: FullName | None = None
    email: EmailStr | None = None
    group_code: GroupCode | None = None
    enrollment_year: EnrollmentYear | None = None

    @model_validator(mode="after")
    def reject_empty_or_null(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("Тіло оновлення має містити хоча б одне поле")
        for name in self.model_fields_set:
            if getattr(self, name) is None:
                raise ValueError(f"Поле {name} не може мати значення null")
        return self


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    """Структуроване тіло контрольованої помилки (404, 409)."""

    detail: ErrorDetail
