"""Моделі API відокремлені від внутрішнього криптографічного конверта."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

Algorithm = Literal["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"]

# Індивідуальний варіант 1: категорія примітки.
NoteCategory = Literal["general", "academic", "administrative"]
NOTE_CATEGORIES: tuple[str, ...] = ("general", "academic", "administrative")

MAX_NOTE_BYTES = 4096


class NoteCreate(BaseModel):
    """Тіло POST: тільки text і category. Ключ, алгоритм, nonce, tag задає сервер."""

    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=MAX_NOTE_BYTES)
    category: NoteCategory = "general"

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        """1–4096 байтів UTF-8, не лише пробіли; текст не обрізається."""
        if not value.strip():
            raise ValueError("Empty note")
        if len(value.encode("utf-8")) > MAX_NOTE_BYTES:
            raise ValueError(f"Note exceeds {MAX_NOTE_BYTES} bytes")
        return value


class NoteMetadata(BaseModel):
    """Відповідь POST: метадані без text, ключа та конверта."""

    model_config = ConfigDict(extra="forbid")
    id: UUID
    student_id: UUID
    algorithm: Algorithm
    category: NoteCategory


class NoteRead(NoteMetadata):
    """Відповідь GET: перевірений і розшифрований текст."""

    text: str


class NoteErrorResponse(BaseModel):
    """Безпечна відповідь 500/503 без внутрішніх подробиць."""

    detail: str
