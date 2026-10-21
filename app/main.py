"""Точка входу застосунку «Цифровий деканат»."""

from fastapi import FastAPI

from app.api import students

app = FastAPI(title="Digital Dean API", version="0.1.0")


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Перевірка готовності застосунку (залежностей у першій версії немає)."""
    return {"status": "ok"}


app.include_router(students.router, prefix="/api/v1")
