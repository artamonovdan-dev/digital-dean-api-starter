"""Точка входу застосунку «Цифровий деканат»."""

from fastapi import FastAPI

from app.api import asymmetric_lab, crypto_lab, hash_lab, secure_notes, students

app = FastAPI(title="Digital Dean API", version="0.4.0")


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Перевірка готовності застосунку."""
    return {"status": "ok"}


app.include_router(students.router, prefix="/api/v1")
# Маршрутизатори роботи 2 уже містять повний префікс /api/v1/...
app.include_router(secure_notes.router)
app.include_router(crypto_lab.router)
app.include_router(asymmetric_lab.router)
app.include_router(hash_lab.router)
