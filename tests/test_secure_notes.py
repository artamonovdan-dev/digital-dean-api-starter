"""Моделі та HTTP-контракт; усі записи вигадані."""

import json
from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.crypto_lab import get_report_path
from app.main import app
from app.repositories.secure_note_repository import (
    EncryptedNote,
    SecureNoteRepository,
    get_secure_note_repository,
)
from app.repositories.student_repository import StudentRepository, get_student_repository
from app.schemas.secure_note import NoteCreate
from app.security.keys import create_process_key, get_process_key
from app.security.profiles import BACKENDS, KEY_BYTES

STUDENTS = "/api/v1/students"
UNAVAILABLE = {"detail": "Protected note unavailable"}


@pytest.mark.parametrize("text", ("x" * 4096, "я" * 2048, "  текст  "))
def test_accepted_text_is_preserved(text):
    assert NoteCreate(text=text).text == text


@pytest.mark.parametrize("payload", (
    {"text": ""}, {"text": " "}, {"text": "x" * 4097},
    {"text": "я" * 2049}, {"text": 42},
    {"text": "demo", "key": "do-not-accept"},
))
def test_invalid_note_input(payload):
    with pytest.raises(ValidationError):
        NoteCreate(**payload)


def test_unknown_student_is_not_found():
    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/students/{uuid4()}/secure-notes/{uuid4()}"
        )
    assert response.status_code == 404


# --- фікстури: чисте сховище і новий ключ на кожен тест ----------------------


class NotesEnv:
    def __init__(self, client, notes, process_key):
        self.client = client
        self.notes = notes
        self.key = process_key

    def student(self, email: str = "olena.koval@example.com") -> str:
        response = self.client.post(STUDENTS, json={
            "full_name": "Олена Коваль",
            "email": email,
            "group_code": "КН-31",
            "enrollment_year": 2024,
        })
        assert response.status_code == 201, response.text
        return response.json()["id"]

    def post_note(self, student_id: str, **payload):
        payload.setdefault("text", "Навчальна примітка про погодження індивідуального плану")
        return self.client.post(f"{STUDENTS}/{student_id}/secure-notes", json=payload)

    def get_note(self, student_id: str, note_id: str):
        return self.client.get(f"{STUDENTS}/{student_id}/secure-notes/{note_id}")

    def stored(self, note_id: str) -> EncryptedNote:
        return self.notes._items[UUID(note_id)]

    def tamper(self, note_id: str, **changes) -> None:
        # Пошкодження конверта лише в тестовій підготовці, не через HTTP.
        self.notes._items[UUID(note_id)] = replace(self.stored(note_id), **changes)


def _make_env(limit: int = 1_000_000):
    students = StudentRepository()
    notes = SecureNoteRepository()
    process_key = create_process_key(limit)
    app.dependency_overrides[get_student_repository] = lambda: students
    app.dependency_overrides[get_secure_note_repository] = lambda: notes
    app.dependency_overrides[get_process_key] = lambda: process_key
    return notes, process_key


@pytest.fixture
def env():
    notes, process_key = _make_env()
    with TestClient(app, raise_server_exceptions=False) as client:
        yield NotesEnv(client, notes, process_key)
    app.dependency_overrides.clear()


@pytest.fixture
def limited_env():
    # Межа лічильника в тестовій конфігурації зменшена до двох записів.
    notes, process_key = _make_env(limit=2)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield NotesEnv(client, notes, process_key)
    app.dependency_overrides.clear()


# --- створення, читання, внутрішній запис ------------------------------------


def test_note_api_and_internal_storage(env):
    student_id = env.student()
    text = "  Навчальна примітка: погоджено індивідуальний план  "
    created = env.post_note(student_id, text=text)

    assert created.status_code == 201
    body = created.json()
    assert set(body) == {"id", "student_id", "algorithm", "category"}
    assert body["student_id"] == student_id
    assert body["algorithm"] == "AES-256-GCM"
    assert body["category"] == "general"

    read = env.get_note(student_id, body["id"])
    assert read.status_code == 200
    assert read.json() == {**body, "text": text}

    stored = env.stored(body["id"])
    fields = set(vars(stored))
    assert "text" not in fields and "key" not in fields
    assert len(stored.nonce) == 12
    assert len(stored.tag) == 16
    assert len(stored.ciphertext) == len(text.encode("utf-8"))
    assert text.encode("utf-8") not in stored.ciphertext
    assert stored.key_id == env.key.key_id
    assert stored.backend == "cryptography"
    assert stored.version == 1


def test_each_note_gets_new_nonce(env):
    student_id = env.student()
    ids = [env.post_note(student_id).json()["id"] for _ in range(5)]
    nonces = {env.stored(note_id).nonce for note_id in ids}
    assert len(nonces) == 5


def test_response_never_contains_internal_fields(env):
    student_id = env.student()
    note_id = env.post_note(student_id).json()["id"]
    body = env.get_note(student_id, note_id).json()
    for field in ("key", "key_id", "nonce", "ciphertext", "tag", "backend"):
        assert field not in body


# --- межі тексту і невідомі поля через API -----------------------------------


@pytest.mark.parametrize("text", ("x" * 4096, "я" * 2048))
def test_api_accepts_byte_limit(env, text):
    student_id = env.student()
    response = env.post_note(student_id, text=text)
    assert response.status_code == 201
    assert env.get_note(student_id, response.json()["id"]).json()["text"] == text


@pytest.mark.parametrize("payload", (
    {"text": "x" * 4097},
    {"text": "я" * 2049},
    {"text": "   "},
    {"text": "demo", "key": "not-a-real-key"},
    {"text": "demo", "algorithm": "AES-128-GCM"},
    {"text": "demo", "nonce": "AAAA"},
))
def test_api_rejects_invalid_input(env, payload):
    student_id = env.student()
    response = env.client.post(f"{STUDENTS}/{student_id}/secure-notes", json=payload)
    assert response.status_code == 422
    assert env.notes._items == {}


def test_invalid_uuid_is_422(env):
    assert env.client.get(f"{STUDENTS}/not-a-uuid/secure-notes/{uuid4()}").status_code == 422
    student_id = env.student()
    assert env.client.get(f"{STUDENTS}/{student_id}/secure-notes/not-a-uuid").status_code == 422


def test_post_for_unknown_student_is_404(env):
    assert env.post_note(str(uuid4())).status_code == 404


def test_unknown_note_is_404(env):
    student_id = env.student()
    assert env.get_note(student_id, str(uuid4())).status_code == 404


# --- прив'язування до студента -----------------------------------------------


def test_note_of_other_student_is_not_returned(env):
    owner = env.student("owner@example.com")
    other = env.student("other@example.com")
    note_id = env.post_note(owner).json()["id"]
    response = env.get_note(other, note_id)
    assert response.status_code == 404
    assert "text" not in response.text


def test_copied_envelope_under_other_context_is_rejected(env):
    owner = env.student("owner@example.com")
    other = env.student("other@example.com")
    note_id = env.post_note(owner).json()["id"]
    # Копія того самого конверта, записана як примітка іншого студента.
    env.tamper(note_id, student_id=UUID(other))
    response = env.get_note(other, note_id)
    assert response.status_code == 500
    assert response.json() == UNAVAILABLE


# --- пошкоджений серверний конверт -------------------------------------------


@pytest.mark.parametrize("field", ("ciphertext", "tag", "nonce"))
def test_damaged_note_is_rejected_without_plaintext(env, field):
    student_id = env.student()
    text = "Секретна вигадана примітка"
    note_id = env.post_note(student_id, text=text).json()["id"]
    original = getattr(env.stored(note_id), field)
    env.tamper(note_id, **{field: bytes([original[0] ^ 1]) + original[1:]})

    response = env.get_note(student_id, note_id)
    assert response.status_code == 500
    assert response.json() == UNAVAILABLE
    assert text not in response.text
    assert "Traceback" not in response.text


@pytest.mark.parametrize("changes", (
    {"version": 2},
    {"algorithm": "AES-128-GCM"},
    {"algorithm": "unknown"},
    {"backend": "unknown"},
    {"key_id": uuid4()},
    {"tag": b"short"},
    {"nonce": bytes(11)},
))
def test_invalid_envelope_format_is_500(env, changes):
    student_id = env.student()
    note_id = env.post_note(student_id).json()["id"]
    env.tamper(note_id, **changes)
    response = env.get_note(student_id, note_id)
    assert response.status_code == 500
    assert response.json() == UNAVAILABLE


def test_other_backend_reads_same_envelope(env):
    # Сумісність: конверт cryptography перевіряє і PyCryptodome.
    student_id = env.student()
    note_id = env.post_note(student_id, text="demo").json()["id"]
    env.tamper(note_id, backend="pycryptodome")
    assert env.get_note(student_id, note_id).json()["text"] == "demo"


# --- лічильник одноразових значень -------------------------------------------


def test_nonce_limit_rejects_only_new_writes(limited_env):
    student_id = limited_env.student()
    first = limited_env.post_note(student_id, text="перша")
    second = limited_env.post_note(student_id, text="друга")
    assert first.status_code == 201 and second.status_code == 201

    third = limited_env.post_note(student_id, text="третя")
    assert third.status_code == 503
    assert third.json() == UNAVAILABLE
    assert len(limited_env.notes._items) == 2

    read = limited_env.get_note(student_id, first.json()["id"])
    assert read.status_code == 200
    assert read.json()["text"] == "перша"


def test_clearing_notes_does_not_reset_counter(limited_env):
    student_id = limited_env.student()
    limited_env.post_note(student_id)
    limited_env.post_note(student_id)
    limited_env.notes.clear()
    assert limited_env.post_note(student_id).status_code == 503


def test_process_key_is_shared_between_requests():
    from app.security import keys

    assert keys.get_process_key() is keys.get_process_key()


# --- індивідуальний варіант 1: категорія примітки ----------------------------


@pytest.mark.parametrize("category", ("general", "academic", "administrative"))
def test_category_round_trip(env, category):
    student_id = env.student()
    created = env.post_note(student_id, text="demo", category=category)
    assert created.status_code == 201
    assert created.json()["category"] == category
    assert env.stored(created.json()["id"]).category == category
    read = env.get_note(student_id, created.json()["id"])
    assert read.json()["category"] == category


def test_default_category_is_general(env):
    student_id = env.student()
    assert env.post_note(student_id).json()["category"] == "general"


@pytest.mark.parametrize("category", ("secret", "General", "", 1, None))
def test_unknown_category_is_422(env, category):
    student_id = env.student()
    assert env.post_note(student_id, category=category).status_code == 422


def test_changed_stored_category_fails_verification(env):
    student_id = env.student()
    note_id = env.post_note(student_id, text="demo", category="academic").json()["id"]
    env.tamper(note_id, category="administrative")
    response = env.get_note(student_id, note_id)
    assert response.status_code == 500
    assert response.json() == UNAVAILABLE


def test_category_is_part_of_associated_data():
    from app.security.context import note_aad

    base = ("s", "n", "AES-256-GCM", "k")
    assert note_aad(*base, "general") != note_aad(*base, "academic")
    assert b'"category":"academic"' in note_aad(*base, "academic")


def test_openapi_documents_category():
    schema = app.openapi()["components"]["schemas"]
    assert set(schema["NoteCreate"]["properties"]["category"]["enum"]) == {
        "general", "academic", "administrative",
    }


# --- регресія роботи 1 разом із примітками -----------------------------------


def test_student_contract_is_unchanged(env):
    student_id = env.student()
    env.post_note(student_id)
    response = env.client.get(f"{STUDENTS}/{student_id}")
    assert response.status_code == 200
    assert set(response.json()) == {"id", "full_name", "email", "group_code", "enrollment_year"}
    patched = env.client.patch(f"{STUDENTS}/{student_id}", json={"enrollment_year": 2018})
    assert patched.status_code == 200
    assert patched.json()["enrollment_year"] == 2018


# --- звіт вимірювань ---------------------------------------------------------


def _valid_report() -> dict:
    results = [
        {
            "backend": backend,
            "algorithm": algorithm,
            "size_bytes": size,
            "operation": operation,
            "series_mean_ns": [1000.0, 1100.0, 1200.0, 1300.0, 1400.0],
            "median_ns": 1200.0,
            "iqr_ns": 200.0,
            "throughput_mib_s": size * 1e9 / (2**20 * 1200.0),
        }
        for algorithm in KEY_BYTES
        for backend in BACKENDS
        for size in (1024, 65536, 1048576)
        for operation in ("encrypt", "decrypt")
    ]
    return {
        "schema_version": 1,
        "run_id": "test-run",
        "environment": {"python": "test"},
        "parameters": {"warmup": 10, "series": 5},
        "results": results,
    }


def _read_report(path):
    app.dependency_overrides[get_report_path] = lambda: path
    try:
        with TestClient(app) as client:
            return client.get("/api/v1/lab/crypto/benchmark-results")
    finally:
        app.dependency_overrides.clear()


def test_benchmark_report_reader(tmp_path):
    good = tmp_path / "report.json"
    good.write_text(json.dumps(_valid_report()), encoding="utf-8")
    response = _read_report(good)
    assert response.status_code == 200
    assert response.json()["schema_version"] == 1
    assert len(response.json()["results"]) == 36

    missing = _read_report(tmp_path / "missing.json")
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Benchmark results unavailable"}

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    response = _read_report(broken)
    assert response.status_code == 500
    assert response.json() == {"detail": "Benchmark results unavailable"}
    assert str(tmp_path) not in response.text


@pytest.mark.parametrize("mutate", (
    lambda r: r.update(schema_version=2),
    lambda r: r.pop("environment"),
    lambda r: r["results"].pop(),
    lambda r: r["results"].__setitem__(0, r["results"][1]),
    lambda r: r["results"][0].update(series_mean_ns=[1, 2, 3]),
    lambda r: r["results"][0].update(algorithm="DES"),
    lambda r: r["results"][0].update(median_ns="fast"),
))
def test_benchmark_report_with_wrong_structure_is_500(tmp_path, mutate):
    report = _valid_report()
    mutate(report)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert _read_report(path).status_code == 500


def test_report_route_does_not_accept_client_path(tmp_path):
    good = tmp_path / "report.json"
    good.write_text(json.dumps(_valid_report()), encoding="utf-8")
    app.dependency_overrides[get_report_path] = lambda: tmp_path / "missing.json"
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/lab/crypto/benchmark-results", params={"path": str(good)})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 404
