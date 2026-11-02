"""Маршрути зашифрованих службових приміток студента."""

from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status

from app.repositories.secure_note_repository import (
    EncryptedNote,
    SecureNoteRepository,
    get_secure_note_repository,
)
from app.repositories.student_repository import (
    StudentNotFoundError,
    StudentRepository,
    get_student_repository,
)
from app.schemas.secure_note import (
    NOTE_CATEGORIES,
    NoteCreate,
    NoteErrorResponse,
    NoteMetadata,
    NoteRead,
)
from app.schemas.student import ErrorResponse
from app.security.adapters import CiphertextError, open_bytes, seal_bytes
from app.security.context import note_aad
from app.security.keys import ProcessKey, get_process_key
from app.security.profiles import BACKENDS, KEY_BYTES, NONCE_BYTES, TAG_BYTES

# Базовий профіль API: AES-256-GCM у бібліотеці cryptography.
NOTE_ALGORITHM = "AES-256-GCM"
NOTE_BACKEND = "cryptography"
ENVELOPE_VERSION = 1
UNAVAILABLE = "Protected note unavailable"

router = APIRouter(prefix="/api/v1/students", tags=["secure-notes"])

StudentsDep = Annotated[StudentRepository, Depends(get_student_repository)]
NotesDep = Annotated[SecureNoteRepository, Depends(get_secure_note_repository)]
KeyDep = Annotated[ProcessKey, Depends(get_process_key)]

NOT_FOUND = {404: {"model": ErrorResponse, "description": "Студента або примітку не знайдено"}}


def _student_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "student_not_found", "message": "Студента з таким ідентифікатором не знайдено"},
    )


def _note_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "note_not_found", "message": "Примітку не знайдено"},
    )


def _unavailable(code: int) -> HTTPException:
    # Однакове безпечне тіло без відкритого тексту, ключа чи внутрішньої траси.
    return HTTPException(status_code=code, detail=UNAVAILABLE)


def _ensure_student(students: StudentRepository, student_id: UUID) -> None:
    try:
        students.get(student_id)
    except StudentNotFoundError:
        raise _student_not_found() from None


@router.post(
    "/{student_id}/secure-notes",
    response_model=NoteMetadata,
    status_code=status.HTTP_201_CREATED,
    responses={**NOT_FOUND, 503: {"model": NoteErrorResponse, "description": "Вичерпано межу використання ключа"}},
    summary="Створити зашифровану службову примітку",
)
def create_secure_note(
    student_id: UUID,
    payload: NoteCreate,
    students: StudentsDep,
    notes: NotesDep,
    process_key: KeyDep,
) -> NoteMetadata:
    _ensure_student(students, student_id)
    note_id = uuid4()
    try:
        # Нове значення резервується до шифрування; навіть якщо запис
        # далі не відбудеться, це значення більше ніколи не використовується.
        nonce = process_key.nonces.next()
    except RuntimeError:
        raise _unavailable(status.HTTP_503_SERVICE_UNAVAILABLE) from None

    aad = note_aad(student_id, note_id, NOTE_ALGORITHM, process_key.key_id, payload.category)
    ciphertext, tag = seal_bytes(
        NOTE_BACKEND, NOTE_ALGORITHM, process_key.key, nonce, payload.text.encode("utf-8"), aad,
    )
    notes.add(
        EncryptedNote(
            version=ENVELOPE_VERSION,
            student_id=student_id,
            note_id=note_id,
            algorithm=NOTE_ALGORITHM,
            backend=NOTE_BACKEND,
            key_id=process_key.key_id,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            category=payload.category,
        )
    )
    return NoteMetadata(id=note_id, student_id=student_id, algorithm=NOTE_ALGORITHM, category=payload.category)


def _envelope_is_acceptable(note: EncryptedNote, process_key: ProcessKey) -> bool:
    """Перевірка формату конверта до спроби розшифрування."""
    return (
        note.version == ENVELOPE_VERSION
        and note.algorithm in KEY_BYTES
        and note.backend in BACKENDS
        and note.key_id == process_key.key_id  # ключ відомий цьому процесу
        and note.category in NOTE_CATEGORIES
        and isinstance(note.nonce, bytes) and len(note.nonce) == NONCE_BYTES
        and isinstance(note.tag, bytes) and len(note.tag) == TAG_BYTES
        and isinstance(note.ciphertext, bytes)
    )


@router.get(
    "/{student_id}/secure-notes/{note_id}",
    response_model=NoteRead,
    responses={**NOT_FOUND, 500: {"model": NoteErrorResponse, "description": "Запис не пройшов перевірку"}},
    summary="Прочитати перевірену службову примітку",
)
def read_secure_note(
    student_id: UUID,
    note_id: UUID,
    students: StudentsDep,
    notes: NotesDep,
    process_key: KeyDep,
) -> NoteRead:
    _ensure_student(students, student_id)
    try:
        note = notes.get(student_id, note_id)
    except KeyError:
        raise _note_not_found() from None

    if not _envelope_is_acceptable(note, process_key):
        raise _unavailable(status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Ідентифікатори контексту беруться з перевіреного запиту (шлях),
    # а не зі скопійованого конверта.
    aad = note_aad(student_id, note_id, note.algorithm, process_key.key_id, note.category)
    try:
        data = open_bytes(
            note.backend, note.algorithm, process_key.key, note.nonce, note.ciphertext, note.tag, aad,
        )
        text = data.decode("utf-8")
    except (CiphertextError, ValueError):  # UnicodeDecodeError — підклас ValueError
        raise _unavailable(status.HTTP_500_INTERNAL_SERVER_ERROR) from None

    return NoteRead(
        id=note_id, student_id=student_id, algorithm=note.algorithm, category=note.category, text=text,
    )
