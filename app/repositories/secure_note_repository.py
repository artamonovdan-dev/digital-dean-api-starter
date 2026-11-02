"""Сховище зберігає конверт, не відкритий текст і не ключ."""

from dataclasses import dataclass
from threading import Lock
from uuid import UUID


@dataclass(frozen=True)
class EncryptedNote:
    version: int
    student_id: UUID
    note_id: UUID
    algorithm: str
    backend: str
    key_id: UUID
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    # Індивідуальний варіант 1: категорія зберігається в конверті
    # і входить до асоційованих даних (не шифрується, але перевіряється).
    category: str = "general"


class NoteAlreadyExistsError(Exception):
    """Запис із таким note_id уже існує."""


class SecureNoteRepository:
    def __init__(self):
        self._items: dict[UUID, EncryptedNote] = {}
        self._lock = Lock()

    def add(self, note: EncryptedNote) -> None:
        """Зберігає конверт без дублювання note_id."""
        if not isinstance(note, EncryptedNote):
            raise TypeError("Only EncryptedNote can be stored")
        with self._lock:
            if note.note_id in self._items:
                raise NoteAlreadyExistsError(note.note_id)
            self._items[note.note_id] = note

    def get(self, student_id: UUID, note_id: UUID) -> EncryptedNote:
        """Пошук з урахуванням власника; невідомий або чужий запис дає KeyError."""
        note = self._items.get(note_id)
        if note is None or note.student_id != student_id:
            raise KeyError(note_id)
        return note

    def clear(self) -> None:
        """Очищення записів не змінює ключ і не скидає його лічильник."""
        with self._lock:
            self._items.clear()


repository = SecureNoteRepository()


def get_secure_note_repository() -> SecureNoteRepository:
    """Залежність FastAPI; у тестах підміняється чистим сховищем."""
    return repository

# Підміна _items допустима лише в тестах, не через окремий HTTP-маршрут.
