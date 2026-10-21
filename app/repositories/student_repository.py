"""Репозиторний шар: тимчасове сховище студентів у пам'яті процесу."""

from threading import Lock
from uuid import UUID, uuid4

from app.schemas.student import StudentCreate, StudentRead, StudentUpdate


class StudentNotFoundError(Exception):
    """Запис із таким ідентифікатором відсутній."""


class EmailAlreadyExistsError(Exception):
    """Електронна адреса вже належить іншому запису."""


class StudentRepository:
    """Сховище в пам'яті. Дані зникають після перезапуску сервера."""

    def __init__(self) -> None:
        self._items: dict[UUID, StudentRead] = {}
        self._lock = Lock()

    @staticmethod
    def _normalize_email(email: str) -> str:
        return email.strip().casefold()

    def _email_taken(self, email: str, exclude_id: UUID | None = None) -> bool:
        key = self._normalize_email(email)
        return any(
            student.id != exclude_id and self._normalize_email(student.email) == key
            for student in self._items.values()
        )

    def create(self, data: StudentCreate) -> StudentRead:
        with self._lock:
            if self._email_taken(data.email):
                raise EmailAlreadyExistsError(data.email)
            student = StudentRead(id=uuid4(), **data.model_dump())
            self._items[student.id] = student
            return student

    def list_all(self, *, enrollment_year: int | None = None) -> list[StudentRead]:
        with self._lock:
            students = list(self._items.values())
        if enrollment_year is not None:
            students = [s for s in students if s.enrollment_year == enrollment_year]
        return students

    def get(self, student_id: UUID) -> StudentRead:
        student = self._items.get(student_id)
        if student is None:
            raise StudentNotFoundError(student_id)
        return student

    def update(self, student_id: UUID, changes: StudentUpdate) -> StudentRead:
        # exclude_unset=True відрізняє непередане поле від явно переданого значення.
        data = changes.model_dump(exclude_unset=True)
        data.pop("id", None)  # id змінювати не можна (додатковий захист)
        with self._lock:
            current = self._items.get(student_id)
            if current is None:
                raise StudentNotFoundError(student_id)
            if "email" in data and self._email_taken(data["email"], exclude_id=student_id):
                raise EmailAlreadyExistsError(data["email"])
            updated = current.model_copy(update=data)
            self._items[student_id] = updated
            return updated

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


_repository = StudentRepository()


def get_student_repository() -> StudentRepository:
    """Залежність FastAPI; у тестах підміняється чистим репозиторієм."""
    return _repository
