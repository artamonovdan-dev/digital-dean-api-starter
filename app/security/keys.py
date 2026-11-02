"""Матеріал ключа створюють один раз під час запуску процесу API."""

from dataclasses import dataclass, field
from secrets import token_bytes
from uuid import UUID, uuid4

from app.security.nonce import NonceSequence


@dataclass(frozen=True)
class ProcessKey:
    key_id: UUID
    key: bytes = field(repr=False)
    nonces: NonceSequence = field(repr=False)


def create_process_key(limit: int = 1_000_000) -> ProcessKey:
    """Викликайте при запуску, а не при кожному запиті чи читанні примітки."""
    return ProcessKey(uuid4(), token_bytes(32), NonceSequence(limit))


# Один ключ AES-256 і один NonceSequence на весь процес API.
# Ключ не зберігається в репозиторії приміток, файлі, JSON чи Git;
# після перезапуску процесу створюється новий ключ (старі примітки втрачаються).
_process_key = create_process_key()


def get_process_key() -> ProcessKey:
    """Залежність FastAPI: маршрути запису й читання отримують той самий ключ.

    У тестах підміняється через app.dependency_overrides новим ключем.
    """
    return _process_key
