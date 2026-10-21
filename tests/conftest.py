import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.repositories.student_repository import StudentRepository, get_student_repository


@pytest.fixture
def client():
    """Кожен тест отримує новий порожній репозиторій — порядок запуску не важливий."""
    repository = StudentRepository()
    app.dependency_overrides[get_student_repository] = lambda: repository
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
