from uuid import UUID, uuid4

import pytest

from app.config import institution_config

YEAR_MIN = institution_config.enrollment_year_min
YEAR_MAX = institution_config.enrollment_year_max

BASE = "/api/v1/students"


def make_payload(**overrides) -> dict:
    # Лише синтетичні дані: вигадані імена, домен example.com.
    payload = {
        "full_name": "Олена Коваль",
        "email": "olena.koval@example.com",
        "group_code": "КН-31",
        "enrollment_year": YEAR_MAX,
    }
    payload.update(overrides)
    return payload


def create(client, **overrides) -> dict:
    response = client.post(BASE, json=make_payload(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


# --- 2. Створення ------------------------------------------------------------


def test_create_student_returns_201_with_server_id(client):
    payload = make_payload()
    response = client.post(BASE, json=payload)

    assert response.status_code == 201
    body = response.json()
    UUID(body["id"])  # id згенеровано сервером і він є коректним UUID
    for key, value in payload.items():
        assert body[key] == value


def test_create_rejects_client_supplied_id(client):
    response = client.post(BASE, json=make_payload(id=str(uuid4())))
    assert response.status_code == 422
    assert client.get(BASE).json() == []


def test_create_strips_whitespace(client):
    body = create(client, full_name="   Олена Коваль   ")
    assert body["full_name"] == "Олена Коваль"


# --- 3. Некоректні дані -------------------------------------------------------


def test_create_with_invalid_email_returns_422_and_nothing_created(client):
    response = client.post(BASE, json=make_payload(email="not-an-email"))
    assert response.status_code == 422
    assert client.get(BASE).json() == []


@pytest.mark.parametrize("group_code", ["кн-31", "КН31", "КН-3", "КН-311", "-31"])
def test_create_with_invalid_group_code_returns_422(client, group_code):
    response = client.post(BASE, json=make_payload(group_code=group_code))
    assert response.status_code == 422


@pytest.mark.parametrize("full_name", ["  Ол  ", "Олен", "Я" * 121])
def test_create_with_invalid_full_name_returns_422(client, full_name):
    response = client.post(BASE, json=make_payload(full_name=full_name))
    assert response.status_code == 422


def test_create_with_malformed_json_returns_422(client):
    response = client.post(
        BASE,
        content='{"full_name": "Олена Коваль", "email": ',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert client.get(BASE).json() == []


def test_create_duplicate_email_case_insensitive_returns_409(client):
    create(client)
    response = client.post(BASE, json=make_payload(email="OLENA.KOVAL@EXAMPLE.COM"))
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "email_conflict"
    assert len(client.get(BASE).json()) == 1


# --- 4. Список ----------------------------------------------------------------


def test_list_empty(client):
    response = client.get(BASE)
    assert response.status_code == 200
    assert response.json() == []


def test_list_returns_all_created_students(client):
    first = create(client)
    second = create(client, full_name="Петро Іваненко", email="petro.ivanenko@example.com")

    response = client.get(BASE)
    assert response.status_code == 200
    assert response.json() == [first, second]


# --- 5–6. Отримання за id ----------------------------------------------------


def test_get_existing_student(client):
    created = create(client)
    response = client.get(f"{BASE}/{created['id']}")
    assert response.status_code == 200
    assert response.json() == created


def test_get_missing_student_returns_controlled_404(client):
    response = client.get(f"{BASE}/{uuid4()}")
    assert response.status_code == 404
    assert response.json() == {
        "detail": {
            "code": "student_not_found",
            "message": "Студента з таким ідентифікатором не знайдено",
        }
    }
    assert "Traceback" not in response.text


def test_get_with_invalid_uuid_returns_422(client):
    response = client.get(f"{BASE}/not-a-uuid")
    assert response.status_code == 422


# --- 7–8. Часткове оновлення (обов'язкова модифікація PATCH) ------------------


def test_patch_changes_only_passed_field(client):
    created = create(client)
    response = client.patch(f"{BASE}/{created['id']}", json={"group_code": "КН-32"})

    assert response.status_code == 200
    expected = {**created, "group_code": "КН-32"}
    assert response.json() == expected
    assert client.get(f"{BASE}/{created['id']}").json() == expected


def test_patch_empty_body_returns_422_and_record_unchanged(client):
    created = create(client)
    response = client.patch(f"{BASE}/{created['id']}", json={})
    assert response.status_code == 422
    assert client.get(f"{BASE}/{created['id']}").json() == created


def test_patch_unknown_field_is_rejected(client):
    created = create(client)
    response = client.patch(f"{BASE}/{created['id']}", json={"is_admin": True})

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "extra_forbidden"
    assert client.get(f"{BASE}/{created['id']}").json() == created


def test_create_unknown_field_is_rejected(client):
    response = client.post(BASE, json=make_payload(is_admin=True))
    assert response.status_code == 422
    assert client.get(BASE).json() == []


def test_patch_cannot_change_id(client):
    created = create(client)
    response = client.patch(f"{BASE}/{created['id']}", json={"id": str(uuid4())})
    assert response.status_code == 422
    assert client.get(f"{BASE}/{created['id']}").json() == created


def test_patch_null_value_is_rejected(client):
    created = create(client)
    response = client.patch(f"{BASE}/{created['id']}", json={"full_name": None})
    assert response.status_code == 422


def test_patch_missing_student_returns_404(client):
    response = client.patch(f"{BASE}/{uuid4()}", json={"group_code": "КН-32"})
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "student_not_found"


def test_patch_email_taken_by_other_student_returns_409(client):
    create(client)
    other = create(client, full_name="Петро Іваненко", email="petro.ivanenko@example.com")
    response = client.patch(f"{BASE}/{other['id']}", json={"email": "Olena.Koval@example.com"})
    assert response.status_code == 409
    assert client.get(f"{BASE}/{other['id']}").json() == other


def test_patch_own_email_is_not_a_conflict(client):
    created = create(client)
    response = client.patch(f"{BASE}/{created['id']}", json={"email": "olena.koval@example.com"})
    assert response.status_code == 200


# --- 9–11. Індивідуальний варіант ---------------------------------------------


def test_filter_by_enrollment_year(client):
    a = create(client, enrollment_year=YEAR_MAX)
    create(client, email="petro.ivanenko@example.com", enrollment_year=YEAR_MIN)
    c = create(client, email="iryna.melnyk@example.com", enrollment_year=YEAR_MAX)

    response = client.get(BASE, params={"enrollment_year": YEAR_MAX})
    assert response.status_code == 200
    body = response.json()
    assert [s["id"] for s in body] == [a["id"], c["id"]]
    assert all(s["enrollment_year"] == YEAR_MAX for s in body)


@pytest.mark.parametrize("year", [YEAR_MIN, YEAR_MAX])
def test_enrollment_year_boundary_values_are_accepted(client, year):
    body = create(client, enrollment_year=year)
    assert body["enrollment_year"] == year


@pytest.mark.parametrize("year", [YEAR_MIN - 1, YEAR_MAX + 1])
def test_enrollment_year_outside_bounds_is_rejected(client, year):
    response = client.post(BASE, json=make_payload(enrollment_year=year))
    assert response.status_code == 422
    assert client.get(BASE).json() == []


@pytest.mark.parametrize("value", [str(YEAR_MAX), 2024.5, True, None])
def test_enrollment_year_wrong_type_is_rejected(client, value):
    response = client.post(BASE, json=make_payload(enrollment_year=value))
    assert response.status_code == 422


def test_patch_enrollment_year(client):
    created = create(client)
    response = client.patch(f"{BASE}/{created['id']}", json={"enrollment_year": YEAR_MIN})
    assert response.status_code == 200
    assert response.json() == {**created, "enrollment_year": YEAR_MIN}


def test_patch_enrollment_year_outside_bounds_is_rejected(client):
    created = create(client)
    response = client.patch(f"{BASE}/{created['id']}", json={"enrollment_year": YEAR_MAX + 1})
    assert response.status_code == 422
    assert client.get(f"{BASE}/{created['id']}").json() == created


@pytest.mark.parametrize("year", [YEAR_MIN - 1, YEAR_MAX + 1])
def test_filter_outside_bounds_returns_422(client, year):
    assert client.get(BASE, params={"enrollment_year": year}).status_code == 422
