"""Ці тести не потребують готових або вигаданих вимірювань."""
import pytest
from pydantic import ValidationError
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.main import app
from app.api import asymmetric_lab as lab
from app.schemas.asymmetric_report import Experiment

ROUTE = "/api/v1/lab/crypto/asymmetric-benchmark-results"


def test_missing_report_reader(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")
    with pytest.raises(HTTPException) as error:
        lab.load_report()
    assert error.value.status_code == 404
    assert error.value.detail == "benchmark report not found"


@pytest.mark.parametrize("raw", [b"{", b'{"x":1,"x":2}', b'{"x":NaN}', b"{}"])
def test_invalid_report_reader(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    with pytest.raises(HTTPException) as error:
        lab.load_report()
    assert error.value.status_code == 500
    assert error.value.detail == "benchmark report invalid"


def test_route_registered():
    paths = app.openapi()["paths"]
    assert ROUTE in paths
    assert "get" in paths[ROUTE]


def test_api_missing_report(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")
    response = TestClient(app).get(ROUTE)
    assert response.status_code == 404
    assert response.json() == {"detail": "benchmark report not found"}


def test_api_invalid_report(tmp_path, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_bytes(b"not json")
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    response = TestClient(app).get(ROUTE)
    assert response.status_code == 500
    assert response.json() == {"detail": "benchmark report invalid"}


@pytest.mark.parametrize("value", [True, 5.0, "5"])
def test_metadata_requires_exact_integer(value):
    metadata = dict(
        series=value, operations_per_series=20, warmup=10, keygen_runs=5,
        direct_payload_bytes=64, hybrid_sizes_bytes=[1024, 65536, 1048576],
        source_commit="0" * 40, created_at_utc="2026-10-07T00:00:00Z",
    )
    with pytest.raises(ValidationError):
        Experiment.model_validate(metadata)


def test_report_limit(tmp_path, monkeypatch):
    path = tmp_path / "oversize.json"
    path.write_bytes(b"x" * (lab.MAX_REPORT_BYTES + 1))
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    with pytest.raises(HTTPException) as error:
        lab.load_report()
    assert error.value.status_code == 500
    assert error.value.detail == "benchmark report invalid"


# --- власні перевірки: синтетичний повний звіт у тимчасовому каталозі ------------

import copy  # noqa: E402
import json  # noqa: E402
import sys  # noqa: E402

from app.schemas.asymmetric_report import (  # noqa: E402
    EXPECTED_CHECKS,
    PROFILE_SPECS,
    PUBLIC_KEY_DER_BYTES,
    expected_ciphertext,
    throughput_mib_s,
    validate_complete_report,
)


def build_report() -> dict:
    """Синтетичний структурно повний звіт для тестів (не результати вимірювань)."""
    results = []
    for profile, (group, _, sizes) in PROFILE_SPECS.items():
        for size in sizes:
            for operation in ("encrypt", "decrypt"):
                median = 1000.0 + size / 100
                results.append({
                    "profile": profile, "group": group, "operation": operation,
                    "payload_bytes": size, "series": 5, "operations_per_series": 20,
                    "median_ns": median, "iqr_ns": 10.0,
                    "ciphertext_bytes": expected_ciphertext(profile, size),
                    "throughput_mib_s": None if group == "direct" else throughput_mib_s(size, median),
                })
    return {
        "schema_version": 1,
        "experiment": {
            "series": 5, "operations_per_series": 20, "warmup": 10, "keygen_runs": 5,
            "direct_payload_bytes": 64, "hybrid_sizes_bytes": [1024, 65536, 1048576],
            "source_commit": "a" * 40, "created_at_utc": "2026-11-02T10:00:00Z",
        },
        "environment": {
            "python": "3.13.0", "cryptography": "48.0.1", "openssl": "OpenSSL 3.x",
            "os": "Windows 11 (AMD64)", "cpu": "Synthetic CPU",
        },
        "key_generation": [
            {"key_profile": k, "runs": 5, "median_ns": 1e6, "iqr_ns": 1e4, "public_key_der_bytes": v}
            for k, v in PUBLIC_KEY_DER_BYTES.items()
        ],
        "results": results,
        "checks": [{"profile": p, "name": n, "passed": True} for p, n in sorted(EXPECTED_CHECKS)],
    }


@pytest.fixture
def report_file(tmp_path, monkeypatch):
    path = tmp_path / "report.json"

    def write(data) -> None:
        path.write_text(json.dumps(data), encoding="utf-8")

    write(build_report())
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    return write


def test_synthetic_report_is_valid():
    report = validate_complete_report(build_report())
    assert len(report.key_generation) == 4
    assert len(report.results) == 22
    assert len(report.checks) == 22


def test_api_valid_report(report_file):
    response = TestClient(app).get(ROUTE)
    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == 1
    assert (len(body["key_generation"]), len(body["results"]), len(body["checks"])) == (4, 22, 22)
    assert all(c["passed"] is True for c in body["checks"])


def _broken(mutate):
    data = build_report()
    mutate(data)
    return data


def _set(path, value):
    def mutate(data):
        target = data
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return mutate


INVALID_REPORTS = {
    "duplicate_result": lambda d: d["results"].__setitem__(1, copy.deepcopy(d["results"][0])),
    "missing_result": lambda d: d["results"].pop(),
    "duplicate_check": lambda d: d["checks"].__setitem__(1, copy.deepcopy(d["checks"][0])),
    "missing_key_profile": lambda d: d["key_generation"].__setitem__(1, copy.deepcopy(d["key_generation"][0])),
    "extra_field": _set(["results", 0, "plaintext"], "secret"),
    "extra_top_field": _set(["private_key"], "x"),
    "wrong_type": _set(["results", 0, "median_ns"], "fast"),
    "bool_as_int": _set(["results", 0, "series"], True),
    "negative_time": _set(["results", 0, "median_ns"], -1.0),
    "zero_time": _set(["key_generation", 0, "median_ns"], 0.0),
    "negative_iqr": _set(["results", 0, "iqr_ns"], -1.0),
    "wrong_formula": lambda d: next(r for r in d["results"] if r["group"] == "hybrid").update(throughput_mib_s=1.0),
    "direct_throughput": lambda d: next(r for r in d["results"] if r["group"] == "direct").update(throughput_mib_s=1.0),
    "wrong_ciphertext": _set(["results", 0, "ciphertext_bytes"], 999),
    "wrong_group": lambda d: d["results"][0].update(group="hybrid"),
    "unknown_profile": _set(["results", 0, "profile"], "rsa1024-oaep"),
    "wrong_cryptography": _set(["environment", "cryptography"], "46.0.0"),
    "bad_commit": _set(["experiment", "source_commit"], "main"),
    "not_utc": _set(["experiment", "created_at_utc"], "2026-11-02T10:00:00+02:00"),
    "wrong_sizes": _set(["experiment", "hybrid_sizes_bytes"], [1024, 65536]),
    "wrong_der": _set(["key_generation", 0, "public_key_der_bytes"], 100),
    "check_as_string": _set(["checks", 0, "passed"], "true"),
    "schema_version": _set(["schema_version"], 2),
}


@pytest.mark.parametrize("name", sorted(INVALID_REPORTS))
def test_invalid_report_semantics(name):
    with pytest.raises((ValueError, ValidationError)):
        validate_complete_report(_broken(INVALID_REPORTS[name]))


@pytest.mark.parametrize("name", ["duplicate_result", "wrong_formula", "extra_field"])
def test_api_invalid_semantics_is_safe_500(report_file, tmp_path, name):
    report_file(_broken(INVALID_REPORTS[name]))
    response = TestClient(app).get(ROUTE)
    assert response.status_code == 500
    assert response.json() == {"detail": "benchmark report invalid"}
    assert str(tmp_path) not in response.text
    assert "Traceback" not in response.text


@pytest.mark.parametrize("raw", [b'{"schema_version": Infinity}', b'{"schema_version": -Infinity}'])
def test_infinity_rejected(tmp_path, monkeypatch, raw):
    path = tmp_path / "inf.json"
    path.write_bytes(raw)
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    with pytest.raises(HTTPException) as error:
        lab.load_report()
    assert error.value.status_code == 500


def test_failed_check_is_kept_visible(report_file):
    data = build_report()
    data["checks"][0]["passed"] = False
    report_file(data)
    response = TestClient(app).get(ROUTE)
    assert response.status_code == 200
    assert any(c["passed"] is False for c in response.json()["checks"])


def test_route_does_not_run_benchmark(report_file, monkeypatch):
    import benchmarks.asymmetric_benchmark as bench

    def forbidden(*args, **kwargs):
        raise AssertionError("benchmark must not run from HTTP")

    monkeypatch.setattr(bench, "run_experiment", forbidden)
    assert TestClient(app).get(ROUTE).status_code == 200
    source = open(lab.__file__, encoding="utf-8").read()
    assert "benchmarks" not in source.split('"""', 2)[2]


def test_route_ignores_client_path(report_file, tmp_path):
    other = tmp_path / "other.json"
    other.write_text("{}", encoding="utf-8")
    response = TestClient(app).get(ROUTE, params={"path": str(other)})
    assert response.status_code == 200
    params = app.openapi()["paths"][ROUTE]["get"].get("parameters", [])
    assert [p["name"] for p in params] == ["payload_bytes"]


def test_openapi_uses_response_model():
    schema = app.openapi()["paths"][ROUTE]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert schema["$ref"].endswith("/BenchmarkResponse")


def test_response_has_no_secrets(report_file):
    text = TestClient(app).get(ROUTE).text.lower()
    for word in ("private", "plaintext", "-----begin", "ciphertext\"", "token"):
        assert word not in text


def test_app_version():
    # Той самий API продовжує версіонуватися в наступних роботах.
    assert tuple(map(int, app.version.split("."))) >= (0, 3, 0)


# --- індивідуальний варіант 1: payload_bytes ----------------------------------------


@pytest.mark.parametrize("size,count", [(64, 4), (1024, 6), (65536, 6), (1048576, 6)])
def test_variant_payload_filter(report_file, size, count):
    response = TestClient(app).get(ROUTE, params={"payload_bytes": size})
    assert response.status_code == 200
    body = response.json()
    assert len(body["results"]) == count
    assert all(r["payload_bytes"] == size for r in body["results"])
    # Базові масиви не втрачено.
    assert len(body["key_generation"]) == 4
    assert len(body["checks"]) == 22


def test_variant_without_filter_returns_full_report(report_file):
    assert len(TestClient(app).get(ROUTE).json()["results"]) == 22


@pytest.mark.parametrize("value", ["65", "0", "-64", "2048", "abc", "true"])
def test_variant_invalid_payload_is_422(report_file, value):
    response = TestClient(app).get(f"{ROUTE}?payload_bytes={value}")
    assert response.status_code == 422


def test_variant_422_does_not_need_report(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")
    assert TestClient(app).get(ROUTE, params={"payload_bytes": 65}).status_code == 422
    assert TestClient(app).get(ROUTE, params={"payload_bytes": 64}).status_code == 404


def test_variant_documented_in_openapi():
    params = app.openapi()["paths"][ROUTE]["get"]["parameters"]
    assert params[0]["name"] == "payload_bytes"
    assert params[0]["in"] == "query"
    assert params[0]["required"] is False


def test_variant_filter_does_not_change_file(report_file):
    before = lab.REPORT_PATH.read_bytes()
    TestClient(app).get(ROUTE, params={"payload_bytes": 1024})
    assert lab.REPORT_PATH.read_bytes() == before


# --- регресії практичних 1 і 2 ---------------------------------------------------------


def test_previous_routes_still_registered():
    paths = app.openapi()["paths"]
    for route in (
        "/health",
        "/api/v1/students",
        "/api/v1/students/{student_id}",
        "/api/v1/students/{student_id}/secure-notes",
        "/api/v1/students/{student_id}/secure-notes/{note_id}",
        "/api/v1/lab/crypto/benchmark-results",
    ):
        assert route in paths


def test_practice1_and_2_flow_still_works(client):
    student = client.post("/api/v1/students", json={
        "full_name": "Олена Коваль", "email": "olena.koval@example.com",
        "group_code": "КН-31", "enrollment_year": 2024,
    })
    assert student.status_code == 201
    student_id = student.json()["id"]
    note = client.post(f"/api/v1/students/{student_id}/secure-notes",
                       json={"text": "Вигадана примітка", "category": "academic"})
    assert note.status_code == 201
    read = client.get(f"/api/v1/students/{student_id}/secure-notes/{note.json()['id']}")
    assert read.status_code == 200
    assert read.json()["text"] == "Вигадана примітка"
