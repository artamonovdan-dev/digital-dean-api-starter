"""Синтетичні фікстури для тестів схеми; це НЕ дані експерименту студента."""
import copy
import json
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from app.api import hash_lab
from app.schemas.hash_report import validate_report
from app.security.hashing.profiles import CHECK_NAMES, PAYLOAD_SIZES, PROFILES

PATH = "/api/v1/lab/crypto/hash-benchmark-results"


def synthetic_report():
    results, avalanche, checks, statuses = [], [], [], []
    for algorithm, profile in PROFILES.items():
        statuses.append(dict(algorithm=algorithm, available=True,
                             reason=None, implementation="test.fixture"))
        for size in PAYLOAD_SIZES:
            for mode in ("whole", "chunked"):
                results.append(dict(algorithm=algorithm, mode=mode,
                    payload_bytes=size, digest_bytes=profile.digest_bytes,
                    repeats=100 if size == 1048576 else 1000,
                    median_ns=1000.0, iqr_ns=10.0,
                    throughput_mib_s=size * 1e9 / (2**20 * 1000.0)))
        n = 8 * profile.digest_bytes
        avalanche.append(dict(algorithm=algorithm, input_bytes=1024, trials=100,
            digest_bits=n, min_flipped_bits=n//2-1, max_flipped_bits=n//2+1,
            mean_flipped_bits=n/2, mean_fraction=0.5))
        checks.extend(dict(algorithm=algorithm, name=name, passed=True)
                      for name in CHECK_NAMES)
    return dict(schema_version=1, created_at="2026-10-23T00:00:00Z",
        source_commit="a"*40, environment=dict(python="test", openssl_ssl="test",
            os="test", cpu="test", architecture="test"),
        parameters=dict(sizes=list(PAYLOAD_SIZES), chunk_bytes=16384, warmup=10,
            series=5, repeats_small=1000, repeats_large=100,
            avalanche_trials=100, avalanche_bytes=1024),
        algorithms=statuses, results=results, avalanche=avalanche, checks=checks)


def test_complete_schema_and_preservation_of_failed_check():
    data = synthetic_report()
    data["checks"][0]["passed"] = False
    report = validate_report(data)
    assert len(report.results) == 56 and report.checks[0].passed is False


def test_absent_legacy_profiles_have_no_fake_results():
    data = synthetic_report()
    for row in data["algorithms"]:
        if row["algorithm"] in ("md5", "sha1"):
            row.update(available=False, reason="not_available_in_environment",
                       implementation=None)
    for field in ("results", "avalanche", "checks"):
        data[field] = [x for x in data[field]
                       if x["algorithm"] not in ("md5", "sha1")]
    assert len(validate_report(data).results) == 40


@pytest.mark.parametrize("path,value", [
    (("schema_version",), True), (("schema_version",), 1.0),
    (("source_commit",), "not-a-commit"),
    (("created_at",), "2026-10-23T00:00:00"),
    (("created_at",), "2026-02-30T00:00:00Z"),
    (("parameters", "sizes"), [64, 1024, 65536, 65536]),
    (("parameters", "series"), 5.0),
    (("results", 0, "payload_bytes"), 65),
    (("results", 0, "digest_bytes"), 64),
    (("results", 0, "repeats"), 100),
    (("results", 0, "median_ns"), float("nan")),
    (("results", 0, "median_ns"), True),
    (("results", 0, "throughput_mib_s"), 1.0),
    (("avalanche", 0, "mean_fraction"), 0.25),
    (("avalanche", 0, "max_flipped_bits"), 257),
    (("checks", 0, "passed"), "true"),
    (("algorithms", 0, "available"), False),
])
def test_rejects_structural_and_semantic_inconsistency(path, value):
    data = synthetic_report()
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        validate_report(data)


@pytest.mark.parametrize("field", ["results", "avalanche", "checks", "algorithms"])
def test_rejects_duplicate_records(field):
    data = synthetic_report()
    data[field][-1] = copy.deepcopy(data[field][0])
    with pytest.raises(ValueError):
        validate_report(data)


def test_rejects_extra_secret_field():
    data = synthetic_report()
    data["private_key"] = "must not be accepted"
    with pytest.raises(ValueError):
        validate_report(data)


@pytest.mark.parametrize("content,status,detail", [
    (None, 404, "hash report not found"),
    (b"broken JSON", 500, "hash report invalid"),
    (b'{"schema_version":1,"schema_version":1}', 500, "hash report invalid"),
    (b'{"n":NaN}', 500, "hash report invalid"),
    (b" " * 1048577, 500, "hash report invalid"),
])
def test_bounded_reader_safe_errors(tmp_path, monkeypatch, content, status, detail):
    path = tmp_path / "report.json"
    if content is not None:
        path.write_bytes(content)
    monkeypatch.setattr(hash_lab, "REPORT_PATH", path)
    with pytest.raises(HTTPException) as error:
        hash_lab.load_report()
    assert error.value.status_code == status and error.value.detail == detail


def test_new_route_reads_valid_report(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(synthetic_report()), encoding="utf-8")
    monkeypatch.setattr(hash_lab, "REPORT_PATH", path)
    app = FastAPI()
    app.include_router(hash_lab.router)
    response = TestClient(app).get(PATH)
    assert response.status_code == 200
    body = response.json()
    assert len(body["results"]) == 56 and len(body["checks"]) == 42


def test_route_connected_to_same_existing_application():
    from app.main import app
    assert PATH in TestClient(app).get("/openapi.json").json()["paths"]


# --- власні перевірки схеми, API та варіанта 1 ----------------------------------------

from pathlib import Path  # noqa: E402

from app.main import app as main_app  # noqa: E402


@pytest.fixture
def report_on_disk(tmp_path, monkeypatch):
    path = tmp_path / "report.json"

    def write(data):
        path.write_text(json.dumps(data), encoding="utf-8")

    write(synthetic_report())
    monkeypatch.setattr(hash_lab, "REPORT_PATH", path)
    return write


def get(params=None):
    return TestClient(main_app).get(PATH, params=params)


def test_missing_matrix_row_rejected():
    data = synthetic_report()
    data["results"].pop()
    with pytest.raises(ValueError):
        validate_report(data)


def test_missing_check_rejected():
    data = synthetic_report()
    data["checks"].pop()
    with pytest.raises(ValueError):
        validate_report(data)


@pytest.mark.parametrize("value,ok", [
    ("2026-10-23T00:00:00Z", True), ("2026-10-23T00:00:00+00:00", True),
    ("2026-10-23T00:00:00+02:00", False), ("2026-10-23 00:00:00", False),
])
def test_created_at_timezone(value, ok):
    data = synthetic_report()
    data["created_at"] = value
    if ok:
        validate_report(data)
    else:
        with pytest.raises(ValueError):
            validate_report(data)


@pytest.mark.parametrize("path,value", [
    (("results", 0, "median_ns"), float("inf")),
    (("results", 0, "iqr_ns"), -1.0),
    (("results", 0, "median_ns"), 0.0),
    (("avalanche", 0, "min_flipped_bits"), 200),
    (("avalanche", 0, "digest_bits"), 128),
    (("algorithms", 5, "implementation"), "test.fixture-but-unavailable"),
])
def test_rejects_non_finite_and_inconsistent_values(path, value):
    data = synthetic_report()
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    if path[1] == 5:  # md5 недоступний, але має implementation — невалідно
        target["available"] = False
        target["reason"] = "not_available_in_environment"
    with pytest.raises(ValueError):
        validate_report(data)


def test_unavailable_legacy_with_fake_results_rejected():
    data = synthetic_report()
    row = next(x for x in data["algorithms"] if x["algorithm"] == "md5")
    row.update(available=False, reason="not_available_in_environment", implementation=None)
    with pytest.raises(ValueError):  # вимірювання недоступного профілю лишилися
        validate_report(data)


def test_api_full_report(report_on_disk):
    response = get()
    assert response.status_code == 200
    body = response.json()
    assert len(body["results"]) == 56 and len(body["avalanche"]) == 7 and len(body["checks"]) == 42
    assert body["summary"] is None


def test_api_keeps_failed_check_visible(report_on_disk):
    data = synthetic_report()
    data["checks"][3]["passed"] = False
    report_on_disk(data)
    assert get().json()["checks"][3]["passed"] is False


def test_api_safe_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(hash_lab, "REPORT_PATH", tmp_path / "absent.json")
    assert get().json() == {"detail": "hash report not found"}
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({**synthetic_report(), "results": []}), encoding="utf-8")
    monkeypatch.setattr(hash_lab, "REPORT_PATH", bad)
    response = get()
    assert response.status_code == 500
    assert response.json() == {"detail": "hash report invalid"}
    assert str(tmp_path) not in response.text and "Traceback" not in response.text


def test_route_does_not_run_or_import_benchmark(report_on_disk, monkeypatch):
    import benchmarks.hash_benchmark as bench

    def forbidden(*args, **kwargs):
        raise AssertionError("experiment must not run from HTTP")

    monkeypatch.setattr(bench, "run_experiment", forbidden)
    assert get().status_code == 200
    code = Path(hash_lab.__file__).read_text(encoding="utf-8").split('"""', 2)[2]
    assert "benchmarks" not in code and "run_experiment" not in code


def test_route_has_no_path_parameter(report_on_disk, tmp_path):
    response = get({"path": str(tmp_path / "other.json")})
    assert response.status_code == 200
    params = main_app.openapi()["paths"][PATH]["get"]["parameters"]
    assert [p["name"] for p in params] == ["payload_bytes"]


def test_openapi_response_model():
    schema = main_app.openapi()["paths"][PATH]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert schema["$ref"].endswith("/HashResponse")


# --- індивідуальний варіант 1: payload_bytes -------------------------------------------


@pytest.mark.parametrize("size", PAYLOAD_SIZES)
def test_variant_payload_filter(report_on_disk, size):
    response = get({"payload_bytes": size})
    assert response.status_code == 200
    body = response.json()
    assert len(body["results"]) == 14  # 7 профілів × 2 способи
    assert all(r["payload_bytes"] == size for r in body["results"])
    assert len(body["algorithms"]) == 7 and len(body["avalanche"]) == 7 and len(body["checks"]) == 42


def test_variant_filter_with_unavailable_legacy(report_on_disk):
    data = synthetic_report()
    for row in data["algorithms"]:
        if row["algorithm"] in ("md5", "sha1"):
            row.update(available=False, reason="not_available_in_environment", implementation=None)
    for field in ("results", "avalanche", "checks"):
        data[field] = [x for x in data[field] if x["algorithm"] not in ("md5", "sha1")]
    report_on_disk(data)
    body = get({"payload_bytes": 64}).json()
    assert len(body["results"]) == 10  # 2A при A=5
    assert len(body["algorithms"]) == 7


@pytest.mark.parametrize("value", ["65", "0", "-64", "2048", "abc", "true", "1024.5"])
def test_variant_invalid_payload_is_422(report_on_disk, value):
    assert TestClient(main_app).get(f"{PATH}?payload_bytes={value}").status_code == 422


def test_variant_422_before_reading_file(tmp_path, monkeypatch):
    monkeypatch.setattr(hash_lab, "REPORT_PATH", tmp_path / "absent.json")
    assert get({"payload_bytes": 65}).status_code == 422
    assert get({"payload_bytes": 64}).status_code == 404


def test_variant_full_validation_before_filter(report_on_disk):
    data = synthetic_report()
    next(r for r in data["results"] if r["payload_bytes"] == 65536)["throughput_mib_s"] = 1.0
    report_on_disk(data)
    # Помилка в рядку 65536 виявляється навіть при фільтрі 64.
    assert get({"payload_bytes": 64}).status_code == 500


def test_variant_documented_in_openapi():
    (param,) = main_app.openapi()["paths"][PATH]["get"]["parameters"]
    assert param["name"] == "payload_bytes" and param["in"] == "query" and param["required"] is False


# --- регресії практичних 1–3 ------------------------------------------------------------


def test_app_version_and_previous_routes():
    assert main_app.version == "0.4.0"
    paths = main_app.openapi()["paths"]
    for route in ("/health", "/api/v1/students", "/api/v1/students/{student_id}",
                  "/api/v1/students/{student_id}/secure-notes",
                  "/api/v1/students/{student_id}/secure-notes/{note_id}",
                  "/api/v1/lab/crypto/benchmark-results",
                  "/api/v1/lab/crypto/asymmetric-benchmark-results", PATH):
        assert route in paths


def test_previous_variant_filter_still_works():
    response = TestClient(main_app).get(
        "/api/v1/lab/crypto/asymmetric-benchmark-results", params={"payload_bytes": 65})
    assert response.status_code == 422


def test_own_measured_files_are_consistent_if_present():
    """Якщо власний експеримент уже запущено, raw.csv і report.json узгоджені."""
    import csv
    import benchmarks.hash_benchmark as bench

    folder = Path(hash_lab.REPORT_PATH).parent
    report_path, raw_path = folder / "report.json", folder / "raw.csv"
    if not (report_path.exists() and raw_path.exists()):
        return
    report = validate_report(json.loads(report_path.read_text(encoding="utf-8")))
    with raw_path.open(encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 5 * len(report.results)
    recomputed = {(r["algorithm"], r["mode"], r["payload_bytes"]): r for r in bench.aggregate_raw(rows)}
    for result in report.results:
        expected = recomputed[(result.algorithm, result.mode, result.payload_bytes)]
        assert result.median_ns == pytest.approx(expected["median_ns"])
        assert result.iqr_ns == pytest.approx(expected["iqr_ns"])
