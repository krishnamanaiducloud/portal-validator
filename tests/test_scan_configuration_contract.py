import time

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.mark.parametrize("endpoint", ["/api/scans", "/api/scan"])
def test_exact_authentication_hosts_reach_scan_engine(monkeypatch, endpoint):
    accepted = []

    async def capture(req, **kwargs):
        accepted.append(req)
        return {"pages": 0, "results": [], "summary": {}, "accepted": True}

    monkeypatch.setattr("app.main.execute_scan", capture)
    with TestClient(app) as client:
        response = client.post(endpoint, json={
            "target": "portal.example", "authentication_hosts": [
                "LOGIN.EXAMPLE.", "identity.example", "login.example",
            ], "authentication": {"mode": "none"},
        })
        assert response.status_code == (202 if endpoint == "/api/scans" else 200)
        for _ in range(100):
            if accepted:
                break
            time.sleep(0.01)
        assert len(accepted) == 1
        assert accepted[0].authentication_hosts == ["login.example", "identity.example"]
        assert accepted[0].authentication.mode == "none"


@pytest.mark.parametrize("field", ["authenticationHosts", "authentiction_hosts"])
def test_unknown_configuration_fields_are_not_silently_discarded(field):
    with TestClient(app) as client:
        response = client.post("/api/scans", json={
            "target": "portal.example", field: ["identity.example"],
        })
    assert response.status_code == 422
    assert response.json()["errors"][0]["code"] == "extra_forbidden"


@pytest.mark.parametrize("invalid", [
    {"authentication": {"mode": "headers", "headers": {"Host": "do-not-echo-secret"}}},
    {"authentication_hosts": ["https://user:do-not-echo-secret@identity.example/auth"]},
    {"authentication": {"mode": "bearer", "token": "do-not-echo-secret", "unknown": "do-not-echo-secret"}},
    {"do-not-echo-secret": {"password": "do-not-echo-secret"}},
])
def test_validation_errors_do_not_echo_secrets_or_unknown_field_names(invalid):
    with TestClient(app) as client:
        response = client.post("/api/scans", json={"target": "portal.example", **invalid})
    assert response.status_code == 422
    assert "do-not-echo-secret" not in response.text
    assert "input" not in response.text
    assert isinstance(response.json()["detail"], str)


@pytest.mark.parametrize("profile", [None, "missing"])
def test_missing_sso_profile_rejected_before_job_or_browser(monkeypatch, tmp_path, profile):
    monkeypatch.setattr("app.main.AUTH_STATE_DIR", tmp_path)

    async def forbidden(*args, **kwargs):
        raise AssertionError("No scan/browser/network activity is permitted for a missing profile")

    monkeypatch.setattr("app.main.execute_scan", forbidden)
    with TestClient(app) as client:
        response = client.post("/api/scans", json={
            "target": "portal.example", "authentication": {
                "mode": "storage_state", "storage_profile": profile,
            },
        })
        assert response.status_code == 202
        created = response.json()
        report = client.get(created["report_url"]).json()
    assert created["state"] == report["scan_status"] == "FAILED"
    assert report["authentication_error"]["category"] == "AUTHENTICATION_CONFIGURATION_ERROR"
    assert report["results"] == []


def test_malformed_sso_profile_rejected_before_job(monkeypatch, tmp_path):
    (tmp_path / "session.json").write_text('{"cookies":"do-not-echo-secret"}')
    monkeypatch.setattr("app.main.AUTH_STATE_DIR", tmp_path)
    with TestClient(app) as client:
        response = client.post("/api/scans", json={
            "target": "portal.example", "authentication": {
                "mode": "storage_state", "storage_profile": "session",
            },
        })
        assert response.status_code == 202
        report = client.get(response.json()["report_url"]).json()
    assert report["scan_status"] == "FAILED"
    assert report["authentication_error"]["category"] == "AUTHENTICATION_CONFIGURATION_ERROR"
    assert "do-not-echo-secret" not in response.text
    assert "do-not-echo-secret" not in str(report)
