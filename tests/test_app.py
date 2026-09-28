import base64

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import Authentication, app, auth_headers, host_in_scope, storage_state_path, url_in_scope

client = TestClient(app)


def test_home_and_security_headers():
    response = client.get("/")
    assert response.status_code == 200
    assert "Know your portal" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_health_endpoint():
    assert client.get("/healthz").json() == {"status": "ok", "version": "1.0.0"}


@pytest.mark.parametrize(("candidate", "subdomains", "expected"), [
    ("example.com", False, True), ("app.example.com", False, False),
    ("app.example.com", True, True), ("badexample.com", True, False),
])
def test_host_scope(candidate, subdomains, expected):
    assert host_in_scope(candidate, "example.com", subdomains) is expected


def test_url_scope():
    assert url_in_scope("https://example.com/page", "example.com", False)
    assert not url_in_scope("file:///etc/passwd", "example.com", False)
    assert not url_in_scope("https://example.com.evil.test", "example.com", True)


def test_basic_auth_header():
    result = auth_headers(Authentication(mode="basic", username="user", password="secret"))
    assert result == {"Authorization": "Basic " + base64.b64encode(b"user:secret").decode()}


def test_forbidden_custom_header():
    with pytest.raises(ValueError):
        Authentication(mode="headers", headers={"Host": "evil.test"})


def test_storage_profile_rejects_path_traversal():
    with pytest.raises(HTTPException):
        storage_state_path("../secret")


def test_scan_rejects_embedded_credentials_before_network_access():
    response = client.post("/api/scan", json={"target": "https://user:secret@example.com"})
    assert response.status_code == 400
    assert "embedded credentials" in response.json()["detail"]


def test_scan_rejects_unsafe_port_before_network_access():
    response = client.post("/api/scan", json={"target": "https://example.com:22"})
    assert response.status_code == 400
    assert "port is not allowed" in response.json()["detail"]


def test_mutation_requires_acknowledgement(monkeypatch):
    async def allow_destination(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.main.validate_destination", allow_destination)
    response = client.post("/api/scan", json={"target": "https://example.com", "allow_mutations": True, "mutation_endpoint_allowlist": ["/test/"]})
    assert response.status_code == 400
    assert "acknowledgement" in response.json()["detail"]
