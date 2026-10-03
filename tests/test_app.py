import base64

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import (
    Authentication,
    ScanRequest,
    app,
    auth_headers,
    classify_page_result,
    evaluate_navigation_scope,
    host_in_scope,
    normalized_host,
    sanitized_diagnostic,
    sanitized_url,
    storage_state_path,
    url_in_scope,
)

client = TestClient(app)


def test_home_and_security_headers():
    response = client.get("/")
    assert response.status_code == 200
    assert "Know your portal" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_health_endpoint():
    assert client.get("/healthz").json() == {"status": "ok", "version": "1.1.3"}


@pytest.mark.parametrize(("candidate", "root", "subdomains", "expected"), [
    ("example.com", "example.com", False, True),
    ("www.example.com", "example.com", False, True),
    ("example.com", "www.example.com", False, True),
    ("www.google.com", "google.com", False, True),
    ("google.com", "www.google.com", False, True),
    ("api.example.com", "example.com", False, False),
    ("api.example.com", "example.com", True, True),
    ("EXAMPLE.COM", "example.com", False, True),
    ("example.com.", "example.com", False, True),
    ("example.com.evil.com", "example.com", True, False),
    ("evilexample.com", "example.com", True, False),
    ("example.com.attacker.example", "example.com", True, False),
    ("notexample.com", "example.com", True, False),
    ("example.co.uk", "co.uk", True, False),
])
def test_host_scope(candidate, root, subdomains, expected):
    assert host_in_scope(candidate, root, subdomains) is expected


def test_host_normalization():
    assert normalized_host(" EXAMPLE.COM. ") == "example.com"


def test_url_scope():
    assert url_in_scope("https://example.com/page", "example.com", False)
    assert url_in_scope("http://www.example.com:8080/page", "example.com", False)
    assert url_in_scope("https://example.com:443/page", "www.example.com", False)
    assert not url_in_scope("file:///etc/passwd", "example.com", False)
    assert not url_in_scope("https://example.com.evil.test", "example.com", True)


def test_www_redirect_is_in_scope():
    requested, final, accepted = evaluate_navigation_scope(
        "https://google.com",
        "https://www.google.com/",
        "google.com",
        False,
    )
    assert (requested, final, accepted) == ("google.com", "www.google.com", True)


def test_unrelated_redirect_is_out_of_scope():
    requested, final, accepted = evaluate_navigation_scope(
        "https://example.com",
        "https://different-company.example/login?token=secret",
        "example.com",
        True,
    )
    assert (requested, final, accepted) == (
        "example.com",
        "different-company.example",
        False,
    )


@pytest.mark.parametrize(("target", "expected"), [
    ("google.com", "https://google.com"),
    ("www.google.com", "https://www.google.com"),
    ("//google.com/path", "https://google.com/path"),
    ("https://google.com", "https://google.com"),
    ("http://google.com", "http://google.com"),
])
def test_target_input_normalization(target, expected):
    assert ScanRequest(target=target).target == expected


def test_urls_and_errors_remove_credentials_and_query_secrets():
    value = "https://user:password@example.com/path?token=secret#fragment"
    assert sanitized_url(value) == "https://example.com/path"
    assert sanitized_diagnostic(f"Navigation failed at {value}") == (
        "Navigation failed at https://example.com"
    )


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


def test_tls_failure_has_distinct_load_and_validation_statuses():
    result = classify_page_result(
        url="https://portal.example.com",
        status=None,
        error="Page.goto: net::ERR_CERT_AUTHORITY_INVALID",
        missing_security_headers=[],
        console_errors=[],
        failed_resources=[],
        security_headers_tested=True,
    )

    assert result == {
        "page_load_status": "FAILED_TO_LOAD",
        "validation_status": "NOT_TESTED",
        "category": "TLS_CERTIFICATE_ERROR",
        "tls_status": "UNTRUSTED",
        "tls_basis": "BROWSER_CERTIFICATE_VALIDATION",
        "tls_detail": "Chromium rejected the HTTPS certificate chain.",
        "security_headers_status": "NOT_TESTED",
        "findings": 0,
        "passed": False,
    }


def test_loaded_page_with_optional_findings_is_warning_not_load_failure():
    result = classify_page_result(
        url="https://portal.example.com",
        status=200,
        error=None,
        missing_security_headers=["content-security-policy"],
        console_errors=["optional widget failed"],
        failed_resources=[],
        security_headers_tested=True,
    )

    assert result["page_load_status"] == "LOADED"
    assert result["tls_status"] == "TRUSTED"
    assert result["validation_status"] == "WARNING"
    assert result["security_headers_status"] == "WARNING"
    assert result["findings"] == 2
    assert result["passed"] is True


def test_failed_subresource_is_warning_not_main_document_failure():
    result = classify_page_result(
        url="https://portal.example.com",
        status=200,
        error=None,
        missing_security_headers=[],
        console_errors=[],
        failed_resources=[{
            "url": "https://analytics.example.net/script.js",
            "error": "net::ERR_BLOCKED_BY_CLIENT.Inspector",
            "resource_type": "script",
            "main_document": False,
        }],
        security_headers_tested=True,
    )

    assert result["page_load_status"] == "LOADED"
    assert result["validation_status"] == "WARNING"
    assert result["category"] == "VALIDATION_FINDINGS"
    assert result["findings"] == 1


def test_main_document_navigation_failure_is_failed_to_load():
    result = classify_page_result(
        url="https://portal.example.com",
        status=None,
        error="Page.goto: net::ERR_NAME_NOT_RESOLVED",
        missing_security_headers=[],
        console_errors=[],
        failed_resources=[{
            "url": "https://portal.example.com",
            "error": "net::ERR_NAME_NOT_RESOLVED",
            "resource_type": "document",
            "main_document": True,
        }],
        security_headers_tested=True,
    )

    assert result["page_load_status"] == "FAILED_TO_LOAD"
    assert result["validation_status"] == "NOT_TESTED"
    assert result["category"] == "PAGE_LOAD_ERROR"
    assert result["tls_status"] == "NOT_TESTED"


def test_loaded_http_error_is_validation_failure():
    result = classify_page_result(
        url="https://portal.example.com/missing",
        status=404,
        error=None,
        missing_security_headers=[],
        console_errors=[],
        failed_resources=[],
        security_headers_tested=False,
    )

    assert result["page_load_status"] == "LOADED"
    assert result["validation_status"] == "FAIL"
    assert result["category"] == "HTTP_ERROR"
    assert result["security_headers_status"] == "NOT_TESTED"
    assert result["findings"] == 1
