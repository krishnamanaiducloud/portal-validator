import pytest

from app.authentication import (
    AuthenticationConfigurationError,
    build_authentication_manager,
)
from app.main import ScanRequest


def test_route_limit_has_one_request_scoped_default():
    assert ScanRequest(target="https://portal.example.com").max_pages == 50


def test_bearer_provider_normalizes_scheme_and_uses_exact_credential_scope():
    manager = build_authentication_manager(
        mode="bearer",
        credential_hosts={"portal.example.com"},
        token="Bearer secret-value",
    )
    approved = manager.headers_for_request({}, "portal.example.com")
    assert approved == {"Authorization": "Bearer secret-value"}
    assert "Bearer Bearer" not in approved["Authorization"]
    assert manager.headers_for_request({}, "www.portal.example.com") == {}
    assert manager.headers_for_request({}, "external.example.net") == {}


def test_bearer_provider_does_not_leak_owned_header_across_redirect():
    manager = build_authentication_manager(
        mode="bearer",
        credential_hosts={"portal.example.com"},
        token="secret-value",
    )
    headers = manager.headers_for_request(
        {"Authorization": "Bearer secret-value", "Accept": "text/html"},
        "identity.example.net",
    )
    assert headers == {"Accept": "text/html"}


def test_session_provider_preserves_application_generated_authorization():
    manager = build_authentication_manager(
        mode="storage_state",
        credential_hosts={"portal.example.com"},
    )
    headers = manager.headers_for_request(
        {"Authorization": "Bearer application-owned", "Accept": "application/json"},
        "api.example.net",
    )
    assert headers["Authorization"] == "Bearer application-owned"


def test_explicit_api_credential_host_receives_bearer_token():
    manager = build_authentication_manager(
        mode="bearer",
        credential_hosts={"portal.example.com", "api.example.net"},
        token="secret-value",
    )
    assert manager.headers_for_request({}, "api.example.net")["Authorization"].startswith(
        "Bearer "
    )


def test_provider_representations_never_include_secrets():
    token = "never-print-this-token"
    manager = build_authentication_manager(
        mode="bearer",
        credential_hosts={"portal.example.com"},
        token=token,
    )
    assert token not in repr(manager)
    assert token not in repr(manager.provider)


def test_empty_bearer_token_fails_without_echoing_input():
    manager = build_authentication_manager(
        mode="bearer",
        credential_hosts={"portal.example.com"},
        token="Bearer   ",
    )
    with pytest.raises(AuthenticationConfigurationError, match="requires a token"):
        manager.configured_headers()
