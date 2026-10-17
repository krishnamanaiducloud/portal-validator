"""Operator approval is distinct from session metadata throughout real scans."""

import copy
import asyncio
import json
import logging
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from playwright.async_api import async_playwright

from app import main
from app.auth_policy import AUTH_POLICIES_FILE_ENV, AuthenticationPolicyConfigurationError
from app.logging_config import LOGGER
from app.main import ScanRequest, authentication_approvals_for_scan, execute_scan
from test_authenticated_spa import authenticated_spa


@pytest.fixture(autouse=True)
def isolated_operator_policy(monkeypatch):
    monkeypatch.delenv(AUTH_POLICIES_FILE_ENV, raising=False)


def configure_operator_policy(tmp_path, monkeypatch, *, portal="portal.example", identity="identity.example", endpoints=()):
    path = tmp_path / "operator-authentication.json"
    path.write_text(json.dumps({"version": 1, "policies": [{
        "id": "operator-sso",
        "portal_hosts": [portal],
        "authentication_hosts": [identity],
        "authentication_endpoints": list(endpoints),
    }]}), encoding="utf-8")
    monkeypatch.setenv(AUTH_POLICIES_FILE_ENV, str(path))
    return path


@pytest.mark.parametrize("target,matched", [
    ("portal.example", True), ("PORTAL.EXAMPLE.", True),
    ("child.portal.example", False), ("portal.example.evil", False), ("unrelated.example", False),
])
def test_main_policy_resolution_is_exact_and_independent_of_profile_contents(tmp_path, monkeypatch, target, matched):
    endpoint = "https://identity.example/custom/acs"
    configure_operator_policy(tmp_path, monkeypatch, endpoints=[endpoint])
    request = ScanRequest(
        target="https://" + target, allow_subdomains=True,
        authentication_hosts=["manual.example"],
        authentication={"mode": "storage_state", "storage_profile": "private-profile"},
    )
    original = request.model_copy(deep=True)

    def forbidden_profile_access(*_args, **_kwargs):
        raise AssertionError("Session state must not establish authentication approval")

    monkeypatch.setattr(main, "storage_state_path", forbidden_profile_access)
    hosts, endpoints, counts = authentication_approvals_for_scan(request, target)
    assert hosts == (["manual.example", "identity.example"] if matched else ["manual.example"])
    assert endpoints == (frozenset({endpoint}) if matched else frozenset())
    assert counts == {
        "submitted_authentication_host_count": 1,
        "operator_authentication_host_count": int(matched),
        "operator_authentication_policy_count": int(matched),
        "operator_authentication_endpoint_count": int(matched),
    }
    assert request == original
    assert authentication_approvals_for_scan(request, target) == (hosts, endpoints, counts)


def test_missing_optional_policy_preserves_manual_approvals_without_mutating_request():
    request = ScanRequest(target="portal.example", authentication_hosts=["identity.example"])
    original = request.model_copy(deep=True)
    hosts, endpoints, counts = authentication_approvals_for_scan(request, "portal.example")
    assert hosts == request.authentication_hosts == ["identity.example"]
    assert endpoints == frozenset()
    assert counts == {
        "submitted_authentication_host_count": 1,
        "operator_authentication_host_count": 0,
        "operator_authentication_policy_count": 0,
        "operator_authentication_endpoint_count": 0,
    }
    hosts.append("unapproved.example")
    assert request == original


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", ["missing", "malformed", "unsupported"])
async def test_invalid_operator_policy_fails_before_dns_or_browser(tmp_path, monkeypatch, configured):
    path = tmp_path / "do-not-echo-secret.json"
    if configured != "missing":
        path.write_text("do-not-echo-secret" if configured == "malformed" else
                        '{"version":999,"policies":[]}', encoding="utf-8")
    monkeypatch.setenv(AUTH_POLICIES_FILE_ENV, str(path))

    async def forbidden_dns(*_args, **_kwargs):
        raise AssertionError("Invalid authorization must fail before network access")

    def forbidden_browser(*_args, **_kwargs):
        raise AssertionError("Invalid authorization must fail before browser startup")

    monkeypatch.setattr(main, "resolve_and_validate", forbidden_dns)
    monkeypatch.setattr(main, "async_playwright", forbidden_browser)
    with pytest.raises(HTTPException) as error:
        await execute_scan(ScanRequest(target="https://portal.example"))
    assert error.value.status_code == 503
    assert error.value.detail == "Administrator authentication policy is invalid"
    assert "do-not-echo-secret" not in str(error.value)


def test_invalid_policy_is_rejected_before_creating_scan_job(tmp_path, monkeypatch):
    def forbidden_job(*_args, **_kwargs):
        raise AssertionError("An invalid operator policy must not queue a scan")

    monkeypatch.setattr(main.SCAN_REGISTRY, "create", forbidden_job)
    with TestClient(main.app) as client:
        # A projected policy can become invalid after a successful startup.
        monkeypatch.setenv(AUTH_POLICIES_FILE_ENV, str(tmp_path / "missing-policy.json"))
        response = client.post("/api/scans", json={"target": "https://portal.example"})
    assert response.status_code == 503
    assert response.json() == {"detail": "Administrator authentication policy is invalid"}
    assert "missing-policy.json" not in response.text


def test_invalid_policy_also_fails_application_startup(tmp_path, monkeypatch):
    monkeypatch.setenv(AUTH_POLICIES_FILE_ENV, str(tmp_path / "missing-policy.json"))
    with pytest.raises(AuthenticationPolicyConfigurationError):
        with TestClient(main.app):
            raise AssertionError("Startup must not succeed without configured authorization")


@pytest.mark.parametrize("identifier", ["fixture", "unknown", "%2e%2e%2fsecret"])
def test_profile_cookie_host_metadata_endpoint_is_not_exposed(monkeypatch, identifier):
    def forbidden_profile_access(*_args, **_kwargs):
        raise AssertionError("The nonexistent host metadata endpoint must not inspect profiles")

    monkeypatch.setattr(main, "storage_state_path", forbidden_profile_access)
    monkeypatch.setattr(main, "discover_storage_profiles", forbidden_profile_access)
    with TestClient(main.app) as client:
        response = client.get(f"/api/auth-profiles/{identifier}/hosts")
    assert response.status_code == 404
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"detail": "Not Found"}


async def require_browser():
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")


def scan_request(origins, **overrides):
    values = dict(
        target=origins["portal"], allow_private_networks=True,
        authentication={"mode": "storage_state", "storage_profile": "fixture"},
        approved_read_post_operations=[{"host": "127.0.0.1", "path": "/api/read"}],
        max_pages=20, max_depth=3, max_navigation_actions=12, max_discovery_scrolls=0,
        timeout_ms=15000, total_timeout_ms=90000, readiness_selector='[data-app-ready="true"]',
        render_settle_ms=100, min_observation_ms=200, network_quiet_ms=100, check_security_headers=False,
    )
    values.update(overrides)
    return ScanRequest(**values)


def append_unrelated_profile_state(profile):
    state = json.loads(profile.read_text(encoding="utf-8"))
    state["cookies"].append({
        "domain": "unapproved.example", "name": "unrelated", "value": "fixture-private-unrelated",
        "path": "/", "expires": -1, "httpOnly": True, "secure": True, "sameSite": "Lax",
    })
    state["origins"].append({
        "origin": "https://unapproved.example", "localStorage": [
            {"name": "unrelated", "value": "fixture-private-local-storage"},
        ],
    })
    profile.write_text(json.dumps(state), encoding="utf-8")


@pytest.mark.asyncio
async def test_operator_policy_authorizes_sso_and_spa_without_profile_host_inference(
    authenticated_spa, tmp_path, monkeypatch, caplog,
):
    await require_browser()
    origins, receipts = authenticated_spa
    endpoints = [origins["identity"] + "/oauth/token", origins["identity"] + "/saml/consume"]
    policy = configure_operator_policy(tmp_path, monkeypatch, portal="127.0.0.1", identity="localhost", endpoints=endpoints)
    policy_before = policy.read_bytes()
    profile = main.AUTH_STATE_DIR / "fixture.json"
    append_unrelated_profile_state(profile)
    profile_before = profile.read_bytes()
    request = scan_request(origins)
    request_before = request.model_copy(deep=True)
    scoped_states = []
    original_options = main.browser_context_options

    def capture_scope(state_path, approved_storage_hosts=None):
        options = original_options(state_path, approved_storage_hosts)
        scoped_states.append(copy.deepcopy(options.get("storage_state")))
        return options

    monkeypatch.setattr(main, "browser_context_options", capture_scope)
    caplog.set_level(logging.DEBUG, logger=LOGGER.name)
    LOGGER.addHandler(caplog.handler)
    try:
        report = await execute_scan(request)
    finally:
        LOGGER.removeHandler(caplog.handler)
    assert request == request_before and request.authentication_hosts == []
    assert profile.read_bytes() == profile_before and policy.read_bytes() == policy_before
    assert len(scoped_states) == 1
    assert {cookie["domain"] for cookie in scoped_states[0]["cookies"]} == {"localhost"}
    assert scoped_states[0]["origins"] == []
    assert report["scan_configuration"]["authentication_host_count"] == 1
    assert {key: report["scan_configuration"][key] for key in (
        "submitted_authentication_host_count", "operator_authentication_host_count",
        "operator_authentication_policy_count", "operator_authentication_endpoint_count",
    )} == {
        "submitted_authentication_host_count": 0,
        "operator_authentication_host_count": 1,
        "operator_authentication_policy_count": 1,
        "operator_authentication_endpoint_count": 2,
    }
    configuration = json.dumps(report["scan_configuration"])
    assert "authentication_hosts" not in report["scan_configuration"]
    assert "authentication_endpoints" not in report["scan_configuration"]
    assert "unapproved.example" not in configuration
    assert all(endpoint not in configuration for endpoint in endpoints)
    results = report["results"]
    assert len(results) == 7
    assert all(route["application_ready"] for route in results)
    assert {urlsplit(route["final_url"]).fragment for route in results} >= {
        "/overview", "/activity", "/reports", "/dynamic",
    }
    assert {route["route_name"] for route in results if route["view_type"] == "UI_TAB"} == {
        "Summary panel", "History panel",
    }
    assert all("ROUTE_DISCOVERY" in [event["state"] for event in route["browser_lifecycle"]["events"]]
               for route in results)
    assert sum(role == "identity" and method == "POST" and path == "/oauth/token"
               for role, method, path in receipts) == 1
    assert sum(role == "identity" and method == "POST" and path == "/saml/consume"
               for role, method, path in receipts) == 1
    assert not any(method == "POST" and path == "/api/write" for _, method, path in receipts)
    inventory = {item["endpoint"]: item for item in report["api_inventory"]}
    assert inventory["/api/shared"]["status_2xx"] >= 7
    assert inventory["/api/read"]["status_2xx"] >= 7
    assert inventory["/api/failure"]["status_5xx"] == 1
    assert inventory["/api/write"]["blocked_calls"] >= 7
    assert "fixture-private" not in json.dumps(report)
    assert "fixture-private" not in caplog.text
    assert all(report["summary"]["counter_invariants"].values())


@pytest.mark.asyncio
async def test_session_cookies_without_operator_or_manual_approval_never_authorize_sso(authenticated_spa):
    await require_browser()
    origins, receipts = authenticated_spa
    profile = main.AUTH_STATE_DIR / "fixture.json"
    append_unrelated_profile_state(profile)
    profile_before = profile.read_bytes()
    request = scan_request(origins, max_pages=1, total_timeout_ms=30000)
    request_before = request.model_copy(deep=True)
    report = await execute_scan(request)
    assert request == request_before and request.authentication_hosts == []
    assert profile.read_bytes() == profile_before
    assert report["scan_configuration"]["authentication_host_count"] == 0
    assert report["scan_configuration"]["operator_authentication_host_count"] == 0
    assert report["scan_configuration"]["operator_authentication_policy_count"] == 0
    assert report["summary"]["application_routes_validated"] == 0
    assert not report["summary"]["coverage_complete"]
    assert not any(role == "identity" and method == "POST" for role, method, _ in receipts)
    assert "fixture-private" not in json.dumps(report)


@pytest.mark.asyncio
async def test_operator_approved_bootstrap_cancellation_preserves_partial_report_and_closes_context(
    authenticated_spa, tmp_path, monkeypatch,
):
    await require_browser()
    origins, _receipts = authenticated_spa
    configure_operator_policy(tmp_path, monkeypatch, portal="127.0.0.1", identity="localhost")
    entered = asyncio.Event()
    pending_capture = asyncio.Event()
    cancelled = asyncio.Event()
    observed_pages = []

    async def blocked_capture(page):
        observed_pages.append(page)
        entered.set()
        await pending_capture.wait()
        raise AssertionError("A cancelled readiness inspection must not resume")

    monkeypatch.setattr(main, "capture_render_health", blocked_capture)
    request = scan_request(origins, timeout_ms=30000, total_timeout_ms=60000)
    request_before = request.model_copy(deep=True)
    task = asyncio.create_task(execute_scan(request, cancel_event=cancelled))
    try:
        await asyncio.wait_for(entered.wait(), timeout=30)
        cancelled.set()
        report = await asyncio.wait_for(task, timeout=10)
    finally:
        cancelled.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert request == request_before and request.authentication_hosts == []
    assert report["summary"]["termination_reason"] == "USER_CANCELLED"
    assert report["summary"]["scan_completeness"] == "CANCELLED"
    assert report["summary"]["healthy_routes"] == 0
    assert report["summary"]["routes_validated"] == 0
    assert report["summary"]["routes_not_tested"] == 1
    assert report["summary"]["not_tested_reason_counts"] == {"NOT_TESTED_CANCELLED": 1}
    assert not report["summary"]["coverage_complete"]
    assert report["results"] == []
    assert all(route["classification"] == "NOT_TESTED" for route in report["route_inventory"])
    assert observed_pages and all(page.is_closed() for page in observed_pages)
    assert not main.SCAN_LIMITER._active and not main.SCAN_LIMITER._waiting
    assert "fixture-private" not in json.dumps(report)
    assert "application shutdown" not in json.dumps(report)
    assert all(report["summary"]["counter_invariants"].values())
