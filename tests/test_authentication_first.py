"""Authentication/readiness is a scan-wide gate, not an application route.

All destinations and state here belong to isolated, generic local fixtures.
No real portal credentials, corporate domains, or external IdPs are used.
"""

import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit

import pytest

from app import main, security
from app.main import ScanRequest, execute_scan
from app.scans import ScanJob
from test_authenticated_spa import authenticated_spa, scan_fixture
from test_public_access_scan import require_browser
from test_scan_post_lifecycle import scanner_logs


@pytest.fixture
def authentication_first_site(tmp_path, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        receipts = Counter()
        expire_session = False
        include_denied = True
        reject_required_api = False

        def reply(self, status, body, content_type="text/html", **headers):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            for name, value in headers.items():
                self.send_header(name.replace("_", "-"), value)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            path = urlsplit(self.path).path
            type(self).receipts[("GET", path)] += 1
            if path in {"/login", "/03-expired"}:
                status = 401 if path == "/03-expired" else 200
                return self.reply(status, '''<!doctype html><title>Account sign in</title>
                    <main><h1>Sign in required</h1><form><input type="password"></form>
                    <nav><a href="/must-not-crawl">Protected destination</a></nav></main>
                    <script>fetch('/api/login-configuration')</script>''')
            if path == "/idp-unavailable":
                return self.reply(302, "", Location=f"http://localhost:{self.server.server_port}/oauth/authorize")
            if path == "/oauth/authorize":
                return self.reply(503, "<main><h1>Identity service temporarily unavailable</h1></main>")
            if path == "/01-denied":
                return self.reply(403, '''<!doctype html><title>Permission required</title>
                    <main><h1>Permission required for this report</h1>
                    <p>The current account lacks this view's role.</p></main>''')
            if path == "/02-authorized":
                return self.reply(200, '''<!doctype html><title>Authorized details</title>
                    <main data-app-ready="true"><h1>Authorized details</h1>
                    <p>Independent authorized application view.</p></main>
                    <script>Promise.allSettled([fetch('/api/denied'),fetch('/api/failure')])</script>''')
            if path.startswith("/api/"):
                status = {"/api/denied": 403, "/api/failure": 502,
                          "/api/session": 401 if self.reject_required_api else 200}.get(path, 200)
                return self.reply(status, '{"fixture":true}', "application/json")
            links = '<a href="/01-denied">Restricted reports</a>' if self.include_denied else ''
            links += '<a href="/02-authorized">Authorized details</a>'
            if self.expire_session:
                links += '<a href="/03-expired">Session renewal</a>'
            return self.reply(200, '''<!doctype html><title>Generic application</title>
                <main data-app-ready="true"><h1>Generic application</h1>
                <p>Ready application content.</p><nav>''' + links +
                '</nav></main><script>fetch("/api/session")</script>')

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = main.resolve_and_validate

    async def fixture_resolver(host, allow_private):
        if host in {"127.0.0.1", "localhost"}:
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_resolver)
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "authorized.json").write_text(json.dumps({
        "cookies": [{"name": "session", "value": "fixture-private-session", "domain": "127.0.0.1",
                     "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"}],
        "origins": [],
    }), encoding="utf-8")
    monkeypatch.setattr(main, "AUTH_STATE_DIR", profiles)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request_for(target, **overrides):
    values = dict(
        target=target, allow_private_networks=True, max_pages=12, max_depth=3,
        timeout_ms=10000, total_timeout_ms=45000, readiness_timeout_ms=1000,
        render_settle_ms=100, min_observation_ms=100, network_quiet_ms=50,
        max_discovery_scrolls=0, max_navigation_actions=8, check_security_headers=False,
    )
    values.update(overrides)
    return ScanRequest(**values)


def assert_authentication_failure(report, category):
    assert report["scan_status"] == "FAILED"
    assert report["authentication_status"] == "FAILED"
    assert report["authentication_error"]["category"] == category
    assert report["authentication_error"]["stage"]
    assert report["authentication_error"]["remediation"]
    assert isinstance(report["authentication_error"]["duration_ms"], (int, float))
    assert report["pages"] == 0
    assert report["results"] == report["route_inventory"] == []
    assert report["api_inventory"] == report["business_api_inventory"] == []
    assert report["api_request_occurrences"] == []
    assert report["summary"]["routes_discovered"] == 0
    assert report["summary"]["routes_validated"] == 0
    assert report["summary"]["routes_tested"] == 0
    assert report["coverage"]["discovery_status"] == "NOT_STARTED"
    assert report["coverage"]["validation_status"] == "NOT_STARTED"
    assert not report["summary"]["coverage_complete"]
    assert report["summary"]["healthy_routes"] == 0
    assert "fixture-private" not in json.dumps(report)
    assert report["scan_lifecycle"]["state"] == "FAILED"
    assert report["scan_lifecycle"]["events"][-1]["state"] == "FAILED"


@pytest.mark.asyncio
async def test_login_http_200_has_zero_routes_and_never_runs_discovery(authentication_first_site, monkeypatch):
    await require_browser()
    origin, handler = authentication_first_site
    discovery_calls = []

    async def forbidden_discovery(*_args, **_kwargs):
        discovery_calls.append(True)
        raise AssertionError("No DOM route discovery is permitted before authentication")

    monkeypatch.setattr(main, "discover_page_routes", forbidden_discovery)
    monkeypatch.setattr(main, "expand_safe_navigation", forbidden_discovery)
    progress = []

    async def collect_progress(state, **_values):
        progress.append(state)

    report = await execute_scan(request_for(origin + "/login"), progress_callback=collect_progress)
    assert_authentication_failure(report, "AUTHENTICATION_FAILED")
    assert discovery_calls == []
    assert not any(state in {"DISCOVERING", "DISCOVERING_ROUTES", "VALIDATING", "VALIDATING_ROUTES"} for state in progress)
    assert handler.receipts[("GET", "/must-not-crawl")] == 0


@pytest.mark.asyncio
async def test_missing_application_readiness_has_zero_routes_without_passive_discovery(authentication_first_site, monkeypatch):
    await require_browser()
    origin, _handler = authentication_first_site
    discovery_calls = []

    async def forbidden_discovery(*_args, **_kwargs):
        discovery_calls.append(True)
        raise AssertionError("Readiness cannot be replaced by passive route collection")

    monkeypatch.setattr(main, "discover_page_routes", forbidden_discovery)
    monkeypatch.setattr(main, "expand_safe_navigation", forbidden_discovery)
    report = await execute_scan(request_for(origin, readiness_selector="[data-missing-shell]"))
    assert_authentication_failure(report, "APPLICATION_NOT_READY")
    assert discovery_calls == []


@pytest.mark.asyncio
async def test_http_200_shell_does_not_accept_rejected_profile_session_api(authentication_first_site, monkeypatch):
    await require_browser()
    origin, handler = authentication_first_site
    handler.reject_required_api = True

    async def forbidden_discovery(*_args, **_kwargs):
        raise AssertionError("A rejected required session API must stop discovery")

    monkeypatch.setattr(main, "discover_page_routes", forbidden_discovery)
    monkeypatch.setattr(main, "expand_safe_navigation", forbidden_discovery)
    report = await execute_scan(request_for(origin, authentication={
        "mode": "storage_state", "storage_profile": "authorized",
    }))
    assert_authentication_failure(report, "SESSION_EXPIRED")
    assert report["authentication_error"]["http_status"] == 401
    assert report["authentication_error"]["method"] == "GET"
    assert report["authentication_error"]["endpoint"].endswith("/api/session")
    assert handler.receipts[("GET", "/02-authorized")] == 0


@pytest.mark.asyncio
async def test_failed_current_scan_never_reuses_previous_successful_routes(authentication_first_site):
    await require_browser()
    origin, handler = authentication_first_site
    handler.include_denied = False
    successful = await execute_scan(request_for(origin), scan_id="fixture-successful-scan")
    failed = await execute_scan(request_for(origin + "/login"), scan_id="fixture-failed-scan")
    assert successful["scan_id"] == "fixture-successful-scan"
    assert successful["results"]
    assert failed["scan_id"] == "fixture-failed-scan"
    assert_authentication_failure(failed, "AUTHENTICATION_FAILED")
    assert successful["results"], "Finalizing the current scan must not mutate a previous report"


@pytest.mark.asyncio
async def test_route_403_is_authorization_denied_and_other_routes_continue(authentication_first_site):
    await require_browser()
    origin, handler = authentication_first_site
    report = await execute_scan(request_for(origin))
    assert report["scan_status"] != "FAILED"
    routes = {urlsplit(route["requested_url"]).path or "/": route for route in report["results"]}
    assert set(routes) == {"/", "/01-denied", "/02-authorized"}
    denied = routes["/01-denied"]
    assert denied["status"] == 403
    assert denied["classification"] == "AUTHORIZATION_DENIED"
    assert denied["validation_status"] == "FAIL"
    assert routes["/02-authorized"]["page_load_status"] == "LOADED"
    assert handler.receipts[("GET", "/02-authorized")] == 1
    failures = {event["endpoint"]: event for event in report["api_request_occurrences"] if event.get("status") in {403, 502}}
    assert failures["/api/denied"]["status"] == 403
    assert failures["/api/failure"]["status"] == 502
    assert all(event.get("initiating_route") == routes["/02-authorized"]["route_id"] for event in failures.values())
    assert report["summary"]["routes_validated"] == 3


@pytest.mark.asyncio
async def test_unrecoverable_session_expiry_after_ready_routes_keeps_validated_routes(authentication_first_site):
    await require_browser()
    origin, handler = authentication_first_site
    handler.include_denied = False
    handler.expire_session = True
    report = await execute_scan(request_for(
        origin, authentication={"mode": "storage_state", "storage_profile": "authorized"},
        session_recovery_attempts=1,
    ))
    assert handler.receipts[("GET", "/02-authorized")] == 1
    # The expired route is retried once after a recovery attempt, then reported as not tested.
    assert handler.receipts[("GET", "/03-expired")] == 2
    assert report["scan_status"] == "PARTIAL"
    assert report["summary"]["termination_reason"] == "SESSION_EXPIRED"
    assert report["session_interruption"]["category"] == "SESSION_EXPIRED"
    paths = {urlsplit(result["final_url"]).path or "/" for result in report["results"]}
    assert paths == {"/", "/02-authorized"}
    assert all(result["authentication_status"] == "PASS" for result in report["results"])
    assert [item["reason"] for item in report["not_tested_routes"]] == ["NOT_TESTED_SESSION_EXPIRED"]
    assert "fixture-private" not in json.dumps(report)


@pytest.mark.asyncio
async def test_explicit_authentication_policy_block_has_sanitized_actionable_diagnostics(authenticated_spa, monkeypatch, scanner_logs):
    origins, receipts = authenticated_spa
    monkeypatch.setattr(main.AuthenticationNavigationPolicy, "allows_browser_request", lambda *_args, **_kwargs: False)
    report = await scan_fixture(origins)
    assert_authentication_failure(report, "AUTHENTICATION_BLOCKED")
    assert report["authentication_diagnostics"]
    error = report["authentication_error"]
    assert error["method"] == "POST"
    assert "oauth/token" in error["endpoint"]
    assert error["policy_decision"]
    assert not any(method == "POST" for _, method, _ in receipts)
    assert "fixture-private" not in scanner_logs.text


@pytest.mark.asyncio
async def test_identity_provider_unavailable_is_not_a_partially_healthy_scan(authentication_first_site):
    await require_browser()
    origin, _handler = authentication_first_site
    report = await execute_scan(request_for(origin + "/idp-unavailable", authentication_hosts=["localhost"]))
    assert_authentication_failure(report, "IDENTITY_PROVIDER_UNAVAILABLE")
    assert report["authentication_error"]["http_status"] == 503


@pytest.mark.asyncio
async def test_missing_session_profile_fails_before_browser_start_with_configuration_diagnostic(authentication_first_site, monkeypatch):
    origin, _handler = authentication_first_site

    def forbidden_browser():
        raise AssertionError("Invalid authentication configuration must not launch Chromium")

    monkeypatch.setattr(main, "async_playwright", forbidden_browser)
    report = await execute_scan(request_for(origin, authentication={
        "mode": "storage_state", "storage_profile": "missing-profile",
    }))
    assert_authentication_failure(report, "AUTHENTICATION_CONFIGURATION_ERROR")
    assert "missing-profile" not in json.dumps(report)


@pytest.mark.asyncio
async def test_failed_authentication_report_is_failed_job_not_partial_completion(monkeypatch):
    failed_report = {
        "scan_id": "fixture-authentication-failed-job",
        "scan_status": "FAILED",
        "authentication_status": "FAILED",
        "authentication_error": {"category": "AUTHENTICATION_BLOCKED", "remediation": "Review approved authentication policy."},
        "results": [], "route_inventory": [], "api_inventory": [],
        "summary": {"scan_completeness": "FAILED", "termination_reason": "AUTHENTICATION_BLOCKED",
                    "routes_discovered": 0, "routes_validated": 0, "healthy_routes": 0, "failed_pages": 0},
    }

    async def completed_with_authentication_failure(_request, **_kwargs):
        await _kwargs["progress_callback"]("FAILED", discovered=0, validated=0)
        assert job.state not in {"FAILED", "PARTIAL", "COMPLETED"}
        assert job.report is None, "Terminal status cannot precede its report"
        return failed_report

    monkeypatch.setattr(main, "execute_scan", completed_with_authentication_failure)
    job = ScanJob(scan_id=failed_report["scan_id"])
    await main._run_scan_job(job, ScanRequest(target="https://portal.example"))
    assert job.state == "FAILED"
    assert job.report is failed_report
    assert job.snapshot()["report_ready"] is True
    assert job.discovered == job.validated == job.healthy == 0


@pytest.mark.asyncio
async def test_successful_authentication_unlocks_all_nested_and_url_less_fixture_views(authenticated_spa):
    origins, receipts = authenticated_spa
    report = await scan_fixture(origins)
    assert report["scan_status"] == "COMPLETED"
    assert [event["state"] for event in report["scan_lifecycle"]["events"]] == [
        "INITIALIZING", "AUTHENTICATING", "AUTHENTICATED", "APPLICATION_READY",
        "DISCOVERING_ROUTES", "VALIDATING_ROUTES", "COMPLETED",
    ]
    assert report["authentication_status"] != "FAILED"
    assert len(report["results"]) == 7
    assert {route["route_name"] for route in report["results"] if route["view_type"] == "UI_TAB"} == {"Summary panel", "History panel"}
    assert {urlsplit(route["final_url"]).fragment for route in report["results"]} >= {"/overview", "/activity", "/reports", "/dynamic"}
    assert all(route["application_ready"] for route in report["results"])
    shared = next(api for api in report["api_inventory"] if api["endpoint"] == "/api/shared")
    assert shared["route_count"] == 7
    failed = next(api for api in report["api_inventory"] if api["endpoint"] == "/api/failure")
    assert failed["response_status_counts"] == {"502": 1}
    assert not any(method == "POST" and path == "/api/write" for _, method, path in receipts)
    assert "fixture-private" not in json.dumps(report)
