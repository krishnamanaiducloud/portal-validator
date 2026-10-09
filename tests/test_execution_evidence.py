"""Keep purpose, policy, transport and coverage evidence independent."""

import asyncio
import json
from pathlib import Path
from threading import Event

import pytest
from pydantic import ValidationError
from playwright.async_api import async_playwright

from app.health import api_health_findings
from app.main import ScanRequest, execute_scan
from app.network import PassiveNetworkObserver, api_timeout_init_script, summarize_route_api_coverage
from app.reporting import aggregate_api_events
from test_scan_post_lifecycle import production_spa
from app import main


class Request:
    method = "POST"
    resource_type = "fetch"
    url = "https://portal.example/api/search"


def observe(observer, request):
    return observer.observe_request(
        request, phase="ROUTE_VALIDATION", importance="REQUIRED",
        initiating_route="https://portal.example/dashboard", main_document=False,
    )


def test_challenge_success_is_not_business_api_success():
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    request.url = "https://portal.example/cdn-cgi/challenge-platform/query"
    event = observe(observer, request)
    observer.mark_allowed(request, "ACCESS_GATE")
    observer.mark_dispatched(request)
    observer.record_response(request, 200)
    observer.record_finished(request)
    item = aggregate_api_events(events)[0]
    assert event["traffic_role"] == item["traffic_role"] == "CHALLENGE_API"
    assert item["status_2xx"] == item["completed_calls"] == 1
    assert item["business_success_calls"] == 0
    assert summarize_route_api_coverage(events)["application_apis_executed"] == 0


def test_block_does_not_erase_semantic_traffic_role():
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    request.url = "https://portal.example/captcha/submit"
    event = observe(observer, request)
    observer.mark_blocked(request, "READ_ONLY_MUTATION_BLOCKED")
    observer.record_failure(request, "net::ERR_BLOCKED_BY_CLIENT")
    item = aggregate_api_events(events)[0]
    assert event["traffic_role"] == "CHALLENGE_API"
    assert item["blocked_calls"] == 1 and item["sent_calls"] == 0
    assert item["network_failures"] == item["failed_calls"] == 0
    assert item["traffic_role"] == "CHALLENGE_API"


@pytest.mark.parametrize("headers_received", [False, True])
def test_cancellation_is_not_fabricated_network_or_server_failure(headers_received):
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    event = observe(observer, request)
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.mark_dispatched(request)
    if headers_received:
        observer.record_response(request, 200)
    observer.record_failure(request, "net::ERR_ABORTED")
    observer.finalize_pending()
    item = aggregate_api_events(events)[0]
    assert event["lifecycle_status"] == "CANCELED"
    assert item["canceled_calls"] == 1
    assert item["failed_calls"] == item["network_failures"] == item["response_body_failures"] == 0
    assert item["average_duration_ms"] is None
    assert api_health_findings(events)[0]["type"] == "API_REQUEST_CANCELED"
    assert api_health_findings(events)[0]["target_failure"] is False


@pytest.mark.parametrize("stage", ["observed", "allowed", "sent", "responded"])
def test_incomplete_lifecycles_are_not_healthy(stage):
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    event = observe(observer, request)
    if stage != "observed":
        observer.mark_allowed(request, "APPROVED_READ_POST")
    if stage in {"sent", "responded"}:
        observer.mark_dispatched(request)
    if stage == "responded":
        observer.record_response(request, 200)
    observer.finalize_pending()
    item = aggregate_api_events(events)[0]
    assert event["lifecycle_status"] == "INCOMPLETE"
    assert item["observation_outcome"] == "INCOMPLETE"
    assert item["health"] == "INCOMPLETE"
    assert item["allowed_calls"] == (stage != "observed")
    assert item["incomplete_calls"] == 1
    assert item["completed_calls"] == item["business_success_calls"] == 0
    assert item["average_duration_ms"] is None
    assert event["status"] is None if stage != "responded" else event["status"] == 200


def test_business_success_requires_complete_actual_response():
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    event = observe(observer, request)
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.mark_dispatched(request)
    observer.record_response(request, 201)
    observer.record_finished(request)
    observer.finalize_pending()
    item = aggregate_api_events(events)[0]
    assert event["lifecycle_status"] == "COMPLETED"
    for field in ("calls", "observed_calls", "allowed_calls", "sent_calls", "responded_calls", "completed_calls", "business_success_calls"):
        assert item[field] == 1


@pytest.mark.parametrize("canceled", [False, True])
@pytest.mark.parametrize("importance", ["REQUIRED", "OPTIONAL"])
def test_known_server_error_is_not_hidden_by_incomplete_response(importance, canceled):
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    observer.observe_request(
        request, phase="ROUTE_VALIDATION", importance=importance,
        initiating_route="https://portal.example/dashboard", main_document=False,
    )
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.mark_dispatched(request)
    observer.record_response(request, 503)
    if canceled:
        observer.record_failure(request, "net::ERR_ABORTED")
    observer.finalize_pending()
    findings = api_health_findings(events)
    server_error = next(item for item in findings if item["type"].startswith("API_SERVER_ERROR"))
    assert server_error["http_status"] == 503
    assert server_error["target_failure"] is True
    assert server_error["severity"] == ("ERROR" if importance == "REQUIRED" else "WARNING")
    assert len(findings) == 2
    inventory = aggregate_api_events(events)[0]
    assert inventory["status_5xx"] == 1 and inventory["network_failures"] == 0
    assert inventory["observation_outcome"] == inventory["health"] == "FAILED"


def test_configuration_and_auth_are_not_business_coverage():
    events = []
    observer = PassiveNetworkObserver(events)
    requests = []
    for path in ("/config.json", "/oauth2/authorization", "/unknown-bootstrap"):
        request = Request()
        request.url = "https://portal.example" + path
        requests.append(request)
        observer.observe_request(request, phase="AUTHENTICATION", importance="REQUIRED", initiating_route=None, main_document=False)
        observer.mark_allowed(request, "SAFE_METHOD")
        observer.record_response(request, 200)
        observer.record_finished(request)
    assert [event["traffic_role"] for event in events] == ["MICROFRONTEND_CONFIG", "AUTH_API", "UNCLASSIFIED_API"]
    assert summarize_route_api_coverage(events)["application_apis_executed"] == 0


def test_optional_phase_timeouts_validate_and_preserve_default_behavior():
    default = ScanRequest(target="portal.example")
    fields = ("navigation_timeout_ms", "authentication_timeout_ms", "readiness_timeout_ms", "api_timeout_ms")
    assert all(getattr(default, field) is None for field in fields)
    for field in fields:
        assert getattr(ScanRequest(target="portal.example", **{field: 2345}), field) == 2345
        for invalid in (0, 999, 120001):
            with pytest.raises(ValidationError):
                ScanRequest(target="portal.example", **{field: invalid})
    with pytest.raises(ValidationError):
        ScanRequest(target="portal.example", readiness_selector="x" * 513)
    script = api_timeout_init_script(2345)
    assert "AbortSignal.any" in script and "AbortSignal.timeout(2345)" not in script
    assert "const timeout = 2345;" in script
    assert "originalSend.call(this, body)" in script
    assert "Authorization" not in script and "ignore_https" not in script
    with pytest.raises(ValueError):
        api_timeout_init_script(0)
    assert "password" not in json.dumps(default.model_dump(exclude={"authentication"}))


@pytest.mark.parametrize("host", ["*.example.net", "https://id.example.net", "user@id.example.net", "id.example.net:443", "id.example.net/path"])
def test_identity_provider_approval_requires_exact_hostname(host):
    with pytest.raises(ValidationError):
        ScanRequest(target="portal.example", authentication_hosts=[host])


@pytest.mark.asyncio
async def test_configured_api_timeout_cancels_natural_fetch_and_xhr_without_replay(production_spa, monkeypatch):
    origin, handler = production_spa
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed")

    def page_get(self):
        body = b'''<!doctype html><html><body><h1>Generic API deadline fixture</h1>
        <script>
        fetch('/api/slow-fetch', {method:'POST',body:'{"query":"read"}'}).catch(()=>{});
        const xhr=new XMLHttpRequest();xhr.open('POST','/api/slow-xhr');
        xhr.onerror=xhr.ontimeout=()=>{};xhr.send('{"query":"read"}');
        </script></body></html>'''
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def slow_post(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        assert body == b'{"query":"read"}'
        type(self).post_paths.append(self.path)
        Event().wait(2)
        try:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    monkeypatch.setattr(handler, "do_GET", page_get)
    monkeypatch.setattr(handler, "do_POST", slow_post)
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=1,
        timeout_ms=8000, total_timeout_ms=20000, api_timeout_ms=1000,
        min_observation_ms=1700, render_settle_ms=100, network_quiet_ms=100,
        max_navigation_actions=0, max_discovery_scrolls=0, check_security_headers=False,
        approved_read_post_operations=[
            {"method": "POST", "host": "127.0.0.1", "path": path}
            for path in ("/api/slow-fetch", "/api/slow-xhr")
        ],
    ))
    assert sorted(handler.post_paths) == ["/api/slow-fetch", "/api/slow-xhr"]
    assert report["network_observation"]["observed_requests"] == 2
    assert report["network_observation"]["requests_canceled"] == 2
    assert report["network_observation"]["requests_failed"] == 0
    assert report["network_observation"]["browser_request_failed_events"] == 2
    assert report["results"][0]["page_load_status"] == "LOADED"
    assert report["results"][0]["classification"] == "PASS_WITH_WARNINGS"
    assert report["results"][0]["failed_api_count"] == 0
    for phase in ("browser_startup_ms", "authentication_ms", "navigation_ms", "readiness_ms", "discovery_ms", "network_observation_ms", "aggregation_ms", "report_generation_ms"):
        assert 0 <= report["scan_timing"][phase] <= report["scan_timing"]["total_scan_ms"]
    for item in report["api_inventory"]:
        assert item["calls"] == item["allowed_calls"] == item["sent_calls"] == item["canceled_calls"] == 1
        assert item["network_failures"] == item["business_success_calls"] == 0
        assert item["average_duration_ms"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("ready", [True, False])
async def test_configured_readiness_observes_condition_without_inventing_load_failure(production_spa, monkeypatch, ready):
    origin, handler = production_spa
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed")

    def page_get(self):
        body = b'''<!doctype html><html><body><h1>Generic readiness fixture</h1>
        <script>setTimeout(()=>{document.body.dataset.ready='true'},250)</script></body></html>'''
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    monkeypatch.setattr(handler, "do_GET", page_get)
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=1,
        timeout_ms=8000, total_timeout_ms=20000, readiness_timeout_ms=1000,
        readiness_selector="body[data-ready=true]" if ready else "#never-present",
        render_settle_ms=100, min_observation_ms=100, network_quiet_ms=100,
        max_navigation_actions=0, max_discovery_scrolls=0, check_security_headers=False,
    ))
    result = report["results"][0]
    assert result["page_load_status"] == "LOADED"
    assert result["render_health"]["configured_readiness_met"] is ready
    assert any(item["type"] == "READINESS_NOT_REACHED" for item in result["finding_details"]) is not ready
    assert result["classification"] == ("PASS" if ready else "PASS_WITH_WARNINGS")
    assert report["scan_configuration"]["readiness_selector_configured"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("slow_target", [False, True])
async def test_slow_route_uses_target_navigation_not_security_policy_wait(production_spa, monkeypatch, slow_target):
    origin, handler = production_spa
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed")

    def page_get(self):
        if slow_target:
            Event().wait(0.9)
        body = b"<!doctype html><html><body><main><h1>Measured application document</h1></main></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    original_resolver = main._resolve_with_logging

    async def slow_policy(*args, **kwargs):
        if not slow_target:
            await asyncio.sleep(0.9)
        return await original_resolver(*args, **kwargs)

    monkeypatch.setattr(handler, "do_GET", page_get)
    monkeypatch.setattr(main, "_resolve_with_logging", slow_policy)
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=1,
        timeout_ms=10000, total_timeout_ms=30000, slow_page_threshold_ms=500,
        render_settle_ms=0, min_observation_ms=0, network_quiet_ms=0,
        max_navigation_actions=0, max_discovery_scrolls=0, check_security_headers=False,
    ))
    route = report["results"][0]
    assert route["page_load_status"] == "LOADED"
    assert ("SLOW_ROUTE" in route["warning_codes"]) is slow_target
    if slow_target:
        assert route["application_navigation_ms"] >= 700
    else:
        assert route["validator_navigation_ms"] >= 700
        assert route["application_navigation_ms"] < 500
        assert route["validator_overhead_ms"] >= route["validator_navigation_ms"]
