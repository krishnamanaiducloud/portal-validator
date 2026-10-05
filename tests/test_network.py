import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from playwright.async_api import async_playwright

from app.network import (
    PassiveNetworkObserver,
    load_read_only_policy,
    normalize_api_endpoint,
    summarize_route_api_coverage,
)
from app.main import acknowledge_configured_access_gate


class FakeRequest:
    def __init__(self, method: str, url: str, resource_type: str = "fetch"):
        self.method = method
        self.url = url
        self.resource_type = resource_type
        self.headers = {"Authorization": "Bearer never-store-this"}
        self.post_data = "password=never-store-this"


@pytest.mark.parametrize(
    ("method", "status"),
    (("GET", 200), ("POST", 200), ("POST", 201), ("POST", 400), ("POST", 500)),
)
def test_passive_observer_records_one_event_per_request(method, status):
    events = []
    observer = PassiveNetworkObserver(events)
    request = FakeRequest(method, "https://portal.example.com/api/query?token=secret")

    event = observer.observe_request(
        request,
        phase="ROUTE_VALIDATION",
        importance="REQUIRED",
        initiating_route="https://portal.example.com/#/reports",
        main_document=False,
    )
    observer.mark_allowed(request, "SAFE_METHOD" if method == "GET" else "APPROVED_READ_POST")
    observer.record_response(request, status)
    observer.record_response(request, status)

    assert events == [event]
    assert event["method"] == method
    assert event["status"] == status
    assert event["lifecycle"] == "RESPONSE"
    assert event["target_reached"] is True
    assert "secret" not in json.dumps(event)
    assert "token" not in event["url"]


@pytest.mark.parametrize("method", ("POST", "PUT", "PATCH", "DELETE"))
def test_blocked_mutations_remain_observable_without_network_failure(method):
    events = []
    observer = PassiveNetworkObserver(events)
    request = FakeRequest(method, "https://portal.example.com/api/resource/123")
    observer.observe_request(
        request,
        phase="ROUTE_VALIDATION",
        importance="REQUIRED",
        initiating_route="https://portal.example.com/settings",
        main_document=False,
    )
    observer.mark_blocked(request, "READ_ONLY_MUTATION_BLOCKED")
    observer.record_failure(request, "net::ERR_BLOCKED_BY_CLIENT")

    assert len(events) == 1
    assert events[0]["endpoint"] == "/api/resource/{id}"
    assert events[0]["blocked_by_validator"] is True
    assert events[0]["block_reason"] == "READ_ONLY_MUTATION_BLOCKED"
    assert events[0]["request_classification"] == "BLOCKED_MUTATION"
    assert events[0]["error"] is None
    assert events[0]["target_reached"] is False
    assert "never-store-this" not in json.dumps(events)


def test_unknown_http_method_is_observed_and_remains_unapproved():
    events = []
    observer = PassiveNetworkObserver(events)
    request = FakeRequest("MKCOL", "https://portal.example.com/api/collection")
    observer.observe_request(
        request,
        phase="ROUTE_VALIDATION",
        importance="REQUIRED",
        initiating_route="https://portal.example.com/settings",
        main_document=False,
    )
    observer.mark_blocked(request, "READ_ONLY_MUTATION_BLOCKED")
    assert events[0]["method"] == "MKCOL"
    assert events[0]["allowed_by_policy"] is False


def test_explicit_policy_is_exact_generic_and_supports_session_refresh():
    policy = load_read_only_policy(raw=json.dumps({
        "safe_application_requests": [
            {
                "method": "POST",
                "host": "portal.example.com",
                "path": "/api/read-query",
                "classification": "APPROVED_READ_POST",
            },
            {
                "method": "POST",
                "host": "identity.example.net",
                "path": "/oauth/refresh",
                "classification": "SESSION_REFRESH",
            },
        ],
    }))

    approved = policy.match("POST", "https://portal.example.com/api/read-query")
    refresh = policy.match("POST", "https://identity.example.net/oauth/refresh")
    assert approved is not None and approved.classification == "APPROVED_READ_POST"
    assert refresh is not None and refresh.classification == "SESSION_REFRESH"
    assert policy.match("POST", "https://portal.example.com/api/update") is None
    assert policy.match("POST", "https://portal.example.com/api/read-query/123") is None
    assert policy.match("POST", "https://evil.example/api/read-query") is None
    assert policy.match("DELETE", "https://portal.example.com/api/read-query") is None


def test_read_only_policy_supports_only_segment_bounded_patterns():
    policy = load_read_only_policy(raw=json.dumps({
        "safe_application_requests": [{
            "method": "POST",
            "host": "portal.example.com",
            "path_pattern": "/api/items/{segment}/query",
            "classification": "APPROVED_READ_POST",
        }],
    }))
    assert policy.match("POST", "https://portal.example.com/api/items/42/query")
    assert policy.match("POST", "https://portal.example.com/api/items/42/update") is None
    assert policy.match("POST", "https://portal.example.com/api/items/42/query/extra") is None

    for unsafe in ("/**", "/api/{segment}", "/{segment}/v1/query"):
        with pytest.raises(ValueError):
            load_read_only_policy(raw=json.dumps({
                "safe_application_requests": [{
                    "method": "POST",
                    "host": "portal.example.com",
                    "path_pattern": unsafe,
                }],
            }))


def test_api_path_normalization_is_conservative_and_redacts_sensitive_segments():
    assert normalize_api_endpoint("/api/users/123") == "/api/users/{id}"
    assert normalize_api_endpoint("/api/users/456") == "/api/users/{id}"
    assert normalize_api_endpoint("/api/v1/users") == "/api/v1/users"
    assert normalize_api_endpoint("/api/token/super-secret-value") == "/api/token/{redacted}"


def test_route_api_coverage_excludes_config_and_reports_blocked_business_api():
    coverage = summarize_route_api_coverage([
        {
            "traffic_category": "MICROFRONTEND_CONFIG",
            "resource_type": "fetch",
            "endpoint": "/micro/dashboard/config.json",
            "blocked_by_validator": False,
        },
        {
            "traffic_category": "VALIDATOR_BLOCKED",
            "resource_type": "fetch",
            "endpoint": "/api/dashboard-query",
            "phase": "ROUTE_VALIDATION",
            "blocked_by_validator": True,
        },
    ])
    assert coverage == {
        "api_coverage": "APPLICATION_API_BLOCKED",
        "apis_observed": 2,
        "application_apis_observed": 1,
        "application_apis_executed": 0,
        "blocked_api_attempts": 1,
    }


@pytest.mark.asyncio
async def test_access_gate_requires_exact_admin_rule_and_is_idempotent():
    policy = load_read_only_policy(raw=json.dumps({
        "access_gates": [{
            "host": "portal.example.com",
            "selector": "#approved-gate",
        }],
    }))

    class Control:
        clicks = 0

        async def count(self):
            return 1

        async def is_visible(self):
            return True

        async def click(self, **_kwargs):
            self.clicks += 1

    class Page:
        control = Control()

        def locator(self, selector):
            assert selector == "#approved-gate"
            return self.control

    page = Page()
    acknowledged = set()
    assert await acknowledge_configured_access_gate(
        page, policy, "https://portal.example.com/", acknowledged
    ) is True
    assert await acknowledge_configured_access_gate(
        page, policy, "https://portal.example.com/", acknowledged
    ) is False
    assert page.control.clicks == 1


@pytest.mark.asyncio
async def test_context_observer_captures_browser_generated_get_and_post():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = b"""<!doctype html><main>Network fixture</main><script>
                  Promise.all([
                    fetch('/api/config'),
                    fetch('/api/query', {method:'POST', body:'password=never-store-this'})
                  ]).then(() => document.body.dataset.done = 'true');
                </script>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            self.send_response(201)
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    events = []
    observer = PassiveNetworkObserver(events)
    try:
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                pytest.skip("matching Playwright Chromium is not installed on this host")
            browser = await playwright.chromium.launch(headless=True)
            try:
                context = await browser.new_context()

                def observe(request):
                    if request.resource_type in {"xhr", "fetch"}:
                        observer.observe_request(
                            request,
                            phase="APPLICATION_BOOTSTRAP",
                            importance="BACKGROUND",
                            initiating_route=None,
                            main_document=False,
                        )
                        observer.mark_allowed(request, "SAFE_METHOD" if request.method == "GET" else "APPROVED_READ_POST")

                context.on("request", observe)
                context.on("response", lambda response: observer.record_response(response.request, response.status))
                context.on("requestfailed", lambda request: observer.record_failure(request, request.failure or "Request failed"))
                page = await context.new_page()
                await page.goto(origin, wait_until="domcontentloaded")
                await page.wait_for_function(
                    "document.body?.dataset.done === 'true'", timeout=5000
                )
                api_events = [event for event in events if event["resource_type"] in {"xhr", "fetch"}]
                assert {(event["method"], event["endpoint"], event["status"]) for event in api_events} == {
                    ("GET", "/api/config", 200),
                    ("POST", "/api/query", 201),
                }
                assert "never-store-this" not in json.dumps(api_events)
            finally:
                await browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_context_observer_keeps_natural_delete_block_visible_and_off_backend():
    class Handler(BaseHTTPRequestHandler):
        delete_calls = 0

        def do_GET(self):
            body = b"""<!doctype html><script>
              fetch('/api/resource/123', {method:'DELETE'})
                .catch(() => document.body.dataset.done = 'true');
            </script>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_DELETE(self):
            type(self).delete_calls += 1
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    events = []
    observer = PassiveNetworkObserver(events)
    try:
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                pytest.skip("matching Playwright Chromium is not installed on this host")
            browser = await playwright.chromium.launch(headless=True)
            try:
                context = await browser.new_context()

                def observe(request):
                    if request.method == "DELETE":
                        observer.observe_request(
                            request,
                            phase="ROUTE_VALIDATION",
                            importance="REQUIRED",
                            initiating_route=f"{origin}/#/settings",
                            main_document=False,
                        )

                async def guard(route):
                    if route.request.method == "DELETE":
                        observer.mark_blocked(route.request, "READ_ONLY_MUTATION_BLOCKED")
                        await route.abort("blockedbyclient")
                    else:
                        await route.continue_()

                context.on("request", observe)
                context.on("requestfailed", lambda request: observer.record_failure(request, request.failure or "Request failed"))
                await context.route("**/*", guard)
                page = await context.new_page()
                await page.goto(origin, wait_until="domcontentloaded")
                await page.wait_for_function(
                    "document.body?.dataset.done === 'true'", timeout=5000
                )
                assert Handler.delete_calls == 0
                assert len(events) == 1
                assert events[0]["method"] == "DELETE"
                assert events[0]["blocked_by_validator"] is True
                assert events[0]["error"] is None
            finally:
                await browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_natural_safe_post_reaches_backend_while_unknown_post_is_observed_and_blocked():
    class Handler(BaseHTTPRequestHandler):
        paths = []

        def do_GET(self):
            body = b"""<!doctype html><body><script>
              Promise.allSettled([
                fetch('/api/read-query', {method:'POST', body:'secret=do-not-capture'}),
                fetch('/api/update', {method:'POST', body:'secret=do-not-capture'})
              ]).then(() => document.body.dataset.done = 'true');
            </script></body>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            type(self).paths.append(self.path)
            self.send_response(201)
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    policy = load_read_only_policy(raw=json.dumps({
        "safe_application_requests": [{
            "method": "POST",
            "host": "127.0.0.1",
            "path": "/api/read-query",
            "classification": "APPROVED_READ_POST",
        }],
    }))
    events = []
    observer = PassiveNetworkObserver(events)
    try:
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                pytest.skip("matching Playwright Chromium is not installed on this host")
            browser = await playwright.chromium.launch(headless=True)
            try:
                context = await browser.new_context()

                def observe(request):
                    if request.method == "POST":
                        observer.observe_request(
                            request,
                            phase="APPLICATION_BOOTSTRAP",
                            importance="REQUIRED",
                            initiating_route=origin,
                            main_document=False,
                        )

                async def guard(route):
                    request = route.request
                    if request.method != "POST":
                        await route.continue_()
                        return
                    event = observer.observe_request(
                        request,
                        phase="APPLICATION_BOOTSTRAP",
                        importance="REQUIRED",
                        initiating_route=origin,
                        main_document=False,
                    )
                    rule = policy.match(request.method, request.url)
                    if rule is None:
                        observer.mark_blocked(request, "READ_ONLY_MUTATION_BLOCKED")
                        await route.abort("blockedbyclient")
                    else:
                        observer.mark_allowed(request, rule.classification)
                        assert event["endpoint"] == "/api/read-query"
                        await route.continue_()

                context.on("request", observe)
                context.on(
                    "response",
                    lambda response: observer.record_response(response.request, response.status),
                )
                context.on(
                    "requestfailed",
                    lambda request: observer.record_failure(
                        request, request.failure or "Request failed"
                    ),
                )
                await context.route("**/*", guard)
                page = await context.new_page()
                await page.goto(origin, wait_until="domcontentloaded")
                await page.wait_for_function(
                    "document.body?.dataset.done === 'true'", timeout=5000
                )
                observer.finalize_pending()

                assert Handler.paths == ["/api/read-query"]
                by_endpoint = {event["endpoint"]: event for event in events}
                assert by_endpoint["/api/read-query"]["status"] == 201
                assert by_endpoint["/api/read-query"]["blocked_by_validator"] is False
                assert by_endpoint["/api/update"]["blocked_by_validator"] is True
                assert by_endpoint["/api/update"]["target_reached"] is False
                assert "do-not-capture" not in json.dumps(events)
            finally:
                await browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
