"""Observe real browser POSTs across frames and navigation without replaying them."""

import json
import logging
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread
from urllib.parse import urlparse

import pytest
from playwright.async_api import async_playwright

from app import main, security
from app.logging_config import LOGGER
from app.main import ScanRequest, execute_scan
from app.navigation_guard import RedirectResponseGuard


@pytest.fixture
def context_post_site(monkeypatch):
    class FixtureState:
        origins = {}
        receipts = []
        session_seen = []
        lock = Lock()
        slow_request_received = Event()
        release_slow_response = Event()
        partial_response = False

    state = FixtureState()

    class Handler(BaseHTTPRequestHandler):
        def record(self):
            with state.lock:
                state.receipts.append((self.server.role, self.command, self.path))

        def reply(self, body, content_type="text/html", **headers):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key.replace("_", "-"), value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # A navigation intentionally cancels one fixture response.
                pass

        def do_GET(self):
            self.record()
            path = urlparse(self.path).path
            if path == "/batch":
                body = ('''<!doctype html><title>Generic application</title>
                <main><h1>Read-only application dashboard</h1><p>Application content is ready.</p></main>
                <iframe title="Same-origin application" src="/same-frame"></iframe>
                <iframe title="Approved cross-origin application" src="'''
                        + state.origins["frame"] + '''/cross-frame"></iframe>
                <script>
                function xhr(url) { return new Promise(resolve => {
                  const request = new XMLHttpRequest(); request.open('POST', url);
                  request.setRequestHeader('Authorization', 'Bearer fixture-private-header');
                  request.onloadend = resolve; request.send('fixture-private-body');
                }); }
                const calls = [xhr('/api/xhr-read'), xhr('/api/xhr-read'), xhr('/api/xhr-read'),
                  fetch('/api/fetch-read?access_token=fixture-private-query', {
                    method:'POST', body:'fixture-private-body',
                    headers:{Authorization:'Bearer fixture-private-header'}}),
                  fetch('/api/unapproved', {method:'POST', body:'fixture-private-body'}),
                  fetch('/api/metadata', {method:'OPTIONS'})];
                for (const method of ['PUT', 'PATCH', 'DELETE']) {
                  calls.push(fetch('/api/mutation', {method, body:'fixture-private-body'}));
                }
                Promise.allSettled(calls).then(() => document.body.dataset.done = 'true');
                </script>''').encode()
                return self.reply(body, Set_Cookie="session=fixture-private-cookie; HttpOnly; SameSite=Lax")
            if path in {"/same-frame", "/cross-frame"}:
                return self.reply(b'''<!doctype html><main><h2>Read-only child application</h2></main>
                <script>
                function xhr() { return new Promise(resolve => {
                  const request = new XMLHttpRequest(); request.open('POST', '/api/frame-read');
                  request.onloadend = resolve; request.send('fixture-private-frame-body');
                }); }
                Promise.allSettled([xhr(), xhr(),
                  fetch('/api/frame-unapproved', {method:'POST', body:'fixture-private-frame-body'})
                ]).then(() => document.body.dataset.done = 'true');
                </script>''', Set_Cookie="session=fixture-private-cookie; HttpOnly; SameSite=Lax")
            if path == "/cancel-page":
                return self.reply(b'''<!doctype html><title>Application navigation</title>
                <main><h1>Application before navigation</h1></main><script>
                const navigationAbort = new AbortController();
                window.addEventListener('pagehide', () => navigationAbort.abort());
                fetch('/api/slow-read', {method:'POST', body:'fixture-private-body', signal:navigationAbort.signal})
                  .then(response => response.json()).catch(() => {});
                fetch('/navigation-trigger').then(() => {
                  navigationAbort.abort(); location.replace('/after-navigation');
                });
                </script>''')
            if path == "/navigation-trigger":
                # Cancellation happens only after the backend really received
                # the POST, while its response is still naturally pending.
                state.slow_request_received.wait(5)
                return self.reply(b'{"navigate":true}', "application/json")
            if path == "/after-navigation":
                return self.reply(b'''<!doctype html><title>Application ready</title>
                <main><h1>Application after navigation</h1><p>Content is available.</p></main>''')
            if path == "/service-worker":
                return self.reply(b'''<!doctype html><title>Application worker policy</title>
                <main><h1>Read-only application dashboard</h1></main><script>
                const registrationCheck = navigator.serviceWorker.register('/worker.js')
                  .then(registration => registration === undefined ? 'blocked' : 'registered',
                    error => error.name === 'SecurityError' ? 'blocked' : 'unexpected-error')
                  .then(state => fetch('/api/sw-status?state=' + state))
                  .then(response => response.arrayBuffer());
                const clientRead = fetch('/api/client-read', {method:'POST', body:'fixture-private-body'})
                  .then(response => response.json());
                Promise.all([registrationCheck, clientRead]).then(() => {
                  document.body.dataset.workerCheckComplete = 'true';
                });
                </script>''')
            if path == "/worker.js":
                return self.reply(b'''self.addEventListener('install', event => {
                  event.waitUntil(fetch('/api/worker-read', {method:'POST'}));
                });''', "application/javascript")
            return self.reply(b'{"ready":true}', "application/json")

        def do_POST(self):
            self.record()
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            with state.lock:
                state.session_seen.append(
                    (self.server.role, "session=fixture-private-cookie" in self.headers.get("Cookie", ""))
                )
            if urlparse(self.path).path == "/api/slow-read":
                if state.partial_response:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    self.wfile.write(b"{")
                    self.wfile.flush()
                state.slow_request_received.set()
                state.release_slow_response.wait(10)
                self.close_connection = True
                return
            return self.reply(b'{"ready":true}', "application/json")

        def do_OPTIONS(self):
            self.record()
            return self.reply(b"", "application/json")

        def do_PUT(self):
            self.record()
            return self.reply(b'{"unexpected":true}', "application/json")

        do_PATCH = do_PUT
        do_DELETE = do_PUT

        def log_message(self, *_args):
            return

    class FixtureServer(ThreadingHTTPServer):
        request_queue_size = 128
        daemon_threads = True

    servers = []
    threads = []
    for role, host in (("portal", "127.0.0.1"), ("frame", "localhost")):
        server = FixtureServer(("127.0.0.1", 0), Handler)
        server.role = role
        servers.append(server)
        state.origins[role] = f"http://{host}:{server.server_port}"
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    monkeypatch.setattr(security, "ALLOWED_PORTS", {
        *security.ALLOWED_PORTS, *(server.server_port for server in servers),
    })
    original_resolver = security.resolve_and_validate

    async def fixture_resolver(host, allow_private):
        if host in {"127.0.0.1", "localhost"}:
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    # Only owned fixture hosts bypass production loopback restrictions.
    monkeypatch.setattr(main, "resolve_and_validate", fixture_resolver)
    try:
        yield state
    finally:
        state.release_slow_response.set()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


async def scan_context_fixture(state, path, *, approved_paths=(), readiness_selector=None):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    return await execute_scan(ScanRequest(
        target=state.origins["portal"] + path, resource_hosts=["localhost"],
        max_pages=1, max_depth=0, timeout_ms=10000, total_timeout_ms=30000,
        render_settle_ms=200, min_observation_ms=200, network_quiet_ms=100,
        readiness_selector=readiness_selector,
        readiness_timeout_ms=4000, max_navigation_actions=0, max_discovery_scrolls=0,
        check_security_headers=False,
        approved_read_post_operations=[
            {"method": "POST", "host": host, "path": endpoint}
            for host, endpoint in approved_paths
        ],
    ))


def observed_events(report):
    return list({
        event["request_id"]: event
        for result in report["results"] for event in result["api_requests"]
    }.values())


def assert_reconciled(report):
    events = observed_events(report)
    raw_events = [event for result in report["results"] for event in result["api_requests"]]
    assert len(raw_events) == len(events)
    assert len({event["request_id"] for event in events}) == len(events)
    assert report["network_observation"]["observed_requests"] == len(events)
    assert report["network_observation"]["aggregated_requests"] == len(events)
    assert sum(item["calls"] for item in report["api_inventory"]) == len(events)
    assert report["network_observation"]["total_http_requests_observed"] > len(events)
    diagnostics = report["summary"]["post_diagnostics"]
    assert diagnostics["total_http_requests_observed"] == report["network_observation"]["total_http_requests_observed"]
    assert diagnostics["post_requests_observed"] == sum(event["method"] == "POST" for event in events)
    assert "fixture-private" not in json.dumps(report)


@pytest.mark.asyncio
async def test_actual_scan_captures_xhr_and_same_cross_origin_frame_posts_once(context_post_site, caplog):
    state = context_post_site
    caplog.set_level(logging.DEBUG, logger=LOGGER.name)
    LOGGER.addHandler(caplog.handler)
    try:
        report = await scan_context_fixture(state, "/batch", approved_paths=[
            ("127.0.0.1", "/api/xhr-read"), ("127.0.0.1", "/api/fetch-read"),
            ("127.0.0.1", "/api/frame-read"), ("localhost", "/api/frame-read"),
        ])
    finally:
        LOGGER.removeHandler(caplog.handler)
    assert_reconciled(report)
    assert "fixture-private" not in caplog.text
    receipts = Counter((role, method, urlparse(path).path) for role, method, path in state.receipts)
    assert receipts[("portal", "POST", "/api/xhr-read")] == 3
    assert receipts[("portal", "POST", "/api/fetch-read")] == 1
    assert receipts[("portal", "POST", "/api/frame-read")] == 2
    assert receipts[("frame", "POST", "/api/frame-read")] == 2
    assert sum(count for (_, method, _), count in receipts.items() if method == "POST") == 8
    assert not any(method in {"PUT", "PATCH", "DELETE"} for _, method, _ in receipts)
    assert [seen for role, seen in state.session_seen if role == "portal"] == [True] * 6
    # The unrelated frame origin does not inherit the portal's host cookie.
    # Let Chromium retain its normal third-party/SameSite cookie policy.
    posts = [event for event in observed_events(report) if event["method"] == "POST"]
    assert len(posts) == 11
    approved = [event for event in posts if event["policy_decision"] == "ALLOW"]
    blocked = [event for event in posts if event["blocked_by_validator"]]
    assert len(approved) == 8 and len(blocked) == 3
    assert all(event["response_completed"] and event["response_status"] == 200 for event in approved)
    assert all("POST_READ_ONLY_APPROVED" in event["post_classifications"] for event in approved)
    assert all({"POST_OBSERVED", "POST_READ_ONLY_UNVERIFIED", "POST_BLOCKED_BY_POLICY", "POST_MUTATION_RESTRICTED"}
               <= set(event["post_classifications"]) for event in blocked)
    frame_posts = [event for event in posts if event["endpoint"] == "/api/frame-read"]
    assert len(frame_posts) == 4
    assert all(event["resource_type"] == "xhr" and event["frame_identity"] == "CHILD_FRAME" for event in frame_posts)
    assert {event["host"] for event in frame_posts} == {"localhost", "127.0.0.1"}
    xhr = next(item for item in report["api_inventory"] if item["endpoint"] == "/api/xhr-read")
    assert xhr["calls"] == xhr["allowed_calls"] == xhr["completed_calls"] == 3
    assert xhr["blocked_calls"] == xhr["failed_calls"] == xhr["incomplete_calls"] == 0
    assert xhr["routes_using_endpoint"] == [state.origins["portal"] + "/batch"]
    diagnostics = report["summary"]["post_diagnostics"]
    assert diagnostics["post_requests_allowed"] == 8
    assert diagnostics["post_requests_blocked"] == 3
    assert diagnostics["approved_read_only_post_endpoints"] == 4
    assert diagnostics["unverified_post_endpoints"] == 3
    assert diagnostics["unique_post_endpoints_reported"] == 7
    assert diagnostics["post_requests_without_completed_responses"] == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("partial_response", [False, True])
async def test_actual_navigation_canceled_post_is_reported_without_replay(context_post_site, monkeypatch, partial_response):
    state = context_post_site
    state.partial_response = partial_response
    cdp_failures = []
    cdp_errors = []
    original_paused = RedirectResponseGuard._paused

    def instrument_paused(guard, event):
        if event.get("responseErrorReason"):
            cdp_errors.append({key: event.get(key) for key in (
                "requestId", "networkId", "resourceType", "responseStatusCode", "responseErrorReason",
            )})
        if not getattr(guard, "_fixture_diagnostics", False):
            guard._fixture_diagnostics = True
            original_send = guard.session.send

            async def recorded_send(method, parameters=None):
                try:
                    return await original_send(method, parameters)
                except Exception as error:
                    if method in {"Fetch.continueRequest", "Fetch.failRequest"}:
                        cdp_failures.append({"method": method, "error": str(error)})
                    raise

            monkeypatch.setattr(guard.session, "send", recorded_send)
        return original_paused(guard, event)

    monkeypatch.setattr(RedirectResponseGuard, "_paused", instrument_paused)
    report = await scan_context_fixture(state, "/cancel-page", approved_paths=[
        ("127.0.0.1", "/api/slow-read"),
    ])
    assert_reconciled(report)
    assert state.slow_request_received.is_set()
    assert [(role, method, path) for role, method, path in state.receipts if method == "POST"] == [
        ("portal", "POST", "/api/slow-read"),
    ]
    assert any(path == "/after-navigation" for _, _, path in state.receipts)
    post = next(event for event in observed_events(report) if event["method"] == "POST")
    assert post["lifecycle_status"] == "CANCELED", json.dumps({
        "lifecycle_status": post["lifecycle_status"], "cdp_failures": cdp_failures, "cdp_errors": cdp_errors,
        "navigation_error": report["results"][0].get("error"),
    })
    assert post["request_canceled"] is True
    assert post["blocked_by_validator"] is False
    assert post["response_completed"] is False
    if not partial_response:
        assert post["response_seen"] is False
    elif post["response_seen"]:
        assert post["response_status"] == 200
    assert "POST_READ_ONLY_APPROVED" in post["post_classifications"]
    assert "POST_NETWORK_FAILED" not in post["post_classifications"]
    inventory = next(item for item in report["api_inventory"] if item["method"] == "POST")
    assert inventory["calls"] == inventory["canceled_calls"] == 1
    assert inventory["incomplete_calls"] == inventory["failed_calls"] == inventory["blocked_calls"] == 0
    assert report["summary"]["post_diagnostics"]["post_requests_without_completed_responses"] == 1


@pytest.mark.asyncio
async def test_service_worker_visibility_policy_blocks_registration_not_client_posts(context_post_site, monkeypatch):
    state = context_post_site
    original_options = main.browser_context_options
    effective_options = []

    def captured_options(state_path):
        options = original_options(state_path)
        effective_options.append(options)
        return options

    monkeypatch.setattr(main, "browser_context_options", captured_options)
    report = await scan_context_fixture(state, "/service-worker", approved_paths=[
        ("127.0.0.1", "/api/client-read"),
    ], readiness_selector='body[data-worker-check-complete="true"]')
    assert_reconciled(report)
    assert len(effective_options) == 1 and effective_options[0]["service_workers"] == "block"
    assert any(path == "/api/sw-status?state=blocked" for _, _, path in state.receipts)
    assert not any(urlparse(path).path in {"/worker.js", "/api/worker-read"} for _, _, path in state.receipts)
    assert [(role, method, path) for role, method, path in state.receipts if method == "POST"] == [
        ("portal", "POST", "/api/client-read"),
    ]
    post = next(event for event in observed_events(report) if event["method"] == "POST")
    assert post["response_completed"] is True and post["response_status"] == 200
    assert "POST_READ_ONLY_APPROVED" in post["post_classifications"]
    assert report["safety"]["service_worker_policy"] == "BLOCKED_TO_PRESERVE_NETWORK_MUTATION_GUARD"
