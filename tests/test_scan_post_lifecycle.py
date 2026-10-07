"""Production scan-path regressions; the SPA creates requests, not the test."""

import gc
import json
import logging
import socket
import weakref
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread

import pytest
from playwright.async_api import async_playwright
from pydantic import ValidationError

from app.main import ScanRequest, execute_scan
from app.logging_config import LOGGER
from app.network import PassiveNetworkObserver, RouteNetworkActivity, load_read_only_policy, request_identity
from app.reporting import aggregate_api_events


class RequestFixture:
    method = "GET"
    url = "https://portal.example/api/config"
    resource_type = "fetch"


@pytest.fixture
def scanner_logs(caplog):
    # Production intentionally does not propagate this redacted logger. Attach
    # pytest's handler explicitly so leakage assertions inspect actual events.
    caplog.set_level(logging.DEBUG, logger=LOGGER.name)
    LOGGER.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        LOGGER.removeHandler(caplog.handler)


def test_completed_request_identity_does_not_alias_a_new_post_after_gc():
    events = []
    observer = PassiveNetworkObserver(events)
    for index in range(100):
        request = RequestFixture()
        request.method = "GET" if index % 2 == 0 else "POST"
        request.url = f"https://portal.example/api/operation-{index}"
        expected_method = request.method
        event = observer.observe_request(
            request, phase="ROUTE_VALIDATION", importance="REQUIRED",
            initiating_route="https://portal.example/#/dashboard", main_document=False,
        )
        observer.record_response(request, 200)
        reference = weakref.ref(request)
        del request
        gc.collect()
        assert reference() is None
        assert len(observer._events_by_request) == 0
        assert event["method"] == expected_method
    assert len(events) == 100
    assert len({event["request_id"] for event in events}) == 100


def test_request_api_wrapper_recreation_keeps_underlying_lifecycle_identity():
    events = []
    observer = PassiveNetworkObserver(events)
    implementation = RequestFixture()
    first_wrapper = RequestFixture()
    first_wrapper._impl_obj = implementation
    first_wrapper.method = "POST"
    event = observer.observe_request(
        first_wrapper, phase="ROUTE_VALIDATION", importance="REQUIRED",
        initiating_route="https://portal.example/#/dashboard", main_document=False,
    )
    del first_wrapper
    gc.collect()
    second_wrapper = RequestFixture()
    second_wrapper._impl_obj = implementation
    observer.record_response(second_wrapper, 201)
    observer.record_finished(second_wrapper)
    assert len(events) == 1
    assert event["status"] == 201
    assert event["response_completed"] is True


def test_route_readiness_uses_underlying_request_identity_without_retaining_requests():
    activity = RouteNetworkActivity()
    implementation = RequestFixture()
    first_wrapper = RequestFixture()
    first_wrapper._impl_obj = implementation
    activity.request_started(first_wrapper, "route-1")
    del first_wrapper
    gc.collect()
    assert activity.snapshot("route-1")["pending"] == 1
    final_wrapper = RequestFixture()
    final_wrapper._impl_obj = implementation
    assert request_identity(final_wrapper) is implementation
    activity.request_finished(final_wrapper)
    assert activity.snapshot("route-1")["pending"] == 0
    assert activity.snapshot("route-1")["generation"] == 2
    reference = weakref.ref(implementation)
    del final_wrapper, implementation
    gc.collect()
    assert reference() is None


def test_background_activity_is_observed_but_does_not_extend_route_readiness():
    request = RequestFixture()
    request.method = "POST"
    activity = RouteNetworkActivity()
    observer = PassiveNetworkObserver([])
    observer.observe_request(
        request, phase="SESSION_REFRESH", importance="AUTHENTICATION",
        initiating_route="route-1", main_document=False,
    )
    activity.request_started(request, "route-1", relevant=False)
    activity.request_finished(request)
    assert len(observer.events) == 1
    assert observer.events[0]["method"] == "POST"
    assert activity.snapshot("route-1")["generation"] == 0
    assert activity.snapshot("route-1")["pending"] == 0


@pytest.mark.parametrize("rule", [
    {"method": "PUT", "host": "api.example.net", "path": "/api/query"},
    {"method": "PATCH", "host": "api.example.net", "path": "/api/query"},
    {"method": "DELETE", "host": "api.example.net", "path": "/api/query"},
    {"method": "POST", "host": "api.example.net", "path": "/**"},
    {"method": "POST", "host": "api.example.net", "path_pattern": "/**"},
    {"method": "POST", "host": "api.example.net:443", "path": "/api/query"},
    {"method": "POST", "host": "user@api.example.net", "path": "/api/query"},
    {"method": "POST", "host": "api.example.net", "path": "/api/../write"},
    {"method": "POST", "host": "api.example.net", "path": "/api/%2fwrite"},
])
def test_scan_read_post_contract_rejects_unsafe_rules(rule):
    with pytest.raises(ValidationError):
        ScanRequest(target="portal.example", approved_read_post_operations=[rule])
    with pytest.raises(ValueError):
        load_read_only_policy(raw=json.dumps({"safe_application_requests": [rule]}))


def test_api_response_average_excludes_failed_pending_and_blocked_requests():
    common = {"method": "POST", "url": "https://portal.example/api/query"}
    inventory = aggregate_api_events([
        {**common, "status": 201, "duration_ms": 20, "response_completed": True},
        {**common, "status": 200, "duration_ms": 80, "response_completed": True},
        {**common, "status": None, "duration_ms": 10000, "error": "NETWORK_FAILURE"},
        {**common, "status": None, "duration_ms": 9000},
        {**common, "status": 200, "duration_ms": 7000, "response_completed": False},
        {**common, "status": None, "duration_ms": 8000, "blocked_by_validator": True},
    ])[0]
    assert inventory["average_duration_ms"] == 50
    assert inventory["worst_duration_ms"] == 80
    assert inventory["network_failures"] == 1


def test_body_failure_after_http_response_keeps_status_but_excludes_response_duration():
    events = []
    observer = PassiveNetworkObserver(events)
    request = RequestFixture()
    request.method = "POST"
    event = observer.observe_request(
        request, phase="ROUTE_VALIDATION", importance="REQUIRED",
        initiating_route="https://portal.example/#/dashboard", main_document=False,
    )
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.record_response(request, 201)
    observer.record_failure(request, "net::ERR_ABORTED")
    inventory = aggregate_api_events(events)[0]
    assert event["request_failed"] is True and event["response_completed"] is False
    assert event["failure_category"] == "RESPONSE_BODY_FAILURE"
    assert inventory["status_2xx"] == 1 and inventory["network_failures"] == 0
    assert inventory["response_body_failures"] == 1
    assert inventory["average_duration_ms"] is None


@pytest.mark.parametrize("segment", [
    "%2fwrite", "%5cwrite", "%00", "%0a", "%7f", ".", "..",
    "%2e%2e", "%252fwrite", "%25252fwrite", "%3fwrite", "%23write", "%c0%af", "%e0%80%af",
])
def test_bounded_post_policy_rejects_ambiguous_actual_path_segments(segment):
    policy = load_read_only_policy(raw=json.dumps({"safe_application_requests": [{
        "method": "POST", "host": "api.example.net",
        "path_pattern": "/api/items/{segment}/query",
    }]}))
    assert policy.match("POST", f"https://api.example.net/api/items/{segment}/query") is None
    assert policy.match("POST", "https://api.example.net/api/items/ordinary-id_42/query") is not None
    assert policy.match("POST", "https://api.example.net/api/items/ordinary-id_42/query//") is None


def test_explicit_policy_source_does_not_inherit_deployment_environment(tmp_path, monkeypatch):
    mounted_policy = tmp_path / "read-only-policy.json"
    mounted_rule = {"method": "POST", "host": "api.example.net", "path": "/api/owner-approved"}
    mounted_policy.write_text(json.dumps({"safe_application_requests": [mounted_rule]}), encoding="utf-8")
    monkeypatch.setenv("PORTAL_VALIDATOR_READ_ONLY_POLICY_FILE", str(mounted_policy))
    administrator_policy = load_read_only_policy()
    scan = ScanRequest(target="portal.example", approved_read_post_operations=[{
        "method": "POST", "host": "api.example.net", "path": "/api/read-query",
    }])
    additional_policy = load_read_only_policy(raw=json.dumps({
        "safe_application_requests": [operation.model_dump(exclude_none=True) for operation in scan.approved_read_post_operations],
    }))
    from app.network import ReadOnlyPolicy
    merged = ReadOnlyPolicy(administrator_policy.safe_application_requests + additional_policy.safe_application_requests)
    assert merged.match("POST", "https://api.example.net/api/owner-approved") is not None
    assert merged.match("POST", "https://api.example.net/api/read-query") is not None
    monkeypatch.setenv("PORTAL_VALIDATOR_READ_ONLY_POLICY", '{"safe_application_requests": []}')
    with pytest.raises(ValueError, match="Configure one"):
        load_read_only_policy()
    assert load_read_only_policy(path=mounted_policy).match("POST", "https://api.example.net/api/owner-approved") is not None
    with pytest.raises(ValueError, match="Configure one"):
        load_read_only_policy(raw='{"safe_application_requests": []}', path=mounted_policy)


@pytest.fixture
def production_spa(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        routes = 1
        post_status = 201
        query_secrets = False
        authentication_flow = False
        authentication_posts = 0
        popup_mode = False
        popup_nested_mode = False
        popup_post_ready = Event()
        late_post_mode = False
        late_failure_mode = None
        missing_resource_mode = False
        release_late_post = Event()
        post_paths = []
        mutation_calls = 0
        session_cookie_seen = False
        image_calls = 0
        script_calls = 0

        def do_GET(self):
            if self.path == "/optional-missing.svg":
                body = b"Optional resource unavailable"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; private-metadata=fixture-private-mime")
            elif self.path == "/release-late-response":
                type(self).release_late_post.set()
                body = b'{"released":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            elif self.path == "/popup":
                body = b'''<!doctype html><html><body><h1>Child application</h1><script>
                fetch('/popup-bootstrap').then(()=>fetch('/api/query',{
                    method:'POST', headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({password:'fixture-private-popup-body'})
                })).then(()=>document.body.dataset.done='true');
                </script></body></html>'''
                if self.popup_nested_mode:
                    body = b'''<!doctype html><html><body><h1>First child application</h1><script>
                    fetch('/popup-bootstrap').then(()=>window.open('/nested-popup','nested-child'));
                    </script></body></html>'''
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
            elif self.path == "/nested-popup":
                body = b'''<!doctype html><html><body><h1>Nested application</h1><script>
                fetch('/api/query',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
                </script></body></html>'''
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
            elif self.path == "/popup-bootstrap":
                # Real application work completes after DOMContentLoaded. The
                # parent gate makes readiness deterministic rather than having
                # the test race the scanner with an arbitrary test sleep.
                if self.popup_nested_mode:
                    self.release_late_post.wait(3)
                else:
                    Event().wait(0.25)
                body = b'{"ready":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            elif self.path == "/popup-gate":
                self.popup_post_ready.wait(2)
                body = b'{"ready":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            elif self.path.startswith("/oauth2/authorize"):
                body = b'''<!doctype html><html><body><h1>Authentication handoff</h1>
                <form id="sso" method="POST" action="/idp/SSO.saml2">
                <input name="SAMLRequest" value="fixture-private-saml">
                <input name="RelayState" value="fixture-private-relay"></form>
                <script>document.querySelector('#sso').submit()</script></body></html>'''
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
            elif self.path.startswith("/callback"):
                self.send_response(303)
                self.send_header("Set-Cookie", "session=fixture-private-cookie; HttpOnly; SameSite=Lax")
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            elif self.path == "/":
                if self.authentication_flow and "session=fixture-private-cookie" not in self.headers.get("Cookie", ""):
                    self.send_response(302)
                    self.send_header("Location", "/oauth2/authorize?client_id=fixture&state=fixture-private-state")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                links = "".join(
                    f'<a href="#/route-{index}">Route {index}</a>'
                    for index in range(1, self.routes + 1)
                )
                api_query = "/api/query?access_token=fixture-private-query" if self.query_secrets else "/api/query"
                body = ("""<!doctype html><html><body><img src="/fixture.svg" alt="fixture"><script src="/fixture.js"></script><nav>""" + links + """</nav>
                <main><h1>Home</h1></main><script>
                document.querySelectorAll('nav a').forEach(link => link.addEventListener('click',event=>{
                  event.preventDefault(); history.pushState({},'',link.getAttribute('href'));
                  document.querySelector('main').innerHTML='<h1>'+link.textContent+'</h1>';
                  fetch('/micro/config.json').then(()=>setTimeout(()=>{
                    const calls=[];
                    for(let i=0;i<7;i++) calls.push(fetch('/api/query',{
                      method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer fixture-private-token'},
                      body:JSON.stringify({password:'fixture-private-body'})
                    }));
                    for(const method of ['PUT','PATCH','DELETE']) calls.push(fetch('/api/write',{method}));
                    Promise.allSettled(calls).then(()=>document.body.dataset.done='true');
                  },180));
                }));</script></body></html>""").replace("'/api/query'", repr(api_query))
                if self.popup_mode:
                    body = body.replace(
                        "fetch('/micro/config.json')",
                        """document.querySelector('main').innerHTML='<h1>Opening child application</h1><span aria-busy="true">Loading</span>';
                        window.open('/popup','child-application');
                        fetch('/popup-gate').then(()=>document.querySelector('main').innerHTML='<h1>Child application ready</h1>');
                        return; fetch('/micro/config.json')""",
                    )
                if self.popup_nested_mode:
                    body = body.replace(
                        "fetch('/micro/config.json')",
                        """if(link.getAttribute('href')==='#/route-1') {
                          window.open('/popup','first-child');
                        } else { fetch('/release-late-response'); }
                        return; fetch('/micro/config.json')""",
                    )
                if self.late_post_mode:
                    body = body.replace(
                        "fetch('/micro/config.json')",
                        """if(link.getAttribute('href')==='#/route-1') {
                          fetch('/analytics/read',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
                        } else { fetch('/release-late-response'); }
                        return; fetch('/micro/config.json')""",
                    )
                if self.missing_resource_mode:
                    body = body.replace(
                        "fetch('/micro/config.json')",
                        """const optionalImage=new Image(); optionalImage.src='/optional-missing.svg';
                        document.querySelector('main').append(optionalImage);
                        return; fetch('/micro/config.json')""",
                    )
                body = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", "session=fixture-private-cookie; HttpOnly; SameSite=Lax")
            elif self.path == "/fixture.svg":
                type(self).image_calls += 1
                body = ('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><!--' + "x" * 2048 + '--></svg>').encode()
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
            elif self.path == "/fixture.js":
                type(self).script_calls += 1
                body = ("/*" + "x" * 2048 + "*/").encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
            else:
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
            if self.path == "/idp/SSO.saml2":
                type(self).authentication_posts += 1
                self.send_response(303)
                self.send_header("Location", "/callback?code=fixture-private-code&state=fixture-private-state")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            type(self).post_paths.append(self.path)
            type(self).session_cookie_seen = "session=fixture-private-cookie" in self.headers.get("Cookie", "")
            body = b'{"ok":true}'
            if self.path == "/analytics/read":
                self.release_late_post.wait(3)
                if self.late_failure_mode:
                    if self.late_failure_mode == "AFTER_HEADERS":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", "100")
                        self.end_headers()
                        self.wfile.write(b"{")
                        self.wfile.flush()
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send_response(500)
            else:
                self.send_response(self.post_status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            type(self).popup_post_ready.set()

        def do_PUT(self):
            type(self).mutation_calls += 1
            self.send_response(200)
            self.end_headers()

        do_PATCH = do_PUT
        do_DELETE = do_PUT

        def log_message(self, _format, *_args):
            return

    class FixtureServer(ThreadingHTTPServer):
        # Natural SPA bursts intentionally issue seven requests concurrently.
        # The stdlib default backlog of five can reset local connections when
        # parallel browser/build work briefly delays the server accept loop.
        request_queue_size = 128

    server = FixtureServer(("127.0.0.1", 0), Handler)
    # The fixture uses an ephemeral test-only port. Production's fixed allowed
    # port policy remains unchanged, as do its DNS/private-network checks.
    from app import security
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = security.resolve_and_validate

    async def fixture_destination(host, allow_private):
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    # Permit only this fixture's loopback host at the resolver boundary; real
    # production policies intentionally reject loopback even in private mode.
    monkeypatch.setattr("app.main.resolve_and_validate", fixture_destination)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize(("approve_post", "route_count"), [(False, 1), (True, 1), (True, 43)])
async def test_full_scan_natural_spa_post_observer_policy_network_and_report(production_spa, approve_post, route_count):
    origin, handler = production_spa
    handler.routes = route_count
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    request = ScanRequest(
        target=origin,
        allow_private_networks=True,
        max_pages=route_count + 1,
        max_depth=2,
        timeout_ms=5000,
        total_timeout_ms=240000,
        render_settle_ms=500,
        max_navigation_actions=0,
        max_discovery_scrolls=0,
        check_security_headers=False,
        large_resource_threshold_bytes=1024,
        large_image_threshold_bytes=1024,
        large_js_threshold_bytes=1024,
        approved_read_post_operations=([{
            "method": "POST", "host": "127.0.0.1", "path": "/api/query",
            "description": "Application owner approved fixture read query",
        }] if approve_post else []),
    )
    report = await execute_scan(request)
    assert report["summary"]["routes_validated"] == route_count + 1
    inventory = {(item["method"], item["endpoint"]): item for item in report["api_inventory"]}
    post = inventory[("POST", "/api/query")]
    assert post["calls"] == 7 * route_count
    assert post["route_count"] == route_count
    assert report["network_observation"]["observed_requests"] == report["network_observation"]["aggregated_requests"]
    assert "POST" in report["network_observation"]["observed_methods"]
    serialized = json.dumps(report)
    assert "fixture-private" not in serialized
    assert handler.mutation_calls == 0
    assert handler.image_calls == 1 and handler.script_calls == 1
    image = next(item for item in report["resource_details"] if item["path"] == "/fixture.svg")
    script = next(item for item in report["resource_details"] if item["path"] == "/fixture.js")
    assert image["type"] == "IMAGE"
    assert image["encoded_body_size_bytes"] > 2048
    assert image["transfer_size_bytes"] > 2048
    assert "LARGE_IMAGE" in image["size_categories"]
    assert "LARGE_JS_BUNDLE" in script["size_categories"]
    for method in ("PUT", "PATCH", "DELETE"):
        assert inventory[(method, "/api/write")]["blocked_calls"] == route_count
    post_events = [event for result in report["results"] for event in result["api_requests"] if event["method"] == "POST"]
    assert len(post_events) == 7 * route_count
    assert all(event["observer_seen"] and event["route_handler_seen"] and event["policy_evaluated"] for event in post_events)
    assert all(event["aggregation_seen"] and event["serialized_to_report"] for event in post_events)
    assert all(event["initiating_route"].endswith(tuple(f"#/route-{index}" for index in range(1, route_count + 1))) for event in post_events)
    if approve_post:
        assert post["allowed_calls"] == 7 * route_count
        assert post["blocked_calls"] == 0
        assert post["status_2xx"] == 7 * route_count
        assert post["health"] == "HEALTHY", [(event["error"], event["status"]) for event in post_events]
        assert post["policies"] == ["APPROVED_READ_POST"]
        assert len(handler.post_paths) == 7 * route_count
        assert handler.session_cookie_seen is True
        assert report["summary"]["read_only_blocks"] == 3 * route_count
        assert all(event["response_status"] == 201 and event["request_reached_network"] is True for event in post_events)
    else:
        assert post["allowed_calls"] == 0
        assert post["blocked_calls"] == 7
        assert post["status_2xx"] == 0
        assert post["health"] == "NOT_EXECUTED"
        assert post["policies"] == ["READ_ONLY_BLOCK"]
        assert post["average_duration_ms"] is None
        assert handler.post_paths == []
        assert report["summary"]["read_only_blocks"] == 10
        assert all(event["request_reached_network"] is False and event["response_status"] is None for event in post_events)


@pytest.mark.asyncio
async def test_disabled_resource_checks_do_not_hide_scan_wide_read_only_blocks(production_spa):
    origin, handler = production_spa
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=2, max_depth=2,
        timeout_ms=5000, render_settle_ms=500, max_navigation_actions=0,
        max_discovery_scrolls=0, check_security_headers=False, check_resources=False,
    ))
    post = next(item for item in report["api_inventory"] if item["method"] == "POST")
    assert post["calls"] == 7 and post["blocked_calls"] == 7 and post["allowed_calls"] == 0
    assert report["summary"]["read_only_blocks"] == 10  # seven POST + PUT/PATCH/DELETE
    route = next(result for result in report["results"] if result["url"].endswith("#/route-1"))
    assert sum(event["method"] == "POST" for event in route["api_requests"]) == 7
    assert handler.post_paths == [] and handler.mutation_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("post_status,approved", [(200, True), (500, True), (200, False)])
async def test_actual_scan_read_post_health_matches_real_target_response(production_spa, scanner_logs, post_status, approved):
    origin, handler = production_spa
    handler.post_status = post_status
    handler.query_secrets = True
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=2, max_depth=2,
        timeout_ms=5000, render_settle_ms=500, max_navigation_actions=0,
        max_discovery_scrolls=0, check_security_headers=False,
        approved_read_post_operations=([{
            "method": "POST", "host": "127.0.0.1", "path": "/api/query",
        }] if approved else []),
    ))
    post = next(item for item in report["api_inventory"] if item["method"] == "POST")
    route = next(item for item in report["results"] if item["url"].endswith("#/route-1"))
    assert post["endpoint"] == "/api/query"
    assert post["calls"] == 7
    assert handler.mutation_calls == 0
    assert "fixture-private" not in json.dumps(report)
    assert "API_REQUEST_OBSERVED" in scanner_logs.text
    assert "fixture-private" not in scanner_logs.text
    if approved:
        assert len(handler.post_paths) == 7
        assert post["allowed_calls"] == 7 and post["blocked_calls"] == 0
        assert post["policy_classifications"] == ["APPROVED_READ_ONLY"]
        assert post["status_2xx" if post_status == 200 else "status_5xx"] == 7
        assert post["target_failure_count"] == (0 if post_status == 200 else 7)
        assert post["health"] == ("HEALTHY" if post_status == 200 else "FAILED")
        assert route["api_status"] == ("PASS" if post_status == 200 else "FAIL")
        assert route["api_failures"] == (0 if post_status == 200 else 7)
        assert route["passed"] is (post_status == 200)
    else:
        assert handler.post_paths == []
        assert post["policy_classifications"] == ["READ_ONLY_BLOCKED"]
        assert post["allowed_calls"] == 0 and post["blocked_calls"] == 7
        assert post["target_failure_count"] == 0 and post["health"] == "NOT_EXECUTED"
        assert route["api_failures"] == 0 and route["passed"] is True


@pytest.mark.asyncio
async def test_actual_scan_authentication_document_post_remains_allowed_and_redacted(production_spa, scanner_logs):
    origin, handler = production_spa
    handler.authentication_flow = True
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=1, max_depth=0,
        timeout_ms=8000, render_settle_ms=500, max_navigation_actions=0,
        max_discovery_scrolls=0, check_security_headers=False,
    ))
    auth_post = next(item for item in report["api_inventory"] if item["endpoint"] == "/idp/SSO.saml2")
    assert handler.authentication_posts == 1
    assert auth_post["method"] == "POST"
    assert auth_post["allowed_calls"] == 1 and auth_post["blocked_calls"] == 0
    assert auth_post["status_3xx"] == 1 and auth_post["target_failure_count"] == 0
    assert auth_post["policies"] == ["AUTH_FLOW"]
    assert auth_post["authentication_phase_count"] == 1
    assert report["results"][0]["authentication_status"] == "PASS"
    assert "fixture-private" not in json.dumps(report)
    assert "AUTH_FLOW_POST_ALLOWED" in scanner_logs.text
    assert "fixture-private" not in scanner_logs.text


@pytest.mark.asyncio
async def test_actual_scan_keeps_popup_alive_for_natural_read_post_after_domcontentloaded(production_spa, scanner_logs):
    origin, handler = production_spa
    handler.popup_mode = True
    handler.post_status = 200
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=2, max_depth=1,
        timeout_ms=5000, render_settle_ms=500, max_navigation_actions=0,
        max_discovery_scrolls=0, check_security_headers=False,
        approved_read_post_operations=[{
            "method": "POST", "host": "127.0.0.1", "path": "/api/query",
        }],
    ))
    post = next(item for item in report["api_inventory"] if item["method"] == "POST")
    assert handler.post_paths == ["/api/query"]
    assert handler.session_cookie_seen is True
    assert post["calls"] == 1 and post["allowed_calls"] == 1
    assert post["blocked_calls"] == 0 and post["status_2xx"] == 1
    assert post["target_failure_count"] == 0 and post["health"] == "HEALTHY"
    assert post["policy_classifications"] == ["APPROVED_READ_ONLY"]
    assert post["routes_using_endpoint"] == [origin + "/#/route-1"]
    assert report["network_observation"]["observed_requests"] == report["network_observation"]["aggregated_requests"]
    assert "fixture-private" not in json.dumps(report) and "fixture-private" not in scanner_logs.text


@pytest.mark.asyncio
async def test_late_approved_post_response_updates_its_own_route_health(production_spa):
    origin, handler = production_spa
    handler.routes = 2
    handler.late_post_mode = True
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=3, max_depth=1,
        timeout_ms=5000, render_settle_ms=500, max_navigation_actions=0,
        max_discovery_scrolls=0, check_security_headers=False, check_resources=False,
        approved_read_post_operations=[{
            "method": "POST", "host": "127.0.0.1", "path": "/analytics/read",
        }],
    ))
    assert handler.release_late_post.is_set()
    post = next(item for item in report["api_inventory"] if item["method"] == "POST")
    assert post["endpoint"] == "/analytics/read" and post["status_5xx"] == 1
    assert post["allowed_calls"] == 1 and post["target_failure_count"] == 1
    assert post["routes_using_endpoint"] == [origin + "/#/route-1"]
    route1 = next(result for result in report["results"] if result["url"].endswith("#/route-1"))
    route2 = next(result for result in report["results"] if result["url"].endswith("#/route-2"))
    assert route1["api_failures"] == 1 and route1["api_status"] == "WARNING"
    assert route1["classification"] == "PASS_WITH_WARNINGS" and route1["passed"] is True
    assert "OPTIONAL_API_FAILURE" in route1["warning_codes"]
    assert route2["api_failures"] == 0 and route2["api_status"] == "PASS"
    assert all(event["endpoint"] != "/analytics/read" for event in route2["api_requests"])
    assert all(event["route_activation_id"] == route1["route_activation_id"] for event in route1["api_requests"])


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_mode", ["BEFORE_HEADERS", "AFTER_HEADERS"])
async def test_late_post_network_failure_does_not_warn_an_unrelated_route(production_spa, failure_mode):
    origin, handler = production_spa
    handler.routes = 2
    handler.late_post_mode = True
    handler.late_failure_mode = failure_mode
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=3, max_depth=1,
        timeout_ms=5000, render_settle_ms=500, max_navigation_actions=0,
        # Isolate request-owned API/resource findings. Browser console messages
        # without request identity remain reported against the active route.
        max_discovery_scrolls=0, check_security_headers=False, check_resources=True, check_console=False,
        approved_read_post_operations=[{
            "method": "POST", "host": "127.0.0.1", "path": "/analytics/read",
        }],
    ))
    route1 = next(result for result in report["results"] if result["url"].endswith("#/route-1"))
    route2 = next(result for result in report["results"] if result["url"].endswith("#/route-2"))
    post = next(item for item in report["api_inventory"] if item["method"] == "POST")
    assert post["target_failure_count"] == 1 and post["blocked_calls"] == 0
    assert route1["api_failures"] == 1 and route1["classification"] == "PASS_WITH_WARNINGS"
    assert route2["api_failures"] == 0 and route2["resource_failure_count"] == 0
    assert route2["classification"] == "PASS" and route2["warning_reasons"] == [], route2["warning_reasons"]
    assert all(failure.get("route_activation_id") == route2["route_activation_id"] for failure in route2["failed_resources"])


@pytest.mark.asyncio
async def test_nested_popup_inherits_original_route_after_parent_scan_advances(production_spa):
    origin, handler = production_spa
    handler.routes = 2
    handler.popup_nested_mode = True
    handler.post_status = 200
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=3, max_depth=1,
        timeout_ms=5000, render_settle_ms=500, max_navigation_actions=0,
        max_discovery_scrolls=0, check_security_headers=False,
        approved_read_post_operations=[{
            "method": "POST", "host": "127.0.0.1", "path": "/api/query",
        }],
    ))
    assert handler.post_paths == ["/api/query"] and handler.session_cookie_seen is True
    post = next(item for item in report["api_inventory"] if item["method"] == "POST")
    assert post["health"] == "HEALTHY" and post["routes_using_endpoint"] == [origin + "/#/route-1"]
    assert post["route_validation_phase_count"] == 1 and post["discovery_phase_count"] == 0
    assert report["scan_timing"]["pages"] == 3
    route1 = next(result for result in report["results"] if result["url"].endswith("#/route-1"))
    assert any(event["method"] == "POST" for event in route1["api_requests"])
    assert all(event["phase"] == "ROUTE_VALIDATION" for event in route1["api_requests"] if event["method"] == "POST")


@pytest.mark.asyncio
async def test_http_404_subresource_is_preserved_as_nonblocking_owned_warning(production_spa):
    origin, handler = production_spa
    handler.missing_resource_mode = True
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=2, max_depth=1,
        timeout_ms=5000, render_settle_ms=500, max_navigation_actions=0,
        max_discovery_scrolls=0, check_security_headers=False, check_resources=True, check_console=False,
    ))
    route = next(result for result in report["results"] if result["url"].endswith("#/route-1"))
    assert route["page_load_status"] == "LOADED" and route["passed"] is True
    assert route["classification"] == "PASS_WITH_WARNINGS" and route["resource_status"] == "WARNING"
    assert route["resource_failure_count"] == 1
    assert route["warning_codes"] == ["NON_CRITICAL_RESOURCE_FAILURE"]
    failure = next(item for item in route["failed_resources"] if item["url"].endswith("/optional-missing.svg"))
    assert failure["route_activation_id"] == route["route_activation_id"]
    assert failure["initiating_route"] == route["url"] and failure["error"] == "Resource returned HTTP 404"
    inventory = next(item for item in report["resource_inventory"] if item["path"] == "/optional-missing.svg")
    assert inventory["failures"] == 1
    detail = next(item for item in report["resource_details"] if item["path"] == "/optional-missing.svg")
    assert detail["content_type"] == "text/plain"
    assert "fixture-private-mime" not in json.dumps(report)
    assert report["summary"]["healthy_routes"] == 2 and report["summary"]["failed_pages"] == 0
