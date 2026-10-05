import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from playwright.async_api import async_playwright

from app.discovery import (
    DOCUMENT_NAVIGATION,
    discover_page_routes,
    perform_route_navigation,
)
from app.health import wait_for_render_settle
from app.network import (
    SAFE_HTTP_METHODS,
    PassiveNetworkObserver,
    RouteNetworkActivity,
    load_read_only_policy,
)
from app.reporting import aggregate_api_events


class SpaHandler(BaseHTTPRequestHandler):
    approved_post_calls = 0
    session_cookie_seen = False

    def do_GET(self):
        if self.path == "/":
            body = b"""<!doctype html>
            <html><body><nav><a id="dashboard" href="#/dashboard">Dashboard</a></nav>
            <main id="app"><h1>Home</h1></main>
            <script>
              document.querySelector('#dashboard').addEventListener('click', (event) => {
                event.preventDefault();
                history.pushState({}, '', '#/dashboard');
                document.querySelector('#app').innerHTML = '<h1>Dashboard</h1><div id="microfrontend"></div>';
                fetch('/micro/dashboard/config.json').then(() => {
                  const script = document.createElement('script');
                  script.src = '/micro/dashboard/lazy.js';
                  document.head.appendChild(script);
                });
              });
            </script></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "session=fixture-only; HttpOnly; SameSite=Lax")
        elif self.path == "/micro/dashboard/config.json":
            body = b'{"module":"dashboard"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/micro/dashboard/lazy.js":
            body = b"""setTimeout(() => {
              Promise.allSettled([
                fetch('/api/dashboard-data'),
                fetch('/api/dashboard-query', {
                  method: 'POST',
                  headers: {'Content-Type': 'application/json'},
                  body: JSON.stringify({credential: 'never-capture-this'})
                })
              ]).then(() => document.body.dataset.routeReady = 'true');
            }, 650);"""
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
        elif self.path == "/api/dashboard-data":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).approved_post_calls += 1
        type(self).session_cookie_seen = "session=fixture-only" in self.headers.get("Cookie", "")
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def spa_origin():
    SpaHandler.approved_post_calls = 0
    SpaHandler.session_cookie_seen = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), SpaHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("approve_post", (False, True))
async def test_spa_route_activation_observes_delayed_microfrontend_post(
    spa_origin, approve_post
):
    policy = load_read_only_policy(raw=json.dumps({
        "safe_application_requests": ([{
            "method": "POST",
            "host": "127.0.0.1",
            "path": "/api/dashboard-query",
            "classification": "APPROVED_READ_POST",
        }] if approve_post else []),
    }))
    events = []
    observer = PassiveNetworkObserver(events)
    activity = RouteNetworkActivity()
    active_route = f"{spa_origin}/"
    started = set()

    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            context = await browser.new_context()

            def observe(request):
                if id(request) in started:
                    return
                started.add(id(request))
                activity.request_started(request, active_route)
                if request.resource_type in {"xhr", "fetch"} or request.method not in SAFE_HTTP_METHODS:
                    observer.observe_request(
                        request,
                        phase="ROUTE_VALIDATION",
                        importance="REQUIRED",
                        initiating_route=active_route,
                        main_document=request.resource_type == "document",
                    )

            async def guard(route):
                request = route.request
                observe(request)
                event = observer.observe_request(
                    request,
                    phase="ROUTE_VALIDATION",
                    importance="REQUIRED",
                    initiating_route=active_route,
                    main_document=False,
                ) if request.method == "POST" else None
                if request.method != "POST":
                    if event is not None:
                        observer.mark_allowed(request, "SAFE_METHOD")
                    await route.continue_()
                    return
                rule = policy.match(request.method, request.url)
                if rule is None:
                    observer.mark_blocked(request, "READ_ONLY_MUTATION_BLOCKED")
                    await route.abort("blockedbyclient")
                else:
                    observer.mark_allowed(request, rule.classification)
                    await route.continue_()

            def response_seen(response):
                observer.record_response(response.request, response.status)

            def request_finished(request):
                activity.request_finished(request)

            def request_failed(request):
                activity.request_finished(request)
                observer.record_failure(request, request.failure or "Request failed")

            context.on("request", observe)
            context.on("response", response_seen)
            context.on("requestfinished", request_finished)
            context.on("requestfailed", request_failed)
            await context.route("**/*", guard)
            page = await context.new_page()
            response, transitioned, activation = await perform_route_navigation(
                page, f"{spa_origin}/", DOCUMENT_NAVIGATION, 5000
            )
            assert response.status == 200
            assert transitioned is False
            assert activation == "DOCUMENT"

            route = next(
                item for item in await discover_page_routes(page)
                if item.url.endswith("/#/dashboard")
            )
            active_route = route.url
            response, transitioned, activation = await perform_route_navigation(
                page,
                route.url,
                route.navigation_mode,
                5000,
                label=route.label,
                source=route.source,
            )
            assert response is None
            assert transitioned is True
            assert activation == "SEMANTIC_CONTROL"

            render = await wait_for_render_settle(
                page,
                settle_ms=200,
                maximum_ms=2500,
                network_activity=lambda: activity.snapshot(active_route),
                minimum_observation_ms=1000,
                network_quiet_ms=500,
            )
            assert render["settle_reason"] == "DOM_AND_NETWORK_QUIET"
            assert await page.locator("h1").inner_text() == "Dashboard"
            observer.finalize_pending()
            inventory = aggregate_api_events(events)
            by_endpoint = {(item["method"], item["endpoint"]): item for item in inventory}

            assert ("GET", "/micro/dashboard/config.json") in by_endpoint
            assert by_endpoint[("GET", "/micro/dashboard/config.json")][
                "traffic_category"
            ] == "MICROFRONTEND_CONFIG"
            assert by_endpoint[("GET", "/api/dashboard-data")]["status_2xx"] == 1
            post = by_endpoint[("POST", "/api/dashboard-query")]
            assert active_route in post["routes_using_endpoint"]
            assert "never-capture-this" not in json.dumps(events)
            if approve_post:
                assert post["status_2xx"] == 1
                assert post["blocked_count"] == 0
                assert post["traffic_category"] == "APPLICATION_API"
                assert SpaHandler.approved_post_calls == 1
                assert SpaHandler.session_cookie_seen is True
            else:
                assert post["allowed_calls"] == 0
                assert post["blocked_count"] == 1
                assert post["observation_outcome"] == "BLOCKED_BY_VALIDATOR"
                assert post["traffic_category"] == "VALIDATOR_BLOCKED"
                assert SpaHandler.approved_post_calls == 0
        finally:
            await browser.close()
