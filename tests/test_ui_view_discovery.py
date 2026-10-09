"""Real-browser coverage for read-only views that do not have distinct URLs."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

import pytest
from playwright.async_api import async_playwright

from app.discovery import SEMANTIC_LINK_NAVIGATION, perform_route_navigation
from app.main import ScanRequest, execute_scan


@pytest.fixture
def ui_view_site(monkeypatch):
    """Only a real UI activation causes an API call; the scanner never replays it."""
    receipts = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlsplit(self.path).path
            if path in {"/aria-tabs", "/history-tabs"}:
                controls = """
                <button type="button" role="tab" aria-selected="true" aria-controls="overview">Overview</button>
                <button type="button" role="tab" aria-selected="false" aria-controls="reports" data-view="reports">Service reports</button>
                <button type="button" role="tab" aria-selected="false" aria-controls="activity" data-view="activity">Recent activity</button>
                """
            elif path == "/hash-tabs":
                controls = """
                <a role="tab" aria-selected="true" aria-controls="overview" href="#overview">Overview</a>
                <a role="tab" aria-selected="false" aria-controls="reports" href="#reports" data-view="reports">Service reports</a>
                <a role="tab" aria-selected="false" aria-controls="activity" href="#activity" data-view="activity">Recent activity</a>
                """
            elif path == "/route-tabs":
                controls = """
                <button type="button" role="tab" aria-selected="true" aria-controls="overview">Overview</button>
                <a role="tab" aria-selected="false" aria-controls="reports" href="#/reports" data-view="reports">Service reports</a>
                <a role="tab" aria-selected="false" aria-controls="activity" href="#/activity" data-view="activity">Recent activity</a>
                """
            elif path.startswith("/semantic-spa"):
                controls = '<a href="/semantic-spa/reports" id="semantic-report">Service reports</a>'
            elif path in {"/delayed-document", "/delayed-redirect"}:
                destination = "/redirect-document" if path == "/delayed-redirect" else "/final-document"
                controls = f'''<a href="{destination}" onclick="event.preventDefault();
                setTimeout(() => location.assign(this.href), 200)">Service reports</a>'''
            elif path == "/redirect-document":
                self.send_response(302)
                self.send_header("Location", "/final-document")
                self.end_headers()
                return
            elif path == "/final-document":
                controls = ""
            else:
                self.send_error(404)
                return
            body = ("""<!doctype html><html><head><title>Read-only portal</title></head>
            <body><main><h1>Read-only service dashboard</h1>
            <p>This portal exposes independent business views through accessible navigation.</p>
            <nav aria-label="Service views"><div role="tablist">""" + controls + """
            <button type="button" role="tab" aria-selected="false" aria-controls="destructive"
              id="destructive-tab">Delete workspace</button></div></nav>
            <section id="overview" role="tabpanel"><h2>Overview</h2><p>Current service availability.</p></section>
            <section id="reports" role="tabpanel" hidden><h2>Service reports</h2><output></output></section>
            <section id="activity" role="tabpanel" hidden><h2>Recent activity</h2><output></output></section>
            <section id="destructive" role="tabpanel" hidden><h2>Workspace controls</h2></section>
            </main><script>
            const readView = async (view) => {
              document.querySelectorAll('[role=tab]').forEach(tab => {
                tab.setAttribute('aria-selected', String(tab.dataset.view === view));
              });
              document.querySelectorAll('[role=tabpanel]').forEach(panel => {
                panel.hidden = panel.id !== view;
              });
              const response = await fetch('/api/read/' + view, {
                method:'POST', headers:{'content-type':'application/json'},
                body:JSON.stringify({operation:'read',view}), credentials:'same-origin'
              });
              const result = await response.json();
              document.querySelector('#' + view + ' output').textContent = result.description;
            };
            document.querySelectorAll('[role=tab][data-view]').forEach(tab => {
              tab.addEventListener('click', event => {
                event.preventDefault();
                if (tab.hasAttribute('href')) history.replaceState({}, '', tab.getAttribute('href'));
                else if (location.pathname === '/history-tabs') history.pushState({}, '', '#/' + tab.dataset.view);
                readView(tab.dataset.view);
              });
            });
            document.querySelector('#destructive-tab').onclick = () => fetch('/api/write', {method:'POST'});
            const semantic = document.querySelector('#semantic-report');
            if (semantic) semantic.addEventListener('click', event => {
              event.preventDefault(); history.pushState({}, '', semantic.href); readView('reports');
            });
            </script></body></html>""").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "session=fixture-view-session; Path=/; HttpOnly; SameSite=Lax")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            # Body consumption is server-side fixture plumbing, never scanner capture/replay.
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            receipts.append({"path": self.path, "cookie_present": "session=fixture-view-session" in self.headers.get("Cookie", "")})
            body = json.dumps({"description": "Read-only business information loaded"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    from app import security
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = security.resolve_and_validate

    async def fixture_destination(host, allow_private):
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr("app.main.resolve_and_validate", fixture_destination)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", receipts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


async def scan_views(origin, path, *, approve_posts=True, scan_options=None):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    values = dict(
        target=origin + path, allow_private_networks=True, max_pages=10, max_depth=2,
        timeout_ms=8000, total_timeout_ms=60000,
        render_settle_ms=100, min_observation_ms=150, network_quiet_ms=50,
        max_navigation_actions=10, max_discovery_scrolls=0,
        check_security_headers=False,
        approved_read_post_operations=[
            {"method": "POST", "host": "127.0.0.1", "path": "/api/read/reports"},
            {"method": "POST", "host": "127.0.0.1", "path": "/api/read/activity"},
        ] if approve_posts else [],
    )
    values.update(scan_options or {})
    return await execute_scan(ScanRequest(**values))


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ("/aria-tabs", "/hash-tabs", "/history-tabs"))
async def test_url_less_tabs_are_independently_validated_with_natural_post_calls(ui_view_site, path):
    origin, receipts = ui_view_site
    report = await scan_views(origin, path)
    views = [route for route in report["results"] if route["navigation_type"] == "UI_VIEW_ACTIVATION"]
    assert {route["route_name"] for route in views} == {"Service reports", "Recent activity"}
    assert len(report["results"]) == 3  # Real document plus two distinct UI views, not invented URLs.
    assert report["summary"]["routes_discovered"] == 3
    assert report["summary"]["routes_validated"] == 3
    assert len({route["route_id"] for route in report["results"]}) == 3
    assert {route["canonical_route"] for route in report["results"]} == {origin + path}
    assert all(route["page_load_status"] == "LOADED" for route in views)
    assert all(route["passed"] is True for route in views)
    assert sorted(item["path"] for item in receipts) == ["/api/read/activity", "/api/read/reports"]
    assert all(item["cookie_present"] for item in receipts)
    assert report["summary"]["post_summary"] == {
        "observed_calls": 2, "approved_read_only_calls": 2, "executed_approved_calls": 2,
    }
    assert "fixture-view-session" not in json.dumps(report)
    for view in views:
        events = [event for event in view["api_requests"] if event["method"] == "POST"]
        assert len(events) == 1
        assert events[0]["initiating_route"] == view["route_id"]
        assert events[0]["phase"] == "ROUTE_VALIDATION"
        assert events[0]["response_completed"] is True
        api = next(item for item in report["api_inventory"] if item["endpoint"] == events[0]["endpoint"])
        assert api["routes_using_endpoint"] == [view["route_id"]]
        assert api["calls"] == api["executed_approved_calls"] == 1
    assert all("Delete workspace" != route["route_name"] for route in report["results"])
    assert not any(item["path"] == "/api/write" for item in receipts)


@pytest.mark.asyncio
async def test_explicit_hash_route_tabs_are_not_also_queued_as_ui_views(ui_view_site):
    origin, receipts = ui_view_site
    report = await scan_views(origin, "/route-tabs")
    assert len(report["results"]) == 3
    assert report["summary"]["routes_discovered"] == 3
    assert report["summary"]["routes_validated"] == 3
    assert not any(route["navigation_type"] == "UI_VIEW_ACTIVATION" for route in report["results"])
    routes = [route for route in report["results"] if route["navigation_type"] == "HASH_ROUTE_TRANSITION"]
    assert {route["canonical_route"] for route in routes} == {
        origin + "/route-tabs#/reports", origin + "/route-tabs#/activity",
    }
    assert sorted(item["path"] for item in receipts) == ["/api/read/activity", "/api/read/reports"]
    assert report["summary"]["post_summary"] == {
        "observed_calls": 2, "approved_read_only_calls": 2, "executed_approved_calls": 2,
    }
    for route in routes:
        events = [event for event in route["api_requests"] if event["method"] == "POST"]
        assert len(events) == 1 and events[0]["response_completed"] is True
        assert events[0]["initiating_route"] == route["route_id"]


@pytest.mark.asyncio
async def test_ui_view_discovery_does_not_grant_post_approval(ui_view_site):
    origin, receipts = ui_view_site
    report = await scan_views(origin, "/aria-tabs", approve_posts=False)
    views = [route for route in report["results"] if route["navigation_type"] == "UI_VIEW_ACTIVATION"]
    assert len(views) == 2
    assert receipts == []
    assert report["summary"]["post_summary"] == {
        "observed_calls": 2, "approved_read_only_calls": 0, "executed_approved_calls": 0,
    }
    assert all(event["blocked_by_validator"] for view in views for event in view["api_requests"] if event["method"] == "POST")
    assert report["network_observation"]["observed_requests"] == report["network_observation"]["aggregated_requests"]


@pytest.mark.asyncio
async def test_semantic_spa_link_runs_native_handler_before_document_fallback(ui_view_site):
    origin, receipts = ui_view_site
    report = await scan_views(origin, "/semantic-spa")
    route = next(route for route in report["results"] if route["canonical_route"] == origin + "/semantic-spa/reports")
    assert route["route_name"] == "Service reports"
    assert route["page_load_status"] == "LOADED" and route["passed"] is True
    assert receipts == [{"path": "/api/read/reports", "cookie_present": True}]
    events = [event for event in route["api_requests"] if event["method"] == "POST"]
    assert len(events) == 1 and events[0]["response_completed"] is True
    assert report["summary"]["post_summary"]["executed_approved_calls"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("start_path,target_path", [
    ("/delayed-document", "/final-document"),
    ("/delayed-redirect", "/redirect-document"),
])
async def test_delayed_native_document_navigation_preserves_real_http_response(ui_view_site, start_path, target_path):
    origin, receipts = ui_view_site
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.goto(origin + start_path)
            response, transitioned, activation = await perform_route_navigation(
                page, origin + target_path, SEMANTIC_LINK_NAVIGATION, 3000,
                label="Service reports", source="a",
            )
            assert response is not None and response.status == 200
            assert transitioned is False  # A delayed real document is not an SPA transition.
            assert activation == "SEMANTIC_CONTROL"
            assert page.url == origin + "/final-document"
            assert receipts == []
        finally:
            await browser.close()


@pytest.mark.asyncio
async def test_unvisited_ui_views_keep_real_urls_and_opaque_coverage_ids(ui_view_site):
    origin, receipts = ui_view_site
    report = await scan_views(origin, "/aria-tabs", scan_options={"max_pages": 1})
    assert receipts == []
    assert report["summary"]["routes_discovered"] == 3
    assert report["summary"]["routes_validated"] == 1
    assert report["summary"]["routes_not_tested"] == 2
    assert report["summary"]["coverage_status"] == "PARTIAL"
    assert len(report["not_tested_routes"]) == 2
    assert all(item["route"].startswith("UI_VIEW_") for item in report["not_tested_routes"])
    assert {item["url"] for item in report["not_tested_routes"]} == {origin + "/aria-tabs"}


@pytest.mark.asyncio
async def test_ui_view_action_budget_reports_unvisited_views_honestly(ui_view_site):
    origin, receipts = ui_view_site
    report = await scan_views(origin, "/aria-tabs", scan_options={"max_navigation_actions": 1})
    assert len(receipts) == 1
    assert report["summary"]["routes_discovered"] == 3
    assert report["summary"]["routes_validated"] == 2
    assert report["summary"]["routes_skipped"] == 1
    assert report["summary"]["termination_reason"] == "MAX_NAVIGATION_ACTIONS_REACHED"
    assert report["summary"]["coverage_status"] == "PARTIAL"
    assert report["skipped_routes"][0]["reason"] == "SKIPPED_MAX_NAVIGATION_ACTIONS"
    assert report["skipped_routes"][0]["route"].startswith("UI_VIEW_")
    assert all(report["summary"]["counter_invariants"].values())
