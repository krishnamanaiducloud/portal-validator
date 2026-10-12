"""Popup navigation remains observable even when DOM settling is disabled."""
import asyncio
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

import pytest
from playwright.async_api import async_playwright

from app.main import ScanRequest, execute_scan


@pytest.mark.asyncio
@pytest.mark.parametrize("popup_kind", ["post_document", "post_redirect", "late_document"])
async def test_initial_popup_post_ownership_and_completed_late_popup_coverage(monkeypatch, popup_kind):
    """Frame-less first POSTs and already-completed late tasks retain evidence."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def respond(self, body):
            body = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            received.append(("GET", self.path))
            script = "" if popup_kind == "late_document" or self.path != "/" else """
            <form id="lookup" method="post" action="/lookup" target="_blank">
              <input name="query" value="fixture-private-query"></form>
            <script>document.getElementById('lookup').submit()</script>"""
            self.respond('<main><h1>Read-only application</h1><p>Available healthy content.</p></main>' + script)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received.append(("POST", self.path))
            if popup_kind == "post_redirect":
                self.send_response(303)
                self.send_header("Location", "/lookup-result")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.respond('<title>Lookup view</title><main><h1>Lookup results</h1><p>Read-only results.</p></main>')

        def log_message(self, *_args):
            pass

    from app import main, security
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = security.resolve_and_validate

    async def fixture_destination(host, allow_private):
        return ["127.0.0.1"] if host == "127.0.0.1" else await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_destination)
    if popup_kind == "late_document":
        source_pages = []
        original_discover = main.discover_page_routes
        original_drain = main.drain_pending_api_observations

        async def capture_page(page, *args, **kwargs):
            source_pages.append(page)
            return await original_discover(page, *args, **kwargs)

        async def open_during_final_drain(*args, **kwargs):
            result = await original_drain(*args, **kwargs)
            page = source_pages[0]
            async with page.context.expect_page() as opened:
                await page.evaluate("window.open('/late', '_blank')")
            popup = await opened.value
            await popup.wait_for_load_state("domcontentloaded")
            # Complete the popup observer before drain returns. Its task has
            # removed itself, but the discovered route must still be reconciled.
            await asyncio.sleep(0.5)
            return result

        monkeypatch.setattr(main, "discover_page_routes", capture_page)
        monkeypatch.setattr(main, "drain_pending_api_observations", open_during_final_drain)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                pytest.skip("matching Playwright Chromium is not installed on this host")
        report = await execute_scan(ScanRequest(
            target=origin, max_pages=3, max_depth=2, timeout_ms=20000, total_timeout_ms=60000,
            render_settle_ms=0, min_observation_ms=50, network_quiet_ms=50,
            max_navigation_actions=0, max_discovery_scrolls=0, check_security_headers=False,
            approved_read_post_operations=[{"host": "127.0.0.1", "path": "/lookup"}],
        ))
        assert report["summary"]["routes_discovered"] == 2
        if popup_kind != "late_document":
            assert report["summary"]["routes_validated"] == 2
            root, popup = report["results"]
            assert root["api_requests"] == []
            assert len(popup["api_requests"]) == 1
            event = popup["api_requests"][0]
            assert event["method"] == "POST" and event["endpoint"] == "/lookup"
            assert event["status"] == (303 if popup_kind == "post_redirect" else 200)
            assert event["main_document"]
            assert event["route_activation_id"] == popup["route_activation_id"]
            assert event["source_page_id"] is not None
            assert received.count(("POST", "/lookup")) == 1
        else:
            assert report["summary"]["routes_validated"] == 1
            assert report["summary"]["coverage_status"] != "COMPLETE"
            assert report["summary"]["termination_reason"] == "LATE_NAVIGATION_OBSERVED"
            assert report["results"][0]["navigation_actions"]["late_popup_observations"] == 1
            assert received.count(("GET", "/late")) == 1
        assert "fixture-private-query" not in str(report)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_slow_permitted_popup_is_discovered_before_scan_completion(monkeypatch):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if self.path == "/reports":
                time.sleep(1.5)
                body = b'<main><h1>Healthy popup report</h1><p>Read-only business content.</p></main>'
            else:
                body = b'''<main><h1>Healthy portal home</h1><p>Read-only content.</p></main>
                <script>window.open('/reports', '_blank')</script>'''
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
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
        return ["127.0.0.1"] if host == "127.0.0.1" else await original_resolver(host, allow_private)

    monkeypatch.setattr("app.main.resolve_and_validate", fixture_destination)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                pytest.skip("matching Playwright Chromium is not installed on this host")
        # This tests discovery of a delayed popup, not a ten-second route SLO.
        # Leave headroom for Chromium/CDP startup on contended CI/WSL hosts;
        # keep the short observation window and every coverage assertion.
        report = await execute_scan(ScanRequest(
            target=origin, max_pages=3, max_depth=2, timeout_ms=20000, total_timeout_ms=60000,
            render_settle_ms=0, min_observation_ms=50, network_quiet_ms=50,
            max_navigation_actions=0, check_security_headers=False,
        ))
        assert {route["requested_url"] for route in report["results"]} == {origin, origin + "/reports"}
        assert report["summary"]["routes_discovered"] == 2
        assert report["summary"]["routes_validated"] == 2
        assert report["summary"]["failed_pages"] == 0
        assert report["summary"]["coverage_status"] == "COMPLETE"
        assert report["scan_timing"]["pages"] == 2
        assert requests.count("/reports") == 1, "Inspect the naturally opened popup, never reload it in the primary page"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("automatic", [False, True])
async def test_original_popup_tabs_nested_windows_and_natural_apis_are_inspected(monkeypatch, automatic):
    """A direct goto cannot reproduce this window-local application state."""
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def reply(self, body, content_type="text/html"):
            body = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            requests.append(("GET", path))
            if path == "/":
                action = "<script>window.open('/workspace','_blank')</script>" if automatic else (
                    '<nav><a href="/workspace" target="_blank" rel="opener">Workspace</a></nav>'
                )
                return self.reply('<main data-app-ready="true"><h1>Portal home</h1><p>Available read-only workspaces.</p></main>' + action)
            if path == "/workspace":
                return self.reply('''<title>Workspace</title><nav><a href="#/activity">Activity</a></nav>
                <main data-app-ready="true"><h1>Workspace overview</h1><p>Window-owned application data.</p></main>
                <div role="tablist" aria-label="Workspace panels"><button role="tab"
                 aria-controls="details-panel" aria-selected="false" onclick="showPanel(this)">Details panel</button></div>
                <section id="details-panel" hidden><h2>Details panel content</h2></section>
                <script>
                function observeView(name) {
                  fetch('/api/view',{method:'POST',headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({view:name,privateValue:'fixture-secret-body'})});
                  fetch('/api/update',{method:'POST',body:'fixture-secret-mutation'}).catch(()=>{});
                }
                function showPanel(button) {
                  button.setAttribute('aria-selected','true');document.querySelector('#details-panel').hidden=false;
                  document.querySelector('main h1').textContent='Details panel';observeView('details');
                }
                if(!window.opener) {
                  document.querySelector('main').removeAttribute('data-app-ready');
                  document.querySelector('main h1').textContent='Lost original window state';
                } else {
                  console.warn('Workspace-only diagnostic');observeView('overview');
                  window.open('/detail','_blank');
                  addEventListener('hashchange',()=>{document.querySelector('main h1').textContent='Activity view';observeView('activity');});
                }
                </script>''')
            if path == "/detail":
                return self.reply('''<title>Nested detail</title><main data-app-ready="true"><h1>Nested detail</h1>
                <p>Safe independent read-only content.</p></main><script>
                console.warn('Nested-window diagnostic');fetch('/api/detail');</script>''')
            return self.reply('{"ok":true}', "application/json")

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append(("POST", urlsplit(self.path).path))
            self.reply('{"ok":true}', "application/json")

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    from app import main, security
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = security.resolve_and_validate

    async def fixture_destination(host, allow_private):
        return ["127.0.0.1"] if host == "127.0.0.1" else await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_destination)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                pytest.skip("matching Playwright Chromium is not installed on this host")
        report = await execute_scan(ScanRequest(
            target=origin, max_pages=12, max_depth=4, max_navigation_actions=8,
            timeout_ms=20000, total_timeout_ms=90000, readiness_timeout_ms=2000,
            readiness_selector='[data-app-ready="true"]', max_discovery_scrolls=0,
            render_settle_ms=50, min_observation_ms=100, network_quiet_ms=50,
            approved_read_post_operations=[{"host": "127.0.0.1", "path": "/api/view"}],
            check_security_headers=False,
        ))
        results = report["results"]
        assert len(results) == 5, [(item["requested_url"], item["route_name"], item.get("error")) for item in results]
        assert {item["route_name"] for item in results} >= {"Workspace", "Activity", "Details panel", "Nested detail"}
        assert all(item["application_ready"] for item in results)
        assert requests.count(("GET", "/workspace")) == 1
        assert requests.count(("GET", "/detail")) == 1
        assert not any(method == "POST" and path == "/api/update" for method, path in requests)
        workspace_views = [item for item in results if urlsplit(item["requested_url"]).path == "/workspace"]
        assert len(workspace_views) == 3
        for route in workspace_views:
            assert any(event["endpoint"] == "/api/view" and event["method"] == "POST" and event["status"] == 200
                       for event in route["api_requests"]), (route["route_name"], route["api_requests"])
            assert any(event["endpoint"] == "/api/update" and event["blocked_by_validator"] for event in route["api_requests"])
        assert any("Workspace-only diagnostic" in text for route in results for text in route["console_errors"])
        assert any("Nested-window diagnostic" in text for route in results for text in route["console_errors"])
        root = results[0]
        assert root["console_errors"] == []
        assert not root["api_requests"], "Popup bootstrap is owned by the popup, not its opener"
        workspace = next(item for item in results if item["requested_url"] == origin + "/workspace")
        detail = next(item for item in results if item["requested_url"] == origin + "/detail")
        assert "Workspace-only diagnostic" in workspace["console_errors"]
        assert "Nested-window diagnostic" not in workspace["console_errors"]
        assert detail["console_errors"] == ["Nested-window diagnostic"]
        assert [event["endpoint"] for event in detail["api_requests"]] == ["/api/detail"]
        assert not any(event["endpoint"] == "/api/detail" for item in workspace_views for event in item["api_requests"])
        assert all(item["browser_lifecycle"]["state"] == "REPORT" for item in results)
        assert all(item["browser_lifecycle"]["failed_stage"] is None for item in results)
        assert report["scan_timing"]["pages"] == 3
        import json
        assert "fixture-secret" not in json.dumps(report)
        assert all(report["summary"]["counter_invariants"].values())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
