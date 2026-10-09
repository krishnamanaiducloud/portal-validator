"""Real anonymous browsing separates application coverage from access barriers."""

import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

import pytest
from playwright.async_api import async_playwright

from app import main, security
from app.main import ScanRequest, execute_scan


@pytest.fixture
def public_access_site(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        receipts = Counter()

        def do_GET(self):
            path = urlsplit(self.path).path
            type(self).receipts[("GET", path)] += 1
            status = {"/denied": 403, "/rate-limited": 429, "/protected": 401}.get(path, 200)
            if path == "/":
                body = b'''<!doctype html><title>Public portal</title>
                <header><form><label>Optional account password <input type="password"></label>
                <button type="submit">Sign in</button></form></header>
                <main><h1>Public application dashboard</h1>
                <nav><a href="/reports">Reports</a><a href="/docs/oauth/getting-started">Help</a></nav>
                <a href="https://identity.example/login">Optional account sign in</a>
                <p>Public content does not require an account.</p></main>'''
            elif path == "/reports":
                body = b'''<!doctype html><title>Public reports</title>
                <main><h1>Public report overview</h1><p>Loading read-only statistics.</p></main>
                <script>
                Promise.allSettled([
                  fetch('/api/read-statistics', {method:'POST',body:'{}'}).then(r=>r.json()),
                  fetch('/api/unapproved', {method:'POST',body:'{}'})
                ]).then(()=>document.querySelector('p').textContent='Public statistics ready.');
                </script>'''
            elif path == "/denied":
                body = b'''<!doctype html><title>Just a moment...</title>
                <main><h1>Access denied</h1><p>This browser cannot access the application.</p>
                <a href="/must-not-crawl">Not an application route</a></main>'''
            elif path == "/rate-limited":
                body = b'''<!doctype html><title>Request limited</title>
                <main><h1>Too many requests</h1><p>Please try again later.</p></main>'''
            elif path == "/protected":
                body = b'''<!doctype html><title>Authentication needed</title>
                <main><h1>Protected application</h1><p>A valid account is required here.</p></main>'''
            else:
                body = b'''<!doctype html><title>Public help</title>
                <main><h1>Public help and support</h1><p>Useful public documentation.</p></main>'''
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            path = urlsplit(self.path).path
            type(self).receipts[("POST", path)] += 1
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = b'{"count":3}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = main.resolve_and_validate

    async def fixture_destination(host, allow_private):
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_destination)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


async def require_browser():
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")


def scan_request(target, **overrides):
    settings = dict(
        target=target, authentication={"mode": "none"}, max_pages=5, max_depth=2,
        timeout_ms=10000, total_timeout_ms=45000, max_navigation_actions=0,
        max_discovery_scrolls=0, render_settle_ms=100, min_observation_ms=300,
        network_quiet_ms=100, check_security_headers=False,
    )
    settings.update(overrides)
    return ScanRequest(**settings)


@pytest.mark.asyncio
async def test_anonymous_public_routes_and_natural_read_post_are_validated(public_access_site):
    await require_browser()
    origin, handler = public_access_site
    phases = []

    async def progress(state, **_values):
        phases.append(state)

    report = await execute_scan(scan_request(origin, approved_read_post_operations=[{
        "method": "POST", "host": "127.0.0.1", "path": "/api/read-statistics",
    }]), progress_callback=progress)
    routes = {urlsplit(item["requested_url"]).path or "/": item for item in report["results"]}
    assert set(routes) == {"/", "/docs/oauth/getting-started", "/reports"}
    assert all(item["page_load_status"] == "LOADED" and item["passed"] for item in routes.values())
    assert report["summary"]["healthy_routes"] == 3
    assert report["summary"]["failed_pages"] == report["summary"]["auth_issues"] == 0
    assert "AUTHENTICATING" not in phases
    posts = {item["endpoint"]: item for item in report["api_inventory"] if item["method"] == "POST"}
    assert set(posts) == {"/api/read-statistics", "/api/unapproved"}
    assert posts["/api/read-statistics"]["completed_calls"] == 1
    assert posts["/api/read-statistics"]["response_status_counts"] == {"200": 1}
    assert posts["/api/unapproved"]["blocked_calls"] == 1
    assert posts["/api/unapproved"]["health"] == "NOT_EXECUTED"
    assert handler.receipts[("POST", "/api/read-statistics")] == 1
    assert handler.receipts[("POST", "/api/unapproved")] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("path,status", [("/denied", 403), ("/rate-limited", 429)])
async def test_access_barriers_are_not_login_requirements_or_application_health(public_access_site, path, status):
    await require_browser()
    origin, handler = public_access_site
    report = await execute_scan(scan_request(origin + path))
    route = report["results"][0]
    assert route["status"] == status
    assert route["page_load_status"] == "LOADED"
    assert route["classification"] == "ACCESS_RESTRICTED"
    assert route["validation_status"] == route["authentication_status"] == "NOT_TESTED"
    assert route["api_status"] == "NOT_TESTED"
    assert "AUTHENTICATION_REQUIRED" not in json.dumps(route)
    assert report["summary"]["auth_issues"] == report["summary"]["failed_pages"] == 0
    assert report["summary"]["coverage_status"] == "NONE"
    assert handler.receipts[("GET", "/must-not-crawl")] == 0


@pytest.mark.asyncio
async def test_real_unauthorized_document_still_requires_authentication(public_access_site):
    await require_browser()
    origin, _handler = public_access_site
    report = await execute_scan(scan_request(origin + "/protected"))
    assert report["results"][0]["classification"] == "AUTH_REQUIRED"
    assert report["summary"]["auth_issues"] == 1
    assert report["summary"]["coverage_status"] == "NONE"


@pytest.mark.asyncio
async def test_primary_modal_and_mfa_forms_still_gate_public_navigation():
    await require_browser()
    public_content = '''<main><h1>Public application</h1><p>Useful public information.</p>
      <a href="/reports">Reports</a><a href="/help">Help</a></main>'''
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            for control in (
                '<dialog open><header><input type="password"></header></dialog>',
                '<main><form><input type="password"></form></main>',
                '<header><input autocomplete="one-time-code"></header>',
            ):
                await page.set_content(public_content + control)
                password, mfa = await main.detect_auth_signals(page)
                assert password or mfa
        finally:
            await browser.close()
