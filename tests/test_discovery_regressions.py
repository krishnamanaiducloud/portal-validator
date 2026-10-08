"""Controlled discovery regressions; never contact enterprise or public targets."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from playwright.async_api import async_playwright

from app.discovery import SPA_ROUTE_TRANSITION, perform_route_navigation
from app.main import ScanRequest, execute_scan


@pytest.fixture
def discovery_site(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = b'''<!doctype html><title>Portal</title><main>
                <h1>Read-only navigation fixture</h1><nav>
                <button aria-expanded="false" aria-controls="links" onclick="
                  this.setAttribute('aria-expanded','true');
                  setTimeout(() => document.querySelector('#links').innerHTML =
                    '<a href=/late-one>Late one</a><a href=/late-two>Late two</a>', 250)
                ">Services</button><div id="links"></div></nav>
                <iframe src="/frame" title="Portal navigation"></iframe></main>'''
            elif self.path == "/frame":
                body = b'''<!doctype html><title>Portal frame</title>
                <main><h1>Embedded portal navigation</h1>
                <a href="/frame/health">Embedded health</a></main>'''
            elif self.path == "/query-nav":
                body = b'''<!doctype html><title>Query navigation</title><main>
                <h1>Query-sensitive portal navigation</h1><nav>
                <a href="?view=one">First</a><a href="?view=two">Second</a></nav>
                <output id="selection">None</output></main><script>
                document.querySelectorAll('a').forEach(link => link.onclick = event => {
                  event.preventDefault(); history.pushState({}, '', link.href);
                  document.querySelector('#selection').textContent = link.textContent;
                });</script>'''
            else:
                body = b'''<!doctype html><title>Portal route</title><main>
                <h1>Healthy discovered application route</h1></main>'''
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
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr("app.main.resolve_and_validate", fixture_destination)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_production_discovery_includes_lazy_menu_and_portal_frame(discovery_site):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=discovery_site + "/", max_pages=10, max_depth=2,
        timeout_ms=10000, total_timeout_ms=60000,
        render_settle_ms=200, min_observation_ms=400, network_quiet_ms=100,
        max_navigation_actions=2, check_security_headers=False,
    ))
    assert {item["requested_url"] for item in report["results"]} == {
        discovery_site + path for path in ("/", "/late-one", "/late-two", "/frame/health")
    }
    assert report["summary"]["routes_discovered"] == 4
    assert report["summary"]["routes_validated"] == 4
    assert report["summary"]["failed_pages"] == 0


@pytest.mark.asyncio
async def test_semantic_activation_preserves_distinct_query_routes(discovery_site):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.goto(discovery_site + "/query-nav")
            _, transitioned, activation = await perform_route_navigation(
                page, discovery_site + "/query-nav?view=two", SPA_ROUTE_TRANSITION, 1000,
                label="Second", source="a",
            )
            assert transitioned and activation == "SEMANTIC_CONTROL"
            assert await page.locator("#selection").inner_text() == "Second"
        finally:
            await browser.close()
