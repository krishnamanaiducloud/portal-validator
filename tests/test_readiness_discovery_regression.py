"""Completed progress must not prevent authenticated safe route discovery."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

import pytest
from playwright.async_api import async_playwright

from app import health, security
from app.main import ScanRequest, execute_scan


@pytest.mark.asyncio
@pytest.mark.parametrize("attributes,ready", [
    ('aria-valuenow="100"', True),
    ('aria-valuemin="0" aria-valuemax="100" aria-valuenow="100"', True),
    ('aria-valuemin="10" aria-valuemax="20" aria-valuenow="20"', True),
    ('aria-valuemin="-100" aria-valuemax="0" aria-valuenow="0"', True),
    ('aria-valuenow="101"', True),
    ('aria-valuenow="99"', False),
    ('aria-valuemin="10" aria-valuemax="20" aria-valuenow="19"', False),
    ('', False),
    ('aria-valuenow=""', False),
    ('aria-valuenow="complete"', False),
    ('aria-valuenow="100" aria-valuemax="unknown"', False),
    ('aria-valuemin="100" aria-valuemax="100" aria-valuenow="100"', False),
    ('aria-valuenow="100" aria-busy="true"', False),
])
async def test_progressbar_completion_preserves_active_loader_gates(attributes, ready):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content(
                '<main><h1>Application workspace is rendered</h1>'
                '<a href="/reports">Reports</a>'
                f'<div role="progressbar" {attributes} style="width:100px;height:20px">Progress</div></main>'
            )
            snapshot = await health.capture_render_health(page)
            assert snapshot["busy_indicators"] == (0 if ready else 1)
            assert health.application_shell_ready(snapshot) is ready
        finally:
            await browser.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", [
    '<main aria-busy="true">The application is still loading</main>',
    '<div data-sitekey="fixture">Interactive verification challenge</div>',
])
async def test_completed_progress_does_not_override_other_readiness_gates(signal):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content(
                '<main><h1>Application workspace is rendered</h1>'
                '<div role="progressbar" aria-valuenow="100" style="width:100px;height:20px">Complete</div></main>'
                + signal
            )
            assert not health.application_shell_ready(await health.capture_render_health(page))
        finally:
            await browser.close()


@pytest.fixture
def completed_progress_site(monkeypatch):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("X-Fixture-Auth") != "fixture":
                self.send_error(401)
                return
            path = urlsplit(self.path).path
            requests.append(path)
            body = (
                '<main><h1>Authenticated application workspace</h1>'
                '<nav><a href="/reports">Reports</a><a href="/details">Details</a></nav>'
                '<p>Application data is rendered and navigation works.</p>'
                '<div role="progressbar" aria-valuenow="100" style="width:100px;height:20px">Complete</div></main>'
                if path == "/" else
                '<main><h1>Authenticated business report</h1><p>Rendered report content.</p></main>'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    from app import main
    original_resolver = main.resolve_and_validate

    async def fixture_destination(host, allow_private):
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_destination)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_completed_progress_allows_authenticated_scan_to_validate_safe_routes(completed_progress_site):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    origin, requests = completed_progress_site
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True,
        authentication={"mode": "headers", "headers": {"X-Fixture-Auth": "fixture"}},
        max_pages=5, max_depth=3, timeout_ms=8000, total_timeout_ms=30000,
        readiness_timeout_ms=1500, render_settle_ms=100,
        min_observation_ms=150, network_quiet_ms=50,
        max_discovery_scrolls=0, check_security_headers=False,
    ))
    assert {urlsplit(route["canonical_route"]).path for route in report["results"]} == {
        "/", "/reports", "/details",
    }
    assert {"/", "/reports", "/details"}.issubset(requests)
    assert all(route["application_ready"] for route in report["results"])
    assert all(route["authentication_status"] == "PASS" for route in report["results"])
    assert all(route["validation_status"] == "PASS" for route in report["results"])
    assert report["results"][0]["render_health"]["busy_indicators"] == 0
    assert report["summary"]["termination_reason"] == "DISCOVERY_EXHAUSTED"
    assert report["summary"]["scan_completeness"] == "COMPLETE"
