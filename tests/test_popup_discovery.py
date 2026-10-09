"""Popup navigation remains observable even when DOM settling is disabled."""
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from playwright.async_api import async_playwright

from app.main import ScanRequest, execute_scan


@pytest.mark.asyncio
async def test_slow_permitted_popup_is_discovered_before_scan_completion(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
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
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
