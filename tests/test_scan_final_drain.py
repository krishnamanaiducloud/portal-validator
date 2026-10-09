"""Finalization observes natural traffic; it never replays a read-only POST."""

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from playwright.async_api import async_playwright

from app.main import ScanRequest, execute_scan


@pytest.fixture
def optional_post_site(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        delay = 0.65
        received_posts = 0

        def do_GET(self):
            body = b'''<!doctype html><title>Healthy portal</title><main>
            <h1>Read-only portal dashboard</h1><p>Application content is available.</p>
            </main><script>fetch('/analytics/read', {method: 'POST', body: '{}'})
            .then(response => response.json()).catch(() => {});</script>'''
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            type(self).received_posts += 1
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            time.sleep(self.delay)
            body = b'{"ok":true}'
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # The bounded incomplete case intentionally closes its client.
                pass

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
        yield f"http://127.0.0.1:{server.server_port}", Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("completed", [True, False])
async def test_final_drain_keeps_optional_post_complete_or_honestly_incomplete(optional_post_site, completed):
    origin, handler = optional_post_site
    handler.delay = 0.65 if completed else 3.0
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=origin, max_pages=1, timeout_ms=5000, total_timeout_ms=20000,
        readiness_timeout_ms=1000, render_settle_ms=100,
        min_observation_ms=100, network_quiet_ms=100,
        max_navigation_actions=0, check_security_headers=False,
        approved_read_post_operations=[{
            "method": "POST", "host": "127.0.0.1", "path": "/analytics/read",
        }],
    ))
    assert handler.received_posts == 1  # No direct probe/retry/replay.
    inventory = next(item for item in report["api_inventory"] if item["method"] == "POST")
    assert inventory["calls"] == inventory["sent_calls"] == 1
    assert report["summary"]["post_summary"] == {
        "observed_calls": 1, "approved_read_only_calls": 1, "executed_approved_calls": 1,
    }
    route = report["results"][0]
    assert route["page_load_status"] == "LOADED"
    assert route["passed"] is True
    if completed:
        assert inventory["completed_calls"] == 1
        assert inventory["incomplete_calls"] == 0
        assert report["network_observation"]["final_drain"]["reason"] == "API_QUIET"
    else:
        assert inventory["completed_calls"] == 0
        assert inventory["incomplete_calls"] == 1
        assert inventory["canceled_calls"] == 0
        assert report["network_observation"]["final_drain"]["reason"] == "FINALIZATION_TIMEOUT"
        assert report["summary"]["coverage_status"] == "PARTIAL"
        assert any(reason["code"] == "API_OBSERVATION_INCOMPLETE"
                   for reason in report["summary"]["coverage_reasons"])
