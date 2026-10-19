"""The scan cutoff, not Chromium teardown, defines observed resource health."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread

import pytest

from app.main import ScanRequest, execute_scan
from app import main, security


@pytest.fixture
def resource_fixture(monkeypatch):
    release = Event()

    class Handler(BaseHTTPRequestHandler):
        mode = "pending"

        def do_GET(self):
            if self.path == "/":
                body = ("<html><title>Resource fixture</title><body><main>"
                        "Controlled application shell is ready for read-only inspection."
                        f'</main><img alt="Optional image" src="/{self.mode}.png"></body></html>').encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/pending.png":
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", "1024")
                self.end_headers()
                self.wfile.flush()
                release.wait(10)
            elif self.path == "/broken.png":
                self.send_response(502)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", "1024")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"short")
                self.wfile.flush()
                self.close_connection = True
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    monkeypatch.setattr(security, "ALLOWED_PORTS", security.ALLOWED_PORTS | {server.server_port})
    original_resolver = security.resolve_and_validate

    async def fixture_destination(host, allow_private):
        # The override is confined to this local fixture; real SSRF policy and
        # every unrelated hostname still use the production resolver.
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_destination)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", Handler
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


async def scan(origin):
    return await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=1,
        timeout_ms=5000, total_timeout_ms=20000, render_settle_ms=250,
        min_observation_ms=250, network_quiet_ms=0,
        check_links=False, check_resources=True, check_console=False,
        check_security_headers=False, max_navigation_actions=0, max_discovery_scrolls=0,
    ))


@pytest.mark.asyncio
async def test_context_cleanup_does_not_manufacture_resource_failure(resource_fixture):
    origin, _handler = resource_fixture
    report = await scan(origin)
    inventory = next(item for item in report["resource_inventory"] if item["path"] == "/pending.png")
    route = report["results"][0]
    assert inventory["calls"] == 1
    assert inventory["response_status_counts"] == {"200": 1}
    assert inventory["health"] == "INCOMPLETE"
    assert inventory["failures"] == route["resource_failure_count"] == 0
    observation = next(item for item in route["resources"] if item["url"].endswith("/pending.png"))
    assert observation["lifecycle_status"] == "INCOMPLETE"
    assert observation["incomplete_reason"] == "RESPONSE_BODY_NOT_COMPLETED"
    detail = next(item for item in report["resource_details"] if item["path"] == "/pending.png")
    assert detail["incomplete_reason"] == detail["failure_reason"] == "RESPONSE_BODY_NOT_COMPLETED"
    assert not any(failure["url"].endswith("/pending.png") for failure in route["failed_resources"])
    assert not any(finding["type"] == "RESOURCE_FAILED" for finding in route["finding_details"])


@pytest.mark.asyncio
async def test_http_error_and_body_error_are_one_owned_resource_failure(resource_fixture):
    origin, handler = resource_fixture
    handler.mode = "broken"
    report = await scan(origin)
    route = report["results"][0]
    inventory = next(item for item in report["resource_inventory"] if item["path"] == "/broken.png")
    assert inventory["calls"] == inventory["failures"] == 1
    assert inventory["response_status_counts"] == {"502": 1}
    failures = [failure for failure in route["failed_resources"] if failure["url"].endswith("/broken.png")]
    assert len(failures) == route["resource_failure_count"] == 1
    assert failures[0]["status"] == 502
    assert failures[0]["route_activation_id"] == route["route_activation_id"]
    assert route["classification"] == "PASS_WITH_WARNINGS"
