"""Scan speed: polling views settle promptly and shared menus are explored once."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from app import discovery, main, security
from app.main import ScanRequest, execute_scan
from test_broad_authenticated_discovery import broad_portal, broad_request
from test_public_access_scan import require_browser

POLLING_PAGE = b'''<!doctype html><title>Polling workspace</title>
<main data-app-ready="true"><h1>Polling workspace</h1><p>Live status is refreshed continuously.</p></main>
<script>setInterval(() => fetch('/api/status'), 80);</script>'''


@pytest.fixture
def polling_site(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = POLLING_PAGE if not self.path.startswith("/api/") else b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "text/html" if body is POLLING_PAGE else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = main.resolve_and_validate

    async def fixture_resolver(host, allow_private):
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_resolver)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def polling_request(target, **overrides):
    values = dict(
        target=target, allow_private_networks=True, max_pages=1, timeout_ms=12000,
        total_timeout_ms=60000, render_settle_ms=200, min_observation_ms=100, network_quiet_ms=300,
        max_navigation_actions=0, max_discovery_scrolls=0, check_security_headers=False,
    )
    values.update(overrides)
    return ScanRequest(**values)


@pytest.mark.asyncio
async def test_polling_view_settles_at_the_network_cap_instead_of_the_route_timeout(polling_site):
    await require_browser()
    report = await execute_scan(polling_request(polling_site, network_settle_cap_ms=800))
    route = report["results"][0]
    assert report["scan_status"] != "FAILED", report.get("authentication_error")
    assert route["classification"] != "TIMEOUT"
    assert route["render_health"]["settle_reason"] == "DOM_STABLE_NETWORK_ACTIVE"
    assert route["total_validation_ms"] < 6000


@pytest.mark.asyncio
async def test_zero_network_cap_keeps_waiting_for_quiet_until_the_readiness_budget(polling_site):
    await require_browser()
    report = await execute_scan(polling_request(
        polling_site, network_settle_cap_ms=0, readiness_timeout_ms=2000,
    ))
    route = report["results"][0]
    assert route["render_health"]["settle_reason"] == "BOUNDED_TIMEOUT"


@pytest.mark.asyncio
@pytest.mark.parametrize("reexplore", [False, True])
async def test_shared_navigation_menus_are_explored_once_per_scan(broad_portal, monkeypatch, reexplore):
    await require_browser()
    origin, _handler = broad_portal
    reveals = []
    original = discovery._reveal_navigation_menu

    async def counted(page, element, timeout_ms):
        reveals.append(await element.evaluate("element => element.textContent.trim()"))
        return await original(page, element, timeout_ms)

    monkeypatch.setattr(discovery, "_reveal_navigation_menu", counted)
    report = await execute_scan(broad_request(
        origin, max_pages=6, reexplore_navigation_each_route=reexplore,
    ))
    validated = len(report["results"])
    assert validated == 6
    shared_menus = {"Operations", "Inventory", "Finance", "People", "Reports"}
    if reexplore:
        assert len(reveals) > len(shared_menus) * 2
    else:
        # Each shared header menu is opened once; later routes reuse the
        # already queued routes and their recorded menu ancestry.
        assert sorted(reveals) == sorted(shared_menus)
    assert report["scan_configuration"]["reexplore_navigation_each_route"] is reexplore


def test_scan_settings_have_no_policy_caps_and_are_served_to_the_dashboard():
    from fastapi.testclient import TestClient

    large = ScanRequest(
        target="portal.example", max_pages=100000, max_depth=100, max_navigation_actions=100000,
        max_discovery_scrolls=500, total_timeout_ms=86_400_000, timeout_ms=600_000,
        render_settle_ms=60_000, min_observation_ms=60_000, network_quiet_ms=60_000,
        discovery_timeout_ms=3_600_000,
        resource_hosts=[f"cdn{index}.example" for index in range(200)],
    )
    assert large.max_pages == 100000 and large.total_timeout_ms == 86_400_000
    with pytest.raises(ValueError):
        ScanRequest(target="portal.example", timeout_ms=2_147_483_648)
    settings = TestClient(main.app).get("/api/scan-settings").json()["settings"]
    for name in ("max_pages", "max_depth", "max_navigation_actions", "max_discovery_scrolls"):
        assert "maximum" not in settings[name], name
    for name in ("timeout_ms", "total_timeout_ms", "discovery_timeout_ms", "network_settle_cap_ms", "shell_marker_grace_ms", "menu_settle_ms"):
        assert settings[name]["maximum"] == 2_147_483_647, name
    assert settings["reexplore_navigation_each_route"]["default"] is False
