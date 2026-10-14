"""SPA fragment parameters remain distinct without retaining auth secrets."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from playwright.async_api import async_playwright

from app.discovery import SENSITIVE_QUERY_KEYS, normalize_route_url
from app.main import ScanRequest, execute_scan


@pytest.mark.parametrize("prefix", ("#/", "#!/"))
def test_default_policy_keeps_spa_parameters_and_ignores_http_query(prefix):
    assert normalize_route_url(
        "https://portal.example/?page=2&token=private-request-token"
        f"{prefix}workspace?view=reports&token=private-fragment-token&utm_source=mail"
    ) == f"https://portal.example/{prefix}workspace?view=reports"


@pytest.mark.parametrize(("policy", "expected"), (
    ("ignore", "https://portal.example/#/workspace?tab=annual&view=reports"),
    ("preserve", "https://portal.example/?page=2&view=home#/workspace?tab=annual&view=reports"),
    ("allowlist", "https://portal.example/?view=home#/workspace?view=reports"),
))
def test_explicit_query_policies_keep_their_document_and_fragment_boundaries(policy, expected):
    assert normalize_route_url(
        "https://portal.example/?view=home&page=2&token=private-request-token"
        "#/workspace?view=reports&tab=annual&token=private-fragment-token&gclid=tracking",
        query_policy=policy,
        allowed_query_parameters={"view", "token"},
    ) == expected


@pytest.mark.parametrize("key", sorted(SENSITIVE_QUERY_KEYS))
def test_default_fragment_identity_never_retains_sensitive_parameters(key):
    assert normalize_route_url(
        f"https://portal.example/#/workspace?{key}=private-fragment-value&view=reports"
    ) == "https://portal.example/#/workspace?view=reports"


def test_non_route_fragment_parameters_are_not_route_identity():
    assert normalize_route_url(
        "https://portal.example/?page=2#section?view=reports&token=private-fragment-token"
    ) == "https://portal.example/"


@pytest.fixture
def fragment_navigation_site(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            prefix = "#!/" if self.path.startswith("/hashbang") else "#/"
            body = f'''<!doctype html><title>Workspace</title><main>
              <h1>Workspace overview</h1><nav>
              <a href="{prefix}workspace?view=reports">Reports</a>
              <a href="{prefix}workspace?view=activity">Activity</a>
              </nav></main><script>
              window.addEventListener('hashchange', () => {{
                const view = new URLSearchParams(location.hash.split('?')[1]).get('view');
                document.querySelector('h1').textContent = 'Workspace ' + view;
              }});
              </script>'''.encode()
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
@pytest.mark.parametrize(("path", "prefix"), (("/hash", "#/"), ("/hashbang", "#!/")))
async def test_default_scan_validates_fragment_query_views_instead_of_collapsing_them(
    fragment_navigation_site, path, prefix,
):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    base = fragment_navigation_site + path
    report = await execute_scan(ScanRequest(
        target=f"{base}{prefix}workspace?view=home",
        max_pages=10, max_depth=2, timeout_ms=10000, total_timeout_ms=60000,
        render_settle_ms=150, min_observation_ms=200, network_quiet_ms=100,
        max_navigation_actions=0, check_security_headers=False,
    ))
    assert {item["requested_url"] for item in report["results"]} == {
        f"{base}{prefix}workspace?view={view}" for view in ("home", "reports", "activity")
    }
    assert report["summary"]["routes_discovered"] == 3
    assert report["summary"]["routes_validated"] == 3
    assert report["summary"]["failed_pages"] == 0
    assert report["summary"]["discovery_status"] == "COMPLETE"
    assert all(report["summary"]["counter_invariants"].values())
