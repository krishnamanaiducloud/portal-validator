"""Auto-loaded read-only POSTs and automatic session renewal.

A generic SPA issues POSTs on its own while it loads: a search, a list, a
GraphQL query, a GraphQL mutation, a preference save and its own session
token renewal. Only requests with read-only (or renewal) evidence may reach
the server; every write stays blocked.
"""

import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit

import pytest

from app import main, security
from app.main import ScanRequest, execute_scan
from app.navigation import json_refresh_grant_signal, session_renewal_path_signal
from app.network import inferred_read_only_post
from test_public_access_scan import require_browser

QUERY = json.dumps({"query": "query Items { items { id } }", "operationName": "Items"})
MUTATION = json.dumps({"query": "mutation Save { save(id: 1) { id } }", "operationName": "Save"})


@pytest.mark.parametrize("url,body,content_type,expected", [
    ("https://portal.example/api/search", '{"q":"x"}', "application/json", "READ_OPERATION_PATH"),
    ("https://portal.example/api/reports/list", "{}", "application/json", "READ_OPERATION_PATH"),
    ("https://portal.example/v1/items/42/getDetails", "{}", "application/json", "READ_OPERATION_PATH"),
    ("https://portal.example/graphql", QUERY, "application/json", "GRAPHQL_QUERY"),
    ("https://portal.example/rpc", '{"jsonrpc":"2.0","method":"listOrders","id":1}', "application/json", "JSON_RPC_READ"),
    ("https://portal.example/graphql", MUTATION, "application/json", None),
    ("https://portal.example/api/search/save", "{}", "application/json", None),
    ("https://portal.example/api/save-preferences", "{}", "application/json", None),
    ("https://portal.example/api/getAndUpdate", "{}", "application/json", None),
    ("https://portal.example/api/items", "{}", "application/json", None),
    ("https://portal.example/api/search", "--b", "multipart/form-data; boundary=b", None),
    ("https://portal.example/rpc", '{"jsonrpc":"2.0","method":"deleteOrder","id":1}', "application/json", None),
    ("https://portal.example/api/events/track", "{}", "application/json", None),
    ("https://portal.example/api/auth/refresh", "{}", "application/json", None),
])
def test_read_only_post_inference(url, body, content_type, expected):
    assert inferred_read_only_post(url, body, content_type) == expected


def test_session_renewal_signals():
    assert session_renewal_path_signal("https://portal.example/api/auth/refresh")
    assert session_renewal_path_signal("https://portal.example/token/refresh")
    assert session_renewal_path_signal("https://portal.example/session/keep-alive")
    assert session_renewal_path_signal("https://portal.example/api/refreshToken")
    assert not session_renewal_path_signal("https://portal.example/api/reports/refresh")
    assert not session_renewal_path_signal("https://portal.example/api/auth/logout")
    assert not session_renewal_path_signal("https://portal.example/api/token/revoke")
    assert json_refresh_grant_signal('{"refresh_token":"r"}')
    assert json_refresh_grant_signal('{"grant_type":"refresh_token","refreshToken":"r"}')
    assert not json_refresh_grant_signal('{"grant_type":"password","refresh_token":"r","password":"p"}')
    assert not json_refresh_grant_signal('{"refresh_token":""}')
    assert not json_refresh_grant_signal("grant_type=refresh_token")


SHELL = r'''<!doctype html><title>Auto-loading workspace</title>
<main><h1>Workspace</h1><p id="state">Loading</p></main>
<script>
const json = body => ({method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
Promise.allSettled([
  fetch('/api/auth/refresh', json({})),
  fetch('/api/search', json({q: 'open items'})),
  fetch('/api/reports/list', json({page: 1})),
  fetch('/graphql', json(%s)),
  fetch('/graphql', json(%s)),
  fetch('/api/preferences/save', json({theme: 'dark'})),
]).then(() => {
  document.querySelector('#state').textContent = 'Loaded';
  document.querySelector('main').dataset.appReady = 'true';
});
</script>''' % (QUERY, MUTATION)


@pytest.fixture
def auto_post_site(monkeypatch):
    receipts = Counter()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, body, kind="text/html"):
            payload = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            receipts[("GET", urlsplit(self.path).path)] += 1
            return self.reply(SHELL)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            path = urlsplit(self.path).path
            kind = "mutation" if path == "/graphql" and "mutation Save" in body else "call"
            receipts[("POST", path, kind)] += 1
            return self.reply('{"ok":true}', "application/json")

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
        yield f"http://127.0.0.1:{server.server_port}", receipts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def auto_request(origin, **overrides):
    values = dict(
        target=origin + "/", allow_private_networks=True, max_pages=1, max_depth=0,
        # Generous budgets: this test asserts policy, not speed, and also runs
        # inside the slower restricted image under full-suite load.
        timeout_ms=30000, total_timeout_ms=120000, readiness_selector='[data-app-ready="true"]',
        render_settle_ms=100, min_observation_ms=100, network_quiet_ms=50,
        max_navigation_actions=0, max_discovery_scrolls=0, check_security_headers=False,
    )
    values.update(overrides)
    return ScanRequest(**values)


@pytest.mark.asyncio
async def test_auto_loaded_read_only_posts_reach_the_application(auto_post_site):
    await require_browser()
    origin, receipts = auto_post_site
    report = await execute_scan(auto_request(origin))
    assert report["results"][0]["route_state"] == "VALIDATED"
    assert receipts[("POST", "/api/search", "call")] == 1
    assert receipts[("POST", "/api/reports/list", "call")] == 1
    assert receipts[("POST", "/graphql", "call")] == 1
    assert receipts[("POST", "/api/auth/refresh", "call")] == 1, "The session renewal must not be blocked"
    assert receipts[("POST", "/graphql", "mutation")] == 0, "A GraphQL mutation must stay blocked"
    assert receipts[("POST", "/api/preferences/save", "call")] == 0, "A write must stay blocked"
    inventory = {item["endpoint"]: item for item in report["api_inventory"] if item["method"] == "POST"}
    assert "POST_READ_ONLY_AUTO_ALLOWED" in inventory["/api/search"]["post_classifications"]
    assert "POST_READ_ONLY_UNVERIFIED" in inventory["/api/preferences/save"]["post_classifications"]
    assert report["session"]["automatic_renewals"] == 1
    assert report["session"]["renewal_hosts"] == ["127.0.0.1"]
    assert report["scan_configuration"]["auto_allow_read_only_posts"] is True


@pytest.mark.asyncio
async def test_operators_can_require_explicit_post_approval(auto_post_site):
    await require_browser()
    origin, receipts = auto_post_site
    await execute_scan(auto_request(origin, auto_allow_read_only_posts=False, auto_allow_session_renewal=False))
    assert not any(key[0] == "POST" for key in receipts), receipts
