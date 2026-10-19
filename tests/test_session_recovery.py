"""A session that expires mid-scan is recovered, or the scan stops with its valid results.

The synthetic portal (127.0.0.1) rotates its session after a few application
API calls. An expired browser is redirected through a separate identity host
(localhost) that silently re-issues the session, like an SSO provider with its
own valid session. With ``idp_signs_in=False`` the provider shows a login form
instead, so recovery is impossible.
"""

import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from urllib.parse import parse_qs, urlsplit

import pytest

from app import main, security
from app.main import ScanRequest, execute_scan
from test_public_access_scan import require_browser

VIEWS = [f"/view-{index}" for index in range(1, 7)]


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def expiring_portal(tmp_path, monkeypatch):
    state = {"generation": 1, "api_calls": 0, "rotate_after": 4, "idp_signs_in": True}
    receipts = Counter()
    lock = Lock()
    portal_origin = {}

    def reply(handler, status, body=b"", kind="text/html", **headers):
        handler.send_response(status)
        handler.send_header("Content-Type", kind)
        handler.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            handler.send_header(name.replace("_", "-"), value)
        handler.end_headers()
        handler.wfile.write(body)

    class Identity(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            receipts[("idp", parsed.path)] += 1
            if not state["idp_signs_in"]:
                return reply(self, 200, b'<title>Sign in</title><main><h1>Sign in</h1>'
                             b'<form><input name="user"><input type="password" name="password"></form></main>')
            redirect = parse_qs(parsed.query).get("redirect_uri", [portal_origin["value"] + "/callback"])[0]
            return reply(self, 302, Location=f"{redirect}?code=fixture-code&state=s")

        def log_message(self, *_args):
            pass

    identity, identity_thread = serve(Identity)
    idp = f"http://localhost:{identity.server_port}"

    class Portal(BaseHTTPRequestHandler):
        def session_valid(self):
            cookie = self.headers.get("Cookie") or ""
            return f"session=gen-{state['generation']}" in cookie

        def do_GET(self):
            parsed = urlsplit(self.path)
            path = parsed.path
            receipts[("portal", path)] += 1
            if path == "/callback":
                with lock:
                    state["generation"] += 1
                    state["api_calls"] = 0
                return reply(self, 302, Location="/",
                             Set_Cookie=f"session=gen-{state['generation']}; Path=/; HttpOnly")
            if path.startswith("/api/"):
                with lock:
                    if self.session_valid():
                        state["api_calls"] += 1
                        if state["api_calls"] > state["rotate_after"]:
                            # Server-side expiry: the current session stops working.
                            state["generation"] += 1
                    valid = self.session_valid()
                return reply(self, 200 if valid else 401, b'{"ok":true}' if valid else b'{"error":"expired"}',
                             "application/json")
            if not self.session_valid():
                return reply(self, 302, Location=(
                    f"{idp}/oauth2/authorize?response_type=code&client_id=portal"
                    f"&redirect_uri={portal_origin['value']}/callback&state=s"))
            links = "".join(f'<a href="{view}">View {view[-1]}</a>' for view in VIEWS)
            body = (f'''<!doctype html><title>Expiring workspace</title>
                <main><h1>Workspace {path}</h1><nav>{links}</nav></main>
                <script>fetch("/api/session").then(response => {{
                  if (response.ok) document.querySelector("main").dataset.appReady = "true";
                }});</script>''').encode()
            return reply(self, 200, body)

        def log_message(self, *_args):
            pass

    portal, portal_thread = serve(Portal)
    portal_origin["value"] = f"http://127.0.0.1:{portal.server_port}"
    monkeypatch.setattr(
        security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, portal.server_port, identity.server_port},
    )
    original_resolver = main.resolve_and_validate

    async def fixture_resolver(host, allow_private):
        if host in {"127.0.0.1", "localhost"}:
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_resolver)
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "expiring.json").write_text(json.dumps({
        "cookies": [{"name": "session", "value": "gen-1", "domain": "127.0.0.1",
                     "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"}],
        "origins": [],
    }), encoding="utf-8")
    monkeypatch.setattr(main, "AUTH_STATE_DIR", profiles)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    try:
        yield portal_origin["value"], state, receipts
    finally:
        for server, thread in ((portal, portal_thread), (identity, identity_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def expiring_request(origin, **overrides):
    values = dict(
        target=origin + "/", allow_private_networks=True, max_pages=7, max_depth=2,
        timeout_ms=10000, total_timeout_ms=120000, readiness_selector='[data-app-ready="true"]',
        render_settle_ms=100, min_observation_ms=100, network_quiet_ms=50,
        max_navigation_actions=0, max_discovery_scrolls=0, check_security_headers=False,
        authentication={"mode": "storage_state", "storage_profile": "expiring"},
        authentication_hosts=["localhost"],
    )
    values.update(overrides)
    return ScanRequest(**values)


def validated_paths(report):
    return {urlsplit(result["final_url"]).path for result in report["results"]}


@pytest.mark.asyncio
async def test_session_expiring_mid_scan_is_silently_recovered_and_every_route_validated(expiring_portal):
    await require_browser()
    origin, state, receipts = expiring_portal
    report = await execute_scan(expiring_request(origin))
    assert report["scan_status"] != "FAILED", report.get("authentication_error")
    assert report["session"]["recoveries"] >= 1
    assert receipts[("idp", "/oauth2/authorize")] >= 1
    assert validated_paths(report) == {"/", *VIEWS}
    assert all(result["authentication_status"] == "PASS" for result in report["results"])
    assert report["summary"]["termination_reason"] != "SESSION_EXPIRED"
    assert report["session_interruption"] is not None  # the recovered interruption is recorded
    assert "fixture-code" not in json.dumps(report)


@pytest.mark.asyncio
async def test_unrecoverable_expiry_keeps_validated_routes_and_marks_the_rest_not_tested(expiring_portal):
    await require_browser()
    origin, state, _receipts = expiring_portal
    state["idp_signs_in"] = False
    report = await execute_scan(expiring_request(origin, session_recovery_attempts=1))
    assert report["scan_status"] == "PARTIAL"
    assert report["summary"]["termination_reason"] == "SESSION_EXPIRED"
    assert report["session_interruption"]["category"] == "SESSION_EXPIRED"
    assert 1 <= len(report["results"]) < len(VIEWS) + 1
    assert all(result["authentication_status"] == "PASS" for result in report["results"])
    not_tested = report["not_tested_routes"]
    assert not_tested and all(item["reason"] == "NOT_TESTED_SESSION_EXPIRED" for item in not_tested)
    assert report["summary"]["routes_validated"] == len(report["results"])


@pytest.mark.asyncio
async def test_zero_recovery_attempts_stops_without_reauthenticating(expiring_portal):
    await require_browser()
    origin, _state, receipts = expiring_portal
    report = await execute_scan(expiring_request(origin, session_recovery_attempts=0))
    assert receipts[("idp", "/oauth2/authorize")] == 0
    assert report["scan_status"] == "PARTIAL"
    assert report["summary"]["termination_reason"] == "SESSION_EXPIRED"
    assert report["results"]
