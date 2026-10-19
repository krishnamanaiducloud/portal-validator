"""Session renewal: the application's own token refresh and periodic profile refresh.

A synthetic portal (127.0.0.1) restores a cookie session from a storage-state
profile and renews its access token with a refresh-token grant against a
separate identity host (localhost). No interactive login flow occurs.
"""

import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit

import pytest

from app import main, security
from app.main import ScanRequest, execute_scan
from app.navigation import AuthenticationNavigationPolicy, oauth_refresh_grant_signal
from test_public_access_scan import require_browser


# Mutable per-test fixture behaviour (reset by monkeypatch in each test).
FIXTURE_OPTIONS = {"renew_on_root": True}


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def renewal_site(tmp_path, monkeypatch):
    receipts = Counter()

    class Identity(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            receipts[("idp", "POST", urlsplit(self.path).path, body.split("&", 1)[0])] += 1
            payload = b'{"access_token":"renewed","expires_in":300}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    identity, identity_thread = serve(Identity)
    idp = f"http://localhost:{identity.server_port}"

    class Portal(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlsplit(self.path).path
            receipts[("portal", "GET", path)] += 1
            if path.startswith("/api/"):
                body, kind = b'{"ok":true}', "application/json"
            elif path == "/session/refresh":
                body, kind = b"<main data-app-ready><h1>Session refreshed</h1></main>", "text/html"
            else:
                links = "".join(f'<a href="/view-{index}">View {index}</a>' for index in range(1, 5))
                body = (f'''<!doctype html><title>Renewing workspace</title>
                    <main><h1>Renewing workspace {path}</h1><nav>{links}</nav></main>
                    <script>
                    ({'Promise.resolve()' if FIXTURE_OPTIONS["renew_on_root"] or path != "/" else 'Promise.reject()'})
                    .then(() => fetch("{idp}/oauth2/token", {{method: "POST",
                      headers: {{"Content-Type": "application/x-www-form-urlencoded"}},
                      body: "grant_type=refresh_token&refresh_token=fixture-refresh&client_id=portal"}}))
                      .catch(() => null)
                      .then(() => fetch("/api/data"))
                      .then(() => new Promise(resolve => {{
                        const open = indexedDB.open("auth", 1);
                        open.onupgradeneeded = () => open.result.createObjectStore("tokens");
                        open.onsuccess = () => {{
                          const write = open.result.transaction("tokens", "readwrite");
                          write.objectStore("tokens").put("renewed-indexeddb-token", "access");
                          write.oncomplete = resolve;
                        }};
                      }}))
                      .then(() => {{ document.querySelector("main").dataset.appReady = "true"; }});
                    </script>''').encode()
                kind = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    portal, portal_thread = serve(Portal)
    origin = f"http://127.0.0.1:{portal.server_port}"
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
    (profiles / "renewing.json").write_text(json.dumps({
        "cookies": [{"name": "session", "value": "fixture-private-session", "domain": "127.0.0.1",
                     "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"}],
        "origins": [],
    }), encoding="utf-8")
    monkeypatch.setattr(main, "AUTH_STATE_DIR", profiles)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    try:
        yield origin, profiles, receipts, tmp_path / "home"
    finally:
        for server, thread in ((portal, portal_thread), (identity, identity_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def renewal_request(origin, **overrides):
    values = dict(
        target=origin + "/", allow_private_networks=True, max_pages=5, max_depth=2,
        timeout_ms=10000, total_timeout_ms=90000, readiness_selector='[data-app-ready="true"]',
        render_settle_ms=100, min_observation_ms=100, network_quiet_ms=50,
        max_navigation_actions=0, max_discovery_scrolls=0, check_security_headers=False,
        authentication={"mode": "storage_state", "storage_profile": "renewing"},
        authentication_hosts=["localhost"],
    )
    values.update(overrides)
    return ScanRequest(**values)


def refresh_posts(receipts):
    return sum(count for key, count in receipts.items()
               if key[:3] == ("idp", "POST", "/oauth2/token") and key[3] == "grant_type=refresh_token")


def test_refresh_grant_signal_excludes_sign_in_grants():
    assert oauth_refresh_grant_signal("grant_type=refresh_token&refresh_token=r&client_id=c")
    assert not oauth_refresh_grant_signal("grant_type=authorization_code&code=c")
    assert not oauth_refresh_grant_signal("grant_type=password&username=u&password=p")
    assert not oauth_refresh_grant_signal("grant_type=refresh_token")
    assert not oauth_refresh_grant_signal(None)


@pytest.mark.parametrize("overrides,allowed", [
    ({}, True),
    ({"host": "unapproved.example"}, False),
    ({"body": "grant_type=authorization_code&code=c"}, False),
    ({"resource_type": "document"}, False),
    ({"source_portal_scoped": False}, False),
])
def test_restored_session_renewal_policy_needs_no_interactive_flow(overrides, allowed):
    policy = AuthenticationNavigationPolicy(approved_hosts=frozenset({"login.example"}))
    assert not policy.active
    values = {"host": "login.example", "body": "grant_type=refresh_token&refresh_token=r",
              "resource_type": "fetch", "source_portal_scoped": True, **overrides}
    result = policy.allows_browser_request(
        "POST", f"https://{values['host']}/oauth2/token", values["body"],
        resource_type=values["resource_type"], document_navigation=values["resource_type"] == "document",
        source_url="https://portal.example/app", source_portal_scoped=values["source_portal_scoped"],
        portal_scoped=False,
    )
    assert result is allowed
    assert not policy.active, "A renewal must not manufacture an interactive authentication flow"


@pytest.mark.asyncio
async def test_application_renews_its_token_against_an_approved_identity_host(renewal_site):
    await require_browser()
    origin, _profiles, receipts, _home = renewal_site
    report = await execute_scan(renewal_request(origin))
    assert report["scan_status"] != "FAILED", report.get("authentication_error")
    assert refresh_posts(receipts) == len(report["results"]) >= 2
    assert all(result["authentication_status"] == "PASS" for result in report["results"])
    assert "fixture-refresh" not in json.dumps(report)
    assert "fixture-private" not in json.dumps(report)


@pytest.mark.asyncio
async def test_renewal_to_an_unapproved_identity_host_stays_blocked(renewal_site):
    await require_browser()
    origin, _profiles, receipts, _home = renewal_site
    await execute_scan(renewal_request(origin, authentication_hosts=[]))
    assert refresh_posts(receipts) == 0


@pytest.mark.asyncio
async def test_periodic_profile_refresh_runs_on_an_internal_tab_during_the_scan(renewal_site):
    await require_browser()
    origin, profiles, receipts, _home = renewal_site
    (profiles / "renewing.refresh.json").write_text(json.dumps({
        "refresh_url": origin + "/session/refresh", "timeout_ms": 5000, "settle_ms": 0,
    }), encoding="utf-8")
    report = await execute_scan(renewal_request(origin, session_refresh_interval_ms=1000))
    assert report["scan_status"] != "FAILED", report.get("authentication_error")
    assert report["session"]["attempted"] is True
    assert report["session"]["periodic_refreshes"] >= 1
    assert receipts[("portal", "GET", "/session/refresh")] == 1 + report["session"]["periodic_refreshes"]
    # The refresh tab is validator-owned: never reported as an application route.
    assert not any("/session/refresh" in result["final_url"] for result in report["results"])
    assert report["scan_configuration"]["session_refresh_interval_ms"] == 1000


@pytest.mark.asyncio
async def test_renewed_indexeddb_token_is_kept_for_the_next_scan(renewal_site):
    await require_browser()
    origin, _profiles, _receipts, home = renewal_site
    report = await execute_scan(renewal_request(origin, max_pages=1))
    assert report["session"]["runtime_state_updated"] is True
    runtime_state = (home / ".portal-validator" / "sessions" / "renewing.json").read_text(encoding="utf-8")
    assert "renewed-indexeddb-token" in runtime_state
    assert "renewed-indexeddb-token" not in json.dumps(report)


@pytest.mark.asyncio
async def test_renewal_blocked_after_the_application_was_ready_does_not_fail_the_scan(renewal_site, monkeypatch):
    """The 1.13.2 failure: a later route's token renewal to an unapproved
    identity host was blocked and the whole scan ended as an authentication
    failure with zero routes."""
    await require_browser()
    monkeypatch.setitem(FIXTURE_OPTIONS, "renew_on_root", False)
    origin, _profiles, receipts, _home = renewal_site
    report = await execute_scan(renewal_request(origin, authentication_hosts=[]))
    assert refresh_posts(receipts) == 0, "An unapproved identity host must stay blocked"
    assert report["scan_status"] != "FAILED", report.get("authentication_error")
    assert report["authentication_status"] == "AUTHENTICATED"
    results = {urlsplit(result["final_url"]).path: result for result in report["results"]}
    assert results["/"]["authentication_status"] == "PASS"
    assert len(results) >= 3
    blocks = report["mid_scan_authentication_blocks"]
    assert blocks and all(item["destination_host"] == "localhost" for item in blocks)
    assert "fixture-refresh" not in json.dumps(report)
