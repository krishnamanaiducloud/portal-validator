"""End-to-end, generic authenticated application with naturally generated traffic."""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

import pytest
from playwright.async_api import Error as PlaywrightError, async_playwright

from app import main, security
from app.main import ScanRequest, execute_scan


@pytest.fixture
def authenticated_spa(tmp_path, monkeypatch):
    receipts = []
    origins = {}

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, body=b"", content_type="text/html", **headers):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key.replace("_", "-"), value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            receipts.append((self.server.role, "GET", path))
            if self.server.role == "identity" and path == "/oauth/authorize":
                if "idp_session=fixture-private-idp" not in self.headers.get("Cookie", ""):
                    return self.reply(200, b'<main><h1>Sign in required</h1><input type="password"></main>')
                # The fetch and auto-post are app-owned, not validator replay.
                return self.reply(200, b'''<main><h1>Authorized session handoff</h1>
                    <form method="POST" action="/saml/consume"><input type="hidden"
                      name="SAMLRequest" value="fixture-private-assertion"></form>
                    <script>fetch('/oauth/token',{method:'POST',headers:{
                      'Content-Type':'application/x-www-form-urlencoded'},
                      body:'grant_type=authorization_code&code=fixture-private-code'})
                      .then(r=>{if(r.ok) document.forms[0].submit();});</script></main>''')
            if path == "/callback":
                return self.reply(303, Location="/index.html", Set_Cookie="app_session=fixture-private-session; HttpOnly; SameSite=Lax")
            if path in {"/", "/index.html"}:
                if "app_session=fixture-private-session" not in self.headers.get("Cookie", ""):
                    return self.reply(302, Location=origins["identity"] + "/oauth/authorize?client_id=fixture&response_type=code")
                return self.reply(200, SHELL.encode())
            if path == "/api/failure":
                return self.reply(502, b'{"error":"fixture unavailable"}', "application/json")
            if path == "/missing-widget.js":
                return self.reply(502, b"Unavailable", "application/javascript")
            if path.startswith("/api/"):
                if path == "/api/bootstrap":
                    time.sleep(0.15)
                return self.reply(200, b'{"ready":true}', "application/json")
            return self.reply(404, b"Not found", "text/plain")

        def do_POST(self):
            path = urlsplit(self.path).path
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            receipts.append((self.server.role, "POST", path))
            if self.server.role == "identity" and path == "/oauth/token":
                return self.reply(200, b'{"ok":true}', "application/json")
            if self.server.role == "identity" and path == "/saml/consume":
                return self.reply(303, Location=origins["portal"] + "/callback?code=fixture-private-code&state=fixture-private-state")
            if path == "/api/read":
                assert "app_session=fixture-private-session" in self.headers.get("Cookie", "")
                return self.reply(200, b'{"ok":true}', "application/json")
            return self.reply(405)

        def log_message(self, *_args):
            pass

    servers = []
    for role in ("portal", "identity"):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.role = role
        host = "127.0.0.1" if role == "portal" else "localhost"
        origins[role] = f"http://{host}:{server.server_port}"
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, *(server.server_port for server, _ in servers)})
    original_resolver = security.resolve_and_validate

    async def fixture_resolver(host, allow_private):
        # Only this isolated test's local servers bypass loopback rejection.
        # Production policy and unrelated destinations still use the real resolver.
        if host in {"127.0.0.1", "localhost"}:
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_resolver)
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    (profile_dir / "fixture.json").write_text(json.dumps({"cookies": [{
        "name": "idp_session", "value": "fixture-private-idp", "domain": "localhost", "path": "/",
        "expires": time.time() + 3600, "httpOnly": True, "secure": False, "sameSite": "Lax",
    }], "origins": []}), encoding="utf-8")
    monkeypatch.setattr(main, "AUTH_STATE_DIR", profile_dir)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    try:
        yield origins, receipts
    finally:
        for server, thread in servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


SHELL = '''<!doctype html><html><head><title>Generic protected application</title>
<style>.hover-menu .panel {display:none}.hover-menu:hover .panel {display:block}</style></head>
<body><nav aria-label="Application navigation">
<a href="/">Home</a><a href="/index.html">Application home</a>
<a href="#/overview">Overview</a>
<div class="hover-menu"><button aria-haspopup="menu" aria-controls="hover-panel">Activity menu</button>
<div class="panel" id="hover-panel" role="menu"><a href="#/activity">Recent activity</a></div></div>
<button aria-expanded="false" aria-controls="sections" onclick="this.setAttribute('aria-expanded','true');
document.querySelector('#sections').hidden=false">Services</button>
<div id="sections" hidden><button aria-expanded="false" aria-controls="details" onclick="
this.setAttribute('aria-expanded','true');document.querySelector('#details').hidden=false">Information</button></div>
<div id="details" hidden><a href="#/reports">Service reports</a></div>
<button onclick="window.unsafeAction=true">Begin Work</button>
</nav><main aria-busy="true"><h1>Loading application</h1></main>
<section id="tabs"><div role="tablist" aria-label="Read-only panels">
<button role="tab" aria-controls="summary-panel" aria-selected="false" onclick="panel(this,'Summary panel')">Summary panel</button>
<button role="tab" aria-controls="history-panel" aria-selected="false" onclick="panel(this,'History panel')">History panel</button>
</div><section id="summary-panel" role="tabpanel" hidden></section><section id="history-panel" role="tabpanel" hidden></section></section>
<script>
async function traffic() {
  await Promise.allSettled([fetch('/api/shared'),fetch('/api/read',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}),
    fetch('/api/write',{method:'POST',body:'{}'})]);
}
async function panel(button,label) {
 document.querySelectorAll('[role=tab]').forEach(x=>x.setAttribute('aria-selected','false'));
 document.querySelectorAll('[role=tabpanel]').forEach(x=>x.hidden=true);
 button.setAttribute('aria-selected','true');const view=document.getElementById(button.getAttribute('aria-controls'));
 view.hidden=false;view.innerHTML='<h2>'+label+'</h2><p>Read-only application information.</p>';await traffic();
}
async function render() {
 const name=location.hash.slice(2)||'Home'; const main=document.querySelector('main');main.setAttribute('aria-busy','true');
 document.querySelector('#tabs').hidden=Boolean(location.hash);
 main.innerHTML='<h1>'+name+'</h1><p>Authorized application view content.</p>';
 await traffic(); if(name==='reports') {
   await fetch('/api/failure');const script=document.createElement('script');script.src='/missing-widget.js';main.append(script);
 }
 main.removeAttribute('aria-busy');document.body.dataset.appReady='true';
}
window.addEventListener('hashchange',render);
fetch('/api/bootstrap').then(()=>{
 const link=document.createElement('a');link.href='#/dynamic';link.textContent='Dynamic destination';document.querySelector('nav').append(link);
 render();
});
</script></body></html>'''


async def scan_fixture(origins, **overrides):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    values = dict(
        target=origins["portal"], allow_private_networks=True, authentication_hosts=["localhost"],
        authentication={"mode": "storage_state", "storage_profile": "fixture"},
        approved_read_post_operations=[{"host": "127.0.0.1", "path": "/api/read"}],
        max_pages=20, max_depth=3, max_navigation_actions=12, max_discovery_scrolls=0,
        timeout_ms=15000, total_timeout_ms=90000, readiness_selector='[data-app-ready="true"]',
        render_settle_ms=100, min_observation_ms=200, network_quiet_ms=100, check_security_headers=False,
    )
    values.update(overrides)
    return await execute_scan(ScanRequest(**values))


@pytest.mark.asyncio
async def test_authenticated_spa_all_safe_views_and_per_tab_api_health(authenticated_spa):
    origins, receipts = authenticated_spa
    report = await scan_fixture(origins)
    print("SPA_METRICS " + json.dumps({
        "routes": report["pages"], "names": [r["route_name"] for r in report["results"]],
        "authentication": [r["authentication_status"] for r in report["results"]],
        "apis": len(report["api_inventory"]), "coverage": report["summary"]["coverage_grade"],
        "receipts": receipts,
    }))
    results = report["results"]
    assert results[0]["authentication_status"] == "PASS", results[0].get("error")
    assert results[0]["application_ready"] is True
    assert results[0]["route_name"] == "Home", "Use the ready application heading, not its bootstrap placeholder"
    assert {urlsplit(r["final_url"]).fragment for r in results} >= {"/overview", "/activity", "/reports", "/dynamic"}
    assert {r["route_name"] for r in results if r["view_type"] == "UI_TAB"} == {"Summary panel", "History panel"}
    assert len(results) == 7  # one entry document, four hash routes, two URL-less tabs
    assert sum(role == "portal" and method == "GET" and path in {"/", "/index.html"}
               for role, method, path in receipts) == 2  # initial request plus auth callback document only
    shared = next(item for item in report["api_inventory"] if item["endpoint"] == "/api/shared")
    assert shared["route_count"] == 7
    assert len(report["api_request_occurrences"]) == sum(item["calls"] for item in report["api_inventory"])
    assert len({item["request_id"] for item in report["api_request_occurrences"]}) == len(report["api_request_occurrences"])
    assert all(item.get("route_name") for item in report["api_request_occurrences"])
    for route in results:
        events = route["api_requests"]
        assert any(event["endpoint"] == "/api/shared" for event in events)
        assert any(event["endpoint"] == "/api/read" and event["status"] == 200 for event in events)
        assert any(event["endpoint"] == "/api/write" and event["blocked_by_validator"] for event in events)
        assert all(event["route_activation_id"] == route["route_activation_id"] for event in events)
    failed = next(item for item in report["api_inventory"] if item["endpoint"] == "/api/failure")
    assert failed["status_5xx"] == 1 and failed["validation_outcome"] == "FAILED"
    resource = next(item for item in report["resource_inventory"] if item["path"] == "/missing-widget.js")
    assert resource["failures"] == 1
    assert not any(method == "POST" and path == "/api/write" for _, method, path in receipts)
    assert sum(role == "identity" and method == "POST" and path == "/oauth/token" for role, method, path in receipts) == 1
    assert sum(role == "identity" and method == "POST" and path == "/saml/consume" for role, method, path in receipts) == 1
    assert "fixture-private" not in json.dumps(report)
    assert all(report["summary"]["counter_invariants"].values())
    assert all(route["browser_lifecycle"]["state"] == "REPORT" for route in results)
    assert all(route["browser_lifecycle"]["failed_stage"] is None for route in results)
    assert all("APPLICATION_READY" in [event["state"] for event in route["browser_lifecycle"]["events"]] for route in results)


@pytest.mark.asyncio
@pytest.mark.parametrize("approved,deny_fetch,expected", [
    (False, False, "SESSION_EXPIRED"),
    (True, True, "AUTHENTICATION_BLOCKED"),
])
async def test_unapproved_authentication_stops_before_discovery(authenticated_spa, monkeypatch, approved, deny_fetch, expected):
    origins, receipts = authenticated_spa
    if deny_fetch:
        # Exercise a genuine denied protocol attempt after approved state load,
        # not a login challenge caused by intentionally excluded profile cookies.
        monkeypatch.setattr(main.AuthenticationNavigationPolicy, "allows_browser_request", lambda *_args, **_kwargs: False)
    report = await scan_fixture(origins, authentication_hosts=["localhost"] if approved else [])
    assert report["scan_status"] == "FAILED"
    assert report["authentication_error"]["category"] == expected
    assert report["results"] == report["route_inventory"] == []
    assert report["summary"]["routes_discovered"] == 0
    assert report["coverage"]["discovery_status"] == "NOT_STARTED"
    assert not report["summary"]["coverage_complete"]
    assert not any(method == "POST" for _, method, _ in receipts)


@pytest.mark.asyncio
async def test_missing_shell_readiness_never_starts_navigation_discovery(authenticated_spa):
    origins, _ = authenticated_spa
    report = await scan_fixture(origins, readiness_selector="[data-nonexistent-shell]", readiness_timeout_ms=1000)
    assert report["scan_status"] == "FAILED"
    assert report["authentication_error"]["stage"] == "APPLICATION_BOOTSTRAP"
    assert report["authentication_error"]["category"] == "APPLICATION_NOT_READY"
    assert report["results"] == report["route_inventory"] == []
    assert not report["summary"]["coverage_complete"]
    assert report["summary"]["navigation_controls_activated"] == 0


@pytest.mark.asyncio
async def test_persistent_discovery_error_preserves_main_document_health_and_limits_coverage(authenticated_spa, monkeypatch):
    origins, _ = authenticated_spa

    async def unavailable(*_args, **_kwargs):
        raise PlaywrightError("Execution context was destroyed after bounded retries")

    monkeypatch.setattr(main, "expand_safe_navigation", unavailable)
    report = await scan_fixture(origins)
    result = report["results"][0]
    assert result["page_load_status"] == "LOADED"
    assert result["authentication_status"] == "PASS"
    assert result["navigation_actions"]["error"]
    assert any(item["type"] == "DISCOVERY_FAILED" for item in result["finding_details"])
    assert not report["summary"]["coverage_complete"]


def test_per_route_timeout_is_an_explicit_optional_execution_ceiling():
    from pydantic import ValidationError

    assert ScanRequest(target="portal.example", per_route_timeout_ms=60000).per_route_timeout_ms == 60000
    assert ScanRequest(target="portal.example").per_route_timeout_ms is None
    with pytest.raises(ValidationError):
        ScanRequest(target="portal.example", per_route_timeout_ms=2_147_483_648)
    assert ScanRequest(target="portal.example", per_route_timeout_ms=600000).per_route_timeout_ms == 600000
