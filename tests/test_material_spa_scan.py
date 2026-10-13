"""Full scanner regression: lazy Material overlays and remote SPA views.

All state and endpoints belong to disposable local fixture servers. No browser
session, certificate, or company-specific route is committed by this test.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

import pytest
from playwright.async_api import async_playwright

from app import main, security
from app.main import ScanRequest, execute_scan


MATERIAL_SHELL = r'''<!doctype html><html><head><title>Authorized service workspace</title>
<style>button,a{display:inline-block;margin:8px;padding:8px}.cdk-overlay-pane{border:1px solid;padding:8px}
[hidden]{display:none!important}</style></head><body>
<header><h1>Authorized service workspace</h1></header>
<nav aria-label="Application sections" id="navigation"></nav>
<main aria-busy="true"><h2>Loading workspace</h2></main>
<div class="cdk-overlay-container"></div>
<script>
const overlay = document.querySelector('.cdk-overlay-container');
let renderGeneration = 0;
const sections = {
  workspace: '<a role="menuitem" href="#/overview">Overview</a>' +
    '<button role="menuitem" class="mat-menu-trigger" aria-haspopup="menu" data-menu="analytics">Analytics</button>',
  analytics: '<a role="menuitem" href="#/reports">Reports</a>',
  services: '<a role="menuitem" href="#/catalog">Catalog</a>'
};
function openMenu(button) {
  const submenu = button.dataset.menu;
  if (submenu !== 'analytics') overlay.replaceChildren();
  const panel = document.createElement('div');
  panel.className = 'cdk-overlay-pane'; panel.id = 'material-' + submenu;
  panel.setAttribute('role', 'menu'); panel.innerHTML = sections[submenu];
  button.setAttribute('aria-controls', panel.id); button.setAttribute('aria-expanded','true');
  overlay.append(panel);
  panel.querySelectorAll('[data-menu]').forEach(item => item.onclick = () => openMenu(item));
  panel.querySelectorAll('a').forEach(item => item.onclick = () => overlay.replaceChildren());
}
async function traffic(view, failed=false) {
  const calls = [fetch('/api/shared?view=' + encodeURIComponent(view)),
    fetch('/api/read/' + view, {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}),
    fetch('/api/write/' + view, {method:'POST',body:'{}'})];
  if (failed) calls.push(fetch('/api/dependency-failure'));
  await Promise.allSettled(calls);
}
async function selectPanel(button, name) {
  const host = document.querySelector('service-view');
  document.querySelectorAll('[role=tab]').forEach(item => item.setAttribute('aria-selected','false'));
  button.setAttribute('aria-selected','true');
  const id = button.getAttribute('aria-controls');
  let panel = document.getElementById(id);
  if (!panel) { panel = document.createElement('section'); panel.id=id; panel.setAttribute('role','tabpanel');host.append(panel); }
  host.querySelectorAll('[role=tabpanel]').forEach(item => item.hidden = item !== panel);
  panel.innerHTML='<h2>' + name + '</h2><p>Read-only application content.</p>';
  if (name === 'Details') {
    panel.innerHTML += '<div role="tablist" aria-label="Detail sections">' +
      '<button role="tab" aria-selected="false" aria-controls="timeline-panel" onclick="selectPanel(this,\'Timeline\')">Timeline</button></div>';
  }
  await traffic(name.toLowerCase());
}
async function render() {
  const generation=++renderGeneration, view=location.hash.slice(2)||'workspace';
  document.body.dataset.appReady='false';
  const main=document.querySelector('main'); main.setAttribute('aria-busy','true');
  await fetch('/remote/' + view + '.json');
  if (generation !== renderGeneration) return;
  const host=document.createElement('service-view');
  host.innerHTML='<h2>'+view+'</h2><p>Remote application view has initialized.</p>';
  if (view==='reports') host.innerHTML += '<div role="tablist" aria-label="Report sections">' +
    '<button role="tab" aria-selected="false" aria-controls="details-panel" onclick="selectPanel(this,\'Details\')">Details</button>' +
    '<button role="tab" aria-selected="false" aria-controls="summary-panel" onclick="selectPanel(this,\'Summary\')">Summary</button></div>';
  main.replaceChildren(host);
  await traffic(view, view==='reports');
  if (generation !== renderGeneration) return;
  main.removeAttribute('aria-busy');document.body.dataset.appReady='true';
}
window.addEventListener('hashchange',render);
fetch('/remote/shell.json').then(() => {
  document.querySelector('#navigation').innerHTML=
    '<button class="mat-menu-trigger" aria-haspopup="menu" data-menu="workspace">Workspace</button>' +
    '<button class="mat-menu-trigger" aria-haspopup="menu" data-menu="services">Services</button>' +
    '<button onclick="fetch(\'/api/destructive\',{method:\'POST\'})">Delete workspace</button>';
  document.querySelectorAll('nav [data-menu]').forEach(button => button.onclick=()=>openMenu(button));
  render();
});
</script></body></html>'''


@pytest.fixture
def material_spa_site(tmp_path, monkeypatch):
    receipts = []

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, body, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # Browser fixture teardown may cancel a pending remote response.
                pass

        def do_GET(self):
            path = urlsplit(self.path).path
            receipts.append(("GET", path))
            if path == "/":
                if "portal_session=fixture-authorized" not in self.headers.get("Cookie", ""):
                    return self.reply(200, b'<main><h1>Sign in</h1><input type="password"></main>', "text/html")
                return self.reply(200, MATERIAL_SHELL.encode(), "text/html")
            if path.startswith("/remote/"):
                # Readiness depends on app-owned request completion and insertion,
                # not a scanner-specific fixed sleep or networkidle.
                time.sleep(0.12)
                return self.reply(200, b'{"module":"service-view"}')
            if path == "/api/dependency-failure":
                return self.reply(502, b'{"error":"fixture unavailable"}')
            if path == "/api/shared":
                return self.reply(200, b'{"ready":true}')
            return self.reply(404, b'{"error":"not found"}')

        def do_POST(self):
            path = urlsplit(self.path).path
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            receipts.append(("POST", path))
            return self.reply(200, b'{"items":[]}')

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = security.resolve_and_validate

    async def fixture_resolver(host, allow_private):
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_resolver)
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    (profile_dir / "material-fixture.json").write_text(json.dumps({"cookies": [{
        "name": "portal_session", "value": "fixture-authorized", "domain": "127.0.0.1", "path": "/",
        "expires": time.time() + 3600, "httpOnly": True, "secure": False, "sameSite": "Lax",
    }], "origins": []}), encoding="utf-8")
    monkeypatch.setattr(main, "AUTH_STATE_DIR", profile_dir)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    try:
        yield f"http://127.0.0.1:{server.server_port}", receipts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


async def scan_material_spa(origin, **overrides):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    options = dict(
        target=origin, allow_private_networks=True,
        authentication={"mode": "storage_state", "storage_profile": "material-fixture"},
        approved_read_post_operations=[
            {"host": "127.0.0.1", "path": "/api/read/" + name}
            for name in ("workspace", "overview", "reports", "catalog", "details", "summary", "timeline")
        ],
        max_pages=20, max_depth=5, max_navigation_actions=40, max_discovery_scrolls=0,
        timeout_ms=12000, total_timeout_ms=120000, readiness_timeout_ms=5000,
        readiness_selector='[data-app-ready="true"] service-view',
        render_settle_ms=100, min_observation_ms=200, network_quiet_ms=100,
        check_security_headers=False,
    )
    options.update(overrides)
    return await execute_scan(ScanRequest(**options))


def material_metrics(report):
    summary = report["summary"]
    return {
        "discovered": summary["routes_discovered"],
        "attempted": len(report["results"]),
        "validated": summary["routes_validated"],
        "failed": summary["failed_pages"],
        "skipped": summary["routes_skipped"],
        "names": [route["route_name"] for route in report["results"]],
        "coverage_status": summary["coverage_status"],
        "unsafe_controls_skipped": summary["unsafe_actions_skipped"],
    }


@pytest.mark.asyncio
async def test_material_overlay_spa_discovers_and_validates_each_safe_view(material_spa_site):
    origin, receipts = material_spa_site
    report = await scan_material_spa(origin)
    print("MATERIAL_SPA_METRICS " + json.dumps(material_metrics(report), sort_keys=True))
    results = report["results"]
    assert results[0]["authentication_status"] == "PASS"
    assert results[0]["application_ready"] is True
    assert {urlsplit(route["final_url"]).fragment for route in results if route.get("final_url")} >= {
        "/overview", "/reports", "/catalog",
    }
    views = [route for route in results if route["view_type"] == "UI_TAB"]
    assert {route["route_name"] for route in views} == {"Details", "Summary", "Timeline"}
    assert len(results) == 7  # Entry, three hash routes, three URL-less views.
    assert report["summary"]["routes_discovered"] == 7
    assert report["summary"]["routes_validated"] == 7
    assert all(route["application_ready"] for route in results)
    assert all(route["page_load_status"] == "LOADED" for route in results)
    assert len({route["route_id"] for route in results}) == 7
    assert len([receipt for receipt in receipts if receipt == ("GET", "/")]) == 1
    shared = next(item for item in report["api_inventory"] if item["endpoint"] == "/api/shared")
    assert shared["route_count"] == 7
    for route in results:
        assert any(event["endpoint"] == "/api/shared" for event in route["api_requests"])
        assert any(event["endpoint"].startswith("/api/read/") and event["status"] == 200
                   for event in route["api_requests"])
        assert any(event["endpoint"].startswith("/api/write/") and event["blocked_by_validator"]
                   for event in route["api_requests"])
        assert all(event["route_activation_id"] == route["route_activation_id"] for event in route["api_requests"])
    failed = next(item for item in report["api_inventory"] if item["endpoint"] == "/api/dependency-failure")
    assert failed["status_5xx"] >= 1
    assert failed["validation_outcome"] == "FAILED"
    failed_occurrences = [event for route in results for event in route["api_requests"] if event["status"] == 502]
    assert failed_occurrences
    assert all(event["response_completed"] and event["lifecycle_status"] == "COMPLETED" for event in failed_occurrences)
    occurrences = report["api_request_occurrences"]
    assert len(occurrences) == sum(item["calls"] for item in report["api_inventory"])
    assert len({event["request_id"] for event in occurrences}) == len(occurrences)
    assert not any(method == "POST" and path.startswith(("/api/write/", "/api/destructive")) for method, path in receipts)
    assert "fixture-authorized" not in json.dumps(report)
    assert all(report["summary"]["counter_invariants"].values())


@pytest.mark.asyncio
async def test_material_discovered_routes_survive_a_validation_limit(material_spa_site):
    origin, receipts = material_spa_site
    report = await scan_material_spa(origin, max_pages=1)
    print("MATERIAL_SPA_LIMIT_METRICS " + json.dumps(material_metrics(report), sort_keys=True))
    assert len(report["results"]) == 1
    assert report["summary"]["routes_discovered"] == 4
    assert report["summary"]["routes_validated"] == 1
    assert report["summary"]["routes_not_tested"] == 3
    assert report["summary"]["coverage_status"] == "PARTIAL"
    assert {urlsplit(route["route"]).fragment for route in report["not_tested_routes"]} == {
        "/overview", "/reports", "/catalog",
    }
    assert sorted(path for method, path in receipts if method == "POST") == ["/api/read/workspace"]
    assert all(report["summary"]["counter_invariants"].values())
