"""Broad authenticated discovery: a synthetic portal with more than 44 safe views.

The fixture is a generic history/hash-routed SPA served from localhost. It
requires a session cookie from a storage-state profile; without it every
document is a login page returning HTTP 200. Views are reachable only through
native disclosures, a Bootstrap-style dropdown, a sidebar and URL-less tabs.
"""

import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit

import pytest

from app import main, security
from app.main import ScanRequest, execute_scan
from test_authentication_first import assert_authentication_failure
from test_public_access_scan import require_browser

SECTIONS = {"operations": 6, "inventory": 6, "finance": 6, "people": 6}
SIDEBAR = [f"workspace-{index}" for index in range(1, 11)]
REPORTS = [f"report-{index}" for index in range(1, 7)]
TABS = ["Summary", "Trends", "Exceptions", "Audit"]
FAILING_VIEW = "/finance/item-3"

SHELL = r'''<!doctype html><html><head><title>Synthetic workspace</title>
<style>.dropdown-menu{display:none}.dropdown-menu.show{display:block}</style></head><body>
<header><nav aria-label="Primary">%(disclosures)s
<div class="dropdown"><button class="dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">Reports</button>
<ul class="dropdown-menu">%(reports)s</ul></div></nav></header>
<aside><nav aria-label="Workspace">%(sidebar)s</nav></aside>
<main aria-busy="true"><h1>Loading</h1></main>
<script>
const tabs = %(tabs)s;
document.querySelector('.dropdown-toggle').addEventListener('click', event => {
  const menu = event.currentTarget.nextElementSibling;
  const open = !menu.classList.contains('show');
  menu.classList.toggle('show', open);
  event.currentTarget.setAttribute('aria-expanded', String(open));
});
document.addEventListener('click', event => {
  const link = event.target.closest('a[data-spa]');
  if (!link) return;
  event.preventDefault();
  history.pushState({}, '', link.getAttribute('href'));
  render();
});
function viewName() {
  if (location.hash.startsWith('#/')) return location.hash.slice(2);
  return location.pathname === '/' ? 'home' : location.pathname.slice(1);
}
function render() {
  const name = viewName();
  const main = document.querySelector('main');
  main.setAttribute('aria-busy', 'true');
  fetch('/api/view/' + encodeURIComponent(name)).then(response => {
    main.innerHTML = '<h1>View ' + name + '</h1><p>Status ' + response.status + '</p>';
    if (name === 'home') {
      const list = document.createElement('div');
      list.setAttribute('role', 'tablist');
      tabs.forEach((label, index) => {
        const tab = document.createElement('button');
        tab.type = 'button'; tab.setAttribute('role', 'tab'); tab.textContent = label + ' panel';
        tab.setAttribute('aria-selected', String(index === 0));
        tab.addEventListener('click', () => {
          list.querySelectorAll('[role=tab]').forEach(item => item.setAttribute('aria-selected', String(item === tab)));
          fetch('/api/tab/' + label.toLowerCase()).then(() => {
            document.querySelector('[role=tabpanel]').textContent = label + ' content';
          });
        });
        list.append(tab);
      });
      const panel = document.createElement('section');
      panel.setAttribute('role', 'tabpanel'); panel.textContent = tabs[0] + ' content';
      main.append(list, panel);
    }
    main.removeAttribute('aria-busy');
    document.body.dataset.appReady = 'true';
  });
}
window.addEventListener('popstate', render);
window.addEventListener('hashchange', render);
fetch('/api/session').then(() => render());
</script></body></html>'''


def portal_shell():
    disclosures = "".join(
        f'<details><summary>{section.title()}</summary><ul>' + "".join(
            f'<li><a data-spa href="/{section}/item-{index}">{section.title()} item {index}</a></li>'
            for index in range(1, count + 1)
        ) + "</ul></details>"
        for section, count in SECTIONS.items()
    )
    reports = "".join(f'<li><a href="/#/reports/{name}">Report {name[7:]}</a></li>' for name in REPORTS)
    sidebar = "".join(f'<a data-spa href="/{name}">Workspace {name[10:]}</a>' for name in SIDEBAR)
    return SHELL % {
        "disclosures": disclosures, "reports": reports, "sidebar": sidebar, "tabs": json.dumps(TABS),
    }


EXPECTED_PATHS = {
    *(f"/{section}/item-{index}" for section, count in SECTIONS.items() for index in range(1, count + 1)),
    *(f"/{name}" for name in SIDEBAR),
}


@pytest.fixture
def broad_portal(tmp_path, monkeypatch):
    shell = portal_shell()

    class Handler(BaseHTTPRequestHandler):
        receipts = Counter()

        def reply(self, status, body, content_type="text/html"):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            path = urlsplit(self.path).path
            type(self).receipts[path] += 1
            authenticated = "session=broad-fixture-session" in (self.headers.get("Cookie") or "")
            if path.startswith("/api/"):
                if not authenticated:
                    return self.reply(401, '{"error":"unauthenticated"}', "application/json")
                status = 500 if path == "/api/view/" + FAILING_VIEW[1:].replace("/", "%2F") else 200
                return self.reply(status, '{"fixture":true}', "application/json")
            if not authenticated:
                return self.reply(200, '''<!doctype html><title>Sign in</title><main><h1>Sign in</h1>
                    <form><input name="user"><input type="password" name="password"></form>
                    <nav><a href="/operations/item-1">Operations</a></nav></main>''')
            return self.reply(200, shell)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = main.resolve_and_validate

    async def fixture_resolver(host, allow_private):
        if host in {"127.0.0.1", "localhost"}:
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_resolver)
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "broad.json").write_text(json.dumps({
        "cookies": [{"name": "session", "value": "broad-fixture-session", "domain": "127.0.0.1",
                     "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"}],
        "origins": [],
    }), encoding="utf-8")
    monkeypatch.setattr(main, "AUTH_STATE_DIR", profiles)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def broad_request(origin, **overrides):
    values = dict(
        target=origin + "/", allow_private_networks=True, max_pages=80, max_depth=3,
        max_navigation_actions=80, max_discovery_scrolls=0, timeout_ms=15000,
        total_timeout_ms=240000, readiness_selector='[data-app-ready="true"]',
        render_settle_ms=50, min_observation_ms=100, network_quiet_ms=50,
        check_security_headers=False,
        authentication={"mode": "storage_state", "storage_profile": "broad"},
    )
    values.update(overrides)
    return ScanRequest(**values)


@pytest.mark.asyncio
async def test_authenticated_portal_discovers_and_validates_at_least_44_views(broad_portal):
    await require_browser()
    origin, handler = broad_portal
    report = await execute_scan(broad_request(origin))
    results = report["results"]
    assert report["scan_status"] != "FAILED", report.get("authentication_error")
    paths = {urlsplit(item["final_url"]).path for item in results}
    fragments = {urlsplit(item["final_url"]).fragment for item in results}
    tabs = {item["route_name"] for item in results if item.get("view_type") == "UI_TAB"}
    print("BROAD_METRICS " + json.dumps({
        "routes": len(results), "paths": sorted(paths), "fragments": sorted(fragments), "tabs": sorted(tabs),
        "summary": {key: report["summary"].get(key) for key in (
            "routes_discovered", "routes_validated", "termination_reason", "coverage_grade")},
    }))
    assert EXPECTED_PATHS <= paths, sorted(EXPECTED_PATHS - paths)
    assert {f"/reports/{name}" for name in REPORTS} <= fragments
    assert len(results) >= 44
    assert report["summary"]["routes_validated"] == len(results) >= 44
    assert report["summary"]["routes_discovered"] >= 44
    assert report["summary"]["termination_reason"] != "SCAN_TIMEOUT"
    assert all(item["authentication_status"] == "PASS" for item in results)
    # Each view initialised its own application code: one view API per view.
    for path in EXPECTED_PATHS:
        assert handler.receipts["/api/view/" + path[1:].replace("/", "%2F")] >= 1, path
    failing = next(item for item in results if urlsplit(item["final_url"]).path == FAILING_VIEW)
    failures = [
        event for event in report["api_request_occurrences"]
        if event.get("status") == 500
    ]
    assert failures and all(event["initiating_route"] == failing["route_id"] for event in failures)
    assert failing["validation_status"] in {"FAIL", "PASS_WITH_WARNINGS"}


@pytest.mark.asyncio
async def test_same_portal_without_session_fails_closed_with_zero_routes(broad_portal):
    await require_browser()
    origin, handler = broad_portal
    report = await execute_scan(broad_request(origin, authentication={"mode": "none"}))
    assert_authentication_failure(report, report["authentication_error"]["category"])
    assert report["authentication_error"]["category"] in {
        "AUTHENTICATION_FAILED", "APPLICATION_NOT_READY", "AUTHENTICATION_REQUIRED",
    }
    assert handler.receipts["/operations/item-1"] == 0
