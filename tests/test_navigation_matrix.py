"""Generic navigation matrix: one synthetic portal per navigation pattern.

Every scenario is a self-contained page under its own path on a synthetic
portal (127.0.0.1), plus a separate origin (localhost) for new-tab external
destinations. Names, hosts and labels are synthetic.
"""

import json
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit

import pytest

from app import main, security
from app.main import ScanRequest, execute_scan
from test_public_access_scan import require_browser


def page(title, body, script=""):
    return f"""<!doctype html><html lang="en"><head><title>{title}</title></head>
<body>{body}<script>{script}</script></body></html>"""


SCENARIOS = {
    # A: buttons replace content in place; the URL never changes.
    "/a/": page("Tabs workspace", """
<nav aria-label="Sections"><button type="button" id="overview">Overview</button>
<button type="button" id="usage">Usage</button></nav>
<main><h1>Overview</h1><p>Overview content for the workspace.</p></main>""", """
document.querySelector('#usage').addEventListener('click', () => {
  fetch('/api/usage').then(r => r.json()).then(() => {
    document.querySelector('main').innerHTML = '<h1>Usage</h1><p>Usage figures for this month.</p>';
  });
});
document.querySelector('#overview').addEventListener('click', () => {
  document.querySelector('main').innerHTML = '<h1>Overview</h1><p>Overview content for the workspace.</p>';
});"""),
    # B: controls open dialogs (ARIA dialog, Bootstrap-style modal, native dialog).
    "/b/": page("Dialog workspace", """
<main><h1>Accounts</h1><p>Account list overview for the workspace.</p>
<button type="button" id="details" aria-haspopup="dialog" aria-controls="details-dialog">Account details</button>
<button type="button" data-bs-toggle="modal" data-bs-target="#help-modal">Help</button>
<button type="button" id="about" aria-controls="about-dialog">About this workspace</button>
</main>
<div role="dialog" id="details-dialog" aria-modal="true" aria-label="Account details" hidden></div>
<div class="modal" id="help-modal" role="dialog" aria-label="Help" style="display:none">
  <div><h2>Help</h2><p>How to read the account list.</p>
  <button type="button" data-bs-dismiss="modal" aria-label="Close">x</button>
  <button type="button" id="help-delete">Delete account</button></div></div>
<dialog id="about-dialog"><h2>About</h2><p>Workspace version information.</p>
  <form method="dialog"><button>Close</button></form></dialog>""", """
const details = document.querySelector('#details-dialog');
document.querySelector('#details').addEventListener('click', () => {
  details.hidden = false;
  fetch('/api/account-details').then(r => r.json()).then(() => {
    details.innerHTML = '<h2>Account details</h2><p>Owner and plan details.</p>'
      + '<button type="button" aria-label="Close" id="close-details">Close</button>';
    document.querySelector('#close-details').addEventListener('click', () => { details.hidden = true; });
  });
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') { details.hidden = true;
  document.querySelector('#help-modal').style.display = 'none'; } });
document.querySelector('[data-bs-target="#help-modal"]').addEventListener('click', () => {
  document.querySelector('#help-modal').style.display = 'block'; fetch('/api/help');
});
document.querySelector('[data-bs-dismiss]').addEventListener('click', () => {
  document.querySelector('#help-modal').style.display = 'none';
});
document.querySelector('#help-delete').addEventListener('click', () => fetch('/api/accounts/1', {method: 'DELETE'}));
document.querySelector('#about').addEventListener('click', () => {
  document.querySelector('#about-dialog').showModal(); fetch('/api/about');
});"""),
    # C: hyperlink opening a separate origin in a new browser tab.
    "/c/": page("Links workspace", """
<nav aria-label="Primary"><a href="/c/home">Home</a>
<a href="EXTERNAL/partner/" target="_blank" rel="noopener">Partner application</a></nav>
<main><h1>Links</h1><p>Links to related applications.</p></main>"""),
    # D: menus whose nested items appear asynchronously after expansion.
    "/d/": page("Menus workspace", """
<nav aria-label="Primary"><button type="button" id="catalog" aria-expanded="false" aria-controls="catalog-menu">Catalog</button>
<div id="catalog-menu" hidden></div></nav>
<main><h1>Catalog</h1><p>Catalog landing content.</p></main>""", """
const menu = document.querySelector('#catalog-menu');
document.querySelector('#catalog').addEventListener('click', e => {
  const open = e.currentTarget.getAttribute('aria-expanded') !== 'true';
  e.currentTarget.setAttribute('aria-expanded', String(open));
  menu.hidden = !open;
  if (open && !menu.children.length) setTimeout(() => {
    menu.innerHTML = '<a href="/d/products">Products</a>'
      + '<button type="button" id="services" aria-expanded="false" aria-controls="services-menu">Services</button>'
      + '<div id="services-menu" hidden></div>';
    document.querySelector('#services').addEventListener('click', ev => {
      const sub = document.querySelector('#services-menu');
      const openSub = ev.currentTarget.getAttribute('aria-expanded') !== 'true';
      ev.currentTarget.setAttribute('aria-expanded', String(openSub)); sub.hidden = !openSub;
      if (openSub && !sub.children.length) setTimeout(() => {
        sub.innerHTML = '<a href="/d/services/support">Support</a><a href="/d/services/training">Training</a>';
      }, 200);
    });
  }, 300);
});"""),
    # E: hash router.
    "/e/": page("Hash workspace", """
<nav aria-label="Primary"><a href="#/inbox">Inbox</a> <a href="#/archive">Archive</a></nav>
<main><h1>Home</h1><p>Hash routed home content.</p></main>""", """
function render() {
  const view = location.hash.replace('#/', '') || 'home';
  document.querySelector('main').innerHTML = '<h1>' + view + '</h1><p>Hash routed ' + view + ' content.</p>';
  if (view !== 'home') fetch('/api/hash-' + view);
}
addEventListener('hashchange', render); render();"""),
    # F: history router.
    "/f/": page("History workspace", """
<nav aria-label="Primary"><a href="/f/orders" data-spa>Orders</a> <a href="/f/invoices" data-spa>Invoices</a></nav>
<main><h1>Home</h1><p>History routed home content.</p></main>""", """
function render() {
  const view = location.pathname.split('/').filter(Boolean)[1] || 'home';
  document.querySelector('main').innerHTML = '<h1>' + view + '</h1><p>History routed ' + view + ' content.</p>';
  if (view !== 'home') fetch('/api/history-' + view);
}
document.addEventListener('click', e => { const a = e.target.closest('a[data-spa]'); if (!a) return;
  e.preventDefault(); history.pushState({}, '', a.getAttribute('href')); render(); });
addEventListener('popstate', render); render();"""),
    # G: delayed microfrontend: configuration first, content much later.
    "/g/": page("Microfrontend workspace", """
<main aria-busy="true"><div role="progressbar" aria-label="Loading">Loading</div></main>""", """
fetch('/api/mfe-config').then(r => r.json()).then(() => new Promise(r => setTimeout(r, 1500))).then(() => {
  const main = document.querySelector('main');
  main.innerHTML = '<h1>Dashboard</h1><p>Remote dashboard widgets rendered.</p>';
  main.removeAttribute('aria-busy');
});"""),
    # H: required configuration returns HTTP 502.
    "/h/": page("Configured workspace", """<main><h1>Loading</h1></main>""", """
fetch('/h/config.json').then(r => { if (!r.ok) throw new Error('config ' + r.status); return r.json(); })
  .then(() => { document.querySelector('main').innerHTML = '<h1>Ready</h1>'; })
  .catch(() => { document.querySelector('main').innerHTML =
    '<h1>Configuration unavailable</h1><p role="alert">The application configuration could not be loaded.</p>'; });"""),
    # I: same labels, different destinations; plus true duplicates.
    "/i/": page("Labels workspace", """
<nav aria-label="Sales"><a href="/i/sales/reports">Reports</a><a href="/i/sales/reports">Reports</a></nav>
<nav aria-label="People"><a href="/i/people/reports">Reports</a></nav>
<main><h1>Labels</h1><p>Two sections with a Reports page each.</p></main>"""),
    # J: read-only security: mutating controls next to navigation.
    "/j/": page("Security workspace", """
<nav aria-label="Primary"><a href="/j/profile">Profile</a> <a href="/logout">Sign out</a></nav>
<main><h1>Records</h1><p>Record list overview.</p>
<button type="button" id="delete">Delete record</button>
<button type="button" id="update">Update record</button>
<form action="/api/records" method="post"><input name="title" value="x"><button type="submit">Save</button></form>
</main>""", """
document.querySelector('#delete').addEventListener('click', () => fetch('/api/records/1', {method: 'DELETE'}));
document.querySelector('#update').addEventListener('click', () => fetch('/api/records/1', {method: 'PUT', body: '{}'}));"""),
    # L: status and lifecycle reporting.
    "/l/": page("Status workspace", """<main><h1>Status</h1><p>Status check content.</p></main>""", """
fetch('/api/ok'); fetch('/api/missing'); fetch('/api/bad-gateway');
fetch('/api/reset').catch(() => null);
fetch('/api/hang').catch(() => null);"""),
}

FAILING_PATHS = {"/api/missing": 404, "/api/bad-gateway": 502, "/h/config.json": 502}


@pytest.fixture
def matrix_site(monkeypatch):
    receipts = Counter()
    release_hang = threading.Event()

    class External(BaseHTTPRequestHandler):
        def do_GET(self):
            receipts[("external", self.command, urlsplit(self.path).path)] += 1
            body = page("Partner application", "<main><h1>Partner</h1><p>Partner application home.</p></main>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    external = ThreadingHTTPServer(("127.0.0.1", 0), External)
    external_origin = f"http://localhost:{external.server_port}"

    class Portal(BaseHTTPRequestHandler):
        def reply(self, status, body, kind="text/html"):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def handle_any(self):
            path = urlsplit(self.path).path
            receipts[("portal", self.command, path)] += 1
            if path == "/api/reset":
                self.connection.shutdown(2)
                return None
            if path == "/api/hang":
                release_hang.wait(30)
                return None
            if path in FAILING_PATHS:
                return self.reply(FAILING_PATHS[path], '{"error":true}', "application/json")
            if path.startswith("/api/") or path.endswith(".json"):
                return self.reply(200, '{"ok":true}', "application/json")
            scenario = "/" + path.strip("/").split("/")[0] + "/"
            body = SCENARIOS.get(scenario)
            if body is None:
                return self.reply(404, page("Not found", "<main><h1>Not found</h1></main>"))
            return self.reply(200, body.replace("EXTERNAL", external_origin))

        do_GET = do_POST = do_PUT = do_DELETE = handle_any

        def log_message(self, *_args):
            pass

    portal = ThreadingHTTPServer(("127.0.0.1", 0), Portal)
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, portal.server_port, external.server_port})
    original_resolver = main.resolve_and_validate

    async def fixture_resolver(host, allow_private):
        if host in {"127.0.0.1", "localhost"}:
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_resolver)
    threads = [Thread(target=server.serve_forever, daemon=True) for server in (portal, external)]
    for thread in threads:
        thread.start()
    try:
        yield f"http://127.0.0.1:{portal.server_port}", external_origin, receipts
    finally:
        release_hang.set()
        for server in (portal, external):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


def matrix_request(origin, scenario, **overrides):
    values = dict(
        target=origin + scenario, allow_private_networks=True, max_pages=20, max_depth=3,
        timeout_ms=15000, total_timeout_ms=180000, max_navigation_actions=30, max_discovery_scrolls=0,
        check_security_headers=False,
    )
    values.update(overrides)
    return ScanRequest(**values)


def rows(report):
    return [(r.get("route_name"), r.get("navigation_type"), r.get("route_state"), r.get("classification"),
             r.get("failure_reason") or r.get("error")) for r in report.get("route_inventory") or report["results"]]


def by_name(report):
    found = {}
    for result in report.get("route_inventory") or report["results"]:
        found.setdefault(result.get("route_name"), []).append(result)
    return found


async def scan(origin, scenario, **overrides):
    await require_browser()
    report = await execute_scan(matrix_request(origin, scenario, **overrides))
    print(scenario, json.dumps(rows(report), indent=1))
    return report


@pytest.mark.asyncio
async def test_a_in_page_tab_without_url_change(matrix_site):
    origin, _external, receipts = matrix_site
    report = await scan(origin, "/a/")
    views = by_name(report)
    assert views["Usage"][0]["route_state"] == "VALIDATED", rows(report)
    assert receipts[("portal", "GET", "/api/usage")] >= 1
    assert not any(r[2] == "TIMEOUT" for r in rows(report))
    # Re-activating the view already on screen changes nothing observable:
    # reported as such, quickly, and not as a failure or a route timeout.
    overview = [r for r in views["Overview"] if r["navigation_type"] == "UI_VIEW_ACTIVATION"]
    assert overview and overview[0]["route_state"] == "NO_OBSERVABLE_CHANGE", rows(report)
    assert overview[0]["passed"] is not True and overview[0]["classification"] == "NO_OBSERVABLE_CHANGE"
    assert report["summary"]["failed_pages"] == 0, report["summary"]["failed_pages"]
    diagnostics = overview[0]["timeout_diagnostics"]
    assert diagnostics["content_changed"] is False and diagnostics["url_changed"] is False
    assert diagnostics["elapsed_ms"] < 14000, "Must be bounded by the UI activation timeout, not the route budget"
    assert views["Usage"][0]["navigation_outcome"] == "IN_PAGE_ACTIVATION"
    metrics = report["summary"]["discovery_metrics"]
    assert metrics["attempted_activations"] == 3 and metrics["no_observable_change"] == 1
    assert metrics["failed_activations"] == 0


@pytest.mark.asyncio
async def test_b_dialogs_without_url_change(matrix_site):
    origin, _external, receipts = matrix_site
    report = await scan(origin, "/b/")
    views = by_name(report)
    for name in ("Account details", "Help", "About this workspace"):
        assert name in views, (name, rows(report))
        assert views[name][0]["route_state"] == "VALIDATED", (name, rows(report))
    assert receipts[("portal", "GET", "/api/account-details")] >= 1
    assert receipts[("portal", "DELETE", "/api/accounts/1")] == 0
    assert all(views[name][0]["navigation_outcome"] == "DIALOG_ACTIVATION"
               for name in ("Account details", "Help", "About this workspace"))
    assert views["Account details"][0]["route_source"] == "ui-dialog"
    assert not any(r[2] == "TIMEOUT" for r in rows(report))


@pytest.mark.asyncio
async def test_c_external_new_tab_out_of_scope_is_skipped(matrix_site):
    origin, external, receipts = matrix_site
    report = await scan(origin, "/c/")
    partner = by_name(report).get("Partner application")
    assert partner, rows(report)
    assert partner[0]["route_state"] == "SKIPPED_OUT_OF_SCOPE", rows(report)
    assert partner[0]["url"].startswith(external)
    assert receipts[("external", "GET", "/partner/")] == 0
    assert not any(r[2] in {"TIMEOUT", "NAVIGATION_FAILED"} for r in rows(report))
    assert partner[0]["failure_reason"] == "VALIDATION_SKIPPED_OUT_OF_SCOPE"
    assert partner[0]["navigation_outcome"] == "EXTERNAL_NAVIGATION"
    assert partner[0]["parent_route_name"] == "Links"
    summary = report["summary"]
    assert summary["external_destinations_discovered"] == 1
    assert summary["route_states"]["SKIPPED_OUT_OF_SCOPE"] == 1
    assert summary["failed_pages"] == 0


@pytest.mark.asyncio
async def test_c_external_new_tab_in_approved_scope_is_validated(matrix_site):
    origin, _external, receipts = matrix_site
    report = await scan(origin, "/c/", portal_hosts=["localhost"])
    partner = by_name(report).get("Partner application")
    assert partner and partner[0]["route_state"] == "VALIDATED", rows(report)
    assert receipts[("external", "GET", "/partner/")] >= 1
    assert partner[0]["navigation_outcome"] == "POPUP_NAVIGATION", partner[0]["navigation_outcome"]


@pytest.mark.asyncio
async def test_d_dynamic_nested_menus(matrix_site):
    origin, _external, receipts = matrix_site
    report = await scan(origin, "/d/")
    names = Counter(r[0] for r in rows(report))
    for name in ("Products", "Support", "Training"):
        assert names[name] == 1, (name, rows(report))
    assert by_name(report)["Training"][0]["route_state"] == "VALIDATED"


@pytest.mark.asyncio
async def test_e_hash_router(matrix_site):
    origin, _external, receipts = matrix_site
    report = await scan(origin, "/e/")
    views = by_name(report)
    for name in ("inbox", "archive"):
        candidates = [r for key, items in views.items() for r in items if name in str(r.get("url"))]
        assert candidates and candidates[0]["route_state"] == "VALIDATED", (name, rows(report))
    assert receipts[("portal", "GET", "/api/hash-archive")] >= 1


@pytest.mark.asyncio
async def test_f_history_router(matrix_site):
    origin, _external, receipts = matrix_site
    report = await scan(origin, "/f/")
    views = by_name(report)
    assert views["Orders"][0]["route_state"] == "VALIDATED", rows(report)
    assert views["Invoices"][0]["route_state"] == "VALIDATED", rows(report)
    assert views["Invoices"][0]["navigation_outcome"] == "HISTORY_NAVIGATION"
    assert receipts[("portal", "GET", "/api/history-invoices")] >= 1


@pytest.mark.asyncio
async def test_g_delayed_microfrontend_waits_for_content(matrix_site):
    origin, _external, _receipts = matrix_site
    report = await scan(origin, "/g/", max_pages=1)
    route = report["results"][0]
    assert route["route_state"] == "VALIDATED", rows(report)
    assert route["route_name"] == "Dashboard" or "Dashboard" in str(route.get("title") or route.get("route_name"))


@pytest.mark.asyncio
async def test_h_required_configuration_502_is_preserved(matrix_site):
    origin, _external, _receipts = matrix_site
    report = await scan(origin, "/h/", max_pages=1)
    config = next(item for item in report["api_inventory"] if item["endpoint"] == "/h/config.json")
    assert config["response_status_counts"] == {"502": 1}, config.get("response_status_counts")
    assert "HTTP_5XX" in config["failure_types"]
    route = report["results"][0]
    assert route["passed"] is False or route["classification"] != "PASS", (route["classification"], route.get("failure_reason"))


@pytest.mark.asyncio
async def test_i_duplicate_labels(matrix_site):
    origin, _external, _receipts = matrix_site
    report = await scan(origin, "/i/")
    reports = [r for r in rows(report) if r[0] == "Reports"]
    urls = sorted(str(r.get("url")) for r in report["route_inventory"] if r.get("route_name") == "Reports")
    assert len(reports) == 2, rows(report)
    metrics = report["summary"]["discovery_metrics"]
    assert metrics["duplicate_discoveries"] >= 1, metrics
    assert any("/i/sales/reports" in url for url in urls) and any("/i/people/reports" in url for url in urls)


@pytest.mark.asyncio
async def test_j_read_only_security(matrix_site):
    origin, _external, receipts = matrix_site
    report = await scan(origin, "/j/")
    assert by_name(report)["Profile"][0]["route_state"] == "VALIDATED"
    assert receipts[("portal", "GET", "/logout")] == 0
    assert receipts[("portal", "DELETE", "/api/records/1")] == 0
    assert receipts[("portal", "PUT", "/api/records/1")] == 0
    assert receipts[("portal", "POST", "/api/records")] == 0


@pytest.mark.asyncio
async def test_k_authentication_configuration_reaches_the_scan(matrix_site):
    origin, _external, _receipts = matrix_site
    report = await scan(origin, "/a/", max_pages=1, authentication_hosts=["login.identity.test"])
    assert report["scan_configuration"]["authentication_host_count"] == 1
    assert "login.identity.test" not in json.dumps(report.get("results"))


@pytest.mark.asyncio
async def test_l_status_and_lifecycle_reporting(matrix_site):
    origin, _external, _receipts = matrix_site
    report = await scan(origin, "/l/", max_pages=1)
    inventory = {item["endpoint"]: item for item in report["api_inventory"]}
    assert inventory["/api/ok"]["response_status_counts"] == {"200": 1} and not inventory["/api/ok"]["failure_types"]
    assert inventory["/api/missing"]["response_status_counts"] == {"404": 1}
    assert inventory["/api/missing"]["failure_types"] == ["HTTP_4XX"]
    assert inventory["/api/bad-gateway"]["response_status_counts"] == {"502": 1}
    assert inventory["/api/bad-gateway"]["failure_types"] == ["HTTP_5XX"]
    # No response: no invented HTTP status, and distinct lifecycle states.
    assert not inventory["/api/reset"]["response_status_counts"] and inventory["/api/reset"]["failure_types"] == ["NETWORK_FAILURE"]
    assert not inventory["/api/hang"]["response_status_counts"] and inventory["/api/hang"]["failure_types"] == ["INCOMPLETE"]
    summary = report["summary"]
    lifecycle = summary["api_request_lifecycle_counts"]
    assert summary["api_requests_observed"] == 5 == sum(lifecycle.values())
    assert lifecycle["COMPLETED"] == summary["api_responses_completed"] == 3
    assert lifecycle["FAILED"] == 1 and lifecycle["INCOMPLETE"] == summary["api_requests_incomplete"] == 1
    assert summary["api_http_failures"] == 2
