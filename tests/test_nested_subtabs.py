"""Nested sub-tabs inside a route's tab panel are validated, with their POST calls.

A generic SPA: the shell links to /reports through a menu. /reports renders
top-level tabs; the "Details" tab panel contains its own sub-tabs. Activating
the "Monthly" sub-tab issues an approved read-only POST search and an
unapproved mutation POST (which must stay blocked).
"""

import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit

import pytest

from app import main, security
from app.main import ScanRequest, execute_scan
from test_public_access_scan import require_browser

SHELL = r'''<!doctype html><title>Generic workspace</title>
<nav aria-label="Primary"><a href="/reports" data-spa>Reports</a></nav>
<main data-app-ready="true"><h1>Home</h1></main>
<script>
const main = document.querySelector('main');
function tabs(container, items) {
  const list = document.createElement('div');
  list.setAttribute('role', 'tablist');
  items.forEach(([label, render], index) => {
    const tab = document.createElement('button');
    tab.type = 'button'; tab.setAttribute('role', 'tab'); tab.textContent = label;
    tab.id = 'tab-' + label.toLowerCase(); tab.setAttribute('aria-controls', 'panel-' + label.toLowerCase());
    tab.setAttribute('aria-selected', String(index === 0));
    const panel = document.createElement('section');
    panel.setAttribute('role', 'tabpanel'); panel.id = 'panel-' + label.toLowerCase(); panel.hidden = index !== 0;
    tab.addEventListener('click', () => {
      list.querySelectorAll('[role=tab]').forEach(other => other.setAttribute('aria-selected', String(other === tab)));
      container.querySelectorAll(':scope > [role=tabpanel]').forEach(other => { other.hidden = other !== panel; });
      render(panel);
    });
    list.append(tab); container.append(panel);
    if (index === 0) render(panel);
  });
  container.prepend(list);
}
function reports() {
  main.innerHTML = '<h1>Reports</h1>';
  tabs(main, [
    ['Summary', panel => { panel.textContent = 'Summary content'; fetch('/api/summary'); }],
    ['Details', panel => {
      panel.replaceChildren();
      tabs(panel, [
        ['Daily', sub => { sub.textContent = 'Daily details'; fetch('/api/daily'); }],
        ['Monthly', sub => {
          fetch('/api/search', {method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({query: 'monthly'})}).then(() => { sub.textContent = 'Monthly details'; });
          fetch('/api/save-preferences', {method: 'POST', body: '{}'}).catch(() => null);
        }],
      ]);
    }],
  ]);
}
document.addEventListener('click', event => {
  const link = event.target.closest('a[data-spa]');
  if (!link) return;
  event.preventDefault(); history.pushState({}, '', link.getAttribute('href')); reports();
});
if (location.pathname === '/reports') reports();
</script>'''


@pytest.fixture
def subtab_site(monkeypatch):
    receipts = Counter()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, body, kind="text/html"):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            path = urlsplit(self.path).path
            receipts[("GET", path)] += 1
            if path.startswith("/api/"):
                return self.reply(200, '{"ok":true}', "application/json")
            return self.reply(200, SHELL)

        def do_POST(self):
            path = urlsplit(self.path).path
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            receipts[("POST", path)] += 1
            return self.reply(200, '{"results":[]}', "application/json")

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


def subtab_request(origin, **overrides):
    values = dict(
        target=origin + "/", allow_private_networks=True, max_pages=20, max_depth=4,
        timeout_ms=10000, total_timeout_ms=120000, readiness_selector='[data-app-ready="true"]',
        render_settle_ms=100, min_observation_ms=150, network_quiet_ms=50,
        max_navigation_actions=20, max_discovery_scrolls=0, check_security_headers=False,
        approved_read_post_operations=[{"host": "127.0.0.1", "path": "/api/search", "description": "Read-only search"}],
    )
    values.update(overrides)
    return ScanRequest(**values)


@pytest.mark.asyncio
async def test_nested_subtabs_are_validated_with_their_read_only_post(subtab_site):
    await require_browser()
    origin, receipts = subtab_site
    report = await execute_scan(subtab_request(origin))
    names = {result.get("route_name"): result for result in report["results"]}
    print("SUBTABS", json.dumps({name: (r.get("classification"), r.get("route_state"), r.get("navigation_type"))
                                 for name, r in names.items()}))
    print("APIS", json.dumps([(i["method"], i["endpoint"], i.get("allowed_calls"), i.get("blocked_count"),
                               i.get("post_classifications")) for i in report["api_inventory"]]))
    for view in ("Summary", "Details", "Daily", "Monthly"):
        assert view in names, sorted(names)
        assert names[view]["route_state"] == "VALIDATED", (view, names[view].get("classification"))
    assert receipts[("POST", "/api/search")] >= 1
    assert receipts[("POST", "/api/save-preferences")] == 0, "An unapproved mutation must stay blocked"
    search = next(item for item in report["api_inventory"] if item["endpoint"] == "/api/search")
    assert search["method"] == "POST" and search["allowed_calls"] >= 1
    monthly_activation = names["Monthly"]["route_activation_id"]
    occurrences = [o for o in report["api_request_occurrences"] if o.get("endpoint") == "/api/search"]
    assert occurrences and all(o.get("route_activation_id") == monthly_activation for o in occurrences)


QUERY_TABS = r'''<!doctype html><title>Query tabs</title>
<main data-app-ready="true"><h1>Reports</h1>
<div role="tablist" aria-label="Report period">
  <a role="tab" href="/reports?tab=daily" aria-selected="true">Daily</a>
  <a role="tab" href="/reports?tab=monthly" aria-selected="false">Monthly</a>
</div><section id="content"></section></main>
<script>
const tab = new URLSearchParams(location.search).get('tab') || 'daily';
document.querySelector('#content').textContent = tab + ' report';
fetch('/api/' + tab);
</script>'''


@pytest.mark.asyncio
async def test_query_addressed_subtabs_are_distinct_views(subtab_site, monkeypatch):
    """Tabs addressed only by a query parameter must not collapse into one route."""
    await require_browser()
    origin, receipts = subtab_site
    import test_nested_subtabs as module
    monkeypatch.setattr(module, "SHELL", QUERY_TABS)
    report = await execute_scan(subtab_request(origin, target=origin + "/reports?tab=daily"))
    print("QUERY_TABS", json.dumps([(r.get("route_name"), r.get("requested_url"), r.get("route_state"))
                                    for r in report["results"]]))
    assert receipts[("GET", "/api/monthly")] >= 1, "The Monthly tab was never validated"
    views = {r.get("route_name"): r for r in report["results"]}
    assert views["Monthly"]["route_state"] == "VALIDATED"
    assert views["Monthly"]["requested_url"].endswith("/reports?tab=monthly")
