"""Hyperlinked pages, notification panels and profile menus are validated.

A generic SPA whose shell carries the configured readiness marker. Besides its
own routes it exposes:

* hyperlinks to ordinary documents that are not part of the application shell
  (same tab and new tab), so they never render the shell readiness marker;
* a notification bell that opens a panel and polls for new notifications;
* a profile menu that loads the signed-in user's identity (user id and token
  claims) and links to a profile page.

None of these may end as a route timeout.
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
<header>
  <nav aria-label="Primary">
    <a href="/" data-spa>Home</a>
    <a href="/reports" data-spa>Reports</a>
    <a href="/help/guide">User guide</a>
    <a href="/help/release-notes" target="_blank" rel="noopener">Release notes</a>
  </nav>
  <button type="button" id="bell" aria-label="Notifications" aria-haspopup="true"
    aria-expanded="false" aria-controls="notification-panel">3</button>
  <div id="notification-panel" role="region" aria-label="Notifications" hidden></div>
  <button type="button" id="avatar" aria-label="Profile" aria-haspopup="menu"
    aria-expanded="false" aria-controls="profile-menu">AB</button>
  <div id="profile-menu" role="menu" hidden></div>
</header>
<main data-app-ready="true"><h1>Home</h1></main>
<script>
const main = document.querySelector('main');
function render() {
  if (location.pathname === '/reports') {
    main.innerHTML = '<h1>Reports</h1><p>Report list</p>'; fetch('/api/reports');
  } else if (location.pathname === '/profile') {
    main.innerHTML = '<h1>My profile</h1><p id="who">Loading</p>';
    fetch('/api/me').then(r => r.json()).then(me => { document.querySelector('#who').textContent = me.user_id; });
  } else {
    main.innerHTML = '<h1>Home</h1>';
  }
}
document.addEventListener('click', event => {
  const link = event.target.closest('a[data-spa]');
  if (!link) return;
  event.preventDefault(); history.pushState({}, '', link.getAttribute('href')); render();
  document.querySelectorAll('[aria-haspopup]').forEach(b => { b.setAttribute('aria-expanded', 'false');
    document.getElementById(b.getAttribute('aria-controls')).hidden = true; });
});
const bell = document.querySelector('#bell'), panel = document.querySelector('#notification-panel');
bell.addEventListener('click', () => {
  const open = bell.getAttribute('aria-expanded') !== 'true';
  bell.setAttribute('aria-expanded', String(open)); panel.hidden = !open;
  if (open) fetch('/api/notifications').then(r => r.json()).then(items => {
    panel.innerHTML = '<h2>Notifications</h2><ul>' + items.map(i => '<li>' + i + '</li>').join('') + '</ul>';
  });
});
const avatar = document.querySelector('#avatar'), menu = document.querySelector('#profile-menu');
avatar.addEventListener('click', () => {
  const open = avatar.getAttribute('aria-expanded') !== 'true';
  avatar.setAttribute('aria-expanded', String(open)); menu.hidden = !open;
  if (open) fetch('/api/me').then(r => r.json()).then(me => {
    menu.innerHTML = '<div role="none">Signed in as ' + me.user_id + '</div>'
      + '<a role="menuitem" href="/profile" data-spa>My profile</a>';
  });
});
// Unread-count polling, as notification widgets commonly do.
setInterval(() => fetch('/api/notifications/count'), 500);
render();
</script>'''

DOCUMENT = '''<!doctype html><title>{title}</title><main><h1>{title}</h1>
<p>Static documentation page outside the application shell.</p></main>'''


@pytest.fixture
def auxiliary_site(monkeypatch):
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
            receipts[path] += 1
            if path == "/api/me":
                return self.reply(200, json.dumps({
                    "user_id": "user-1234", "id_token_claims": {"sub": "user-1234"},
                }), "application/json")
            if path == "/api/notifications":
                return self.reply(200, '["Report ready","Password expires soon"]', "application/json")
            if path.startswith("/api/"):
                return self.reply(200, '{"ok":true}', "application/json")
            if path == "/help/guide":
                return self.reply(200, DOCUMENT.format(title="User guide"))
            if path == "/help/release-notes":
                return self.reply(200, DOCUMENT.format(title="Release notes"))
            return self.reply(200, SHELL)

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


def auxiliary_request(origin, **overrides):
    values = dict(
        target=origin + "/", allow_private_networks=True, max_pages=30, max_depth=4,
        timeout_ms=8000, total_timeout_ms=240000, readiness_selector='[data-app-ready="true"]',
        max_navigation_actions=40, max_discovery_scrolls=0, check_security_headers=False,
    )
    values.update(overrides)
    return ScanRequest(**values)


def summarize(report):
    return [
        (r.get("route_name"), r.get("requested_url"), r.get("navigation_type"), r.get("classification"),
         r.get("route_state"), r.get("error"), r.get("load_time_ms"))
        for r in report["results"]
    ]


@pytest.mark.asyncio
async def test_hyperlinks_notifications_and_profile_views_are_validated(auxiliary_site):
    await require_browser()
    origin, receipts = auxiliary_site
    report = await execute_scan(auxiliary_request(origin))
    rows = summarize(report)
    print("AUXILIARY", json.dumps(rows, indent=1))
    timeouts = [row for row in rows if row[3] == "TIMEOUT" or "maximum time" in str(row[5] or "")]
    assert not timeouts, timeouts
    names = {r.get("route_name"): r for r in report["results"]}
    for view in ("Reports", "User guide", "Release notes", "Notifications", "Profile", "My profile"):
        assert view in names, (view, sorted(map(str, names)))
        assert names[view]["route_state"] == "VALIDATED", (view, names[view].get("classification"),
                                                          names[view].get("error"))
    assert receipts["/api/notifications"] >= 1
    assert receipts["/api/me"] >= 1
    # Shared header popovers are validated once per scan, not on every route.
    labels = [r.get("route_name") for r in report["results"]]
    assert labels.count("Notifications") == 1 and labels.count("Profile") == 1, labels
    assert names["Notifications"]["route_source"] == "ui-popover"
    # Linked documents outside the shell are reported as such.
    assert names["User guide"]["application_readiness"] == "LINKED_DOCUMENT"
    assert names["Reports"]["application_readiness"] == "READY"
    # The notification panel's own API call belongs to the Notifications view.
    notifications_activation = names["Notifications"]["route_activation_id"]
    occurrences = [o for o in report["api_request_occurrences"] if o.get("endpoint") == "/api/notifications"]
    # (Menu exploration on the first route may also open it; that call stays
    # attributed to the route that explored it.)
    assert any(o.get("route_activation_id") == notifications_activation for o in occurrences)


@pytest.mark.asyncio
async def test_linked_document_grace_zero_keeps_strict_readiness(auxiliary_site):
    """Operators can require the configured shell condition on every page."""
    await require_browser()
    origin, _receipts = auxiliary_site
    report = await execute_scan(auxiliary_request(origin, shell_marker_grace_ms=0, max_depth=1))
    names = {r.get("route_name"): r for r in report["results"]}
    assert names["User guide"]["route_state"] != "VALIDATED"
    assert names["Reports"]["route_state"] == "VALIDATED"
