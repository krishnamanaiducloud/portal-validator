"""Microfrontend routes that require their own SAML round trip.

A generic SPA portal (127.0.0.1) keeps an application session cookie. Some
menu routes belong to a microfrontend that requires its own SAML login: the
route sends the browser to a separate identity host (localhost), which
auto-posts a SAMLRequest to itself and then auto-posts a SAMLResponse back to
the portal's assertion consumer service, returning to the requested route.
Menu entries are both real links and menu items, like many enterprise portals.
"""

import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest

from app import main, security
from app.main import ScanRequest, execute_scan
from test_public_access_scan import require_browser

PLAIN_ROUTES = ["/home-a", "/home-b"]
SSO_ROUTES = ["/micro-a", "/micro-b"]


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def reply(handler, status, body=b"", kind="text/html", **headers):
    handler.send_response(status)
    handler.send_header("Content-Type", kind)
    handler.send_header("Content-Length", str(len(body)))
    for name, value in headers.items():
        handler.send_header(name.replace("_", "-"), value)
    handler.end_headers()
    handler.wfile.write(body)


@pytest.fixture
def sso_route_portal(tmp_path, monkeypatch):
    receipts = Counter()
    origins = {}

    class Identity(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            receipts[("idp", "GET", parsed.path)] += 1
            relay = parse_qs(parsed.query).get("RelayState", ["/"])[0]
            body = (f'''<!doctype html><title>Signing in</title><body onload="document.forms[0].submit()">
                <form method="post" action="/idp/SSO.saml2">
                <input type="hidden" name="SAMLRequest" value="fixture-request">
                <input type="hidden" name="RelayState" value="{relay}"></form></body>''').encode()
            reply(self, 200, body)

        def do_POST(self):
            parsed = urlsplit(self.path)
            fields = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
            receipts[("idp", "POST", parsed.path)] += 1
            relay = fields.get("RelayState", ["/"])[0]
            body = (f'''<!doctype html><title>Returning</title><body onload="document.forms[0].submit()">
                <form method="post" action="{origins['portal']}/saml/acs">
                <input type="hidden" name="SAMLResponse" value="fixture-assertion">
                <input type="hidden" name="RelayState" value="{relay}"></form></body>''').encode()
            reply(self, 200, body)

        def log_message(self, *_args):
            pass

    identity, identity_thread = serve(Identity)
    origins["idp"] = f"http://localhost:{identity.server_port}"

    class Portal(BaseHTTPRequestHandler):
        def cookies(self):
            return self.headers.get("Cookie") or ""

        def do_POST(self):
            parsed = urlsplit(self.path)
            fields = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode())
            receipts[("portal", "POST", parsed.path)] += 1
            if parsed.path == "/saml/acs" and fields.get("SAMLResponse"):
                relay = fields.get("RelayState", ["/"])[0]
                return reply(self, 302, Location=relay, Set_Cookie="micro=granted; Path=/")
            return reply(self, 404)

        def do_GET(self):
            parsed = urlsplit(self.path)
            path = parsed.path
            receipts[("portal", "GET", path)] += 1
            if path.startswith("/api/"):
                return reply(self, 200, b'{"ok":true}', "application/json")
            if path in SSO_ROUTES and "micro=granted" not in self.cookies():
                return reply(self, 302, Location=f"{origins['idp']}/idp/startSSO?RelayState={path}")
            menu = "".join(
                f'<li><a role="menuitem" href="{route}">Workspace {route[1:]}</a></li>'
                for route in PLAIN_ROUTES + SSO_ROUTES
            )
            # The same destination is also rendered as a clickable menu item.
            menu += (
                """<li><button type="button" role="menuitem" onclick="history.pushState({}, '', '/home-a');"""
                """ document.querySelector('h1').textContent = 'Workspace /home-a'">Workspace home-a</button></li>"""
            )
            body = (f'''<!doctype html><title>Generic portal</title><nav aria-label="Primary">
                <button aria-haspopup="menu" aria-expanded="false" aria-controls="work-menu"
                  onclick="this.setAttribute('aria-expanded','true');document.querySelector('#work-menu').hidden=false">Work</button>
                <ul role="menu" id="work-menu" hidden>{menu}</ul></nav>
                <main><h1>Workspace {path}</h1></main>
                <script>
                document.addEventListener('click', event => {{
                  const link = event.target.closest('a');
                  if (!link || !{json.dumps(PLAIN_ROUTES)}.includes(link.getAttribute('href'))) return;
                  event.preventDefault(); history.pushState({{}}, '', link.getAttribute('href'));
                  document.querySelector('h1').textContent = 'Workspace ' + location.pathname;
                  fetch('/api/view' + location.pathname);
                }});
                fetch('/api/session').then(() => document.querySelector('main').dataset.appReady = 'true');
                </script>''').encode()
            return reply(self, 200, body)

        def log_message(self, *_args):
            pass

    portal, portal_thread = serve(Portal)
    origins["portal"] = f"http://127.0.0.1:{portal.server_port}"
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
    (profiles / "portal.json").write_text(json.dumps({
        "cookies": [{"name": "session", "value": "fixture-private-session", "domain": "127.0.0.1",
                     "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"}],
        "origins": [],
    }), encoding="utf-8")
    monkeypatch.setattr(main, "AUTH_STATE_DIR", profiles)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    try:
        yield origins["portal"], receipts
    finally:
        for server, thread in ((portal, portal_thread), (identity, identity_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def portal_request(origin, **overrides):
    values = dict(
        target=origin + "/", allow_private_networks=True, max_pages=12, max_depth=3,
        timeout_ms=8000, total_timeout_ms=180000, readiness_selector='[data-app-ready="true"]',
        render_settle_ms=100, min_observation_ms=100, network_quiet_ms=50,
        max_navigation_actions=10, max_discovery_scrolls=0, check_security_headers=False,
        authentication={"mode": "storage_state", "storage_profile": "portal"},
    )
    values.update(overrides)
    return ScanRequest(**values)


def by_path(report):
    output = {}
    for result in report["results"]:
        output.setdefault(urlsplit(result["requested_url"]).path or "/", []).append(result)
    return output


@pytest.mark.asyncio
async def test_approved_identity_host_completes_each_microfrontend_sso_round_trip(sso_route_portal):
    await require_browser()
    origin, receipts = sso_route_portal
    report = await execute_scan(portal_request(origin, authentication_hosts=["localhost"]))
    routes = by_path(report)
    print("ROUNDTRIP", json.dumps({path: [(r["classification"], r.get("error"), r.get("navigation_type"))
                                          for r in items] for path, items in routes.items()}))
    assert report["scan_status"] != "FAILED", report.get("authentication_error")
    for path in PLAIN_ROUTES + SSO_ROUTES:
        assert path in routes, path
        assert any(r["classification"] in {"PASS", "PASS_WITH_WARNINGS"} for r in routes[path]), routes[path]
    assert receipts[("portal", "POST", "/saml/acs")] >= 1
    assert "fixture-assertion" not in json.dumps(report)
    assert report["suggested_authentication_hosts"] == []
    assert report["summary"]["route_states"]["VALIDATED"] == len(report["results"])


@pytest.mark.asyncio
async def test_unapproved_identity_host_blocks_only_sso_routes_without_stranding_the_scan(sso_route_portal):
    await require_browser()
    origin, receipts = sso_route_portal
    report = await execute_scan(portal_request(origin))
    routes = by_path(report)
    print("UNAPPROVED", json.dumps({path: [(r["classification"], r.get("error"), r.get("navigation_type"))
                                           for r in items] for path, items in routes.items()}))
    assert report["scan_status"] != "FAILED", report.get("authentication_error")
    for path in PLAIN_ROUTES:
        assert any(r["classification"] in {"PASS", "PASS_WITH_WARNINGS"} for r in routes[path]), routes[path]
    for path in SSO_ROUTES:
        assert all(r["classification"] == "AUTHENTICATION_BLOCKED" for r in routes[path]), routes[path]
    assert receipts[("portal", "POST", "/saml/acs")] == 0
    hosts = {item["destination_host"] for item in report["mid_scan_authentication_blocks"]}
    assert "localhost" in hosts
    # The actionable cause is the unapproved identity host, reported once per root cause.
    assert report["suggested_authentication_hosts"] == ["localhost"]
    group = report["authentication_diagnostic_groups"][0]
    assert group["reason"] == "AUTHENTICATION_HOSTS_REQUIRED"
    assert group["affects_authentication"] is True
    assert group["occurrences"] == len(SSO_ROUTES)
    assert group["suggested_authentication_host"] == "localhost"
    assert len(group["routes"]) == len(SSO_ROUTES)
    states = report["summary"]["route_states"]
    assert states["AUTHENTICATION_BLOCKED"] == len(SSO_ROUTES)
    assert states["VALIDATED"] == len(PLAIN_ROUTES) + 1
    assert report["summary"]["routes_application_validated"] == len(PLAIN_ROUTES) + 1
    blocked = next(r for r in report["results"] if urlsplit(r["requested_url"]).path == SSO_ROUTES[0])
    assert blocked["route_state"] == "AUTHENTICATION_BLOCKED"


@pytest.mark.asyncio
async def test_menu_entry_rendered_as_link_and_menu_item_is_validated_once(sso_route_portal):
    await require_browser()
    origin, _receipts = sso_route_portal
    report = await execute_scan(portal_request(origin, authentication_hosts=["localhost"]))
    entries = [result for result in report["results"] if result.get("route_name") == "Workspace home-a"]
    assert len(entries) == 1, [(r.get("view_type"), r.get("navigation_type")) for r in entries]
    assert entries[0]["view_type"] == "URL_ROUTE"
    assert entries[0]["classification"] in {"PASS", "PASS_WITH_WARNINGS"}
