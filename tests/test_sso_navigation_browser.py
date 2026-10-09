"""Real browser SSO handoffs against isolated, generic loopback fixtures."""

import asyncio
import json
import logging
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlparse

import pytest
from playwright.async_api import Error as PlaywrightError, async_playwright

from app import main, security
from app.logging_config import LOGGER
from app.main import ScanRequest, execute_scan
from app.navigation_guard import RedirectResponseGuard


@pytest.fixture
def sso_portal(tmp_path, monkeypatch):
    requests = []
    resolved_hosts = []
    servers = {}
    class FixtureOrigins(dict):
        application_delay_ms = 0
        saml_redirect_status = 303
        saml_redirect_delay_ms = 0

    origins = FixtureOrigins()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, body=b"", **headers):
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key.replace("_", "-"), value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            role = self.server.role
            path = urlparse(self.path).path
            cookies = self.headers.get("Cookie", "")
            requests.append((role, "GET", path, cookies))
            if role == "portal":
                if path == "/popup-window-page":
                    return self.reply(200, ('''<html><body><h1>Generic application</h1>
                        <main>The application document remains ready while its separate
                        authentication window completes the approved sign-in workflow.</main>
                        <script>window.open(''' + json.dumps(origins["oauth"] + "/authorize")
                        + ''');</script></body></html>''').encode())
                if path == "/bridge-start":
                    return self.reply(302, Location=origins["oauth"] + "/bridge")
                if path == "/plain-page":
                    return self.reply(200, b"<html><head><title>Generic fixture</title></head><body>Application fixture</body></html>")
                if path in {"/post-redirect-page", "/post-redirect-allowed-page"}:
                    endpoint = "/api/read-redirect" if path == "/post-redirect-page" else "/api/read-redirect-approved"
                    return self.reply(200, ('''<html><body><h1>Read-only application fixture</h1>
                        <main>Application content remains available.</main><script>fetch('''
                        + json.dumps(endpoint) + ''',{method:'POST',headers:{'Content-Type':'application/json'},
                        body:'{"operation":"read"}'});</script></body></html>''').encode())
                if path == "/api-page":
                    return self.reply(200, b'''<html><body><h1>Public application fixture</h1>
                        <main>Application content remains available.</main>
                        <script>fetch('/api/redirect');</script></body></html>''')
                if path == "/api/redirect":
                    return self.reply(302, Location=origins["oauth"] + "/identity-only")
                if path == "/iframe-page":
                    return self.reply(200, ('''<html><body><h1>Frame fixture</h1><iframe src="'''
                        + origins["oauth"] + '''/iframe-redirect"></iframe></body></html>''').encode())
                if path == "/oopif-page":
                    return self.reply(200, ('''<html><body><h1>Frame fixture</h1><iframe src="'''
                        + origins["oauth"] + '''/iframe-app"></iframe></body></html>''').encode())
                if path == "/unsafe":
                    return self.reply(302, Location="http://169.254.169.254/latest/meta-data/")
                if path == "/unsafe-local":
                    return self.reply(302, Location=origins["oauth"] + "/identity-only")
                if path == "/callback":
                    return self.reply(
                        303, Set_Cookie="portal_session=fixture-private-portal; HttpOnly; SameSite=Lax",
                        Location=origins["portal"] + "/",
                    )
                if "portal_session=fixture-private-portal" not in cookies:
                    return self.reply(
                        302, Location=origins["oauth"]
                        + "/authorize?client_id=portal&response_type=code&state=fixture-private-state",
                    )
                if origins.application_delay_ms:
                    time.sleep(origins.application_delay_ms / 1000)
                return self.reply(200, b'''<!doctype html><html><body>
                    <h1>Protected generic portal application</h1>
                    <nav><a href="/protected/dashboard">Application dashboard</a></nav>
                    <main>Authenticated application content is available.</main>
                    <script>fetch('/api/read',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});</script>
                    </body></html>''')
            if role == "oauth":
                if path == "/bridge":
                    destination = json.dumps(origins["oauth"] + "/authorize?client_id=portal&response_type=code&state=fixture-private-state")
                    return self.reply(200, ('''<html><body><h1>Completing sign-in</h1><script>
                        setTimeout(() => { location.href = ''' + destination + '''; }, 200);
                        </script></body></html>''').encode())
                if path == "/iframe-app":
                    return self.reply(200, b'''<html><body><h1>Cross-origin child application</h1>
                        <img src="/iframe-redirect" alt="isolated child resource"></body></html>''')
                if path == "/iframe-redirect":
                    return self.reply(302, Location=origins["portal"] + "/blocked-hit")
                if "idp_session=fixture-private-idp" not in cookies:
                    return self.reply(200, b'''<html><body><h1>Sign in</h1>
                        <form><input type="password" name="password"></form>
                        <a href="/identity-only">Identity account settings</a></body></html>''')
                body = ('''<!doctype html><html><body><h1>Federated authentication handoff</h1>
                    <a href="/identity-only">Identity account settings</a>
                    <form id="handoff" method="POST" action="''' + origins["saml"] + '''/saml/consume">
                    <input type="hidden" name="SAMLRequest" value="fixture-private-saml">
                    <input type="hidden" name="RelayState" value="fixture-private-relay"></form>
                    <script>document.querySelector('#handoff').submit();</script></body></html>''').encode()
                return self.reply(
                    200, body, Set_Cookie="bridge_session=fixture-private-bridge; HttpOnly; SameSite=Lax",
                )
            return self.reply(404, b"<html><body>Unexpected fixture destination</body></html>")

        def do_POST(self):
            role = self.server.role
            path = urlparse(self.path).path
            # Bodies are deliberately not retained in fixture traces or report evidence.
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            cookies = self.headers.get("Cookie", "")
            requests.append((role, "POST", path, cookies))
            if role == "saml" and path == "/saml/consume":
                if origins.saml_redirect_delay_ms:
                    time.sleep(origins.saml_redirect_delay_ms / 1000)
                return self.reply(
                    origins.saml_redirect_status, Location=origins["portal"]
                    + "/callback?code=fixture-private-code&state=fixture-private-state",
                )
            if role == "portal" and path == "/callback":
                return self.reply(
                    303, Set_Cookie="portal_session=fixture-private-portal; HttpOnly; SameSite=Lax",
                    Location=origins["portal"] + "/",
                )
            if role == "portal" and path == "/api/read":
                return self.reply(200, b'{"ready":true}')
            if role == "portal" and path == "/api/read-redirect":
                return self.reply(307, Location=origins["oauth"] + "/api/unapproved-read")
            if role == "portal" and path == "/api/read-redirect-approved":
                return self.reply(307, Location="/api/read-redirect-approved-two")
            if role == "portal" and path == "/api/read-redirect-approved-two":
                return self.reply(308, Location="/api/read-result")
            if role == "portal" and path == "/api/read-result":
                return self.reply(200, b'{"ready":true}')
            return self.reply(405)

        def log_message(self, *_args):
            return

    threads = []
    for role in ("portal", "oauth", "saml"):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.role = role
        servers[role] = server
        host = "127.0.0.1" if role == "portal" else "localhost"
        origins[role] = f"http://{host}:{server.server_port}"
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    monkeypatch.setattr(
        security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, *(server.server_port for server in servers.values())},
    )
    original_resolver = security.resolve_and_validate

    async def fixture_resolver(host, allow_private):
        resolved_hosts.append(host)
        if host in {"127.0.0.1", "localhost"}:
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    # Only fixture hosts bypass loopback rejection. Every other destination still
    # uses the real SSRF resolver, including the cloud-metadata regression below.
    monkeypatch.setattr(main, "resolve_and_validate", fixture_resolver)
    profile_dir = tmp_path / "auth"
    profile_dir.mkdir()
    monkeypatch.setattr(main, "AUTH_STATE_DIR", profile_dir)
    monkeypatch.setenv("HOME", str(tmp_path / "runtime-home"))
    try:
        yield origins, requests, resolved_hosts, profile_dir
    finally:
        for server in servers.values():
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


async def require_browser():
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")


def configuration(origin, **overrides):
    values = dict(
        target=origin, authentication_hosts=["localhost"], max_pages=2, max_depth=1,
        timeout_ms=10000, total_timeout_ms=30000, authentication_timeout_ms=6000,
        render_settle_ms=100, min_observation_ms=100, network_quiet_ms=100,
        max_navigation_actions=0, max_discovery_scrolls=0, check_security_headers=False,
        approved_read_post_operations=[{"host": "127.0.0.1", "path": "/api/read"}],
    )
    values.update(overrides)
    return ScanRequest(**values)


def write_profile(directory, *, expired=False):
    state = {"cookies": [{
        "name": "idp_session", "value": "fixture-private-idp", "domain": "localhost", "path": "/",
        "expires": time.time() + (-60 if expired else 3600), "httpOnly": True,
        "secure": False, "sameSite": "Lax",
    }], "origins": []}
    profile = directory / "approved.json"
    profile.write_text(json.dumps(state), encoding="utf-8")
    return profile


@pytest.mark.asyncio
@pytest.mark.parametrize("session", ["valid", "expired", "anonymous"])
async def test_real_cross_origin_oauth_saml_callback_preserves_session_and_crawl_boundary(sso_portal, caplog, session):
    await require_browser()
    origins, requests, resolved, profile_dir = sso_portal
    authentication = {"mode": "none"}
    mounted_state = None
    if session != "anonymous":
        mounted_state = write_profile(profile_dir, expired=session == "expired")
        original_state = mounted_state.read_bytes()
        authentication = {"mode": "storage_state", "storage_profile": "approved"}
    caplog.set_level(logging.DEBUG, logger=LOGGER.name)
    LOGGER.addHandler(caplog.handler)
    try:
        report = await execute_scan(configuration(origins["portal"], authentication=authentication))
    finally:
        LOGGER.removeHandler(caplog.handler)
    assert {"127.0.0.1", "localhost"} <= set(resolved)
    assert not any(path == "/identity-only" for _, _, path, _ in requests)
    assert all(urlparse(result["requested_url"]).hostname == "127.0.0.1" for result in report["results"])
    assert "fixture-private" not in json.dumps(report)
    assert "fixture-private" not in caplog.text
    if mounted_state is not None:
        assert mounted_state.read_bytes() == original_state
    if session == "valid":
        posts = [item for item in requests if item[0] == "saml" and item[1] == "POST"]
        assert len(posts) == 1
        assert "idp_session=fixture-private-idp" in posts[0][3]
        assert "bridge_session=fixture-private-bridge" in posts[0][3]
        assert report["results"][0]["authentication_status"] == "PASS"
        assert report["summary"]["application_routes_validated"] == 2
        auth = next(item for item in report["api_inventory"] if item["endpoint"] == "/saml/consume")
        assert auth["allowed_calls"] == 1 and auth["blocked_calls"] == 0
        assert auth["policies"] == ["AUTH_FLOW"]
        assert any(role == "portal" and path == "/protected/dashboard" for role, _, path, _ in requests)
        assert any(role == "portal" and method == "POST" and "portal_session=" in cookies
                   for role, method, _, cookies in requests)
    else:
        expected = "SESSION_EXPIRED" if session == "expired" else "AUTH_REQUIRED"
        assert report["results"][0]["authentication_status"] == expected
        assert report["summary"]["coverage_status"] == "NONE"
        assert not any(role == "saml" and method == "POST" for role, method, _, _ in requests)


@pytest.mark.asyncio
async def test_real_authentication_post_to_unapproved_identity_host_stays_blocked(sso_portal):
    await require_browser()
    origins, requests, _, profile_dir = sso_portal
    write_profile(profile_dir)
    report = await execute_scan(configuration(
        origins["portal"], authentication_hosts=[],
        authentication={"mode": "storage_state", "storage_profile": "approved"},
    ))
    assert not any(role == "saml" and method == "POST" for role, method, _, _ in requests)
    auth = next(item for item in report["api_inventory"] if item["endpoint"] == "/saml/consume")
    assert auth["blocked_calls"] == 1 and auth["allowed_calls"] == 0
    assert not report["summary"]["coverage_complete"]


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
async def test_popup_authentication_post_redirect_keeps_the_approved_sso_boundary(sso_portal, approved):
    await require_browser()
    origins, requests, _, profile_dir = sso_portal
    origins.saml_redirect_status = 307
    # The primary page must settle before the popup's native POST redirect.
    # Clearing context authentication evidence at primary-page readiness used
    # to nondeterministically block this approved callback on a busy host.
    origins.saml_redirect_delay_ms = 700
    write_profile(profile_dir)
    report = await execute_scan(configuration(
        origins["portal"] + "/popup-window-page", max_pages=1, min_observation_ms=2000,
        authentication_hosts=["localhost"] if approved else [],
        authentication={"mode": "storage_state", "storage_profile": "approved"},
    ))
    assert sum(role == "saml" and method == "POST" for role, method, _, _ in requests) == int(approved), (
        [(role, method, path) for role, method, path, _ in requests],
        report["results"][0].get("failed_resources"),
    )
    assert sum(role == "portal" and method == "POST" and path == "/callback"
               for role, method, path, _ in requests) == int(approved)
    if approved:
        assert any(role == "portal" and method == "GET" and "portal_session=" in cookies
                   for role, method, _, cookies in requests)
        assert all(item["blocked_calls"] == 0 for item in report["api_inventory"])
    else:
        assert any(item["blocked_calls"] == 1 for item in report["api_inventory"])
    assert report["results"][0]["page_load_status"] == "LOADED"
    assert "fixture-private" not in json.dumps(report)


@pytest.mark.asyncio
async def test_final_sso_application_navigation_delay_remains_a_dynamic_slow_route_warning(sso_portal):
    await require_browser()
    origins, _, _, profile_dir = sso_portal
    origins.application_delay_ms = 900
    write_profile(profile_dir)
    report = await execute_scan(configuration(
        origins["portal"], max_pages=1, slow_page_threshold_ms=500,
        authentication={"mode": "storage_state", "storage_profile": "approved"},
    ))
    result = report["results"][0]
    assert result["authentication_status"] == "PASS"
    assert result["page_load_status"] == "LOADED"
    assert result["classification"] == "PASS_WITH_WARNINGS"
    assert result["application_navigation_ms"] >= 850
    warning = next(item for item in result["warning_reasons"] if item["code"] == "SLOW_ROUTE")
    assert warning["evidence"]["threshold_ms"] == 500
    assert "configured 0.5s threshold" in warning["description"]
    assert report["summary"]["failed_pages"] == 0


@pytest.mark.asyncio
async def test_real_approved_identity_bridge_waits_for_delayed_script_redirect(sso_portal):
    await require_browser()
    origins, requests, _, profile_dir = sso_portal
    write_profile(profile_dir)
    report = await execute_scan(configuration(
        origins["portal"] + "/bridge-start", max_pages=1,
        authentication={"mode": "storage_state", "storage_profile": "approved"},
    ))
    result = report["results"][0]
    assert result["authentication_status"] == "PASS"
    assert result["page_load_status"] == "LOADED"
    assert urlparse(result["final_url"]).hostname == "127.0.0.1"
    assert any(role == "oauth" and path == "/bridge" for role, _, path, _ in requests)
    assert any(role == "saml" and method == "POST" for role, method, _, _ in requests)
    assert not any(path == "/identity-only" for _, _, path, _ in requests)
    assert "fixture-private" not in json.dumps(report)


@pytest.mark.asyncio
async def test_real_navigation_to_metadata_remains_ssrf_blocked(sso_portal):
    await require_browser()
    origins, _, resolved, _ = sso_portal
    report = await execute_scan(configuration(origins["portal"] + "/unsafe", max_pages=1))
    assert "169.254.169.254" in resolved
    assert report["results"][0]["classification"] == "NETWORK_ERROR"
    assert not report["summary"]["coverage_complete"]


@pytest.mark.asyncio
async def test_cdp_redirect_guard_blocks_native_hop_before_destination_receives_request(sso_portal):
    await require_browser()
    origins, requests, _, _ = sso_portal
    errors = []

    async def validate_destination(url, source_url, metadata):
        if urlparse(url).hostname == "localhost":
            raise security.DestinationError("NETWORK_ERROR", "Fixture destination is not approved")

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context()
        # Coexistence with the existing route mechanism is required, not assumed.
        await context.route("**/*", lambda route: route.continue_())
        page = await context.new_page()
        guard = await RedirectResponseGuard.install(
            context, page, validate_destination=validate_destination,
            on_policy_error=lambda error, metadata: errors.append(error),
        )
        try:
            with pytest.raises(PlaywrightError):
                await page.goto(origins["portal"] + "/unsafe-local", timeout=5000)
            assert errors and errors[0].classification == "NETWORK_ERROR"
            assert not any(role == "oauth" for role, _, _, _ in requests)
        finally:
            await page.close()
            await guard.close()
            await context.close()
            await browser.close()


@pytest.mark.asyncio
async def test_actual_configured_authorization_header_does_not_follow_unapproved_redirect(sso_portal):
    await require_browser()
    origins, requests, _, _ = sso_portal
    report = await execute_scan(configuration(
        origins["portal"] + "/unsafe-local", max_pages=1,
        authentication={"mode": "bearer", "token": "fixture-private-bearer"},
    ))
    assert not any(role == "oauth" for role, _, _, _ in requests)
    assert report["results"][0]["classification"] == "NAVIGATION_ERROR"
    assert "fixture-private" not in json.dumps(report)


@pytest.mark.asyncio
async def test_api_redirect_header_guard_does_not_fail_successful_main_document(sso_portal):
    await require_browser()
    origins, requests, _, _ = sso_portal
    report = await execute_scan(configuration(
        origins["portal"] + "/api-page", max_pages=1,
        authentication={"mode": "bearer", "token": "fixture-private-bearer"},
    ))
    assert not any(role == "oauth" for role, _, _, _ in requests)
    result = report["results"][0]
    assert result["page_load_status"] == "LOADED"
    assert result["classification"] in {"PASS", "PASS_WITH_WARNINGS"}
    api = next(item for item in report["api_inventory"] if item["endpoint"] == "/api/redirect")
    assert api["blocked_calls"] == 1 and api["target_failure_count"] == 0
    assert "fixture-private" not in json.dumps(report)

@pytest.mark.asyncio
async def test_read_only_post_307_cannot_bypass_destination_approval(sso_portal):
    await require_browser()
    origins, requests, _, _ = sso_portal
    report = await execute_scan(configuration(
        origins["portal"] + "/post-redirect-page", max_pages=1,
        approved_read_post_operations=[{"host": "127.0.0.1", "path": "/api/read-redirect"}],
    ))
    assert not any(role == "oauth" and method == "POST" for role, method, _, _ in requests)
    assert report["results"][0]["page_load_status"] == "LOADED"
    assert report["results"][0]["classification"] in {"PASS", "PASS_WITH_WARNINGS"}
    api = next(item for item in report["api_inventory"] if item["endpoint"] == "/api/read-redirect")
    assert api["blocked_calls"] == 1 and api["target_failure_count"] == 0


@pytest.mark.asyncio
async def test_approved_read_only_post_survives_native_307_308_without_replay(sso_portal):
    await require_browser()
    origins, requests, _, _ = sso_portal
    paths = ["/api/read-redirect-approved", "/api/read-redirect-approved-two", "/api/read-result"]
    report = await execute_scan(configuration(
        origins["portal"] + "/post-redirect-allowed-page", max_pages=1,
        approved_read_post_operations=[{"host": "127.0.0.1", "path": path} for path in paths],
    ))
    assert [path for role, method, path, _ in requests if role == "portal" and method == "POST"] == paths
    assert report["results"][0]["page_load_status"] == "LOADED"
    assert report["results"][0]["classification"] in {"PASS", "PASS_WITH_WARNINGS"}
    assert all(item["blocked_calls"] == 0 for item in report["api_inventory"])


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["main", "popup", "oopif"])
async def test_browser_level_guard_intercepts_first_popup_and_actual_oopif_redirect(sso_portal, target):
    await require_browser()
    origins, requests, _, _ = sso_portal
    errors = []
    denied = asyncio.Event()

    async def validate_destination(url, source, metadata):
        if urlparse(url).path in {"/identity-only", "/blocked-hit"}:
            raise security.DestinationError("NETWORK_ERROR", "Fixture destination is not approved")

    def on_error(error, metadata):
        errors.append(metadata)
        denied.set()

    async with async_playwright() as playwright:
        # TEST ONLY: require a genuine isolated child renderer in the OOPIF case.
        browser = await playwright.chromium.launch(headless=True, args=["--site-per-process"])
        guard = await RedirectResponseGuard.install_browser(
            browser, validate_destination=validate_destination, on_policy_error=on_error,
        )
        context = await browser.new_context()
        await context.route("**/*", lambda route: route.continue_())
        page = await context.new_page()
        await guard.bind_primary_page(context, page)
        try:
            if target == "main":
                with pytest.raises(PlaywrightError):
                    await page.goto(origins["portal"] + "/unsafe-local", timeout=8000)
            elif target == "popup":
                await page.goto(origins["portal"] + "/plain-page", wait_until="domcontentloaded")
                async with context.expect_page(timeout=8000):
                    await page.evaluate("url => window.open(url)", origins["portal"] + "/unsafe-local")
            else:
                response = await page.goto(origins["portal"] + "/oopif-page", wait_until="load", timeout=8000)
                assert response.status == 200
                child = next(frame for frame in page.frames if frame is not page.main_frame)
                session = await context.new_cdp_session(child)
                target_info = await session.send("Target.getTargetInfo", {})
                assert target_info["targetInfo"]["type"] == "iframe"
                await session.detach()
            await asyncio.wait_for(denied.wait(), timeout=8)
            assert errors[0]["main_document"] is (target == "main")
            assert errors[0]["primary_page"] is (target == "main")
            assert errors[0]["document_navigation"] is (target != "oopif")
            assert errors[0]["response_status"] == 302
            assert not any(path in {"/identity-only", "/blocked-hit"} for _, _, path, _ in requests)
        finally:
            await browser.close()
            await guard.close()
