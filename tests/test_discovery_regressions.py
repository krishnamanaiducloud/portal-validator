"""Controlled discovery regressions; never contact enterprise or public targets."""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from playwright.async_api import async_playwright

from app.discovery import SPA_ROUTE_TRANSITION, expand_safe_navigation, perform_route_navigation
from app.main import ScanRequest, detect_auth_signals, execute_scan


@pytest.fixture
def discovery_site(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = b'''<!doctype html><title>Portal</title><main>
                <h1>Read-only navigation fixture</h1><nav>
                <button aria-expanded="false" aria-controls="links" onclick="
                  this.setAttribute('aria-expanded','true');
                  setTimeout(() => document.querySelector('#links').innerHTML =
                    '<a href=/late-one>Late one</a><a href=/late-two>Late two</a>', 250)
                ">Services</button><div id="links"></div></nav>
                <iframe src="/frame" title="Portal navigation"></iframe></main>'''
            elif self.path == "/frame":
                body = b'''<!doctype html><title>Portal frame</title>
                <main><h1>Embedded portal navigation</h1>
                <a href="/frame/health">Embedded health</a></main>'''
            elif self.path == "/query-nav":
                body = b'''<!doctype html><title>Query navigation</title><main>
                <h1>Query-sensitive portal navigation</h1><nav>
                <a href="?view=one">First</a><a href="?view=two">Second</a></nav>
                <output id="selection">None</output></main><script>
                document.querySelectorAll('a').forEach(link => link.onclick = event => {
                  event.preventDefault(); history.pushState({}, '', link.href);
                  document.querySelector('#selection').textContent = link.textContent;
                });</script>'''
            elif self.path in {"/hidden-password", "/business-numeric"}:
                control = (
                    b'<input type="password" hidden aria-label="Unused password field">'
                    if self.path == "/hidden-password" else
                    b'<label>Record number <input inputmode="numeric" maxlength="8"></label>'
                )
                body = b'''<!doctype html><title>Authenticated dashboard</title><main>
                <h1>Read-only authenticated dashboard</h1>
                <nav><a href="/healthy-one">Health overview</a>
                <a href="/healthy-two">Service reports</a></nav>''' + control + b'</main>'
            elif self.path == "/delayed-menu":
                body = b'''<!doctype html><title>Lazy navigation</title><main>
                <h1>Application shell with lazy navigation</h1><nav>
                <button aria-expanded="false" aria-controls="links" onclick="
                  this.setAttribute('aria-expanded','true');
                  fetch('/menu-model').then(response => response.json()).then(items => {
                    document.querySelector('#links').innerHTML = items.map(item =>
                      '<a href=' + item.url + '>' + item.label + '</a>').join('');
                  });
                ">Services</button><div id="links"></div></nav></main>'''
            elif self.path == "/menu-model":
                # This request begins in DISCOVERY, not initial bootstrap. Its
                # completion must keep the bounded menu observer alive.
                time.sleep(0.65)
                body = json.dumps([
                    {"url": "/healthy-one", "label": "Health overview"},
                    {"url": "/healthy-two", "label": "Service reports"},
                ]).encode()
            elif self.path == "/exclusive-menus":
                body = b'''<!doctype html><title>Exclusive navigation</title><main>
                <h1>Application shell with independent menus</h1><nav>
                <button aria-expanded="false" aria-controls="links" onclick="
                  this.setAttribute('aria-expanded','true');
                  document.querySelector('#links').innerHTML =
                    '<a href=/healthy-one>Health overview</a>';
                ">Overview menu</button>
                <button aria-expanded="false" aria-controls="links" onclick="
                  this.setAttribute('aria-expanded','true');
                  document.querySelector('#links').innerHTML =
                    '<a href=/healthy-two>Service reports</a>';
                ">Reports menu</button><div id="links"></div></nav></main>'''
            elif self.path == "/nested-menus":
                body = b'''<!doctype html><title>Nested navigation</title><main>
                <h1>Application shell with nested navigation</h1><nav>
                <button aria-expanded="false" aria-controls="submenu" onclick="
                  this.setAttribute('aria-expanded','true');
                  document.querySelector('#submenu').innerHTML =
                    '<button aria-expanded=false aria-controls=links id=nested>Reports menu</button>';
                  document.querySelector('#nested').onclick = function () {
                    this.setAttribute('aria-expanded','true');
                    document.querySelector('#links').innerHTML =
                      '<a href=/healthy-one>Health overview</a><a href=/healthy-two>Service reports</a>';
                  };
                ">Services</button><div id="submenu"></div><div id="links"></div>
                </nav></main>'''
            elif self.path == "/partial-menu-deadline":
                body = b'''<!doctype html><title>Bounded navigation</title><main>
                <h1>Application shell with a stalled optional menu</h1><nav>
                <button aria-expanded="false" aria-controls="links" onclick="
                  this.setAttribute('aria-expanded','true');
                  document.querySelector('#links').innerHTML =
                    '<a href=/healthy-one>Health overview</a>';
                ">Overview menu</button>
                <button aria-expanded="false" aria-controls="links" onclick="
                  this.setAttribute('aria-expanded','true');
                  document.querySelector('#links').innerHTML =
                    '<div role=progressbar>Loading remaining navigation</div>';
                ">Reports menu</button><div id="links"></div></nav></main>'''
            elif self.path == "/router-links":
                body = b'''<!doctype html><title>Router navigation</title><main>
                <h1>Application shell with accessible router navigation</h1><nav>
                <a routerLink="/healthy-one">Health overview</a>
                <a role="link" routerLink="/healthy-two">Service reports</a>
                <a href="https://outside.example.net/docs">External documentation</a>
                </nav></main><script>
                // A router directive is metadata, not a browser navigation.
                // Simulate its actual handler so native activation is tested.
                document.querySelectorAll('[routerlink]').forEach(link => {
                  link.onclick = () => location.assign(link.getAttribute('routerlink'));
                });</script>'''
            elif self.path == "/non-document-links":
                body = b'''<!doctype html><title>Navigation resources</title><main>
                <h1>Application shell with document and resource links</h1><nav>
                <a href="/healthy-one">Health overview</a>
                <a href="/assets/config.json">Configuration JSON</a>
                <a href="/assets/lazy.js">Application module</a>
                <a href="/assets/theme.css">Theme stylesheet</a>
                <a href="/assets/status.png">Status image</a>
                </nav></main>'''
            elif self.path == "/role-navigation":
                body = b'''<!doctype html><title>Semantic navigation</title><main>
                <h1>Application shell with semantic navigation controls</h1><nav role="menu">
                <button role="menuitem" onclick="history.pushState({},'', '#/deleted')">Delete workspace</button>
                <button role="menuitem" onclick="history.pushState({},'', '#/overview')">Health overview</button>
                <button role="tab" onclick="history.pushState({},'', '#/reports')">Service reports</button>
                </nav></main>'''
            else:
                body = b'''<!doctype html><title>Portal route</title><main>
                <h1>Healthy discovered application route</h1></main>'''
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if self.path == "/menu-model" else "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    from app import security
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = security.resolve_and_validate

    async def fixture_destination(host, allow_private):
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr("app.main.resolve_and_validate", fixture_destination)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_production_discovery_includes_lazy_menu_and_portal_frame(discovery_site):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=discovery_site + "/", max_pages=10, max_depth=2,
        timeout_ms=10000, total_timeout_ms=60000,
        render_settle_ms=200, min_observation_ms=400, network_quiet_ms=100,
        max_navigation_actions=2, check_security_headers=False,
    ))
    assert {item["requested_url"] for item in report["results"]} == {
        discovery_site + path for path in ("/", "/late-one", "/late-two", "/frame/health")
    }
    assert report["summary"]["routes_discovered"] == 4
    assert report["summary"]["routes_validated"] == 4
    assert report["summary"]["failed_pages"] == 0


@pytest.mark.asyncio
async def test_semantic_activation_preserves_distinct_query_routes(discovery_site):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.goto(discovery_site + "/query-nav")
            _, transitioned, activation = await perform_route_navigation(
                page, discovery_site + "/query-nav?view=two", SPA_ROUTE_TRANSITION, 1000,
                label="Second", source="a",
            )
            assert transitioned and activation == "SEMANTIC_CONTROL"
            assert await page.locator("#selection").inner_text() == "Second"
        finally:
            await browser.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ("/hidden-password", "/business-numeric"))
async def test_unrelated_form_controls_do_not_block_authenticated_route_discovery(discovery_site, path):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.goto(discovery_site + path)
            assert await detect_auth_signals(page) == (False, False)
        finally:
            await browser.close()
    report = await execute_scan(ScanRequest(
        target=discovery_site + path, max_pages=10, max_depth=2,
        timeout_ms=10000, total_timeout_ms=60000,
        render_settle_ms=150, min_observation_ms=200, network_quiet_ms=100,
        max_navigation_actions=0, check_security_headers=False,
    ))
    assert {item["requested_url"] for item in report["results"]} == {
        discovery_site + route for route in (path, "/healthy-one", "/healthy-two")
    }
    assert report["summary"]["failed_pages"] == 0
    assert report["summary"]["routes_validated"] == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ("/delayed-menu", "/exclusive-menus", "/nested-menus", "/router-links"))
async def test_production_discovery_retains_lazy_and_transient_navigation_routes(discovery_site, path):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=discovery_site + path, max_pages=10, max_depth=2,
        timeout_ms=10000, total_timeout_ms=60000,
        render_settle_ms=150, min_observation_ms=200, network_quiet_ms=100,
        max_navigation_actions=2, check_security_headers=False,
    ))
    assert {item["requested_url"] for item in report["results"]} == {
        discovery_site + route for route in (path, "/healthy-one", "/healthy-two")
    }
    assert report["summary"]["routes_discovered"] == 3
    assert report["summary"]["routes_validated"] == 3
    assert report["summary"]["failed_pages"] == 0
    assert report["summary"]["discovery_status"] == "COMPLETE"
    if path == "/router-links":
        root = next(item for item in report["results"] if item["requested_url"] == discovery_site + path)
        assert root["external_links_found"] == 1
        assert report["summary"]["external_routes_skipped"] == 1
    if path == "/delayed-menu":
        menu = next(item for item in report["api_inventory"] if item["endpoint"] == "/menu-model")
        assert menu["completed_calls"] == 1
        assert menu["incomplete_calls"] == 0
        assert not any(item["requested_url"].endswith("/menu-model") for item in report["results"])


@pytest.mark.asyncio
@pytest.mark.parametrize("control", (
    '<form><label>Password <input type="password"></label><button>Sign in</button></form>',
    '<form><label>Verification code <input autocomplete="one-time-code"></label></form>',
))
async def test_real_visible_authentication_inputs_remain_gated(control):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content('<main><h1>Authentication required</h1>' + control + '</main>')
            password, mfa = await detect_auth_signals(page)
            assert password if 'type="password"' in control else mfa
        finally:
            await browser.close()


@pytest.mark.asyncio
async def test_document_discovery_does_not_queue_static_configuration_resources(discovery_site):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    report = await execute_scan(ScanRequest(
        target=discovery_site + "/non-document-links", max_pages=10, max_depth=2,
        timeout_ms=10000, total_timeout_ms=60000,
        render_settle_ms=150, min_observation_ms=200, network_quiet_ms=100,
        max_navigation_actions=0, check_security_headers=False,
    ))
    assert {item["requested_url"] for item in report["results"]} == {
        discovery_site + "/non-document-links", discovery_site + "/healthy-one",
    }
    assert report["summary"]["routes_discovered"] == 2


@pytest.mark.asyncio
async def test_semantic_url_less_navigation_is_discovered_without_destructive_actions(discovery_site):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    target = discovery_site + "/role-navigation"
    report = await execute_scan(ScanRequest(
        target=target, max_pages=10, max_depth=2,
        timeout_ms=10000, total_timeout_ms=60000,
        render_settle_ms=150, min_observation_ms=200, network_quiet_ms=100,
        max_navigation_actions=2, check_security_headers=False,
    ))
    assert {item["requested_url"] for item in report["results"]} == {
        target, target + "#/overview", target + "#/reports",
    }
    assert report["summary"]["routes_validated"] == 3
    assert report["summary"]["failed_pages"] == 0
    assert report["results"][0]["navigation_actions"]["skipped"] >= 1


@pytest.mark.asyncio
@pytest.mark.parametrize("deadline_kind", ("route", "scan"))
async def test_successful_panel_routes_survive_a_later_discovery_deadline(discovery_site, deadline_kind):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    route_budget_ms = 4000 if deadline_kind == "route" else 20000
    total_budget_ms = 60000 if deadline_kind == "route" else 10000
    target = discovery_site + "/partial-menu-deadline"
    started = time.perf_counter()
    report = await execute_scan(ScanRequest(
        target=target, max_pages=10, max_depth=2,
        timeout_ms=route_budget_ms, total_timeout_ms=total_budget_ms,
        render_settle_ms=150, min_observation_ms=200, network_quiet_ms=100,
        max_navigation_actions=2, check_security_headers=False,
    ))
    summary = report["summary"]
    assert summary["routes_discovered"] == 2
    assert summary["routes_queued"] == 2
    assert summary["discovery_status"] == "PARTIAL"
    assert all(summary["counter_invariants"].values())
    if deadline_kind == "route":
        healthy = next(item for item in report["results"] if item["requested_url"].endswith("/healthy-one"))
        assert healthy["passed"]
        assert summary["routes_validated"] == 2
        assert summary["routes_not_tested"] == 0
        stalled = next(item for item in report["results"] if item["requested_url"] == target)
        assert stalled["page_load_status"] == "LOADED"
        assert stalled["classification"] == "PASS_WITH_WARNINGS"
        assert stalled["passed"]
        assert stalled["discovery_limitations"] >= 1
        assert any(
            item["evidence"]["original_code"] == "DISCOVERY_TIMEOUT"
            for item in stalled["warning_reasons"]
        )
        # Discovery remains validator overhead, separate from application/
        # validation timing, even when its budget is exhausted.
        route_elapsed_ms = stalled["total_validation_ms"] + stalled["discovery_ms"]
        assert route_budget_ms - 300 <= route_elapsed_ms < route_budget_ms + 1200
    else:
        assert summary["termination_reason"] == "SCAN_TIMEOUT"
        assert summary["execution_status"] == "TIMED_OUT"
        assert summary["routes_validated"] == 0
        assert summary["routes_not_tested"] == 2
        assert report["not_tested_routes"] == [
            {"route": discovery_site + "/healthy-one", "reason": "NOT_TESTED_TIMEOUT"},
            {"route": target, "reason": "NOT_TESTED_TIMEOUT"},
        ]
        assert time.perf_counter() - started < total_budget_ms / 1000 + 2.5


@pytest.mark.asyncio
async def test_hidden_submenu_is_reconsidered_after_its_opener_reveals_it():
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.route("https://portal.example/**", lambda route: route.fulfill(
                content_type="text/html", body='''<main><h1>Portal navigation</h1><nav>
                <div id="submenu" hidden><button role="menuitem" onclick="
                  document.querySelector('#links').innerHTML='<a href=/reports>Reports</a>'
                ">Reports</button></div>
                <button aria-expanded="false" aria-controls="submenu" onclick="
                  this.setAttribute('aria-expanded','true');
                  document.querySelector('#submenu').hidden=false;
                ">Sections</button><div id="links"></div></nav></main>''',
            ))
            await page.goto("https://portal.example/")
            result = await expand_safe_navigation(page, 5)
            assert result["activated"] == 2
            assert any(route.url == "https://portal.example/reports" for route in result["routes"])
        finally:
            await browser.close()


@pytest.mark.asyncio
async def test_observed_semantic_transition_is_retained_before_panel_timeout():
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.route("https://portal.example/**", lambda route: route.fulfill(
                content_type="text/html", body='''<main><h1>Portal navigation</h1>
                <button role="tab" onclick="history.pushState({},'', '#/busy')">Reports</button>
                </main>''',
            ))
            await page.goto("https://portal.example/app")
            retained = []

            async def remember(routes):
                retained.extend(routes)

            async def timeout():
                raise TimeoutError("configured panel budget exhausted")

            with pytest.raises(TimeoutError):
                await expand_safe_navigation(page, 1, wait_after_action=timeout, on_routes_discovered=remember)
            assert any(route.url == "https://portal.example/app#/busy" for route in retained)
        finally:
            await browser.close()
