"""Readiness evidence belongs to its document and selected view."""

import json
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

import pytest
from playwright.async_api import async_playwright

from app import health, security
from app.discovery import activate_ui_view, discover_page_routes
from app.main import ScanRequest, execute_scan


@asynccontextmanager
async def browser_context(*, readiness_event=None):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            context = await browser.new_context()
            if readiness_event:
                await context.add_init_script(script=health.readiness_event_init_script(readiness_event))
            yield context
        finally:
            await browser.close()


@pytest.mark.asyncio
async def test_readiness_selector_retries_transient_document_replacement(monkeypatch):
    async def capture(_page):
        return {
            "ready_state": "complete", "title": "Workspace", "text_length": 40,
            "visible_elements": 5, "busy_indicators": 0, "challenge_indicators": 0,
        }

    class Page:
        calls = waits = 0

        def locator(self, _selector):
            return self

        @property
        def first(self):
            return self

        async def is_visible(self):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("Execution context was destroyed, most likely because of a navigation")
            return True

        async def wait_for_load_state(self, state, timeout):
            assert state == "domcontentloaded" and timeout <= 1000
            self.waits += 1

    monkeypatch.setattr(health, "capture_render_health", capture)
    page = Page()
    result = await health.wait_for_render_settle(
        page, settle_ms=0, maximum_ms=1000, readiness_selector="[data-ready]",
        minimum_observation_ms=0, network_quiet_ms=0,
    )
    assert result["configured_readiness_met"] is True
    assert page.calls == 2 and page.waits == 1


@pytest.mark.parametrize("value", ["", "event name", "x'\nalert(1)", "x" * 129])
def test_readiness_event_accepts_a_bounded_event_name_only(value):
    with pytest.raises(ValueError):
        ScanRequest(target="portal.example", readiness_event=value)
    with pytest.raises(ValueError):
        health.readiness_event_init_script(value)


@pytest.mark.asyncio
async def test_bootstrap_readiness_event_is_document_scoped_and_payload_free():
    async with browser_context(readiness_event="workspace:ready") as context:
        page = await context.new_page()
        documents = {
            "https://portal.example/ready": '''<main data-ready>Workspace content is rendered</main>
              <script>document.dispatchEvent(new CustomEvent('workspace:ready',
                {detail:{token:'private-event-payload'}}));</script>''',
            "https://portal.example/next": '<main data-ready>Another application document</main>',
        }
        await page.route("**/*", lambda route: route.fulfill(
            content_type="text/html", body=documents[route.request.url],
        ))
        await page.goto("https://portal.example/ready")
        options = dict(settle_ms=0, maximum_ms=200, minimum_observation_ms=0,
                       network_quiet_ms=0, readiness_selector="[data-ready]", readiness_event="workspace:ready")
        ready = await health.wait_for_render_settle(page, **options)
        assert health.application_shell_ready(ready)
        assert ready["readiness_event_seen"] is True
        assert "private-event-payload" not in json.dumps(ready)
        await page.goto("https://portal.example/next")
        missing = await health.wait_for_render_settle(page, **options)
        assert missing["configured_readiness_met"] is False
        assert missing["readiness_event_seen"] is False
        assert not health.application_shell_ready(missing)


@pytest.mark.asyncio
async def test_readiness_selector_and_event_must_both_be_observed():
    async with browser_context(readiness_event="workspace-ready") as context:
        page = await context.new_page()
        await page.route("**/*", lambda route: route.fulfill(
            content_type="text/html", body='''<main data-ready>Application shell is visible</main>
              <script>setTimeout(()=>window.dispatchEvent(new Event('workspace-ready')),150);</script>''',
        ))
        await page.goto("https://portal.example/")
        ready = await health.wait_for_render_settle(
            page, settle_ms=0, maximum_ms=1000, minimum_observation_ms=0, network_quiet_ms=0,
            readiness_selector="[data-ready]", readiness_event="workspace-ready",
        )
        assert ready["configured_readiness_met"] is True
        missing_selector = await health.wait_for_render_settle(
            page, settle_ms=0, maximum_ms=100, minimum_observation_ms=0, network_quiet_ms=0,
            readiness_selector="[data-never-ready]", readiness_event="workspace-ready",
        )
        assert missing_selector["readiness_event_seen"] is True
        assert missing_selector["configured_readiness_met"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("content,expected_ready", [("", False), ("7", True)])
async def test_selected_panel_requires_its_own_rendered_content(content, expected_ready):
    async with browser_context() as context:
        page = await context.new_page()
        await page.set_content('''<main><h1>Healthy application shell content</h1><nav>
          <button role="tab" aria-selected="false" aria-controls="report" onclick="
            this.setAttribute('aria-selected','true');document.querySelector('#report').hidden=false">
            Reports</button></nav><section id="report" hidden style="height:100px">''' + content + '</section></main>')
        view = next(route for route in await discover_page_routes(page, 0) if route.view_control)
        await activate_ui_view(page, view.view_control, 1000)
        result = await health.wait_for_render_settle(
            page, view_control=view.view_control, settle_ms=0, maximum_ms=150,
            minimum_observation_ms=0, network_quiet_ms=0,
        )
        assert result["view_scoped"] is True
        assert result["text_length"] == len(content)
        assert health.application_shell_ready(result) is expected_ready
        classification, _ = health.assess_page_health(result, load_ms=0, slow_page_threshold_ms=5000)
        assert (classification == "PAGE_RENDER_ERROR") is not expected_ready


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["panel_busy", "shell_challenge"])
async def test_selected_panel_does_not_hide_its_loader_or_parent_challenge(signal):
    async with browser_context() as context:
        page = await context.new_page()
        await page.set_content('''<main><h1>Healthy application shell content</h1><nav>
          <button role="tab" aria-selected="false" aria-controls="report" onclick="
            this.setAttribute('aria-selected','true');document.querySelector('#report').hidden=false">
            Reports</button></nav><section id="report" hidden>Business view content</section></main>''')
        view = next(route for route in await discover_page_routes(page, 0) if route.view_control)
        await activate_ui_view(page, view.view_control, 1000)
        if signal == "panel_busy":
            await page.locator("#report").evaluate("element => element.setAttribute('aria-busy','true')")
        else:
            await page.evaluate("""() => {
              const challenge=document.createElement('div');challenge.dataset.sitekey='fixture';
              challenge.textContent='Interactive challenge';document.body.append(challenge);
            }""")
        result = await health.wait_for_render_settle(
            page, view_control=view.view_control, settle_ms=0, maximum_ms=150,
            minimum_observation_ms=0, network_quiet_ms=0,
        )
        assert not health.application_shell_ready(result)
        assert result["busy_indicators" if signal == "panel_busy" else "challenge_indicators"] == 1


@pytest.mark.asyncio
async def test_selected_shadow_host_panel_uses_its_rendered_component_content():
    async with browser_context() as context:
        page = await context.new_page()
        await page.set_content('''<main><h1>Parent shell content</h1><nav>
          <button role="tab" aria-selected="false" aria-controls="report" onclick="
            this.setAttribute('aria-selected','true');document.querySelector('#report').hidden=false">Reports</button>
          </nav><remote-view id="report" hidden></remote-view></main><script>
          document.querySelector('remote-view').attachShadow({mode:'open'}).innerHTML=
            '<section>Business view in an open component</section>';</script>''')
        view = next(route for route in await discover_page_routes(page, 0) if route.view_control)
        await activate_ui_view(page, view.view_control, 1000)
        result = await health.wait_for_render_settle(
            page, view_control=view.view_control, settle_ms=0, maximum_ms=150,
            minimum_observation_ms=0, network_quiet_ms=0,
        )
        assert result["view_scoped"] is True
        assert result["text_length"] == len("Business view in an open component")
        assert health.application_shell_ready(result)


@pytest.fixture
def readiness_site(monkeypatch):
    documents = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = documents.get(urlsplit(self.path).path, '<main>Unknown fixture destination</main>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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
        yield f"http://127.0.0.1:{server.server_port}", documents
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


async def scan_readiness(origin, **overrides):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    options = dict(
        target=origin, allow_private_networks=True, max_pages=5, max_depth=3,
        timeout_ms=8000, total_timeout_ms=30000, readiness_timeout_ms=1500,
        render_settle_ms=100, min_observation_ms=150, network_quiet_ms=50,
        max_navigation_actions=10, max_discovery_scrolls=0, check_security_headers=False,
    )
    options.update(overrides)
    return await execute_scan(ScanRequest(**options))


@pytest.mark.asyncio
async def test_blank_nested_view_is_reported_as_failed_readiness(readiness_site):
    origin, documents = readiness_site
    documents["/"] = '''<main><h1>Healthy application workspace</h1><nav>
      <button role="tab" aria-selected="false" aria-controls="report" onclick="
        this.setAttribute('aria-selected','true');document.querySelector('#report').hidden=false">Reports</button>
      </nav><section id="report" hidden style="height:100px"></section></main>'''
    report = await scan_readiness(origin)
    entry, view = report["results"]
    assert entry["application_ready"] is True
    assert view["route_name"] == "Reports"
    assert view["application_ready"] is False
    assert view["validation_status"] == "FAIL"
    assert view["render_health"]["view_scoped"] is True
    assert any(item["type"] == "BLANK_PAGE" for item in view["finding_details"])


@pytest.mark.asyncio
@pytest.mark.parametrize("ready", [False, True])
async def test_readiness_event_reaches_scan_engine_and_report(readiness_site, ready):
    origin, documents = readiness_site
    documents["/"] = '<main data-ready>Application shell content is ready</main>'
    if ready:
        documents["/"] += "<script>window.dispatchEvent(new Event('workspace:ready'));</script>"
    report = await scan_readiness(origin, readiness_selector="[data-ready]", readiness_event="workspace:ready")
    assert report["results"][0]["application_ready"] is ready
    assert report["results"][0]["render_health"]["readiness_event_seen"] is ready
    assert report["results"][0]["page_load_status"] == "LOADED"
    assert report["scan_configuration"]["readiness_event_configured"] is True
    assert "readiness_event" not in report["scan_configuration"]


@pytest.mark.asyncio
async def test_blank_frame_view_is_a_readiness_failure_without_navigation_timeout(readiness_site):
    origin, documents = readiness_site
    documents["/"] = '''<body data-ready><main>Healthy parent application shell
      <iframe name="reports" src="/frame"></iframe></main></body>'''
    documents["/frame"] = '''<nav><button role="tab" aria-selected="false" aria-controls="report" onclick="
      this.setAttribute('aria-selected','true');document.querySelector('#report').hidden=false">Reports</button>
      </nav><section id="report" hidden style="height:100px"></section>'''
    report = await scan_readiness(origin, readiness_selector="body[data-ready]")
    view = next(route for route in report["results"] if route["view_type"] == "UI_TAB")
    assert view["application_ready"] is False
    assert view["page_load_status"] == "LOADED"
    assert view["classification"] != "TIMEOUT"
    assert view["validation_status"] == "FAIL"
    assert view["error"] is None


@pytest.mark.asyncio
async def test_frame_view_waits_for_parent_readiness_within_remaining_budget(readiness_site):
    origin, documents = readiness_site
    documents["/"] = '''<body data-ready><main>Healthy parent application shell
      <iframe name="reports" src="/frame"></iframe></main></body>'''
    documents["/frame"] = '''<nav><button role="tab" aria-selected="false" aria-controls="report" onclick="
      this.setAttribute('aria-selected','true');document.querySelector('#report').hidden=false;
      parent.document.body.removeAttribute('data-ready');
      setTimeout(()=>parent.document.body.setAttribute('data-ready','true'),700)">Reports</button>
      </nav><section id="report" hidden>Business view content is rendered</section>'''
    report = await scan_readiness(origin, readiness_selector="body[data-ready]")
    view = next(route for route in report["results"] if route["view_type"] == "UI_TAB")
    assert view["application_ready"] is True
    assert view["render_health"]["configured_readiness_met"] is True
    assert view["validation_status"] == "PASS"
    assert view["error"] is None


@pytest.mark.asyncio
async def test_frame_menu_readiness_observes_its_own_delayed_navigation(readiness_site):
    origin, documents = readiness_site
    documents["/"] = '<main>Healthy parent application shell<iframe name="reports" src="/frame"></iframe></main>'
    documents["/frame"] = '''<nav><button aria-expanded="false" aria-controls="menu" onclick="
      this.setAttribute('aria-expanded','true');document.querySelector('#menu').hidden=false;
      setTimeout(()=>{document.querySelector('#menu').innerHTML='<a href=/late>Late report</a>';
        document.querySelector('#menu').removeAttribute('aria-busy')},700)">Reports</button>
      <div id="menu" aria-busy="true" hidden>Loading reports</div></nav>'''
    documents["/late"] = '<main><h1>Late report application content</h1></main>'
    report = await scan_readiness(origin)
    late = next(route for route in report["results"] if route["canonical_route"] == origin + "/late")
    assert late["application_ready"] is True
    assert late["route_name"] == "Late report"
