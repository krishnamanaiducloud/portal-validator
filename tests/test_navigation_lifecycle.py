"""Generic navigation replacement, hover and stable-view browser regressions."""

from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from app.discovery import (
    UI_VIEW_ACTIVATION,
    activate_ui_view,
    discover_page_routes,
    discovered_route_key,
    expand_safe_navigation,
    perform_route_navigation,
    resolve_view_target,
    retry_dom_operation,
    safe_navigation_control,
)
from app.health import application_shell_ready, wait_for_render_settle


class ReplacingDocument:
    def __init__(self, failures):
        self.failures = failures
        self.calls = self.waits = 0

    async def inspect(self):
        self.calls += 1
        if self.calls <= self.failures:
            raise RuntimeError("Page.evaluate: Execution context was destroyed, most likely because of a navigation")
        return "ready"

    async def wait_for_load_state(self, state, timeout):
        assert state == "domcontentloaded" and timeout > 0
        self.waits += 1


def test_begin_work_is_not_a_safe_navigation_action():
    assert not safe_navigation_control({
        "role": "button", "text": "Begin Work", "aria_expanded": "false", "aria_controls": "work",
    })


@pytest.mark.asyncio
async def test_transient_document_replacement_is_retried_after_document_readiness():
    document = ReplacingDocument(1)
    assert await retry_dom_operation(document, document.inspect) == "ready"
    assert document.calls == 2 and document.waits == 1


@pytest.mark.asyncio
async def test_persistent_document_replacement_is_bounded_and_not_swallowed():
    document = ReplacingDocument(10)
    with pytest.raises(RuntimeError, match="Execution context was destroyed"):
        await retry_dom_operation(document, document.inspect, attempts=3)
    assert document.calls == 3 and document.waits == 2


@pytest.mark.asyncio
async def test_unexpected_inspection_error_is_not_retried():
    document = ReplacingDocument(0)

    async def broken():
        document.calls += 1
        raise RuntimeError("invalid JavaScript expression")

    with pytest.raises(RuntimeError, match="invalid JavaScript"):
        await retry_dom_operation(document, broken)
    assert document.calls == 1 and document.waits == 0


@asynccontextmanager
async def local_page(documents):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.route("**/*", lambda route: route.fulfill(
                content_type="text/html", body=documents.get(route.request.url, "<main>Not found</main>"),
            ))
            await page.goto("https://portal.example/")
            yield page
        finally:
            await browser.close()


@pytest.mark.asyncio
async def test_discovery_survives_actual_document_replacement_during_scroll_inspection():
    documents = {
        "https://portal.example/": '''<nav style="height:20px;overflow:auto"><div style="height:100px">Menu</div>
          <a href="/old">Old view</a></nav><script>setTimeout(()=>location.replace('/ready'),20)</script>''',
        "https://portal.example/ready": '<main><a href="/final-view">Final view</a></main>',
    }
    async with local_page(documents) as page:
        routes = await discover_page_routes(page, 3)
        assert page.url == "https://portal.example/ready"
        assert any(route.label == "Final view" for route in routes)


@pytest.mark.asyncio
async def test_hover_only_dropdown_is_revealed_without_dispatching_click():
    body = '''<main><nav><button aria-controls="reports" aria-expanded="false"
      onmouseenter="this.setAttribute('aria-expanded','true');document.querySelector('#reports').hidden=false"
      onclick="window.wrongClick=true">Reports menu</button>
      <div id="reports" hidden><a href="/#/reports">Service reports</a></div></nav></main>'''
    async with local_page({"https://portal.example/": body}) as page:
        result = await expand_safe_navigation(page, 3, maximum_scrolls=0)
        report = next(route for route in result["routes"] if route.label == "Service reports")
        assert report.navigation_hierarchy == ("Reports menu",)
        assert result["activated"] == 1
        assert not await page.evaluate("Boolean(window.wrongClick)")


@pytest.mark.asyncio
async def test_framework_id_changes_do_not_change_view_identity_or_prevent_activation():
    body = '''<main><nav id="generated-nav-1" aria-label="Application views">
      <button id="generated-control-1" role="tab" aria-controls="generated-panel-1" aria-selected="false"
      onclick="this.setAttribute('aria-selected','true');document.querySelector('section').hidden=false">Reports</button>
      </nav><section id="generated-panel-1" hidden>Service report content</section></main>'''
    async with local_page({"https://portal.example/": body}) as page:
        original = next(route for route in await discover_page_routes(page, 0) if route.view_control)
        await page.evaluate("""() => {
          document.querySelector('nav').id='generated-nav-99';
          document.querySelector('button').id='generated-control-99';
          document.querySelector('button').setAttribute('aria-controls','generated-panel-99');
          document.querySelector('section').id='generated-panel-99';
        }""")
        updated = next(route for route in await discover_page_routes(page, 0) if route.view_control)
        assert discovered_route_key(original, original.url) == discovered_route_key(updated, updated.url)
        await activate_ui_view(page, original.view_control, 5000)
        assert await page.locator("section").is_visible()


@pytest.mark.asyncio
async def test_visible_panel_content_change_is_a_verified_view_not_a_noop():
    body = '''<main><nav><button role="link" aria-controls="detail" onclick="
      document.querySelector('#detail').textContent='Report content'">Reports</button></nav>
      <section id="detail">Overview content</section></main>'''
    async with local_page({"https://portal.example/": body}) as page:
        view = next(route for route in await discover_page_routes(page, 0) if route.view_control)
        await activate_ui_view(page, view.view_control, 5000)
        assert await page.locator("section").inner_text() == "Report content"


@pytest.mark.asyncio
async def test_same_origin_frame_tab_activates_in_its_observed_frame_not_the_top_document():
    documents = {
        "https://portal.example/": '<main>Application shell<iframe name="reports" src="/frame"></iframe></main>',
        "https://portal.example/frame": '''<main><nav aria-label="Frame views">
          <button role="tab" aria-controls="report" aria-selected="false" onclick="
          this.setAttribute('aria-selected','true');document.querySelector('#report').hidden=false">Reports</button>
          </nav><section id="report" hidden>Service report</section></main>''',
    }
    async with local_page(documents) as page:
        frame = page.frame(name="reports")
        await frame.wait_for_load_state("domcontentloaded")
        view = next(route for route in await discover_page_routes(frame, 0) if route.view_control)
        assert view.view_control["frame_url"] == "https://portal.example/frame"
        assert resolve_view_target(page, view.view_control) == frame
        response, transitioned, mechanism = await perform_route_navigation(
            page, view.url, UI_VIEW_ACTIVATION, 5000, view_control=view.view_control,
        )
        assert response is None and transitioned
        assert mechanism == "SAME_ORIGIN_FRAME_UI_CONTROL"
        assert page.url == "https://portal.example/"
        assert await frame.locator("#report").is_visible()


@pytest.mark.asyncio
async def test_frame_loading_view_does_not_inherit_ready_parent_shell():
    documents = {
        "https://portal.example/": '<main>Healthy application shell content<iframe name="reports" src="/frame"></iframe></main>',
        "https://portal.example/frame": '''<main><nav><button role="tab" aria-controls="report" aria-selected="false"
          onclick="this.setAttribute('aria-selected','true');document.querySelector('#report').hidden=false">Reports</button>
          </nav><section id="report" hidden aria-busy="true">Loading report content</section></main>''',
    }
    async with local_page(documents) as page:
        frame = page.frame(name="reports")
        await frame.wait_for_load_state("domcontentloaded")
        view = next(route for route in await discover_page_routes(frame, 0) if route.view_control)
        target = resolve_view_target(page, view.view_control)
        await activate_ui_view(target, view.view_control, 5000)
        options = dict(settle_ms=0, maximum_ms=250, minimum_observation_ms=0, network_quiet_ms=0)
        assert application_shell_ready(await wait_for_render_settle(page, **options))
        assert not application_shell_ready(await wait_for_render_settle(target, **options))
