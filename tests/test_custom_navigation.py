"""Real browser regressions for custom/Angular navigation and coverage limits."""

from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from app.discovery import (
    UI_VIEW_ACTIVATION,
    activate_semantic_route,
    activate_ui_view,
    discover_page_routes,
    discovered_route_key,
    expand_safe_navigation,
    perform_route_navigation,
)


@asynccontextmanager
async def navigation_page(body):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.route("**/*", lambda route: route.fulfill(content_type="text/html", body=body))
            await page.goto("https://portal.example/")
            yield page
        finally:
            await browser.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("attribute", ["data-url", "data-route", "ng-reflect-router-link"])
async def test_custom_url_metadata_is_activated_on_the_actual_discovered_control(attribute):
    body = f'''<main><button data-url="/other" onclick="window.wrong=true">Other</button>
      <a href="/link">Plain link</a>
      <portal-item {attribute}="/reports" onclick="window.selected='Reports'"
        style="display:block">Reports</portal-item></main>'''
    async with navigation_page(body) as page:
        routes = await discover_page_routes(page, 0)
        assert any(route.url == "https://portal.example/reports" and route.label == "Reports" for route in routes)
        assert await activate_semantic_route(
            page, "https://portal.example/reports", label="Reports", source="portal-item", timeout_ms=1000,
        )
        assert await page.evaluate("window.selected") == "Reports"
        assert not await page.evaluate("Boolean(window.wrong)")


@pytest.mark.asyncio
async def test_shadow_root_control_activation_does_not_depend_on_locator_index_order():
    body = '''<main><portal-menu id="first"></portal-menu>
      <a href="/outer" onclick="event.preventDefault();window.wrong=true">Outer</a>
      <portal-menu id="second"></portal-menu></main><script>
      document.querySelectorAll('portal-menu').forEach((host,index) => {
        const root=host.attachShadow({mode:'open'});
        root.innerHTML='<button data-route="/reports-'+index+'">Report '+index+'</button>';
        root.querySelector('button').onclick=()=>window.selected=index;
      });</script>'''
    async with navigation_page(body) as page:
        routes = await discover_page_routes(page, 0)
        assert {route.url for route in routes} >= {
            "https://portal.example/reports-0", "https://portal.example/reports-1",
        }
        assert await activate_semantic_route(
            page, "https://portal.example/reports-1", label="Report 1", source="button", timeout_ms=1000,
        )
        assert await page.evaluate("window.selected") == 1
        assert not await page.evaluate("Boolean(window.wrong)")


@pytest.mark.asyncio
async def test_custom_menu_panel_view_is_queued_and_activated_exactly_once():
    body = '''<main><nav><portal-item role="menuitem" aria-controls="reports"
      style="display:block" onclick="window.calls=(window.calls||0)+1;document.querySelector('#reports').hidden=false"
      >Service reports</portal-item></nav><section id="reports" hidden>Read-only report content</section></main>'''
    async with navigation_page(body) as page:
        navigation = await expand_safe_navigation(page, 5, maximum_scrolls=0)
        views = [route for route in navigation["routes"] if route.view_control]
        assert len(views) == 1 and views[0].label == "Service reports"
        assert navigation["activated"] == 0
        assert await page.evaluate("window.calls || 0") == 0
        await perform_route_navigation(
            page, views[0].url, UI_VIEW_ACTIVATION, 2000, view_control=views[0].view_control,
        )
        assert await page.evaluate("window.calls") == 1


@pytest.mark.asyncio
async def test_custom_navigation_without_url_or_panel_has_distinct_verified_view_identity():
    body = '''<main><nav aria-label="Application views">
      <button onclick="window.calls=(window.calls||0)+1;document.querySelector('output').textContent='Report content'">Reports</button>
      <button onclick="document.querySelector('output').textContent='Activity content'">Activity</button>
      </nav><output>Overview content</output></main>'''
    async with navigation_page(body) as page:
        routes = await discover_page_routes(page, 0)
        views = [route for route in routes if route.view_control]
        assert {route.label for route in views} == {"Reports", "Activity"}
        assert len({discovered_route_key(route, route.url) for route in views}) == 2
        assert {route.url for route in views} == {"https://portal.example/"}
        report = next(route for route in views if route.label == "Reports")
        await activate_ui_view(page, report.view_control, 1000)
        assert await page.locator("output").inner_text() == "Report content"
        assert await page.evaluate("window.calls") == 1


@pytest.mark.asyncio
async def test_menu_expander_is_not_also_queued_as_ui_view_and_preserves_nested_hierarchy():
    body = '''<main><nav>
      <button data-target="#menu" aria-expanded="false" onclick="
        window.menuCalls=(window.menuCalls||0)+1;this.setAttribute('aria-expanded','true');
        document.querySelector('#menu').hidden=false">Dashboards</button>
      <div id="menu" role="menu" hidden><button role="menuitem" aria-controls="reports"
        onclick="document.querySelector('#reports').hidden=false">Service reports</button></div>
      </nav><section id="reports" hidden>Read-only report</section></main>'''
    async with navigation_page(body) as page:
        result = await expand_safe_navigation(page, 5, maximum_scrolls=0)
        views = [route for route in result["routes"] if route.view_control]
        assert [route.label for route in views] == ["Service reports"]
        assert views[0].navigation_hierarchy == ("Dashboards",)
        assert result["activated"] == 1
        assert await page.evaluate("window.menuCalls") == 1
        assert result["remaining"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("maximum,activated,remaining", [(0,0,2), (1,1,1)])
async def test_bounded_discovery_reports_remaining_controls_without_inventing_routes(maximum, activated, remaining):
    body = '''<main><nav>
      <button aria-expanded="false" aria-controls="first" onclick="this.setAttribute('aria-expanded','true')">Overview menu</button>
      <button aria-expanded="false" aria-controls="second" onclick="this.setAttribute('aria-expanded','true')">Reports menu</button>
      <div id="first"></div><div id="second"></div></nav></main>'''
    async with navigation_page(body) as page:
        result = await expand_safe_navigation(page, maximum, maximum_scrolls=0)
        assert result["activated"] == activated
        assert result["remaining"] == result["unresolved"] == remaining
        assert result["discovered"] == 2
        assert result["limit_reached"] is True
        assert result["routes"] == []


@pytest.mark.asyncio
async def test_hidden_nested_view_restores_its_observed_parent_menu_before_activation():
    body = '''<main><nav>
      <button aria-expanded="false" aria-controls="first" onclick="this.setAttribute('aria-expanded','true');
        document.querySelector('#first').hidden=false;document.querySelector('#second').hidden=true">Overview menu</button>
      <button aria-expanded="false" aria-controls="second" onclick="this.setAttribute('aria-expanded','true');
        document.querySelector('#second').hidden=false;document.querySelector('#first').hidden=true">Reports menu</button>
      <div id="first" hidden><button role="menuitem" aria-controls="detail" onclick="
        window.calls=(window.calls||0)+1;document.querySelector('#detail').hidden=false">Service details</button></div>
      <div id="second" hidden>Other navigation</div></nav><section id="detail" hidden>Service status</section></main>'''
    async with navigation_page(body) as page:
        result = await expand_safe_navigation(page, 5, maximum_scrolls=0)
        detail = next(route for route in result["routes"] if route.label == "Service details")
        assert detail.navigation_hierarchy == ("Overview menu",)
        assert not await page.locator("#first").is_visible()
        await activate_ui_view(page, detail.view_control, 1000)
        assert await page.locator("#detail").is_visible()
        assert await page.evaluate("window.calls") == 1


@pytest.mark.asyncio
async def test_nested_shadow_hosts_with_equal_panel_ids_keep_distinct_view_identities():
    body = '''<main><portal-menu></portal-menu></main><script>
      const outer=document.querySelector('portal-menu').attachShadow({mode:'open'});
      outer.innerHTML='<portal-view></portal-view><portal-view></portal-view>';
      outer.querySelectorAll('portal-view').forEach((host,index) => {
        const root=host.attachShadow({mode:'open'});
        root.innerHTML='<button role="tab" aria-controls="detail" aria-selected="false">Reports</button>'+
          '<section id="detail" hidden>Read-only report '+index+'</section>';
        root.querySelector('button').onclick=()=>{root.querySelector('#detail').hidden=false;
          root.querySelector('button').setAttribute('aria-selected','true');};
      });</script>'''
    async with navigation_page(body) as page:
        views = [route for route in await discover_page_routes(page, 0) if route.view_control]
        assert len(views) == 2
        assert len({discovered_route_key(route, route.url) for route in views}) == 2
        await activate_ui_view(page, views[1].view_control, 1000)
        panels = page.locator('portal-view section')
        assert not await panels.nth(0).is_visible()
        assert await panels.nth(1).is_visible()


@pytest.mark.asyncio
async def test_shadow_control_inside_form_is_never_discovered_or_activated():
    body = '''<main><form><nav><portal-menu></portal-menu></nav></form></main><script>
      const root=document.querySelector('portal-menu').attachShadow({mode:'open'});
      root.innerHTML='<button role="tab" aria-controls="detail" aria-selected="false">Reports</button>'+
        '<section id="detail" hidden>Read-only report</section>';
      root.querySelector('button').onclick=()=>window.wrong=true;</script>'''
    async with navigation_page(body) as page:
        result = await expand_safe_navigation(page, 5, maximum_scrolls=0)
        assert result["routes"] == []
        assert result["activated"] == 0
        assert result["skipped"] == result["unresolved"] == 1
        assert not await page.evaluate("Boolean(window.wrong)")


@pytest.mark.asyncio
@pytest.mark.parametrize("shadow", [False, True])
async def test_two_level_sibling_panels_retain_the_openers_full_observed_hierarchy(shadow):
    markup = '''<nav>
      <button aria-expanded="false" aria-controls="sections" onclick="this.setAttribute('aria-expanded','true');
        this.getRootNode().querySelector('#sections').hidden=false">Services</button>
      <div id="sections" hidden><button aria-expanded="false" aria-controls="links"
        onclick="this.setAttribute('aria-expanded','true');this.getRootNode().querySelector('#links').hidden=false"
        >Reports menu</button></div>
      <div id="links" hidden><a href="/reports">Service reports</a></div></nav>'''
    body = "<main>" + markup + "</main>"
    if shadow:
        body = """<main><portal-shell></portal-shell></main><script>
          const shell=document.querySelector('portal-shell').attachShadow({mode:'open'});
          shell.innerHTML='<portal-navigation></portal-navigation>';
          const navigation=shell.querySelector('portal-navigation').attachShadow({mode:'open'});
          navigation.innerHTML=""" + repr(markup) + ";</script>"
    async with navigation_page(body) as page:
        result = await expand_safe_navigation(page, 2, maximum_scrolls=0)
        report = next(route for route in result["routes"] if route.label == "Service reports")
        assert report.navigation_hierarchy == ("Services", "Reports menu")
        assert result["activated"] == 2
        assert result["remaining"] == 0
