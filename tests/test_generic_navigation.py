"""Cross-framework navigation regression: no portal or identity-provider assumptions."""

from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from app.discovery import (
    UI_VIEW_ACTIVATION,
    activate_ui_view,
    discover_page_routes,
    expand_safe_navigation,
)


PORTAL_HTML = """<!doctype html>
<html><head><title>Synthetic portal</title></head>
<body>
<nav aria-label="Main navigation">
  <details id="native-menu">
    <summary>Analytics</summary>
    <a href="#/analytics/overview">Overview</a>
    <a href="#/analytics/detailed">Details</a>
  </details>
  <div class="dropdown">
    <button id="dropdown-toggle" type="button" data-bs-toggle="dropdown"
      onclick="document.getElementById('dynamic-menu').hidden=false;this.setAttribute('aria-expanded','true')"
      aria-expanded="false">Operations</button>
    <div id="dynamic-menu" class="dropdown-menu" hidden>
      <a href="#/operations/audit">Audit</a>
      <a href="#/operations/queue">Queue</a>
    </div>
  </div>
</nav>
<section aria-label="Main workspace">
  <div role="tablist" aria-label="Workspace tabs">
    <button type="button" role="tab" id="overview-tab"
      aria-controls="overview-panel" aria-selected="true">Overview</button>
    <button type="button" role="tab" id="insights-tab"
      aria-controls="insights-panel" aria-selected="false"
      onclick="document.getElementById('insights-panel').hidden=false;this.setAttribute('aria-selected','true')">Insights</button>
  </div>
  <div role="tabpanel" id="overview-panel">Home view</div>
  <div role="tabpanel" id="insights-panel" hidden>
    <div role="tablist" aria-label="Insights subtabs">
      <button type="button" role="tab" id="snapshot-tab"
        aria-controls="snapshot-panel" aria-selected="true">Snapshot</button>
      <button type="button" role="tab" id="history-tab"
        aria-controls="history-panel" aria-selected="false"
        onclick="document.getElementById('history-panel').hidden=false;this.setAttribute('aria-selected','true')">History</button>
    </div>
    <div role="tabpanel" id="snapshot-panel">Snapshot data</div>
    <div role="tabpanel" id="history-panel" hidden>History data</div>
  </div>
</section>
<details id="unsafe-control">
  <summary>Delete Account</summary>
  <a href="#/delete/account">Dangerous action</a>
</details>
</body></html>"""


@pytest.mark.asyncio
async def test_generic_disclosure_dropdown_and_nested_tabs_are_discovered():
    """Menu expansion must expose real destinations without executing form actions."""
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            async def serve_portal(route):
                await route.fulfill(status=200, content_type="text/html", body=PORTAL_HTML)

            await page.route("https://portal.test/**", serve_portal)
            await page.goto("https://portal.test/")
            initial = await discover_page_routes(page, 0)
            assert any(route.label == "Insights" and route.navigation_mode == UI_VIEW_ACTIVATION
                       for route in initial)
            expanded = await expand_safe_navigation(
                page, 12, timeout_ms=4500, maximum_scrolls=0,
            )
            paths = {route.url for route in expanded["routes"]}
            for fragment in ("#/analytics/overview", "#/analytics/detailed",
                             "#/operations/audit", "#/operations/queue"):
                assert any(value.endswith(fragment) for value in paths), (fragment, paths)
            assert await page.locator("#native-menu").get_attribute("open") is not None
            assert not await page.locator("#dynamic-menu").is_hidden()
            assert await page.locator("#unsafe-control").get_attribute("open") is None
            assert expanded["menus_expanded"] >= 2

            insights = next(route for route in initial if route.label == "Insights")
            await activate_ui_view(page, insights.view_control, 5000)
            subviews = await discover_page_routes(page, 0)
            history = next(route for route in subviews if route.label == "History")
            assert history.navigation_mode == UI_VIEW_ACTIVATION
            await activate_ui_view(page, history.view_control, 5000)
            assert await page.locator("#history-panel").is_visible()
        finally:
            await browser.close()
