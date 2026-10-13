"""Generic lazy Material/CDK and semantic nested-tab regressions."""
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from playwright.async_api import TimeoutError as PlaywrightTimeoutError, async_playwright

from app.discovery import activate_ui_view, discover_page_routes, expand_safe_navigation


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [TimeoutError, PlaywrightTimeoutError])
async def test_view_control_timeout_race_preserves_safe_failure_contract(monkeypatch, error):
    import app.discovery as discovery
    monkeypatch.setattr(discovery, "retry_dom_operation", AsyncMock(side_effect=error("deadline")))
    with pytest.raises(RuntimeError, match="not uniquely and safely activatable"):
        await activate_ui_view(object(), {"panel": "reports", "label": "Reports"}, 1000)


@asynccontextmanager
async def _page(body):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.route("**/*", lambda route: route.fulfill(content_type="text/html", body=body))
            await page.goto("https://portal.example/")
            yield page
        finally:
            await browser.close()


MATERIAL_MENUS = r'''<main><nav>
<button class="mat-menu-trigger" aria-haspopup="menu" onclick="openMenu(this,'Operations')">Operations</button>
<button class="mat-menu-trigger" aria-haspopup="menu" onclick="openMenu(this,'Insights')">Insights</button>
<button aria-haspopup="menu" onclick="window.unsafe++">Delete account</button>
</nav><div class="cdk-overlay-container"></div><section>Application shell</section></main>
<script>
window.opened=[];window.unsafe=0;
function openMenu(button,name) {
 window.opened.push(name);
 const overlay=document.querySelector('.cdk-overlay-container');
 if(name!=='Daily') overlay.replaceChildren();
 const panel=document.createElement('div');panel.setAttribute('role','menu');
 panel.className='mat-mdc-menu-panel';panel.id='generated-'+window.opened.length;
 button.setAttribute('aria-controls',panel.id);button.setAttribute('aria-expanded','true');
 panel.innerHTML=name==='Operations' ?
  '<button role="menuitem" aria-haspopup="menu" onclick="openMenu(this,\'Daily\')">Daily</button><a href="#/operations">Overview</a>' :
  name==='Daily' ? '<a href="#/daily/tasks">Tasks</a><button role="menuitem" onclick="window.unsafe++">Export records</button>' :
  '<a href="#/insights">Analytics</a>';
 overlay.append(panel);
}
</script>'''


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["document", "outside-nav", "shadow", "frame"])
async def test_dynamic_material_overlay_nested_menus_are_explored_before_other_top_levels(location):
    async with _page(MATERIAL_MENUS) as page:
        if location == "outside-nav":
            await page.evaluate("document.querySelector('nav').replaceWith(...document.querySelector('nav').childNodes)")
        elif location == "shadow":
            await page.evaluate("""() => {
              const nav=document.querySelector('nav'), host=document.createElement('portal-navigation');
              nav.replaceWith(host);host.attachShadow({mode:'open'}).append(nav);
            }""")
        elif location == "frame":
            async with page.expect_event("frameattached") as attached:
                await page.evaluate("""() => {
                  const frame=document.createElement('iframe');frame.name='navigation';frame.src='/frame';
                  document.querySelector('main').append(frame);
                }""")
            page = await attached.value
            await page.wait_for_url("https://portal.example/frame")
        base = page.url
        result = await expand_safe_navigation(page, 8, maximum_scrolls=0, timeout_ms=2000)
        routes = {route.url: route for route in result["routes"]}
        assert base + "#/daily/tasks" in routes
        assert routes[base + "#/daily/tasks"].navigation_hierarchy == ("Operations", "Daily")
        assert routes[base + "#/operations"].navigation_hierarchy == ("Operations",)
        assert routes[base + "#/insights"].navigation_hierarchy == ("Insights",)
        assert await page.evaluate("window.opened") == ["Operations", "Daily", "Insights"]
        assert await page.evaluate("window.unsafe") == 0


@pytest.mark.asyncio
async def test_overlay_without_aria_controls_uses_only_uniquely_new_menu_panel():
    body = MATERIAL_MENUS.replace("button.setAttribute('aria-controls',panel.id);", "")
    async with _page(body) as page:
        result = await expand_safe_navigation(page, 8, maximum_scrolls=0, timeout_ms=2000)
        tasks = next(route for route in result["routes"] if route.url.endswith("#/daily/tasks"))
        assert tasks.navigation_hierarchy == ("Operations", "Daily")
        assert await page.evaluate("window.unsafe") == 0


@pytest.mark.asyncio
async def test_cdk_backdrop_is_closed_with_escape_before_next_top_level_menu():
    body = MATERIAL_MENUS.replace("overlay.append(panel);", """
      overlay.append(panel);
      if(name!=='Daily') {
        const backdrop=document.createElement('div');backdrop.className='cdk-overlay-backdrop';
        backdrop.style.cssText='position:fixed;inset:0;background:transparent;z-index:9';
        overlay.prepend(backdrop);panel.style.cssText='position:relative;z-index:10';
      }
    """).replace("window.opened=[];", """
      document.addEventListener('keydown',event=>{
        if(event.key==='Escape') {
          document.querySelector('.cdk-overlay-container').replaceChildren();
          document.querySelectorAll('[aria-expanded]').forEach(e=>e.setAttribute('aria-expanded','false'));
        }
      });window.opened=[];
    """)
    async with _page(body) as page:
        result = await expand_safe_navigation(page, 8, maximum_scrolls=0, timeout_ms=2000)
        assert {route.label for route in result["routes"]} >= {"Tasks", "Overview", "Analytics"}
        assert await page.evaluate("window.opened") == ["Operations", "Daily", "Insights"]
        assert await page.evaluate("window.unsafe") == 0


@pytest.mark.asyncio
async def test_async_menu_panel_is_associated_after_configured_readiness_callback():
    body = MATERIAL_MENUS.replace("overlay.append(panel);", "setTimeout(()=>overlay.append(panel),30);")
    async with _page(body) as page:
        async def ready():
            await page.wait_for_function("document.querySelector('.cdk-overlay-container [role=menu]')", timeout=2000)
        result = await expand_safe_navigation(
            page, 8, maximum_scrolls=0, timeout_ms=2000, wait_after_action=ready,
        )
        tasks = next(route for route in result["routes"] if route.label == "Tasks")
        assert tasks.navigation_hierarchy == ("Operations", "Daily")


LAZY_TABS = '''<main><div role="tablist" aria-label="Report views">
<button role="tab" aria-selected="false" aria-controls="details" onclick="select(this)">Details</button>
<button role="tab" aria-selected="false" aria-controls="summary" onclick="select(this)">Summary</button>
<button aria-controls="missing" onclick="window.unsafe++">Unclassified operation</button>
</div><section id="content">Application shell</section></main>
<script>
window.actions=[];window.unsafe=0;
function select(button) {
 const id=button.getAttribute('aria-controls');window.actions.push(button.textContent);
 const region=button.closest('[role=tablist]');
 region.querySelectorAll('[role=tab]').forEach(tab=>tab.setAttribute('aria-selected',String(tab===button)));
 if(id==='timeline') {document.getElementById('timeline').hidden=false;return;}
 document.querySelectorAll('main>section[data-view]').forEach(panel=>panel.hidden=true);
 let panel=document.getElementById(id);
 if(!panel) {
  panel=document.createElement('section');panel.id=id;panel.dataset.view=id;
  panel.innerHTML=id==='details' ?
   '<h2>Details view</h2><div role="tablist" aria-label="Details views"><button role="tab" aria-selected="false" aria-controls="timeline" onclick="select(this)">Timeline</button></div><section id="timeline" hidden>Timeline contents</section>' : '<h2>Summary view</h2>';
  document.querySelector('main').append(panel);
 }
 panel.hidden=false;
}
</script>'''


@pytest.mark.asyncio
async def test_lazy_semantic_tab_is_discovered_and_verified_after_its_panel_is_created():
    async with _page(LAZY_TABS) as page:
        routes = await discover_page_routes(page, 0)
        assert {route.label for route in routes if route.view_control} == {"Details", "Summary"}
        details = next(route for route in routes if route.label == "Details")
        await activate_ui_view(page, details.view_control, 2000)
        assert await page.locator('#details').is_visible()
        assert await page.evaluate("window.actions") == ["Details"]
        assert await page.evaluate("window.unsafe") == 0


@pytest.mark.asyncio
async def test_nested_url_less_tab_restores_its_parent_after_sibling_view_activation():
    async with _page(LAZY_TABS) as page:
        routes = await discover_page_routes(page, 0)
        details = next(route for route in routes if route.label == "Details")
        summary = next(route for route in routes if route.label == "Summary")
        await activate_ui_view(page, details.view_control, 2000)
        nested = next(route for route in await discover_page_routes(page, 0) if route.label == "Timeline")
        assert nested.navigation_hierarchy == ("Details",)
        await activate_ui_view(page, summary.view_control, 2000)
        await activate_ui_view(page, nested.view_control, 2000)
        assert await page.locator('#timeline').is_visible()
        assert await page.evaluate("window.actions") == ["Details", "Summary", "Details", "Timeline"]
        assert await page.evaluate("window.unsafe") == 0
