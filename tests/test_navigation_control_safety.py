from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from playwright.async_api import Locator, TimeoutError as PlaywrightTimeoutError, async_playwright

from app.discovery import (
    SEMANTIC_LINK_NAVIGATION,
    UI_VIEW_ACTIVATION,
    activate_semantic_route,
    activate_ui_view,
    discover_page_routes,
    expand_safe_navigation,
    perform_route_navigation,
    safe_navigation_control,
)


def _tab(label, **overrides):
    return {
        "role": "tab",
        "aria_selected": "false",
        "aria_controls": "details-panel",
        "text": label,
        "inside_form": "false",
        "disabled": "false",
        "href": None,
        **overrides,
    }


@pytest.mark.parametrize("label", [
    "Address book",
    "Credit reports",
    "Status",
    "Senders",
    "Importantly reviewed",
    "Editorial overview",
    "Restarted services overview",
    "AddressBook",
    "CreditReports",
    "HTTPStatus",
])
def test_navigation_control_does_not_treat_embedded_action_substrings_as_actions(label):
    assert safe_navigation_control(_tab(label))


@pytest.mark.parametrize("label", [
    "Delete account",
    "Send payment",
    "Start deployment",
    "Sign out",
    "SIGN OUT",
    "Sign-out",
    "Delete/account",
    "Create report",
    "Export records",
    "Stop service",
    "DeleteAccount",
    "DeleteALL",
    "DELETEAccount",
    "RemoveUsers",
    "ExportRecords",
    "HTTPRequestDeleteAccount",
])
def test_navigation_control_still_rejects_explicit_mutating_action_tokens(label):
    assert not safe_navigation_control(_tab(label))


@pytest.mark.parametrize("overrides", [
    {"inside_form": "true"},
    {"disabled": "true"},
    {"href": "/reports"},
    {"role": "button", "aria_controls": None},
])
def test_safe_label_does_not_override_existing_control_security_boundaries(overrides):
    assert not safe_navigation_control(_tab("Address book", **overrides))


def test_dangerous_accessible_name_is_not_hidden_by_benign_visible_text():
    assert not safe_navigation_control(_tab("Reports", aria_label="Delete account"))


def test_dangerous_title_is_not_hidden_by_benign_visible_text():
    assert not safe_navigation_control(_tab("Reports", title="Send payment"))


@asynccontextmanager
async def _local_page(body):
    """Browser evidence with all requests fulfilled locally, never an external scan."""
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.route("**/*", lambda route: route.fulfill(
                content_type="text/html", body=body,
            ))
            await page.goto("https://portal.example/")
            yield page
        finally:
            await browser.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("hidden_attributes", [
    "hidden",
    "inert",
    'aria-hidden="true"',
    'style="display:none"',
    'style="visibility:hidden"',
])
async def test_ui_view_discovery_does_not_queue_hidden_template_tabs(hidden_attributes):
    body = f'''<main>
      <div {hidden_attributes}>
        <button role="tab" aria-controls="hidden-panel" aria-selected="false">Template</button>
      </div>
      <button role="tab" aria-controls="reports-panel" aria-selected="false">Reports</button>
      <section id="hidden-panel" hidden>Template contents</section>
      <section id="reports-panel" hidden>Report contents</section>
    </main>'''
    async with _local_page(body) as page:
        routes = await discover_page_routes(page, 0)
        views = [route for route in routes if route.view_control]
        assert [route.label for route in views] == ["Reports"]


@pytest.mark.asyncio
async def test_ui_view_discovery_does_not_duplicate_initially_selected_panel():
    body = '''<main>
      <button role="tab" aria-controls="initial-panel" aria-selected="true">Overview</button>
      <button role="tab" aria-controls="reports-panel" aria-selected="false">Reports</button>
      <section id="initial-panel">Overview contents</section>
      <section id="reports-panel" hidden>Report contents</section>
    </main>'''
    async with _local_page(body) as page:
        for _ in range(2):
            routes = await discover_page_routes(page, 0)
            assert [route.label for route in routes if route.view_control] == ["Reports"]


@pytest.mark.asyncio
async def test_hidden_selected_template_cannot_mark_a_visible_view_as_the_baseline():
    body = '''<main>
      <div hidden><button role="tab" aria-controls="reports-panel" aria-selected="true">Template</button></div>
      <button role="tab" aria-controls="reports-panel" aria-selected="false">Reports</button>
      <section id="reports-panel" hidden>Report contents</section>
    </main>'''
    async with _local_page(body) as page:
        routes = await discover_page_routes(page, 0)
        assert [route.label for route in routes if route.view_control] == ["Reports"]


@pytest.mark.asyncio
async def test_browser_safety_filters_keep_camelcase_action_boundaries():
    body = '''<main><nav>
      <button role="menuitem" aria-expanded="false" aria-controls="dangerous-panel"
        onclick="window.actions.push('DeleteAccount')">DeleteAccount</button>
      <button role="menuitem" aria-expanded="false" aria-controls="dangerous-panel"
        onclick="window.actions.push('DELETEAccount')">DELETEAccount</button>
      <button role="menuitem" aria-expanded="false" aria-controls="reports-panel"
        onclick="window.actions.push('CreditReports');this.setAttribute('aria-expanded','true')">CreditReports</button>
      <a href="/dangerous-action" onclick="event.preventDefault();window.actions.push('DeleteALL')">DeleteALL</a>
      <a href="/reports" onclick="event.preventDefault();window.actions.push('AddressBook')">AddressBook</a>
      </nav><section id="dangerous-panel"></section><section id="reports-panel">Report contents</section>
      <script>window.actions=[]</script></main>'''
    async with _local_page(body) as page:
        result = await expand_safe_navigation(page, 10, maximum_scrolls=0)
        assert result["activated"] == 1
        assert await page.evaluate("window.actions") == ["CreditReports"]
        assert not await activate_semantic_route(
            page, "https://portal.example/dangerous-action", label="DeleteALL", source="a", timeout_ms=1500,
        )
        assert await activate_semantic_route(
            page, "https://portal.example/reports", label="AddressBook", source="a", timeout_ms=1500,
        )
        assert await page.evaluate("window.actions") == ["CreditReports", "AddressBook"]


@pytest.mark.asyncio
async def test_noop_tab_does_not_pass_because_its_panel_was_already_visible():
    body = '''<main>
      <button role="tab" aria-controls="reports-panel" aria-selected="false"
        onclick="window.activations=(window.activations||0)+1">Reports</button>
      <section id="reports-panel">Always visible report contents</section>
    </main>'''
    async with _local_page(body) as page:
        with pytest.raises((RuntimeError, PlaywrightTimeoutError)):
            await activate_ui_view(
                # Allow click dispatch on a contended browser test runner; the
                # unchanged assertions still require the no-op to fail once.
                page, {"panel": "reports-panel", "label": "Reports"}, 5000,
            )
        assert await page.evaluate("window.activations") == 1


@pytest.mark.asyncio
async def test_tab_requires_real_selected_state_or_revealed_panel_evidence():
    body = '''<main>
      <button role="tab" aria-controls="reports-panel" aria-selected="false"
        onclick="this.setAttribute('aria-selected','true');document.querySelector('#reports-panel').hidden=false;window.activations=(window.activations||0)+1">Reports</button>
      <section id="reports-panel" hidden>Report contents</section>
    </main>'''
    async with _local_page(body) as page:
        response, transitioned, method = await perform_route_navigation(
            page, "https://portal.example/", UI_VIEW_ACTIVATION, 1000,
            view_control={"panel": "reports-panel", "label": "Reports"},
        )
        assert response is None
        assert transitioned
        assert method == "UI_TAB_CONTROL"
        assert await page.evaluate("window.activations") == 1


@pytest.mark.asyncio
async def test_ambiguous_visible_tab_controls_fail_without_dispatching_a_click():
    body = '''<main>
      <button role="tab" aria-controls="reports-panel" aria-selected="false"
        onclick="window.activations=(window.activations||0)+1">Reports</button>
      <button role="tab" aria-controls="reports-panel" aria-selected="false"
        onclick="window.activations=(window.activations||0)+1">Reports</button>
      <section id="reports-panel" hidden>Report contents</section>
    </main>'''
    async with _local_page(body) as page:
        with pytest.raises(RuntimeError, match="uniquely"):
            await activate_ui_view(
                page, {"panel": "reports-panel", "label": "Reports"}, 1500,
            )
        assert await page.evaluate("window.activations || 0") == 0


@pytest.mark.asyncio
async def test_noop_semantic_navigation_does_not_fabricate_route_transition_or_repeat_post():
    body = '''<main>
      <a href="/reports" onclick="event.preventDefault();window.activations=(window.activations||0)+1;fetch('/api/read',{method:'POST'})">Reports</a>
      <a href="/reports" onclick="event.preventDefault();window.activations=(window.activations||0)+1;fetch('/api/read',{method:'POST'})">Reports</a>
    </main>'''
    async with _local_page(body) as page:
        post_requests = []
        report_documents = []

        def observe(request):
            if request.method == "POST":
                post_requests.append(request.url)
            if request.is_navigation_request() and request.url.endswith("/reports"):
                report_documents.append(request.url)

        page.on("request", observe)
        with pytest.raises((RuntimeError, PlaywrightTimeoutError)):
            await perform_route_navigation(
                page, "https://portal.example/reports", SEMANTIC_LINK_NAVIGATION, 1500,
                label="Reports", source="a",
            )
        assert page.url == "https://portal.example/"
        assert await page.evaluate("window.activations") == 1
        assert post_requests == ["https://portal.example/api/read"]
        assert report_documents == []


@pytest.mark.asyncio
async def test_semantic_click_failure_after_dispatch_does_not_retry_another_control(monkeypatch):
    body = '''<main>
      <a href="/reports" onclick="event.preventDefault();window.activations=(window.activations||0)+1;fetch('/api/read',{method:'POST'}).finally(()=>window.completed=true)">Reports</a>
      <a href="/reports" onclick="event.preventDefault();window.activations=(window.activations||0)+1;fetch('/api/read',{method:'POST'}).finally(()=>window.completed=true)">Reports</a>
    </main>'''
    async with _local_page(body) as page:
        post_requests = []
        page.on("request", lambda request: post_requests.append(request.url) if request.method == "POST" else None)
        real_click = Locator.click

        async def dispatched_click_then_timeout(locator, *args, **kwargs):
            await real_click(locator, *args, **kwargs)
            await page.wait_for_function("window.completed === true", timeout=1000)
            raise PlaywrightTimeoutError("fixture deadline after real browser click dispatch")

        monkeypatch.setattr(Locator, "click", dispatched_click_then_timeout)
        with pytest.raises(PlaywrightTimeoutError, match="after real browser click dispatch"):
            await perform_route_navigation(
                page, "https://portal.example/reports", SEMANTIC_LINK_NAVIGATION, 1500,
                label="Reports", source="a",
            )
        assert page.url == "https://portal.example/"
        assert await page.evaluate("window.activations") == 1
        assert post_requests == ["https://portal.example/api/read"]
