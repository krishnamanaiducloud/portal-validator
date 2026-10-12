import pytest

from app.browser_lifecycle import BrowserLifecycle
from app.main import ScanRequest


def test_explicit_browser_lifecycle_records_ordered_safe_stages():
    lifecycle = BrowserLifecycle()
    for stage in (
        "INITIAL_NAVIGATION", "AUTHENTICATING", "SESSION_ESTABLISHED",
        "APPLICATION_BOOTSTRAP", "APPLICATION_READY", "ROUTE_DISCOVERY", "ROUTE_VALIDATION", "REPORT",
    ):
        lifecycle.advance(stage)
    snapshot = lifecycle.snapshot()
    assert snapshot["state"] == "REPORT"
    assert snapshot["failed_stage"] is None
    assert [item["elapsed_ms"] for item in snapshot["events"]] == sorted(item["elapsed_ms"] for item in snapshot["events"])
    snapshot["events"].clear()
    assert lifecycle.events, "Report snapshots cannot mutate running evidence"


def test_authentication_failure_cannot_claim_application_readiness():
    lifecycle = BrowserLifecycle()
    lifecycle.advance("INITIAL_NAVIGATION")
    lifecycle.advance("AUTHENTICATING")
    lifecycle.fail("AUTHENTICATION_BLOCKED")
    lifecycle.advance("SESSION_ESTABLISHED")
    assert lifecycle.state == "AUTHENTICATING"
    lifecycle.advance("REPORT")
    assert lifecycle.snapshot()["failed_stage"] == "AUTHENTICATING"
    assert lifecycle.snapshot()["failure_reason"] == "AUTHENTICATION_BLOCKED"
    assert "APPLICATION_READY" not in [item["state"] for item in lifecycle.events]


def test_impossible_healthy_transition_and_sensitive_failure_reason_are_rejected():
    lifecycle = BrowserLifecycle()
    with pytest.raises(ValueError, match="Invalid browser lifecycle transition"):
        lifecycle.advance("APPLICATION_READY")
    with pytest.raises(ValueError, match="safe classification"):
        lifecycle.fail("https://portal.example/?token=secret")


def test_navigation_action_limit_is_configurable_without_hidden_fifty_cap():
    assert ScanRequest(target="portal.example").max_navigation_actions == 20
    assert ScanRequest(target="portal.example", max_navigation_actions=1500).max_navigation_actions == 1500
    with pytest.raises(ValueError):
        ScanRequest(target="portal.example", max_navigation_actions=1501)


@pytest.mark.asyncio
async def test_discovery_honors_navigation_action_limit_above_fifty(monkeypatch):
    from app import discovery

    async def routes(*_args):
        return []

    async def expand(*_args, **_kwargs):
        return {"activated": 1, "inspected": 1, "menus_expanded": 1}

    async def inspect(*_args):
        return {"remaining": 1}

    monkeypatch.setattr(discovery, "discover_page_routes", routes)
    monkeypatch.setattr(discovery, "_expand_one_menu", expand)
    monkeypatch.setattr(discovery, "evaluate_dom", inspect)
    result = await discovery.expand_safe_navigation(object(), 51)
    assert result["activated"] == 51
    assert result["menus_expanded"] == 51
    assert result["limit_reached"] is True


@pytest.mark.asyncio
async def test_open_shadow_application_readiness_and_busy_evidence():
    from pathlib import Path
    from playwright.async_api import async_playwright
    from app.health import application_shell_ready, capture_render_health

    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content('<portal-shell></portal-shell><script>document.querySelector("portal-shell")'
                                   '.attachShadow({mode:"open"}).innerHTML=`<main><h1>Component application</h1>'
                                   '<p>Rendered independent application content.</p>'
                                   '<nav><a href="#/overview">Overview</a></nav></main>`;</script>')
            snapshot = await capture_render_health(page)
            assert snapshot["text_length"] >= 20
            assert snapshot["visible_elements"] >= 3
            assert application_shell_ready(snapshot)
            await page.locator("portal-shell main").evaluate("element => element.setAttribute('aria-busy','true')")
            assert not application_shell_ready(await capture_render_health(page))
        finally:
            await browser.close()
