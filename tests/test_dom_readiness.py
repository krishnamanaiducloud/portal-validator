"""Microfrontend DOM changes must invalidate the configured stability window."""
import asyncio
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from app import health


@pytest.mark.asyncio
async def test_navigation_dom_substitution_resets_stability_even_with_unchanged_counts(monkeypatch):
    clock = 0.0
    captures = 0
    real_sleep = asyncio.sleep

    async def capture(_page):
        nonlocal captures
        captures += 1
        return {
            "ready_state": "complete", "title": "Workspace", "text_length": 40,
            "visible_elements": 5, "busy_indicators": 0, "challenge_indicators": 0,
            "alert_text": "", "dom_generation": int(captures >= 3),
        }

    async def advance(delay):
        nonlocal clock
        clock += delay
        await real_sleep(0)

    monkeypatch.setattr(health.time, "perf_counter", lambda: clock)
    monkeypatch.setattr(health, "capture_render_health", capture)
    monkeypatch.setattr(health.asyncio, "sleep", advance)
    snapshot = await health.wait_for_render_settle(
        object(), settle_ms=150, maximum_ms=1000,
        minimum_observation_ms=0, network_quiet_ms=0,
    )
    assert captures >= 5
    assert snapshot["settle_reason"] == "DOM_AND_NETWORK_QUIET"
    assert snapshot["dom_generation"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("attribute", ["href", "data-route", "aria-label"])
async def test_render_health_observes_navigation_changes_inside_open_shadow_root(attribute):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content('''<portal-shell></portal-shell><script>
              document.querySelector('portal-shell').attachShadow({mode:'open'}).innerHTML=
                '<main><h1>Generic navigation workspace</h1><nav><a href="#/old">Open view</a></nav></main>';
            </script>''')
            before = await health.capture_render_health(page)
            await page.locator("portal-shell a").evaluate(
                "(element, attribute) => element.setAttribute(attribute,'#/new')", attribute,
            )
            after = await health.capture_render_health(page)
            assert after["text_length"] == before["text_length"]
            assert after["visible_elements"] == before["visible_elements"]
            assert after["dom_generation"] > before["dom_generation"]
        finally:
            await browser.close()


@pytest.mark.asyncio
async def test_animation_styles_do_not_manufacture_navigation_activity():
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed")
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content('<main><h1>Read-only application workspace</h1><a href="#/view">View</a></main>')
            before = await health.capture_render_health(page)
            await page.locator("main").evaluate("element => element.style.setProperty('--animation-progress','0.1')")
            after = await health.capture_render_health(page)
            assert after["dom_generation"] == before["dom_generation"]
        finally:
            await browser.close()
