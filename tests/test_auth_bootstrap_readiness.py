"""Authentication bootstrap observes actual readiness, not a redirect quiet window."""

import asyncio
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from playwright.async_api import Error as PlaywrightError, async_playwright

from app.navigation import AuthenticationObservationCancelled, settle_authentication_navigation


class ObservedPage:
    def __init__(self, url="https://portal.example/"):
        self.url = url
        self.main_frame = object()
        self.listeners = defaultdict(list)
        self.ready = False
        self.password = self.mfa = False
        self.loads = 0

    def on(self, event, callback):
        self.listeners[event].append(callback)

    def remove_listener(self, event, callback):
        self.listeners[event].remove(callback)

    def navigate(self, url):
        self.url = url
        for callback in tuple(self.listeners["framenavigated"]):
            callback(self.main_frame)

    async def evaluate(self, _script):
        return False

    async def wait_for_load_state(self, state, *, timeout):
        assert state == "domcontentloaded" and timeout > 0
        self.loads += 1


async def detect_signals(page):
    return page.password, page.mfa


async def application_ready(page):
    return page.ready


async def settle(page, **options):
    arguments = dict(
        in_portal_scope=lambda url: url.startswith("https://portal.example/"),
        detect_signals=detect_signals, timeout_ms=2000,
    )
    arguments.update(options)
    return await settle_authentication_navigation(page, **arguments)


def assert_listeners_removed(page):
    assert not any(page.listeners.values())


@pytest.mark.asyncio
async def test_legacy_caller_without_readiness_predicate_keeps_immediate_application_result():
    page = ObservedPage()
    result = await settle(page)
    assert result["stage"] == "APPLICATION" and result["completed"]
    assert result["elapsed_ms"] < 750
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_configured_readiness_is_not_assumed_after_a_quiet_window():
    page = ObservedPage()
    result = await settle(page, application_ready=application_ready, timeout_ms=900)
    assert result["stage"] == "APPLICATION_BOOTSTRAP_PENDING"
    assert result["timed_out"] and not result["completed"]
    assert result["elapsed_ms"] >= 850
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_late_bootstrap_redirect_observes_multiple_approved_identity_hosts_before_ready():
    page = ObservedPage()
    visited = []

    async def flow():
        # This deliberately occurs after the old proposed 750 ms quiet window.
        await asyncio.sleep(0.85)
        for url in (
            "https://identity-one.example/authorize",
            "https://identity-two.example/saml/continue",
            "https://portal.example/callback?code=private-fixture-code&state=private-fixture-state",
            "https://portal.example/workspace",
        ):
            visited.append(url)
            page.navigate(url)
            await asyncio.sleep(0.025)
        page.ready = True

    task = asyncio.create_task(flow())
    try:
        result = await settle(
            page, application_ready=application_ready,
            is_approved_authentication_host=lambda host: host in {
                "identity-one.example", "identity-two.example",
            },
        )
    finally:
        await task
    assert len(visited) == 4
    assert result["stage"] == "APPLICATION" and result["completed"]
    assert result["elapsed_ms"] > 750
    assert result["final_host"] == "portal.example"
    assert "private-fixture" not in str(result)
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_redirect_loop_is_bounded_by_authentication_deadline():
    page = ObservedPage("https://identity-one.example/authorize")

    async def loop():
        while True:
            page.navigate("https://identity-two.example/saml/continue")
            await asyncio.sleep(0.01)
            page.navigate("https://identity-one.example/authorize")
            await asyncio.sleep(0.01)

    task = asyncio.create_task(loop())
    try:
        result = await settle(
            page, application_ready=application_ready, timeout_ms=120,
            is_approved_authentication_host=lambda host: host in {
                "identity-one.example", "identity-two.example",
            },
        )
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert result["stage"] == "AUTHENTICATION_PENDING" and result["timed_out"]
    assert not result["completed"] and result["elapsed_ms"] < 1000
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_unapproved_non_protocol_cross_origin_never_becomes_application():
    page = ObservedPage("https://unrelated.example/analytics")
    page.ready = True
    result = await settle(page, application_ready=application_ready, flow_active=True)
    assert result["stage"] == "OUTSIDE_PORTAL" and not result["completed"]
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_readiness_snapshot_retries_same_url_document_replacement():
    page = ObservedPage()
    calls = 0

    async def ready(current):
        nonlocal calls
        calls += 1
        if calls == 1:
            # A same-URL reload must not combine old DOM readiness with a new document.
            current.navigate(current.url)
            return True
        return True

    result = await settle(page, application_ready=ready)
    assert result["completed"] and calls == 2 and page.loads == 1
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_readiness_predicate_retries_transient_context_replacement_only():
    page = ObservedPage()
    calls = 0

    async def ready(_page):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PlaywrightError("Execution context was destroyed, most likely because of a navigation")
        return True

    result = await settle(page, application_ready=ready)
    assert result["completed"] and calls == 2 and page.loads == 1
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_persistent_unrelated_readiness_failure_is_not_swallowed():
    page = ObservedPage()

    async def ready(_page):
        raise PlaywrightError("unexpected readiness evaluation failure")

    with pytest.raises(PlaywrightError, match="unexpected readiness evaluation failure"):
        await settle(page, application_ready=ready)
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_slow_readiness_predicate_obeys_same_bootstrap_deadline():
    page = ObservedPage()

    async def ready(_page):
        await asyncio.sleep(10)
        return True

    result = await settle(page, application_ready=ready, timeout_ms=100)
    assert result["stage"] == "APPLICATION_BOOTSTRAP_PENDING" and result["timed_out"]
    assert not result["completed"] and result["elapsed_ms"] < 1000
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_bootstrap_readiness_uses_its_separate_configured_budget():
    page = ObservedPage()
    result = await settle(
        page, application_ready=application_ready, timeout_ms=5000,
        application_readiness_timeout_ms=100,
    )
    assert result["stage"] == "APPLICATION_BOOTSTRAP_PENDING" and result["timed_out"]
    assert not result["completed"] and result["elapsed_ms"] < 1000
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_short_application_readiness_budget_does_not_truncate_identity_redirects():
    page = ObservedPage("https://identity-one.example/authorize")

    async def flow():
        await asyncio.sleep(0.2)
        page.navigate("https://identity-two.example/saml/continue")
        await asyncio.sleep(0.2)
        page.ready = True
        page.navigate("https://portal.example/workspace")

    task = asyncio.create_task(flow())
    try:
        result = await settle(
            page, application_ready=application_ready, timeout_ms=2000,
            application_readiness_timeout_ms=50,
            is_approved_authentication_host=lambda host: host in {
                "identity-one.example", "identity-two.example",
            },
        )
    finally:
        await task
    assert result["completed"] and result["stage"] == "APPLICATION"
    assert result["elapsed_ms"] >= 350
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_new_authentication_redirect_resets_only_application_readiness_budget():
    page = ObservedPage()

    async def flow():
        await asyncio.sleep(0.05)
        page.navigate("https://identity-one.example/authorize")
        await asyncio.sleep(0.15)
        page.navigate("https://portal.example/workspace")
        await asyncio.sleep(0.05)
        page.ready = True

    task = asyncio.create_task(flow())
    try:
        result = await settle(
            page, application_ready=application_ready, timeout_ms=2000,
            application_readiness_timeout_ms=100,
            is_approved_authentication_host=lambda host: host == "identity-one.example",
        )
    finally:
        await task
    assert result["completed"] and result["elapsed_ms"] >= 200
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_cancel_event_interrupts_readiness_and_cleans_up_listeners():
    page = ObservedPage()
    cancel = asyncio.Event()
    inspecting = asyncio.Event()
    inspection_stopped = asyncio.Event()

    async def ready(_page):
        inspecting.set()
        try:
            await asyncio.sleep(10)
        finally:
            inspection_stopped.set()
        return True

    task = asyncio.create_task(settle(page, application_ready=ready, cancel_event=cancel))
    await inspecting.wait()
    cancel.set()
    with pytest.raises(AuthenticationObservationCancelled):
        await asyncio.wait_for(task, 1)
    assert inspection_stopped.is_set()
    assert_listeners_removed(page)


@pytest.mark.asyncio
@pytest.mark.parametrize("simultaneous_event", [False, True])
async def test_external_task_cancellation_remains_distinct_from_user_cancel_event(simultaneous_event):
    page = ObservedPage()
    inspecting = asyncio.Event()
    cancel = asyncio.Event()

    async def ready(_page):
        inspecting.set()
        await asyncio.sleep(10)
        return True

    task = asyncio.create_task(settle(page, application_ready=ready, cancel_event=cancel))
    await inspecting.wait()
    if simultaneous_event:
        cancel.set()
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as error:
        await task
    assert type(error.value) is asyncio.CancelledError
    assert_listeners_removed(page)


@pytest.mark.asyncio
async def test_http_failure_does_not_wait_for_application_readiness():
    page = ObservedPage()

    async def ready(_page):
        raise AssertionError("An HTTP failure is already definitive")

    result = await settle(page, application_ready=ready, status=502)
    assert result["stage"] == "HTTP_ERROR" and not result["completed"]
    assert_listeners_removed(page)


@asynccontextmanager
async def browser_page():
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
        browser = await playwright.chromium.launch(headless=True)
        try:
            yield await browser.new_page()
        finally:
            await browser.close()


@pytest.mark.asyncio
async def test_real_browser_delayed_redirect_waits_for_actual_microfrontend_readiness():
    documents = {
        "https://portal.example/": """<main aria-busy="true">Starting application</main>
          <script>setTimeout(() => location.href='https://identity-one.example/authorize', 900)</script>""",
        "https://identity-one.example/authorize": """<main>Processing authentication</main>
          <script>setTimeout(() => location.href='https://identity-two.example/saml/continue', 30)</script>""",
        "https://identity-two.example/saml/continue": """<main>Processing federation callback</main>
          <script>setTimeout(() => location.href='https://portal.example/workspace', 30)</script>""",
        "https://portal.example/workspace": """<main aria-busy="true">Loading remote workspace</main>
          <script>setTimeout(() => {document.querySelector('main').outerHTML =
            '<main data-workspace-ready>Workspace loaded<nav><a href="/#/reports">Reports</a></nav></main>'}, 250)</script>""",
    }
    async with browser_page() as page:
        await page.route("**/*", lambda route: route.fulfill(
            content_type="text/html", body=documents[route.request.url],
        ))
        await page.goto("https://portal.example/", wait_until="domcontentloaded")
        visited = []
        page.on("framenavigated", lambda frame: visited.append(frame.url) if frame == page.main_frame else None)
        async def ready(current):
            return await current.locator("[data-workspace-ready]").count() > 0

        result = await settle_authentication_navigation(
            page, in_portal_scope=lambda url: url.startswith("https://portal.example/"),
            detect_signals=lambda current: current.evaluate("() => [false, false]"),
            application_ready=ready, timeout_ms=8000,
            is_approved_authentication_host=lambda host: host in {
                "identity-one.example", "identity-two.example",
            },
        )
        assert result["stage"] == "APPLICATION" and result["completed"]
        assert result["elapsed_ms"] > 750
        assert page.url == "https://portal.example/workspace"
        assert visited == [
            "https://identity-one.example/authorize", "https://identity-two.example/saml/continue",
            "https://portal.example/workspace",
        ]
        assert await page.locator('a[href="/#/reports"]').count() == 1
