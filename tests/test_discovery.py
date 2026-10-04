from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from playwright.async_api import async_playwright

from app.discovery import (
    DOCUMENT_NAVIGATION,
    SEMANTIC_LINK_NAVIGATION,
    HASH_ROUTE_TRANSITION,
    SAFE_CLICK_NAVIGATION,
    SPA_ROUTE_TRANSITION,
    ROUTE_OBSERVER_SCRIPT,
    discover_page_routes,
    navigation_mode_for_route,
    normalize_route_url,
    perform_route_navigation,
    safe_navigation_control,
)
from app.main import partition_links, url_in_scan_scope


@pytest.mark.parametrize(("value", "policy", "allowed", "expected"), [
    (
        "HTTPS://EXAMPLE.COM:443/products?utm_source=x&token=secret#section",
        "preserve",
        set(),
        "https://example.com/products",
    ),
    (
        "https://example.com/view?tab=health&id=123",
        "allowlist",
        {"tab"},
        "https://example.com/view?tab=health",
    ),
    (
        "https://example.com/app#/dashboard",
        "ignore",
        set(),
        "https://example.com/app#/dashboard",
    ),
    (
        "https://example.com/app#heading",
        "ignore",
        set(),
        "https://example.com/app",
    ),
])
def test_route_identity_normalization(value, policy, allowed, expected):
    assert normalize_route_url(
        value,
        query_policy=policy,
        allowed_query_parameters=allowed,
    ) == expected


def test_relative_and_invalid_route_normalization():
    assert normalize_route_url("../health", base_url="https://example.com/app/") == (
        "https://example.com/health"
    )
    assert normalize_route_url("javascript:alert(1)", base_url="https://example.com") is None
    assert normalize_route_url("file:///etc/passwd") is None
    assert normalize_route_url("https://user:secret@example.com/private") is None
    assert normalize_route_url("https://example.com/#/callback?code=secret") == "https://example.com/"


def test_duplicate_and_query_loop_routes_collapse():
    crawl, external = partition_links(
        [
            "https://example.com/items?page=1&utm_source=a",
            "https://example.com/items?page=2&utm_source=b",
            "https://example.com/items?page=3",
            "https://outside.example.net/",
        ],
        "example.com",
        False,
        query_parameter_policy="ignore",
    )
    assert crawl == ["https://example.com/items"]
    assert external == ["https://outside.example.net/"]


def test_explicit_portal_hosts_are_crawlable_without_broadening_subdomains():
    approved = {"app.example.net"}
    assert url_in_scan_scope("https://app.example.net/home", "example.com", False, approved)
    assert not url_in_scan_scope("https://api.example.net/home", "example.com", False, approved)
    assert not url_in_scan_scope("https://app.example.net.evil.test", "example.com", True, approved)


def test_only_semantic_non_form_controls_are_safe_to_expand():
    assert safe_navigation_control({
        "role": "button", "aria_expanded": "false", "aria_controls": "menu",
        "text": "Services", "inside_form": "false", "disabled": "false", "href": None,
    })
    assert safe_navigation_control({
        "role": "tab", "aria_selected": "false", "aria_controls": "panel",
        "text": "Health", "inside_form": "false", "disabled": "false", "href": None,
    })
    assert not safe_navigation_control({
        "role": "button", "aria_expanded": "false", "aria_controls": "menu",
        "text": "Delete account", "inside_form": "false", "disabled": "false", "href": None,
    })
    assert not safe_navigation_control({
        "role": "button", "aria_expanded": "false", "aria_controls": "menu",
        "text": "Menu", "inside_form": "true", "disabled": "false", "href": None,
    })


def test_navigation_modes_distinguish_documents_spa_hash_and_safe_clicks():
    document = "https://portal.example.com/app"
    assert navigation_mode_for_route(
        "https://portal.example.com/help", "a", document,
    ) == SEMANTIC_LINK_NAVIGATION
    assert navigation_mode_for_route(
        "https://portal.example.com/reports", "browser-history", document,
    ) == SPA_ROUTE_TRANSITION
    assert navigation_mode_for_route(
        "https://portal.example.com/app#/health", "browser-history", document,
    ) == HASH_ROUTE_TRANSITION
    assert navigation_mode_for_route(
        "https://portal.example.com/settings", "safe-click", document,
    ) == SAFE_CLICK_NAVIGATION


class _TransitionFailurePage:
    url = "https://portal.example.com/app"

    async def evaluate(self, _script, _argument):
        return True

    async def wait_for_function(self, *_args, **_kwargs):
        raise TimeoutError("route did not change")

    def is_closed(self):
        return False


@pytest.mark.asyncio
async def test_same_document_transition_that_never_completes_fails():
    with pytest.raises(RuntimeError, match="did not reach"):
        await perform_route_navigation(
            _TransitionFailurePage(),
            "https://portal.example.com/missing",
            SPA_ROUTE_TRANSITION,
            50,
        )


@pytest.mark.asyncio
async def test_synthetic_spa_routes_render_without_additional_document_requests():
    class Handler(BaseHTTPRequestHandler):
        document_requests = 0

        def do_GET(self):
            type(self).document_requests += 1
            body = b"""<!doctype html><title>SPA</title>
            <main id='content'>Home route</main>
            <button id='reports' aria-controls='content' aria-expanded='false'
              onclick=\"history.pushState({},'', '/reports'); render()\">Reports</button>
            <script>
              function render() {
                document.querySelector('#content').textContent = location.hash || location.pathname;
              }
              addEventListener('popstate', render);
              addEventListener('hashchange', render);
            </script>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                pytest.skip("matching Playwright Chromium is not installed on this host")
            browser = await playwright.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                await context.add_init_script(script=ROUTE_OBSERVER_SCRIPT)
                page = await context.new_page()
                response, transitioned = await perform_route_navigation(
                    page, f"{origin}/", DOCUMENT_NAVIGATION, 5000,
                )
                assert response.status == 200
                assert transitioned is False
                await page.click("#reports")
                discovered = await discover_page_routes(page)
                reports = next(route for route in discovered if route.url.endswith("/reports"))
                assert reports.navigation_mode == SPA_ROUTE_TRANSITION

                for target, mode, expected_text in (
                    (f"{origin}/dashboard", SPA_ROUTE_TRANSITION, "/dashboard"),
                    (f"{origin}/dashboard#/health", HASH_ROUTE_TRANSITION, "#/health"),
                    (f"{origin}/settings", SAFE_CLICK_NAVIGATION, "/settings"),
                ):
                    response, transitioned = await perform_route_navigation(
                        page, target, mode, 5000,
                    )
                    assert response is None
                    assert transitioned is True
                    assert expected_text in await page.locator("#content").inner_text()
                assert Handler.document_requests == 1
            finally:
                await browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
