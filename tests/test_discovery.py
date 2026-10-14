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
    finalize_duplicate_route_names,
    navigation_mode_for_route,
    normalize_route_url,
    perform_route_navigation,
    resolve_route_name,
    route_identity_fields,
    safe_navigation_control,
)
from app.main import ScanRequest, execute_scan, partition_links, url_in_scan_scope


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
    assert normalize_route_url("https://example.com/#/callback?code=secret") == "https://example.com/#/callback"


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


def test_hash_and_hashbang_routes_keep_distinct_identity_and_display_paths():
    reports = route_identity_fields("https://portal.example.com/#/reports")
    accounts = route_identity_fields("https://portal.example.com/#!/accounts")
    assert reports["canonical_route"] == "https://portal.example.com/#/reports"
    assert reports["spa_route"] == "#/reports"
    assert reports["display_path"] == "#/reports"
    assert accounts["canonical_route"] == "https://portal.example.com/#!/accounts"
    assert accounts["display_path"] == "#!/accounts"
    assert reports["canonical_route"] != accounts["canonical_route"]


def test_route_name_prefers_navigation_evidence_over_generic_document_title():
    assert resolve_route_name(
        navigation_label="Audit Dashboard",
        accessible_name=None,
        primary_heading=None,
        breadcrumb=None,
        metadata_name=None,
        document_title="Portal",
        display_path="#/workqueue/audit-dashboard",
    ) == ("Audit Dashboard", "NAVIGATION_LABEL", "HIGH")


def test_repeated_document_titles_fall_back_to_distinct_route_segments():
    results = [
        {"document_title": "Shared Portal", "route_name": "Shared Portal", "route_name_source": "DOCUMENT_TITLE", "display_path": "#/reports"},
        {"document_title": "Shared Portal", "route_name": "Shared Portal", "route_name_source": "DOCUMENT_TITLE", "display_path": "#/accounts"},
    ]
    finalize_duplicate_route_names(results)
    assert [(item["route_name"], item["route_name_source"]) for item in results] == [
        ("Reports", "ROUTE_SEGMENT"),
        ("Accounts", "ROUTE_SEGMENT"),
    ]


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

    async def evaluate_handle(self, _script, _argument):
        class EmptyHandle:
            def as_element(self):
                return None

            async def dispose(self):
                pass

        return EmptyHandle()

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
async def test_displaced_spa_without_observed_get_source_is_not_replayed():
    class DisplacedPage(_TransitionFailurePage):
        url = "https://portal.example.com/other"

        async def evaluate(self, _script, _argument):
            return False

    with pytest.raises(RuntimeError, match="no observed GET restoration target"):
        await perform_route_navigation(
            DisplacedPage(), "https://portal.example.com/reports", SPA_ROUTE_TRANSITION, 50,
            source_route_url="https://portal.example.com/post-authenticated-shell",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("initial_fragment", ["", "#/home"])
async def test_synthetic_spa_routes_render_without_additional_document_requests(initial_fragment):
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
                response, transitioned, activation = await perform_route_navigation(
                    page, f"{origin}/{initial_fragment}", DOCUMENT_NAVIGATION, 5000,
                )
                assert response.status == 200
                assert transitioned is False
                assert activation == "DOCUMENT"
                await page.click("#reports")
                discovered = await discover_page_routes(page)
                reports = next(route for route in discovered if route.url.endswith("/reports"))
                assert reports.navigation_mode == SPA_ROUTE_TRANSITION

                for target, mode, expected_text in (
                    (f"{origin}/dashboard", SPA_ROUTE_TRANSITION, "/dashboard"),
                    (f"{origin}/dashboard#/health", HASH_ROUTE_TRANSITION, "#/health"),
                    (f"{origin}/settings", SAFE_CLICK_NAVIGATION, "/settings"),
                ):
                    response, transitioned, activation = await perform_route_navigation(
                        page, target, mode, 5000,
                        source_document_url=f"{origin}/",
                        source_route_url=f"{origin}/reports",
                    )
                    assert response is None
                    assert transitioned is True
                    assert activation in {"SEMANTIC_CONTROL", "SYNTHETIC_FALLBACK"}
                    assert expected_text in await page.locator("#content").inner_text()
                assert Handler.document_requests == 1
            finally:
                await browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("route_mode", [HASH_ROUTE_TRANSITION, SPA_ROUTE_TRANSITION])
@pytest.mark.parametrize("overlapping_history", [False, True])
async def test_queued_spa_route_restores_its_source_document_and_api_context(
    monkeypatch, route_mode, overlapping_history,
):
    """A prior document branch must not receive a sibling SPA's history update."""
    from app import main, security

    hash_route = route_mode == HASH_ROUTE_TRANSITION

    class Handler(BaseHTTPRequestHandler):
        report_cookies = []

        def do_GET(self):
            if self.path == "/api/report-data":
                type(self).report_cookies.append(self.headers.get("Cookie", ""))
                body = b'{"message":"Rendered reports application data"}'
                content_type = "application/json"
            elif self.path == "/other":
                body = b"<title>Other document</title><main><h1>Unrelated document contents</h1></main>"
                if overlapping_history:
                    body += b'''<script>history.replaceState({}, '', '/workspace');
                      history.replaceState({}, '', '/other');</script>'''
                content_type = "text/html"
            elif self.path == "/index":
                navigation = '<a href="#/reports">Reports</a>' if hash_route else ""
                observe_history = "" if hash_route else (
                    "history.pushState({}, '', '/reports'); history.replaceState({}, '', '/workspace');"
                )
                route_event = "hashchange" if hash_route else "popstate"
                body = ('''<!doctype html><title>Original SPA workspace</title><main>
                  <h1 id="heading">Original SPA workspace content</h1><nav>
                  <a href="/other">Other document</a>''' + navigation + '''</nav>
                  <output id="data">Home view data</output></main><script>
                  document.cookie = 'scan_session=retained; path=/';
                  ''' + observe_history + '''
                  function render() {
                    if (!(location.hash === '#/reports' || location.pathname === '/reports')) return;
                    document.title = 'Reports application workspace';
                    document.querySelector('#heading').textContent = 'Reports application content';
                    fetch('/api/report-data').then(response => response.json()).then(data => {
                      document.querySelector('#data').textContent = data.message;
                    });
                  }
                  addEventListener("''' + route_event + '''", render);
                  </script>''').encode()
                content_type = "text/html"
            else:
                self.send_error(404, "History routes have no server document fallback")
                return
            self.send_response(200)
            if self.path == "/other":
                self.send_header("Set-Cookie", "sibling_session=retained; Path=/")
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setattr(security, "ALLOWED_PORTS", {*security.ALLOWED_PORTS, server.server_port})
    original_resolver = main.resolve_and_validate

    async def fixture_destination(host, allow_private):
        if host == "127.0.0.1":
            return ["127.0.0.1"]
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", fixture_destination)
    try:
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                pytest.skip("matching Playwright Chromium is not installed on this host")
        report = await execute_scan(ScanRequest(
            target=origin + "/index", allow_private_networks=True, max_pages=3, max_depth=2,
            timeout_ms=5000, total_timeout_ms=20000, max_discovery_scrolls=0,
            min_observation_ms=100, network_quiet_ms=50, render_settle_ms=100,
            check_security_headers=False,
        ))
        target = origin + ("/index#/reports" if hash_route else "/reports")
        assert [item["requested_url"] for item in report["results"]] == [
            origin + "/index", origin + "/other", target,
        ]
        route = report["results"][-1]
        assert route["title"] == "Reports application workspace"
        assert route["navigation_type"] == route_mode
        assert route["status"] == 200
        assert route["application_ready"] is True
        assert route["render_health"]["text_length"] >= len("Rendered reports application data")
        events = [event for event in route["api_requests"] if event["url"] == origin + "/api/report-data"]
        assert len(events) == 1
        assert events[0]["status"] == 200
        assert events[0]["route_activation_id"] == route["route_activation_id"]
        assert events[0]["initiating_route"] == route["route_id"]
        assert len(Handler.report_cookies) == 1
        assert set(Handler.report_cookies[0].split("; ")) == {
            "scan_session=retained", "sibling_session=retained",
        }
        assert all(report["summary"]["counter_invariants"].values())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
