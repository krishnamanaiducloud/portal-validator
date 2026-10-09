"""Runtime deadline and effective-configuration regressions through execute_scan."""
import asyncio
import time
from pathlib import Path

import pytest
from playwright.async_api import async_playwright
from pydantic import ValidationError

from app.main import ScanRequest, execute_scan
from test_scan_post_lifecycle import production_spa


async def require_browser():
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")


def scan_request(origin, **overrides):
    values = {
        "target": origin, "allow_private_networks": True, "max_pages": 4,
        "max_depth": 2, "timeout_ms": 1000, "total_timeout_ms": 15000,
        "render_settle_ms": 100, "min_observation_ms": 100, "network_quiet_ms": 100,
        "max_navigation_actions": 0, "max_discovery_scrolls": 0,
        "check_security_headers": False,
    }
    values.update(overrides)
    return ScanRequest(**values)


def test_scan_settings_are_frozen_and_dynamic_thresholds_are_validated():
    request = ScanRequest(
        target="portal.example.net", timeout_ms=17000, total_timeout_ms=45000,
        slow_page_threshold_ms=6500, min_observation_ms=800, network_quiet_ms=400,
        large_image_threshold_bytes=3072, large_js_threshold_bytes=4096,
        large_css_font_threshold_bytes=2048, large_resource_threshold_bytes=8192,
    )
    assert request.timeout_ms == 17000
    with pytest.raises(ValidationError, match="frozen"):
        request.timeout_ms = 15000
    for invalid in (
        {"timeout_ms": 999}, {"total_timeout_ms": 999},
        {"slow_page_threshold_ms": 499}, {"min_observation_ms": -1},
        {"network_quiet_ms": -1}, {"large_js_threshold_bytes": 1023},
        {"large_css_font_threshold_bytes": 1023},
    ):
        with pytest.raises(ValidationError):
            ScanRequest(target="portal.example.net", **invalid)


@pytest.mark.asyncio
async def test_route_maximum_bounds_a_persistent_visible_loader(production_spa, monkeypatch):
    await require_browser()
    origin, handler = production_spa
    original_get = handler.do_GET

    def fixture_get(self):
        if self.path != "/":
            return original_get(self)
        body = b'''<!doctype html><html><body><nav><a href="#/busy">Busy route</a></nav>
        <main><h1>Generic ready home route</h1></main><script>
        document.querySelector('a').onclick=event=>{
          event.preventDefault();history.pushState({},'', '#/busy');
          document.querySelector('main').innerHTML='<h1>Generic busy route</h1><div role="progressbar">Loading</div>';
        };</script></body></html>'''
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    monkeypatch.setattr(handler, "do_GET", fixture_get)
    # Allow the initial document to be discovered on a contended CI host;
    # the busy route must still stop at the explicitly configured deadline.
    route_budget_ms = 5000
    report = await execute_scan(scan_request(
        origin, max_pages=2, timeout_ms=route_budget_ms, total_timeout_ms=30000,
    ))
    busy = next(item for item in report["results"] if item["requested_url"].endswith("#/busy"))
    if busy["render_health"] is None:
        # The enclosing absolute route deadline can win the same-time race
        # against the settle helper's bounded result on a busy event loop.
        assert busy["classification"] == "TIMEOUT"
    else:
        assert busy["render_health"]["settle_reason"] == "BOUNDED_TIMEOUT"
    assert busy["classification"] in {"PASS_WITH_WARNINGS", "TIMEOUT"}
    assert route_budget_ms - 200 <= busy["total_validation_ms"] < route_budget_ms + 800
    assert report["summary"]["routes_validated"] == 2
    assert report["scan_configuration"]["timeout_ms"] == route_budget_ms


@pytest.mark.asyncio
async def test_route_timeout_bounds_a_real_main_document_request(production_spa, monkeypatch):
    await require_browser()
    origin, handler = production_spa

    def delayed_get(self):
        time.sleep(2)
        body = b"<html><body><h1>Generic delayed document</h1></body></html>"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # The browser is expected to close this fixture's timed-out socket.
            pass

    monkeypatch.setattr(handler, "do_GET", delayed_get)
    report = await execute_scan(scan_request(origin, max_pages=1))
    result = report["results"][0]
    assert result["classification"] == "TIMEOUT"
    assert result["page_load_status"] == "FAILED_TO_LOAD"
    assert result["validation_status"] == "NOT_TESTED"
    assert 800 <= result["total_validation_ms"] < 1800


@pytest.mark.asyncio
async def test_total_deadline_preserves_completed_results_and_timeout_counters(production_spa):
    await require_browser()
    origin, handler = production_spa
    handler.routes = 3
    completed_before_deadline = []

    async def progress(state, **values):
        if state == "VALIDATING" and values.get("validated") == 1 and not completed_before_deadline:
            completed_before_deadline.append(True)
            # Model an expensive downstream observer after a completed route;
            # even non-navigation work must respect the absolute scan deadline.
            await asyncio.sleep(20)

    report = await execute_scan(
        scan_request(origin, total_timeout_ms=10000), progress_callback=progress,
    )
    summary = report["summary"]
    assert completed_before_deadline
    assert len(report["results"]) == 1
    assert summary["termination_reason"] == "SCAN_TIMEOUT"
    assert summary["scan_completeness"] == "PARTIAL"
    assert summary["routes_not_tested"] == 3
    assert summary["not_tested_reason_counts"] == {"NOT_TESTED_TIMEOUT": 3}
    assert summary["routes_discovered"] == (
        summary["routes_validated"] + summary["routes_not_tested"] + summary["routes_skipped"]
    )


@pytest.mark.asyncio
async def test_total_budget_starts_before_configuration_and_browser_launch(production_spa, monkeypatch):
    await require_browser()
    origin, _handler = production_spa
    from app import main
    original_resolver = main.resolve_and_validate

    async def slow_preflight(host, allow_private):
        # This must be cancelled, not merely checked after resolution returns.
        await asyncio.sleep(20)
        return await original_resolver(host, allow_private)

    monkeypatch.setattr(main, "resolve_and_validate", slow_preflight)
    started = time.perf_counter()
    report = await execute_scan(scan_request(origin, total_timeout_ms=1000))
    assert time.perf_counter() - started < 2.5
    assert report["summary"]["termination_reason"] == "SCAN_TIMEOUT"
    assert report["summary"]["routes_validated"] == 0
    assert report["summary"]["routes_not_tested"] == 1
    assert report["timings"]["browser_contexts"] == 0


@pytest.mark.asyncio
async def test_fast_spa_uses_adaptive_observation_not_the_route_timeout(production_spa):
    await require_browser()
    origin, handler = production_spa
    handler.routes = 1
    report = await execute_scan(scan_request(
        origin, max_pages=2, timeout_ms=15000, render_settle_ms=200,
        min_observation_ms=500, network_quiet_ms=300,
        slow_page_threshold_ms=1200,
        large_js_threshold_bytes=4096, large_css_font_threshold_bytes=3072,
        approved_read_post_operations=[{
            "method": "POST", "host": "127.0.0.1", "path": "/api/query",
        }],
    ))
    route = next(item for item in report["results"] if item["requested_url"].endswith("#/route-1"))
    assert route["navigation_type"] != "DOCUMENT_NAVIGATION"
    # Assert adaptive readiness directly. Full validation also includes DOM
    # diagnostics/security instrumentation and host scheduling; a 2.5s total
    # wall-clock limit falsely failed when readiness actually completed in 603ms.
    assert route["render_health"]["settle_reason"] == "DOM_AND_NETWORK_QUIET"
    assert route["render_health"]["settle_elapsed_ms"] < 2500
    assert route["total_validation_ms"] < report["scan_configuration"]["timeout_ms"] / 2
    assert route["application_load_ms"] < 1200
    assert not route["slow"]
    assert not any(reason["code"] == "SLOW_ROUTE" for reason in route["warning_reasons"])
    assert report["scan_configuration"]["slow_page_threshold_ms"] == 1200
    assert report["scan_configuration"]["large_js_threshold_bytes"] == 4096
    assert report["scan_configuration"]["large_css_font_threshold_bytes"] == 3072
    assert report["scan_timing"]["browser_contexts"] == 1
    assert report["scan_timing"]["pages"] == 1
    assert len(handler.post_paths) == 7


@pytest.mark.asyncio
async def test_optional_resource_diagnostics_cannot_extend_route_deadline(production_spa, monkeypatch):
    await require_browser()
    origin, _handler = production_spa
    from app import main
    diagnostic_started = []

    async def slow_diagnostic(*_args):
        diagnostic_started.append(True)
        await asyncio.sleep(20)

    monkeypatch.setattr(main, "enrich_resource_timings", slow_diagnostic)
    # Reaching optional diagnostics requires a successfully loaded document.
    # Give fixture setup room without relaxing the deadline under test: the
    # twenty-second diagnostic must be cancelled by this five-second budget.
    route_budget_ms = 5000
    report = await execute_scan(scan_request(
        origin, max_pages=1, timeout_ms=route_budget_ms, total_timeout_ms=30000,
    ))
    route = report["results"][0]
    assert diagnostic_started
    assert route["page_load_status"] == "LOADED"
    assert route["passed"] is True
    assert route_budget_ms - 200 <= route["total_validation_ms"] < route_budget_ms + 800


@pytest.mark.asyncio
@pytest.mark.parametrize(("limits", "validated", "termination"), [
    ({"max_pages": 2, "max_depth": 2}, 2, "MAX_ROUTES_REACHED"),
    ({"max_pages": 4, "max_depth": 0}, 1, "MAX_DEPTH_REACHED"),
])
async def test_runtime_route_and_depth_limits_preserve_counter_invariants(
    production_spa, limits, validated, termination,
):
    await require_browser()
    origin, handler = production_spa
    handler.routes = 3
    # These cases test count/depth limits, not machine-speed-dependent deadlines.
    # Dedicated deadline tests above retain their deliberately short budgets.
    report = await execute_scan(scan_request(
        origin, timeout_ms=10000, total_timeout_ms=60000, **limits,
    ))
    summary = report["summary"]
    assert summary["routes_validated"] == validated
    assert summary["termination_reason"] == termination
    assert summary["routes_discovered"] == (
        summary["routes_validated"] + summary["routes_not_tested"] + summary["routes_skipped"]
    )
    assert report["scan_configuration"]["max_pages"] == limits["max_pages"]
    assert report["scan_configuration"]["max_depth"] == limits["max_depth"]
