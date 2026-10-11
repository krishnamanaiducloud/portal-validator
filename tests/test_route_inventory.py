"""Retain discovered routes when scan budgets prevent their validation."""

import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.async_api import async_playwright

from app.main import ScanRequest, execute_scan
from test_scan_post_lifecycle import production_spa
from test_ui_view_discovery import scan_views, ui_view_site


@pytest.mark.asyncio
@pytest.mark.parametrize("scan_options,reason,classification,validated", [
    ({"max_pages": 1}, "NOT_TESTED_MAX_ROUTES", "NOT_TESTED", 1),
    ({"max_depth": 0}, "SKIPPED_MAX_DEPTH", "SKIPPED", 1),
    ({"max_navigation_actions": 1}, "SKIPPED_MAX_NAVIGATION_ACTIONS", "SKIPPED", 2),
])
async def test_limits_retain_real_ui_views_without_counting_them_as_failures(
    ui_view_site, scan_options, reason, classification, validated,
):
    origin, receipts = ui_view_site
    report = await scan_views(origin, "/aria-tabs", scan_options=scan_options)
    inventory = report["route_inventory"]
    summary = report["summary"]

    assert summary["routes_discovered"] == len(inventory) == 3
    assert summary["routes_validated"] == len(report["results"]) == validated
    assert summary["failed_pages"] == 0
    assert summary["coverage_grade"] == "PARTIAL"
    assert summary["execution_status"] == "COMPLETE"
    assert summary["view_controls_discovered"] == 2
    assert summary["view_controls_activated"] == validated - 1
    assert summary["view_controls_unresolved"] == 3 - validated
    assert summary["navigation_controls_discovered"] >= summary["view_controls_discovered"]
    assert summary["navigation_controls_activated"] >= summary["view_controls_activated"]
    assert summary["navigation_controls_unresolved"] >= summary["view_controls_unresolved"]
    assert len({item["route_id"] for item in inventory}) == len(inventory)
    assert len(receipts) == validated - 1

    root = report["results"][0]
    children = [item for item in inventory if item["route_id"] != root["route_id"]]
    assert {item["route_name"] for item in children} == {"Service reports", "Recent activity"}
    assert all(item["route_id"].startswith("UI_VIEW_") for item in children)
    assert all(item["url"] == origin + "/aria-tabs" for item in children)
    assert all(item["parent_route_id"] == root["route_id"] for item in children)
    assert all(item["parent_route_name"] == root["route_name"] for item in children)
    assert all(item["navigation_hierarchy"] == [root["route_name"], item["route_name"]] for item in children)
    assert all(item["discovery_sources"] for item in children)

    unvisited = [item for item in inventory if item["page_load_status"] == "NOT_TESTED"]
    assert len(unvisited) == 3 - validated
    assert all(item["classification"] == classification for item in unvisited)
    assert all(item["validation_status"] == "NOT_TESTED" for item in unvisited)
    assert all(item["coverage_reason"] == item["failure_reason"] == reason for item in unvisited)
    assert all(item["failure_dimension"] == "COVERAGE" for item in unvisited)
    assert all(item["status"] is None and item["final_url"] is None for item in unvisited)
    assert all(item["finding_details"] == [] for item in unvisited)
    assert "fixture-view-session" not in json.dumps(report)
    assert all(summary["counter_invariants"].values())


@pytest.mark.asyncio
async def test_unvisited_hash_routes_preserve_identity_and_hierarchy_without_url_secrets(
    production_spa, monkeypatch,
):
    origin, handler = production_spa
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")

    def document(self):
        body = b'''<!doctype html><html><head><title>Generic service portal</title></head>
        <body><h1>Service directory</h1><nav>
        <a href="#/reports?access_token=private-inventory-token&amp;view=annual">Annual reports</a>
        <a href="#/activity?code=private-inventory-code&amp;view=recent">Recent activity</a>
        </nav><p>Select a read-only information view.</p></body></html>'''
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    monkeypatch.setattr(handler, "do_GET", document)
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=1,
        max_depth=2, timeout_ms=8000, total_timeout_ms=30000,
        render_settle_ms=100, min_observation_ms=100, network_quiet_ms=50,
        max_navigation_actions=0, max_discovery_scrolls=0,
        check_security_headers=False, query_parameter_policy="preserve",
    ))
    root = report["results"][0]
    children = [item for item in report["route_inventory"] if item["classification"] == "NOT_TESTED"]
    assert report["summary"]["routes_discovered"] == len(report["route_inventory"]) == 3
    assert len(children) == 2
    assert {item["route_name"] for item in children} == {"Annual reports", "Recent activity"}
    assert {urlsplit(item["url"]).fragment for item in children} == {
        "/reports?view=annual", "/activity?view=recent",
    }
    assert all(item["route_id"] == item["canonical_route"] == item["url"] for item in children)
    assert all(item["parent_route_id"] == root["route_id"] for item in children)
    assert all(item["navigation_hierarchy"] == [root["route_name"], item["route_name"]] for item in children)
    assert all(item["coverage_reason"] == "NOT_TESTED_MAX_ROUTES" for item in children)
    assert "private-inventory-token" not in json.dumps(report)
    assert "private-inventory-code" not in json.dumps(report)
    assert report["summary"]["failed_pages"] == 0
