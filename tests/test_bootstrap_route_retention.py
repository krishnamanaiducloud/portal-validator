"""Readiness/auth failures must not inspect even passive application routes."""
import json

import pytest

from app.main import ScanRequest, execute_scan
from test_scan_post_lifecycle import production_spa


@pytest.mark.asyncio
@pytest.mark.parametrize("requires_login", [False, True])
async def test_unready_shell_does_not_discover_visible_hash_routes(production_spa, monkeypatch, requires_login):
    origin, handler = production_spa

    def document(self):
        form = '<form><label>Password <input type="password"></label></form>' if requires_login else ''
        body = ('''<!doctype html><title>Generic workspace</title><main>
          <h1>Service workspace</h1><nav>
          <a href="#/reports" onclick="fetch('/api/write',{method:'POST'})">Reports</a>
          <a href="#/activity" onclick="fetch('/api/read',{method:'POST'})">Activity</a>
          </nav><p>Readiness has not been established for this workspace.</p>'''
          + form + '</main>').encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    monkeypatch.setattr(handler, "do_GET", document)
    report = await execute_scan(ScanRequest(
        target=origin, allow_private_networks=True, max_pages=10, max_depth=3,
        timeout_ms=8000, total_timeout_ms=20000, readiness_timeout_ms=1000,
        readiness_selector="[data-app-ready=true]", max_navigation_actions=10,
        max_discovery_scrolls=0, min_observation_ms=100, network_quiet_ms=50,
        render_settle_ms=100, check_security_headers=False,
    ))
    category = "AUTHENTICATION_FAILED" if requires_login else "APPLICATION_NOT_READY"
    assert report["scan_status"] == "FAILED"
    assert report["authentication_error"]["category"] == category
    assert report["results"] == report["route_inventory"] == []
    assert report["summary"]["routes_discovered"] == 0
    assert report["summary"]["application_routes_validated"] == 0
    assert not report["summary"]["coverage_complete"]
    assert report["coverage"]["discovery_status"] == "NOT_STARTED"
    assert report["summary"]["navigation_controls_activated"] == 0
    assert handler.post_paths == []
    assert report["network_observation"]["http_methods_observed"].get("POST", 0) == 0
    assert all(report["summary"]["counter_invariants"].values())
    assert "Password" not in json.dumps(report.get("api_request_occurrences", []))
