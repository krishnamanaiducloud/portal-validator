"""Authentication failures invalidate all route and API coverage for that scan."""

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.reporting import (
    AUTHENTICATION_SCAN_FAILURE_REASONS,
    fail_closed_authentication_report,
)


def sample_scan_report(scan_id="scan-one"):
    return {
        "scan_id": scan_id,
        "run_id": scan_id,
        "target": "https://portal.example/",
        "pages": 2,
        "summary": {
            "routes_discovered": 7,
            "routes_validated": 2,
            "healthy_routes": 1,
            "scan_completeness": "PARTIAL",
            "total_scan_duration_ms": 1234,
        },
        "results": [{"route": "https://portal.example/private"}],
        "route_inventory": [{"route": "https://portal.example/private"}],
        "not_tested_routes": [{"route": "https://portal.example/old"}],
        "skipped_routes": [{"route": "https://portal.example/skipped"}],
        "api_inventory": [{"endpoint": "/api/private"}],
        "business_api_inventory": [{"endpoint": "/api/private"}],
        "api_request_occurrences": [{"endpoint": "/api/private"}],
        "resource_inventory": [{"url": "/asset.js"}],
        "resource_details": [{"url": "/asset.js"}],
        "resource_summary": {"resources_observed": 18},
        "security_recommendations": [{"type": "SECURITY_HEADER"}],
        "network_observation": {"api_requests_observed": 99},
        "authentication_diagnostics": [{
            "reason": "AUTHENTICATION_POLICY_BLOCKED",
            "destination_host": "login.example",
            "affects_authentication": True,
        }],
        "scan_configuration": {"authentication_mode": "storage_state"},
    }


@pytest.mark.parametrize("reason", sorted(AUTHENTICATION_SCAN_FAILURE_REASONS))
def test_failed_authentication_discards_every_route_and_application_api(reason):
    report = fail_closed_authentication_report(sample_scan_report(), reason)
    assert report["scan_status"] == "FAILED"
    assert report["failure"]["classification"] == reason
    assert report["failure"]["stage"] == "AUTHENTICATING"
    assert report["pages"] == 0
    for field in (
        "results", "route_inventory", "not_tested_routes", "skipped_routes",
        "api_inventory", "business_api_inventory", "api_request_occurrences",
        "resource_inventory", "resource_details", "security_recommendations",
    ):
        assert report[field] == []
    for counter in (
        "routes_discovered", "routes_eligible", "routes_queued", "routes_validated",
        "routes_remaining", "routes_not_tested", "routes_skipped", "healthy_routes",
        "api_requests_observed", "unique_apis",
    ):
        assert report["summary"][counter] == 0
    assert report["summary"]["scan_completeness"] == "FAILED"
    assert report["summary"]["execution_status"] == "FAILED"
    assert report["summary"]["auth_issues"] == 1
    assert report["summary"]["counter_invariants"] == {
        "api_lifecycles_reconciled": True,
        "validated_not_above_eligible": True,
        "eligible_reconciled": True,
        "warnings_are_subset_of_passed": True,
    }
    assert report["coverage"]["routes_discovered"] == 0
    assert report["coverage_dimensions"]["authentication"]["status"] == "FAILED"
    assert report["authentication_diagnostics"][0]["destination_host"] == "login.example"
    assert report["scan_configuration"]["authentication_mode"] == "storage_state"
    assert report["summary"]["total_scan_duration_ms"] == 1234


def test_fail_closed_rejects_unrelated_route_or_access_error():
    with pytest.raises(ValueError, match="classified authentication failure"):
        fail_closed_authentication_report(sample_scan_report(), "ACCESS_RESTRICTED")


def test_scan_job_reports_auth_failure_with_accessible_zero_route_report(monkeypatch):
    async def fake_execute(req, *, scan_id, progress_callback, cancel_event):
        await progress_callback("AUTHENTICATING", discovered=0, validated=0)
        await asyncio.sleep(0.01)
        if req.target.endswith("/protected"):
            return fail_closed_authentication_report(
                sample_scan_report(scan_id), "AUTHENTICATION_BLOCKED",
            )
        return {
            "scan_id": scan_id, "run_id": scan_id,
            "pages": 1, "results": [{"route_name": "Prior successful route"}],
            "summary": {
                "scan_completeness": "COMPLETE",
                "termination_reason": "DISCOVERY_EXHAUSTED",
                "routes_discovered": 1, "routes_validated": 1,
                "healthy_routes": 1, "failed_pages": 0,
                "routes_with_warnings": 0,
            },
        }

    monkeypatch.setattr("app.main.execute_scan", fake_execute)
    with TestClient(app) as client:
        def completed_scan(target):
            created = client.post("/api/scans", json={"target": target})
            assert created.status_code == 202
            scan_id = created.json()["scan_id"]
            for _ in range(100):
                status = client.get(f"/api/scans/{scan_id}").json()
                if status["state"] in {"COMPLETED", "PARTIAL", "FAILED"}:
                    return status, client.get(f"/api/scans/{scan_id}/report").json()
                time.sleep(0.01)
            pytest.fail("Scan did not terminate in time")

        first, first_report = completed_scan("https://portal.example/")
        assert first["state"] == "COMPLETED"
        assert first_report["summary"]["routes_discovered"] == 1

        failed, failed_report = completed_scan("https://portal.example/protected")
        assert failed["state"] == "FAILED"
        assert failed["report_ready"] is True
        assert failed["discovered"] == failed["validated"] == failed["healthy"] == 0
        assert failed_report["pages"] == 0
        assert failed_report["route_inventory"] == []
        assert failed_report["results"] == []
        assert failed_report["api_inventory"] == []
        assert failed_report["failure"]["classification"] == "AUTHENTICATION_BLOCKED"
        assert "Prior successful route" not in str(failed_report)
