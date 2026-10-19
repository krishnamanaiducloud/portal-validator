"""Global bootstrap failure is not a partially successful application scan."""
from copy import deepcopy
import json

import pytest

from app.reporting import (
    aggregate_report,
    apply_global_authentication_failure,
    classify_page_result,
    create_authentication_error,
)
from app.scans import SCAN_STATES, ScanJob


def loaded_result(status=200, classification=None):
    return classify_page_result(
        url="https://portal.example/reports", status=status, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, authentication_classification=classification,
    )


@pytest.mark.parametrize("category", [
    "AUTHENTICATION_BLOCKED", "AUTHENTICATION_FAILED", "AUTHENTICATION_TIMEOUT",
    "SESSION_EXPIRED", "IDENTITY_PROVIDER_UNAVAILABLE", "AUTHENTICATION_CONFIGURATION_ERROR",
    "APPLICATION_NOT_READY", "AUTHENTICATION_REQUIRED", "MFA_REQUIRED", "ACCESS_RESTRICTED", "TLS_ERROR",
])
def test_failed_global_authentication_has_zero_application_coverage(category):
    old_result = loaded_result()
    old_report = {
        "scan_id": "current-scan", "run_id": "current-scan", "target": "https://portal.example/",
        "results": [old_result], "route_inventory": [old_result],
        "summary": aggregate_report([old_result]),
        "api_inventory": [{"url": "https://portal.example/previous-api"}],
        "api_request_occurrences": [{"url": "https://portal.example/previous-api"}],
        "business_api_inventory": [{"url": "https://portal.example/previous-api"}],
        "resource_details": [{"url": "https://portal.example/previous-script.js"}],
        "resource_inventory": [{"url": "https://portal.example/previous-script.js"}],
        "unexpected_cached_routes": [old_result],
    }
    before = deepcopy(old_report)
    report = apply_global_authentication_failure(old_report, create_authentication_error(category))
    assert old_report == before, "A failed scan must not modify another report's state"
    assert report["scan_id"] == report["run_id"] == "current-scan"
    assert report["scan_status"] == report["outcome"] == report["authentication_status"] == "FAILED"
    assert report["authentication_error"]["category"] == category
    assert report["authentication_error"]["remediation"]
    assert report["pages"] == 0
    assert "unexpected_cached_routes" not in report
    for field in (
        "results", "route_inventory", "api_inventory", "api_request_occurrences", "business_api_inventory",
        "resource_details", "resource_inventory", "not_tested_routes", "skipped_routes", "security_recommendations",
    ):
        assert report[field] == []
    summary = report["summary"]
    for field in (
        "routes_discovered", "routes_eligible", "routes_validated", "routes_queued", "routes_remaining",
        "routes_not_tested", "routes_tested", "tested_routes", "total_pages", "loaded_pages", "passed",
        "passed_pages", "healthy_routes", "pass_with_warnings", "api_requests_observed", "api_calls",
        "api_failures", "business_apis", "unique_apis", "api_requests_not_actively_tested",
    ):
        assert summary[field] == 0, field
    assert summary["execution_status"] == summary["scan_completeness"] == "FAILED"
    assert summary["coverage_status"] == summary["route_coverage"] == summary["discovery_status"] == "NOT_STARTED"
    assert summary["validation_status"] == "NOT_STARTED"
    assert not summary["execution_complete"] and not summary["coverage_complete"]
    assert all(summary["counter_invariants"].values())
    assert report["coverage"]["coverage_status"] == "NOT_STARTED"
    assert report["coverage_dimensions"]["authentication"]["status"] == "FAILED"
    assert report["coverage_dimensions"]["api"]["status"] == "NOT_STARTED"
    assert report["navigation_coverage"]["visited_views"] == report["navigation_coverage"]["validated_views"] == 0


@pytest.mark.parametrize("source,canonical", [
    ("AUTH_FAILED", "AUTHENTICATION_FAILED"), ("AUTH_TIMEOUT", "AUTHENTICATION_TIMEOUT"),
    ("AUTH_REQUIRED", "AUTHENTICATION_REQUIRED"), ("MFA_REQUIRED", "MFA_REQUIRED"),
    ("AUTH_CONFIGURATION_ERROR", "AUTHENTICATION_CONFIGURATION_ERROR"),
])
def test_authentication_error_preserves_canonical_failure_category(source, canonical):
    assert create_authentication_error(source)["category"] == canonical


def test_authentication_error_is_sanitized_without_headers_payloads_or_query_values():
    error = create_authentication_error(
        "AUTHENTICATION_BLOCKED", stage="REQUEST_POLICY", http_status=403, method="post",
        endpoint="https://user:password@identity.example/as/authorize?code=secret-code&ordinary=secret-value#secret-fragment",
        policy_decision="AUTHENTICATION_HOST_NOT_APPROVED", duration_ms=12.7,
    )
    assert error["endpoint"] == "https://identity.example/as/authorize"
    assert error["http_status"] == 403 and error["method"] == "POST" and error["duration_ms"] == 13
    assert error["policy_decision"] == "AUTHENTICATION_HOST_NOT_APPROVED"
    serialized = json.dumps(error)
    for secret in ("password", "secret-code", "secret-value", "secret-fragment", "user:"):
        assert secret not in serialized


def test_authentication_diagnostics_are_separate_from_all_application_api_counters():
    report = apply_global_authentication_failure(
        {"scan_id": "failed-scan"}, create_authentication_error("AUTHENTICATION_BLOCKED"), diagnostics=[{
            "reason": "AUTHENTICATION_HOST_NOT_APPROVED", "affects_authentication": True,
            "protocol": "AUTHENTICATION_FORM", "source_approved": True, "destination_approved": False,
            "method": "POST", "url": "https://identity.example/saml/acs?SAMLResponse=private-assertion",
            "source_host": "portal.example", "destination_host": "identity.example",
            "http_status": 403, "policy_reason": "THIRD_PARTY_RESOURCE_POLICY",
            "headers": {"Authorization": "Bearer private-header"}, "body": "private-body",
            "cookies": ["private-cookie"], "storage_state": {"private-state": True},
        }],
    )
    assert len(report["authentication_diagnostics"]) == 1
    diagnostic = report["authentication_diagnostics"][0]
    assert diagnostic["reason"] == "AUTHENTICATION_HOST_NOT_APPROVED"
    assert diagnostic["protocol"] == "AUTHENTICATION_FORM"
    assert diagnostic["source_approved"] is True and diagnostic["destination_approved"] is False
    assert diagnostic["endpoint"] == "https://identity.example/saml/acs"
    assert diagnostic["http_status"] == 403 and diagnostic["method"] == "POST"
    assert diagnostic["source_host"] == "portal.example" and diagnostic["destination_host"] == "identity.example"
    assert report["network_observation"]["api_requests_observed"] == report["summary"]["api_requests_observed"] == 0
    assert report["api_inventory"] == report["api_request_occurrences"] == []
    assert "private-" not in json.dumps(report)


@pytest.mark.parametrize("bad_duration", [-1, True, float("nan"), float("inf"), "private"])
def test_invalid_diagnostic_metadata_is_not_serialized(bad_duration):
    error = create_authentication_error(
        "unknown private category", stage="Authorization: Bearer private", http_status=True,
        method="POST Cookie: private", endpoint="file:///private", policy_decision="private-value",
        duration_ms=bad_duration,
    )
    assert error["category"] == "AUTHENTICATION_FAILED" and error["stage"] == "AUTHENTICATING"
    assert all(error[key] is None for key in ("http_status", "method", "endpoint", "policy_decision", "duration_ms"))
    assert "private" not in json.dumps(error)


def test_minimal_preflight_configuration_failure_returns_full_zero_report_contract():
    report = apply_global_authentication_failure(
        {"scan_id": "configuration-failure", "validator_version": "test"},
        create_authentication_error("AUTHENTICATION_CONFIGURATION_ERROR", stage="INITIALIZING"),
    )
    assert report["scan_id"] == "configuration-failure"
    assert report["authentication_error"]["stage"] == "INITIALIZING"
    assert report["summary"]["routes_discovered"] == report["summary"]["routes_tested"] == 0
    assert report["results"] == []


def test_individual_forbidden_route_does_not_become_global_authentication_failure():
    allowed, forbidden = loaded_result(), loaded_result(403, "AUTHORIZATION_DENIED")
    assert forbidden["classification"] == "AUTHORIZATION_DENIED"
    assert forbidden["validation_status"] == "FAIL" and forbidden["authentication_status"] == "PASS"
    assert forbidden["page_load_status"] == "LOADED"
    assert forbidden["finding_details"] == [{
        "type": "AUTHORIZATION_DENIED", "severity": "ERROR", "impact": "BLOCKING", "blocking": True,
        "message": "The established application session is not authorized for this route (HTTP 403).", "count": 1,
    }]
    summary = aggregate_report([allowed, forbidden])
    assert summary["routes_validated"] == 2 and summary["healthy_routes"] == 1
    assert summary["failed_pages"] == 1 and summary["auth_issues"] == 0


def test_scan_job_accepts_required_lifecycle_and_has_terminal_failed_state():
    job = ScanJob(scan_id="authentication-first")
    for state in (
        "INITIALIZING", "AUTHENTICATING", "AUTHENTICATED", "APPLICATION_READY",
        "DISCOVERING_ROUTES", "VALIDATING_ROUTES", "COMPLETED",
    ):
        job.update(state)
        assert job.snapshot()["state"] == state
    assert job.completed_at is not None
    for old_state in ("QUEUED", "STARTING", "DISCOVERING", "VALIDATING", "FINALIZING", "PARTIAL"):
        assert old_state in SCAN_STATES
