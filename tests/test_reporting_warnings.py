"""Non-blocking route warnings must be actionable without raw JSON."""

import json

import pytest

from app.reporting import aggregate_report, classify_page_result, finding, refresh_route_api_health, structured_warning_reasons


def result_with(*findings, classification=None):
    return classify_page_result(
        url="https://portal.example/#/dashboard", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, additional_findings=list(findings),
        authentication_classification=classification,
    )


def test_pass_has_no_warning_reasons_or_codes():
    result = result_with()
    assert result["classification"] == "PASS"
    assert result["warning_reasons"] == []
    assert result["warning_codes"] == [] and result["warning_count"] == 0


@pytest.mark.parametrize("kind,metadata,code", [
    ("SLOW_ROUTE", {"observed_ms": 5820, "threshold_ms": 5000}, "SLOW_ROUTE"),
    ("SLOW_PAGE", {"observed_ms": 5820, "threshold_ms": 5000}, "SLOW_ROUTE"),
    ("CONSOLE_ERROR", {}, "CONSOLE_WARNING"),
    ("API_SERVER_ERROR_OPTIONAL", {"http_status": 503, "importance": "OPTIONAL"}, "OPTIONAL_API_FAILURE"),
    ("API_REQUEST_FAILED", {"importance": "BACKGROUND"}, "BACKGROUND_API_WARNING"),
    ("RESOURCE_FAILED", {}, "NON_CRITICAL_RESOURCE_FAILURE"),
    ("MISSING_SECURITY_HEADER", {}, "SECURITY_RECOMMENDATION"),
    ("FUTURE_NON_BLOCKING_FINDING", {}, "OTHER_NON_BLOCKING_WARNING"),
])
def test_warning_route_always_contains_structured_reasons_and_remains_healthy(kind, metadata, code):
    result = result_with(finding(kind, "WARNING", "Safe warning explanation", **metadata))
    assert result["classification"] == "PASS_WITH_WARNINGS"
    assert result["passed"] is True
    assert result["warning_count"] == 1 and result["warning_codes"] == [code]
    reason = result["warning_reasons"][0]
    assert reason["code"] == code
    assert reason["description"] == "Safe warning explanation"
    assert reason["severity"] == "WARNING"
    assert reason["affected_component"]
    assert reason["evidence"]["original_code"] == kind
    if "threshold_ms" in metadata:
        assert reason["threshold"] == {"value": 5000, "unit": "ms"}
        assert result["performance_status"] == "WARNING"
    summary = aggregate_report([result])
    assert summary["healthy_routes"] == 1 and summary["failed_pages"] == 0
    assert summary["counter_invariants"]["warnings_are_subset_of_passed"] is True


def test_nonblocking_error_is_explained_instead_of_clean_pass():
    result = result_with(finding("UNEXPECTED_NON_BLOCKING_DIAGNOSTIC", "ERROR", "Requires review"))
    assert result["classification"] == "PASS_WITH_WARNINGS"
    assert result["warning_count"] == 1 and result["passed"] is True


def test_legacy_warning_outcome_still_has_explicit_safe_fallback_reason():
    result = result_with(classification="PASS_WITH_WARNINGS")
    assert result["warning_count"] == 1
    assert result["warning_codes"] == ["OTHER_NON_BLOCKING_WARNING"]
    assert result["validation_status"] == "WARNING" and result["passed"] is True


def test_warning_evidence_reuses_central_redaction_and_does_not_copy_arbitrary_payloads():
    reasons = structured_warning_reasons("PASS_WITH_WARNINGS", [finding(
        "API_CLIENT_ERROR", "WARNING",
        "Request https://portal.example/api?access_token=private-token failed; Authorization: Bearer private-authorization",
        resource="https://portal.example/api?code=private-code",
        headers={"Cookie": "private-cookie"}, request_body="private-body",
        threshold_ms=float("inf"), duration_ms=float("nan"),
    )])
    serialized = json.dumps(reasons, allow_nan=False)
    assert "private-" not in serialized
    assert "headers" not in serialized and "request_body" not in serialized
    assert "threshold" not in reasons[0]


def test_absolute_scan_deadline_before_first_route_is_partial_not_failed():
    summary = aggregate_report([], routes_discovered=3, routes_eligible=3, termination_reason="SCAN_TIMEOUT")
    assert summary["scan_completeness"] == "PARTIAL"
    assert summary["termination_reason"] == "SCAN_TIMEOUT"
    assert summary["routes_validated"] == 0 and summary["routes_not_tested"] == 3
    assert summary["not_tested_reason_counts"] == {"NOT_TESTED_TIMEOUT": 3}


@pytest.mark.parametrize("status,importance,outcome,api_status", [
    (200, "REQUIRED", "PASS", "PASS"),
    (500, "REQUIRED", "VALIDATION_FAILED", "FAIL"),
    (500, "OPTIONAL", "PASS_WITH_WARNINGS", "WARNING"),
])
def test_late_target_response_reconciles_health_without_changing_navigation_or_tls(status, importance, outcome, api_status):
    original = result_with()
    original["timings"] = {"validator_overhead_ms": 2000}
    event = {"method": "POST", "url": "https://portal.example/api/query", "status": status, "importance": importance}
    updated = refresh_route_api_health(original, [event])
    assert original["classification"] == "PASS" and original.get("api_requests") is None
    assert updated["classification"] == outcome and updated["api_status"] == api_status
    assert updated["api_failures"] == (1 if status == 500 else 0)
    for key in ("tls", "tls_status", "tls_basis", "page_load_status", "navigation_status", "render_status", "timings"):
        assert updated[key] == original[key]
    if outcome == "PASS_WITH_WARNINGS":
        assert updated["warning_codes"] == ["OPTIONAL_API_FAILURE"]
        assert updated["passed"] is True


def test_reconciliation_does_not_turn_validator_blocks_into_target_failures_or_erase_other_warnings():
    original = result_with(finding("SLOW_ROUTE", "WARNING", "Slow route", observed_ms=8000, threshold_ms=5000))
    updated = refresh_route_api_health(original, [{
        "method": "POST", "url": "https://portal.example/api/query", "error": "net::ERR_BLOCKED_BY_CLIENT",
        "blocked_by_validator": True, "block_reason": "READ_ONLY_MUTATION_BLOCKED",
    }])
    assert updated["api_failures"] == 0 and updated["api_status"] == "PASS"
    assert updated["read_only_blocks"] == 1
    assert updated["classification"] == "PASS_WITH_WARNINGS" and updated["passed"] is True
    assert updated["warning_codes"] == ["SLOW_ROUTE"]


def test_reconciliation_preserves_authentication_classification():
    original = result_with(classification="SESSION_EXPIRED")
    updated = refresh_route_api_health(original, [{
        "method": "POST", "url": "https://portal.example/api/query", "status": 401,
    }])
    assert updated["classification"] == "SESSION_EXPIRED"
    assert updated["authentication_status"] == "SESSION_EXPIRED"
    assert updated["validation_status"] == "NOT_TESTED" and updated["passed"] is False
