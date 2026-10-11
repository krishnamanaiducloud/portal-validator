"""Report only the API and navigation coverage that the browser actually observed."""

import pytest

from app.reporting import aggregate_api_events, aggregate_report, classify_page_result


def api_event(**values):
    return {"url": "https://portal.example/api/query", "method": "POST", **values}


def loaded_route(**values):
    result = classify_page_result(
        url="https://portal.example/", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True,
    )
    return {**result, **values}


def test_headers_only_200_is_incomplete_before_observer_finalization():
    item = aggregate_api_events([api_event(
        status=200, response_seen=True, response_completed=False,
        lifecycle_status="RESPONDED", request_dispatched=True,
    )])[0]
    assert item["status_2xx"] == item["responded_calls"] == 1
    assert item["completed_calls"] == item["business_success_calls"] == 0
    assert item["health"] == item["validation_outcome"] == "INCOMPLETE"
    assert item["validation_reasons"] == [{
        "code": "RESPONSE_BODY_NOT_COMPLETED", "count": 1,
        "message": "HTTP response headers arrived; response completion was not observed.",
    }]


def test_url_only_observation_is_not_a_pass_or_an_active_probe():
    item = aggregate_api_events([api_event()])[0]
    assert item["completed_calls"] == item["responded_calls"] == 0
    assert item["health"] == "NOT_EXECUTED"
    assert item["validation_status"] == "OBSERVED"
    assert item["validation_outcome"] == "NOT_TESTED"
    assert item["validation_reasons"][0]["code"] == "REQUEST_OBSERVED_ONLY"
    assert item["active_validation_status"] == "NOT_ACTIVELY_TESTED"
    assert item["validation_basis"] == "PASSIVE_BROWSER_OBSERVATION"
    assert item["actively_tested"] is False


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 429, 500, 503])
def test_completed_http_error_is_failed_validation_with_explicit_http_evidence(status):
    item = aggregate_api_events([api_event(
        status=status, response_seen=True, response_completed=True,
    )])[0]
    assert item["completed_calls"] == 1
    assert item["validation_status"] == item["validation_outcome"] == "FAILED"
    assert item["validation_reasons"] == [{
        "code": f"HTTP_{status}", "count": 1,
        "message": f"The endpoint returned HTTP {status}.",
    }]


def test_completed_passive_response_does_not_claim_independent_api_testing():
    item = aggregate_api_events([api_event(
        status=200, response_seen=True, response_completed=True,
        traffic_role="APPLICATION_API",
    )])[0]
    assert item["health"] == "HEALTHY"
    assert item["validation_outcome"] == "PASSED"
    assert item["business_success_calls"] == 1
    assert item["actively_tested"] is False
    assert item["active_validation_status"] == "NOT_ACTIVELY_TESTED"


def test_policy_abort_never_becomes_transport_or_server_failure():
    item = aggregate_api_events([api_event(
        blocked_by_validator=True, error="net::ERR_BLOCKED_BY_CLIENT",
        lifecycle_status="BLOCKED", request_failed=True,
    )])[0]
    assert item["blocked_calls"] == 1
    assert item["failed_calls"] == item["network_failures"] == item["target_failure_count"] == 0
    assert item["validation_outcome"] == "BLOCKED"
    assert item["validation_reasons"][0]["code"] == "BLOCKED_BY_POLICY"


def test_endpoint_with_a_success_and_a_blocked_attempt_retains_partial_validation():
    item = aggregate_api_events([
        api_event(status=200, response_seen=True, response_completed=True),
        api_event(blocked_by_validator=True, lifecycle_status="BLOCKED"),
    ])[0]
    assert item["completed_calls"] == item["blocked_calls"] == 1
    assert item["validation_status"] == "PARTIALLY_VALIDATED"
    assert item["validation_outcome"] == "PARTIAL"
    assert item["validation_reasons"][0]["code"] == "BLOCKED_BY_POLICY"


def test_unresolved_navigation_prevents_complete_coverage_even_when_queue_finishes():
    summary = aggregate_report([loaded_route(
        navigation_controls_discovered=5, navigation_controls_activated=3,
        navigation_controls_unresolved=2,
    )])
    assert summary["execution_status"] == "COMPLETE"
    assert summary["coverage_grade"] == summary["coverage_status"] == "PARTIAL"
    assert summary["coverage_complete"] is False
    assert summary["discovery_status"] == "LIMITED"
    assert summary["healthy_routes"] == 1 and summary["failed_pages"] == 0
    assert summary["coverage_reasons"] == [{"code": "NAVIGATION_CONTROLS_UNRESOLVED", "count": 2}]


def test_complete_observed_scope_does_not_claim_total_application_enumeration():
    summary = aggregate_report([loaded_route()])
    assert summary["coverage_grade"] == "COMPLETE"
    assert summary["coverage_scope"] == "OBSERVED_REACHABLE_SCOPE"
    assert summary["total_application_coverage"] == "UNKNOWN"


def test_pending_headers_limit_coverage_and_api_counters_without_failing_loaded_page():
    summary = aggregate_report([loaded_route()], api_events=[api_event(
        status=200, response_seen=True, response_completed=False, lifecycle_status="RESPONDED",
    )])
    assert summary["api_requests_observed"] == summary["api_requests_incomplete"] == 1
    assert summary["api_responses_completed"] == summary["api_requests_failed"] == 0
    assert summary["api_requests_not_actively_tested"] == 1
    assert summary["coverage_grade"] == "PARTIAL"
    assert summary["healthy_routes"] == 1 and summary["failed_pages"] == 0
