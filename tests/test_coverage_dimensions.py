"""Coverage is not an alias for successful execution or HTTP 200."""

import json

import pytest

from app.reporting import aggregate_report, build_coverage_dimensions, classify_page_result, navigation_coverage


def loaded(**changes):
    return {
        **classify_page_result(
            url="https://portal.example/", status=200, error=None,
            missing_security_headers=[], console_errors=[], failed_resources=[],
            security_headers_tested=True,
        ),
        **changes,
    }


def test_finished_queue_does_not_claim_authentication_or_navigation_completed():
    results = [loaded(
        authentication_status="AUTHENTICATION_BLOCKED", application_ready=False,
        browser_lifecycle={"failed_stage": "AUTHENTICATING", "failure_reason": "token=private-secret", "events": []},
    )]
    dimensions = build_coverage_dimensions(results, aggregate_report(results))
    assert dimensions["execution"]["status"] == "COMPLETE"
    assert dimensions["navigation"]["status"] == "LIMITED"
    assert dimensions["authentication"]["status"] == "BLOCKED"
    assert dimensions["api"]["status"] == "NOT_OBSERVED"
    assert "private-secret" not in json.dumps(dimensions)
    assert "AUTHENTICATION_INCOMPLETE" in dimensions["navigation"]["reason"]


def test_http_200_legacy_snapshot_is_not_session_establishment_evidence():
    results = [loaded()]
    dimensions = build_coverage_dimensions(results, aggregate_report(results))
    assert dimensions["authentication"]["status"] == "UNKNOWN"
    assert "HTTP 200 alone is insufficient" in dimensions["authentication"]["reason"]


def test_session_established_and_bootstrap_not_ready_are_independent():
    results = [loaded(application_ready=False, browser_lifecycle={
        "state": "REPORT", "failed_stage": "APPLICATION_BOOTSTRAP",
        "events": [{"state": "SESSION_ESTABLISHED"}, {"state": "APPLICATION_BOOTSTRAP"}, {"state": "REPORT"}],
    })]
    dimensions = build_coverage_dimensions(results, aggregate_report(results))
    assert dimensions["authentication"]["status"] == "READY"
    assert dimensions["navigation"]["status"] == "LIMITED"


@pytest.mark.parametrize(("status", "expected"), [
    ("AUTH_REQUIRED", "REQUIRED"), ("SESSION_EXPIRED", "SESSION_EXPIRED"),
    ("AUTH_TIMEOUT", "FAILED"), ("AUTH_FAILED", "FAILED"), ("MFA_REQUIRED", "REQUIRED"),
])
def test_authentication_dimension_preserves_required_expired_and_failed_states(status, expected):
    results = [loaded(classification=status, authentication_status=status)]
    dimensions = build_coverage_dimensions(results, aggregate_report(results))
    assert dimensions["authentication"]["status"] == expected


def test_api_observation_can_be_partial_without_affecting_navigation_completion():
    results = [loaded()]
    event = {
        "request_id": "request-1", "url": "https://portal.example/api/query", "method": "POST",
        "status": 200, "response_seen": True, "response_completed": False, "lifecycle_status": "INCOMPLETE",
    }
    summary = aggregate_report(results, api_events=[event])
    dimensions = build_coverage_dimensions(results, summary)
    assert dimensions["navigation"]["status"] == "COMPLETE"
    assert dimensions["api"]["status"] == "PARTIAL"
    assert summary["coverage_complete"] is False
    assert "1 unfinished" in dimensions["api"]["reason"]


def test_definitive_http_failures_and_passive_lifecycle_counters_reconcile():
    events = [
        {"request_id": "1", "status": 200, "response_seen": True, "response_completed": True,
         "request_dispatched": True, "policy_decision": "ALLOW", "lifecycle_status": "COMPLETED"},
        {"request_id": "2", "status": 502, "response_seen": True, "request_failed": True,
         "error": "net::ERR_CONNECTION_RESET", "request_dispatched": True, "policy_decision": "ALLOW",
         "lifecycle_status": "FAILED", "response_completed": False},
        {"request_id": "3", "status": None, "response_seen": False, "request_failed": True,
         "error": "net::ERR_CONNECTION_RESET", "request_dispatched": True, "policy_decision": "ALLOW",
         "lifecycle_status": "FAILED", "response_completed": False},
        {"request_id": "4", "status": None, "blocked_by_validator": True, "policy_decision": "BLOCK",
         "lifecycle_status": "BLOCKED"},
        {"request_id": "5", "status": None, "request_failed": True, "request_canceled": True,
         "lifecycle_status": "CANCELED", "response_completed": False},
        {"request_id": "6", "status": None, "lifecycle_status": "INCOMPLETE", "response_completed": False},
    ]
    summary = aggregate_report([loaded(api_requests=events)], api_events=events)
    assert summary["api_requests_observed"] == 6  # continuous + snapshots are not double-counted
    assert summary["api_requests_allowed"] == summary["api_requests_sent"] == 3
    assert summary["api_requests_responded"] == 2
    assert summary["api_http_failures"] == 1
    assert summary["api_requests_failed"] == 2
    assert sum(summary[key] for key in (
        "api_responses_completed", "api_requests_failed", "api_requests_blocked",
        "api_requests_canceled", "api_requests_incomplete",
    )) == summary["api_requests_observed"]
    assert summary["api_request_lifecycle_counts"] == {
        "COMPLETED": 1, "FAILED": 2, "BLOCKED": 1, "CANCELED": 1, "INCOMPLETE": 1, "OBSERVED_ONLY": 0,
    }


def test_completed_http_failure_has_separate_reconciled_lifecycle_and_http_dimensions():
    event = {"request_id": "request-1", "status": 502, "response_seen": True,
             "response_completed": True, "lifecycle_status": "COMPLETED"}
    summary = aggregate_report([loaded()], api_events=[event])
    assert summary["api_http_failures"] == 1
    assert summary["api_requests_failed"] == 1  # target health, not transfer lifecycle
    assert summary["api_request_lifecycle_counts"]["COMPLETED"] == 1
    assert summary["api_request_lifecycle_counts"]["FAILED"] == 0
    assert sum(summary["api_request_lifecycle_counts"].values()) == 1


def test_navigation_reports_menu_expansion_not_every_activation_and_counts_warning_views_healthy():
    results = [loaded(navigation_actions={"activated": 8, "menus_expanded": 2}),
               loaded(classification="PASS_WITH_WARNINGS", navigation_actions={"activated": 4, "menus_expanded": 1})]
    coverage = navigation_coverage(results, aggregate_report(results))
    assert coverage["menus_expanded"] == 3
    assert coverage["successful_views"] == 2
    assert coverage["failed_views"] == 0
    legacy = navigation_coverage([loaded(navigation_actions={"activated": 5})], aggregate_report([loaded()]))
    assert legacy["menus_expanded"] is None


def test_no_results_does_not_claim_authentication_or_observed_apis():
    dimensions = build_coverage_dimensions([], aggregate_report([], termination_reason="SCAN_TIMEOUT"))
    assert dimensions["execution"]["status"] == "TIMED_OUT"
    assert dimensions["navigation"]["status"] == dimensions["authentication"]["status"] == "UNKNOWN"
    assert dimensions["api"]["status"] == "NOT_OBSERVED"
    assert all(set(dimension) == {"status", "reason"} and dimension["reason"] for dimension in dimensions.values())
