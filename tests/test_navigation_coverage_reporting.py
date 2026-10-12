"""Navigation, HTTP evidence and transfer lifecycle are independent dimensions."""

import pytest

from app.reporting import (
    aggregate_api_events,
    aggregate_report,
    aggregate_resource_events,
    classify_page_result,
    navigation_coverage,
    request_failure_types,
    refresh_route_api_health,
)
from app.resources import build_resource_report


def loaded(**changes):
    return {
        **classify_page_result(
            url="https://portal.example/", status=200, error=None,
            missing_security_headers=[], console_errors=[], failed_resources=[],
            security_headers_tested=True,
        ),
        **changes,
    }


def test_final_page_owned_diagnostics_remove_popup_errors_from_opener_only():
    initial = classify_page_result(
        url="https://portal.example/", status=200, error=None,
        missing_security_headers=[], console_errors=["Popup initial warning"], page_errors=["Popup script warning"],
        failed_resources=[], security_headers_tested=True,
    )
    assert initial["classification"] == "PASS_WITH_WARNINGS"
    opener = refresh_route_api_health(initial, [], console_errors=[], page_errors=[])
    assert opener["classification"] == "PASS"
    assert opener["console_errors"] == opener["page_errors"] == []
    assert opener["console_status"] == "PASS"
    assert opener["warning_count"] == 0
    popup = refresh_route_api_health(
        loaded(), [], console_errors=["Popup initial warning"], page_errors=["Popup script warning"],
    )
    assert popup["classification"] == "PASS_WITH_WARNINGS"
    assert popup["console_status"] == "WARNING"
    assert {item["type"] for item in popup["finding_details"]} == {"CONSOLE_ERROR", "PAGE_SCRIPT_ERROR"}
    assert popup["warning_count"] >= 1


def test_final_diagnostic_reconciliation_preserves_main_document_and_security_evidence():
    result = classify_page_result(
        url="https://portal.example/", status=None, error="net::ERR_CONNECTION_RESET",
        missing_security_headers=["x-frame-options"], console_errors=["Wrong page warning"],
        failed_resources=[], security_headers_tested=False,
    )
    updated = refresh_route_api_health(result, [], console_errors=[], page_errors=["Owned script warning"])
    assert updated["page_load_status"] == "FAILED_TO_LOAD"
    assert updated["classification"] == result["classification"]
    assert updated["passed"] is False
    assert updated["console_errors"] == []
    assert updated["page_errors"] == ["Owned script warning"]
    assert "NAVIGATION_FAILURE" in {item["type"] for item in updated["finding_details"]}
    assert "MISSING_SECURITY_HEADER" in {item["type"] for item in updated["finding_details"]}


@pytest.mark.parametrize("status", [404, 502])
def test_definitive_http_failure_remains_failed_when_transfer_incomplete(status):
    event = {
        "url": "https://portal.example/api/shared", "method": "GET", "status": status,
        "response_seen": True, "response_completed": False, "lifecycle_status": "INCOMPLETE",
    }
    endpoint = aggregate_api_events([event])[0]
    assert endpoint["validation_outcome"] == "FAILED"
    assert endpoint["response_status_counts"] == {str(status): 1}
    assert f"HTTP_{status // 100}XX" in endpoint["failure_types"]
    assert endpoint["incomplete_calls"] == 1
    assert endpoint["lifecycle_status_counts"] == {"INCOMPLETE": 1}
    assert {reason["code"] for reason in endpoint["validation_reasons"]} == {
        f"HTTP_{status}", "RESPONSE_BODY_NOT_COMPLETED",
    }


def test_shared_endpoint_lists_all_initiating_views():
    events = [
        {"url": "https://portal.example/api/shared", "method": "POST", "status": 200,
         "response_completed": True, "initiating_route": route}
        for route in ["https://portal.example/#/view-a", "view:menu:second-tab"]
    ]
    endpoint = aggregate_api_events(events)[0]
    assert endpoint["calls"] == endpoint["route_count"] == 2
    assert endpoint["routes_using_endpoint"] == sorted(event["initiating_route"] for event in events)


def test_policy_abort_is_not_a_target_or_transport_failure():
    assert request_failure_types({
        "blocked_by_validator": True, "error": "net::ERR_BLOCKED_BY_CLIENT",
        "lifecycle_status": "BLOCKED",
    }) == ["POLICY_BLOCKED"]


def test_failed_configuration_and_scripts_remain_resource_failures():
    resources = aggregate_resource_events([
        {"url": "https://portal.example/config.json", "resource_type": "fetch", "status": 502,
         "lifecycle_status": "INCOMPLETE", "response_seen": True,
         "initiating_route": "view:a"},
        {"url": "https://portal.example/app.js", "resource_type": "script", "status": 404,
         "initiating_route": "view:b"},
    ])
    assert len(resources) == 2
    assert sum(item["failures"] for item in resources) == 2
    assert all(item["health"] == "DEGRADED" for item in resources)
    config = next(item for item in resources if item["path"] == "/config.json")
    assert config["response_status_counts"] == {"502": 1}
    assert config["routes_using_resource"] == ["view:a"]
    assert config["failure_types"] == ["HTTP_5XX", "INCOMPLETE"]


def test_blocked_resource_is_not_reported_healthy_or_failed_target():
    resource = aggregate_resource_events([{
        "url": "https://cdn.example/script.js", "resource_type": "script",
        "blocked_by_validator": True, "error": "net::ERR_BLOCKED_BY_CLIENT",
    }])[0]
    assert resource["health"] == "BLOCKED_BY_POLICY"
    assert resource["failures"] == 0
    assert resource["failure_types"] == ["POLICY_BLOCKED"]


def test_canceled_resource_does_not_become_a_target_network_failure():
    resource = aggregate_resource_events([{
        "url": "https://portal.example/optional.png", "resource_type": "image",
        "error": "net::ERR_ABORTED", "lifecycle_status": "CANCELED",
    }])[0]
    assert resource["health"] == "INCOMPLETE"
    assert resource["failures"] == 0
    assert resource["failure_types"] == ["CANCELED"]


def test_navigation_coverage_separates_control_observations_from_unique_views():
    results = [loaded(navigation_controls_discovered=7, unsafe_actions_skipped=2)]
    summary = aggregate_report(results, routes_discovered=4, routes_eligible=4,
                               termination_reason="MAX_ROUTES_REACHED")
    coverage = navigation_coverage(results, summary)
    assert coverage["controls_discovered"] == 7
    assert coverage["safe_candidates"] == 4
    assert coverage["visited_views"] == coverage["validated_views"] == 1
    assert coverage["not_tested_views"] == 3
    assert coverage["skipped_unsafe_controls"] == 2
    assert coverage["total_application_coverage"] == "UNKNOWN"
    assert coverage["limitations"]


def test_http_200_without_ready_shell_does_not_claim_complete_coverage():
    results = [loaded(application_ready=False, authentication_status="AUTHENTICATION_BLOCKED")]
    summary = aggregate_report(results)
    coverage = navigation_coverage(results, summary)
    assert summary["coverage_complete"] is False
    assert coverage["validated_views"] == 0
    assert coverage["authentication_blocked_views"] == coverage["application_not_ready_views"] == 1
    assert {reason["code"] for reason in summary["coverage_reasons"]} == {
        "APPLICATION_NOT_READY", "AUTHENTICATION_INCOMPLETE", "NO_APPLICATION_ROUTES",
    }


def test_authentication_policy_block_is_user_action_not_a_healthy_application():
    result = classify_page_result(
        url="https://portal.example/", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, authentication_classification="AUTHENTICATION_BLOCKED",
    )
    assert result["passed"] is False
    assert result["authentication_status"] == "AUTHENTICATION_BLOCKED"
    assert result["validation_status"] == result["render_status"] == "NOT_TESTED"
    assert result["finding_details"][0]["user_action_required"] is True
    summary = aggregate_report([result])
    assert summary["auth_issues"] == summary["authentication_blocked_pages"] == 1
    assert summary["healthy_routes"] == summary["application_routes_validated"] == 0


def test_resource_details_keep_http_evidence_and_safe_lifecycle_metadata():
    details, summary = build_resource_report([{
        "url": "https://portal.example/config.json?token=do-not-report",
        "resource_type": "fetch", "status": 502, "lifecycle_status": "INCOMPLETE",
        "response_seen": True, "initiating_route": "UI_VIEW_" + "a" * 24,
        "error": None, "Authorization": "do-not-report",
    }])
    assert summary["resource_failures"] == 1
    assert details[0]["failure_reason"] == "HTTP_502"
    assert details[0]["failure_types"] == ["HTTP_5XX", "INCOMPLETE"]
    assert details[0]["lifecycle_status"] == "INCOMPLETE"
    assert details[0]["route"] == "UI_VIEW_" + "a" * 24
    assert "do-not-report" not in str(details)


@pytest.mark.parametrize("blocked,lifecycle,error,reason", [
    (True, "BLOCKED", "net::ERR_BLOCKED_BY_CLIENT", "VALIDATOR_POLICY_BLOCK"),
    (False, "CANCELED", "net::ERR_ABORTED", "CANCELED"),
])
def test_resource_details_policy_and_cancellation_are_not_target_http_failure(blocked, lifecycle, error, reason):
    details, summary = build_resource_report([{
        "url": "https://portal.example/optional.js", "resource_type": "script",
        "blocked_by_validator": blocked, "lifecycle_status": lifecycle, "error": error,
    }])
    assert summary["resource_failures"] == 0
    assert details[0]["failed"] is False
    assert details[0]["failure_reason"] == reason


@pytest.mark.parametrize("flags", [
    {"error": "net::ERR_ABORTED", "lifecycle_status": "FAILED"},
    {"request_canceled": True, "lifecycle_status": "FAILED"},
])
def test_cancellation_survives_resource_report_roundtrip(flags):
    details, _ = build_resource_report([{
        "url": "https://portal.example/optional.js", "resource_type": "script", **flags,
    }])
    assert details[0]["lifecycle_status"] == "CANCELED"
    assert details[0]["request_canceled"] is True
    inventory = aggregate_resource_events(details)
    assert inventory[0]["failures"] == 0
    assert inventory[0]["health"] == "INCOMPLETE"
    assert inventory[0]["failure_types"] == ["CANCELED"]


def test_http_and_body_failure_count_as_one_failed_api_occurrence():
    item = aggregate_api_events([{
        "url": "https://portal.example/api/shared", "method": "GET", "status": 502,
        "response_seen": True, "response_completed": False, "request_failed": True,
        "error": "net::ERR_CONNECTION_RESET", "lifecycle_status": "FAILED",
    }])[0]
    assert item["status_5xx"] == item["response_body_failures"] == 1
    assert item["failure_count"] == item["target_failure_count"] == 1
    assert item["failure_types"] == ["HTTP_5XX", "RESPONSE_BODY_FAILURE"]


def test_late_resource_response_reconciles_original_route_without_renavigation():
    initial = loaded(
        failed_resources=[], resource_failure_count=0, resource_status="PASS",
        api_requests=[],
    )
    final_failure = {
        "url": "https://portal.example/config.json", "status": 502,
        "error": "Resource returned HTTP 502", "main_document": False,
    }
    final = refresh_route_api_health(initial, [], resource_failures=[final_failure])
    assert final["page_load_status"] == "LOADED"
    assert final["classification"] == "PASS_WITH_WARNINGS"
    assert final["resource_status"] == "WARNING"
    assert final["resource_failure_count"] == 1
    assert final["failed_resources"] == [final_failure]
    assert [item["type"] for item in final["finding_details"]] == ["RESOURCE_FAILED"]
    assert final["warning_reasons"][0]["code"] == "NON_CRITICAL_RESOURCE_FAILURE"
    # Reconciliation is idempotent and does not retain a stale resource finding.
    again = refresh_route_api_health(final, [], resource_failures=[final_failure])
    assert again["findings"] == final["findings"] == 1
    cleared = refresh_route_api_health(final, [], resource_failures=[])
    assert cleared["classification"] == "PASS"
    assert cleared["resource_status"] == "PASS"
    assert cleared["resource_failure_count"] == 0


def test_resource_reconciliation_preserves_genuine_main_navigation_failure():
    initial = classify_page_result(
        url="https://portal.example/", status=None, error="net::ERR_CONNECTION_RESET",
        missing_security_headers=[], console_errors=[],
        failed_resources=[{"url": "https://portal.example/", "main_document": True,
                           "error": "net::ERR_CONNECTION_RESET"}],
        security_headers_tested=False,
    )
    final = refresh_route_api_health(initial, [], resource_failures=[])
    assert final["page_load_status"] == "FAILED_TO_LOAD"
    assert final["passed"] is False
    assert any(item["type"] == "MAIN_DOCUMENT_FAILED" for item in final["finding_details"])


@pytest.mark.parametrize("response_seen,reason", [
    (False, "NO_RESPONSE_BEFORE_SCAN_END"),
    (True, "RESPONSE_BODY_NOT_COMPLETED"),
])
def test_resource_incomplete_reason_is_explicit_and_does_not_copy_freeform_input(response_seen, reason):
    details, _ = build_resource_report([{
        "url": "https://portal.example/optional.png", "resource_type": "image",
        "response_seen": response_seen, "response_completed": False,
        "lifecycle_status": "INCOMPLETE", "incomplete_reason": "private-freeform-do-not-report",
    }])
    assert details[0]["incomplete_reason"] == details[0]["failure_reason"] == reason
    assert "private-freeform" not in str(details)


def test_resource_http_error_still_takes_precedence_over_safe_incomplete_reason():
    details, _ = build_resource_report([{
        "url": "https://portal.example/optional.png", "resource_type": "image", "status": 502,
        "response_seen": True, "response_completed": False, "lifecycle_status": "INCOMPLETE",
        "incomplete_reason": "RESPONSE_BODY_NOT_COMPLETED",
    }])
    assert details[0]["failure_reason"] == "HTTP_502"
    assert details[0]["incomplete_reason"] == "RESPONSE_BODY_NOT_COMPLETED"
