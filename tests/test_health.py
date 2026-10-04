import pytest

from app.health import api_health_findings, assess_page_health
from app.reporting import (
    aggregate_api_events,
    aggregate_api_inventory,
    aggregate_report,
    aggregate_resource_inventory,
    aggregate_security_recommendations,
    classify_page_result,
)


def test_blank_main_document_is_a_render_failure():
    classification, findings = assess_page_health(
        {"text_length": 0, "visible_elements": 1, "busy_indicators": 0, "title": "", "alert_text": ""},
        load_ms=100,
        slow_page_threshold_ms=5000,
    )
    result = classify_page_result(
        url="https://portal.example.com", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, render_classification=classification,
        additional_findings=findings,
    )
    assert result["page_load_status"] == "LOADED"
    assert result["classification"] == "PAGE_RENDER_ERROR"
    assert result["validation_status"] == "FAIL"


def test_slow_busy_route_is_warning_not_failed_load():
    classification, findings = assess_page_health(
        {"text_length": 500, "visible_elements": 25, "busy_indicators": 1, "title": "Portal", "alert_text": ""},
        load_ms=6000,
        slow_page_threshold_ms=5000,
    )
    result = classify_page_result(
        url="https://portal.example.com", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, render_classification=classification,
        additional_findings=findings,
    )
    assert result["classification"] == "PASS_WITH_WARNINGS"
    assert result["page_load_status"] == "LOADED"
    assert {item["type"] for item in result["finding_details"]} == {"SLOW_PAGE", "RENDER_STILL_BUSY"}


def test_api_failures_are_observed_without_calling_apis():
    findings = api_health_findings([
        {"url": "https://api.example.net/data", "status": 503, "error": None},
        {"url": "https://api.example.net/profile", "status": 401, "error": None},
    ])
    assert [item["type"] for item in findings] == [
        "API_SERVER_ERROR", "API_AUTHENTICATION_FAILURE",
    ]
    assert findings[0]["blocking"] is True
    assert findings[1]["blocking"] is False


def test_read_only_mutation_block_is_a_non_load_warning():
    result = classify_page_result(
        url="https://portal.example.com", status=200, error=None,
        missing_security_headers=[], console_errors=[],
        failed_resources=[{
            "url": "https://portal.example.com/api/update", "error": "net::ERR_BLOCKED_BY_CLIENT",
            "resource_type": "fetch", "main_document": False, "blocked_by_validator": True,
            "block_reason": "read_only_mutation_policy",
        }],
        security_headers_tested=True,
    )
    assert result["page_load_status"] == "LOADED"
    assert result["classification"] == "PASS_WITH_WARNINGS"
    assert result["finding_details"][0]["type"] == "READ_ONLY_MUTATION_BLOCKED"


def test_portal_health_summary_counts_operational_signals():
    result = classify_page_result(
        url="https://portal.example.com", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True,
    )
    result.update({
        "load_ms": 5100, "slow": True, "api_failures": 2, "resource_failure_count": 1,
        "unsafe_actions_skipped": 3, "read_only_blocks": 1,
    })
    summary = aggregate_report([result], routes_discovered=4)
    assert summary["routes_discovered"] == 4
    assert summary["routes_validated"] == 1
    assert summary["healthy_routes"] == 1
    assert summary["api_failures"] == 2
    assert summary["slow_pages"] == 1
    assert summary["read_only_blocks"] == 1


def test_spa_route_without_http_response_is_loaded_with_inherited_tls_and_headers():
    result = classify_page_result(
        url="https://portal.example.com/dashboard", status=None, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, route_transition_succeeded=True,
        navigation_mode="SPA_ROUTE_TRANSITION", inherited_strict_tls=True,
        security_headers_inherited=True,
    )
    assert result["page_load_status"] == "LOADED"
    assert result["classification"] == "PASS"
    assert result["validation_status"] == "PASS"
    assert result["tls_status"] == "TRUSTED"
    assert result["tls_basis"] == "INHERITED_STRICT_BROWSER_CONTEXT"
    assert result["tls"]["new_handshake"] is False
    assert result["security_headers_basis"] == "INHERITED_DOCUMENT_RESPONSE"


def test_spa_api_failure_fails_health_without_failing_page_load():
    findings = api_health_findings([
        {"url": "https://portal.example.com/api/health", "status": 502, "error": None},
    ])
    result = classify_page_result(
        url="https://portal.example.com/health", status=None, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, route_transition_succeeded=True,
        navigation_mode="SPA_ROUTE_TRANSITION", inherited_strict_tls=True,
        security_headers_inherited=True, additional_findings=findings,
    )
    assert result["page_load_status"] == "LOADED"
    assert result["classification"] == "VALIDATION_FAILED"
    assert result["validation_status"] == "FAIL"
    assert result["api_status"] == "FAIL"
    assert result["failure_dimension"] == "API"
    assert "HTTP 502" in result["failure_reason"]


def test_optional_background_api_failure_is_explained_without_failing_route():
    findings = api_health_findings([{
        "url": "https://telemetry.example.net/collect",
        "status": 503,
        "error": None,
        "importance": "OPTIONAL",
    }])
    result = classify_page_result(
        url="https://portal.example.com/reports", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, additional_findings=findings,
    )
    assert result["classification"] == "PASS_WITH_WARNINGS"
    assert result["api_status"] == "WARNING"
    assert result["failure_reason"] is None


def test_failed_spa_transition_is_a_navigation_failure():
    result = classify_page_result(
        url="https://portal.example.com/missing", status=None,
        error="Same-document route transition did not reach the requested route",
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=False, route_transition_succeeded=False,
        navigation_mode="SPA_ROUTE_TRANSITION",
    )
    assert result["page_load_status"] == "FAILED_TO_LOAD"
    assert result["classification"] == "NAVIGATION_ERROR"
    assert result["security_headers_status"] == "NOT_TESTED"


def test_blank_spa_route_is_loaded_but_render_failed():
    classification, findings = assess_page_health(
        {"text_length": 0, "visible_elements": 0, "busy_indicators": 0, "title": "", "alert_text": ""},
        load_ms=50,
        slow_page_threshold_ms=5000,
    )
    result = classify_page_result(
        url="https://portal.example.com/blank", status=None, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, route_transition_succeeded=True,
        navigation_mode="SPA_ROUTE_TRANSITION", inherited_strict_tls=True,
        security_headers_inherited=True, render_classification=classification,
        additional_findings=findings,
    )
    assert result["page_load_status"] == "LOADED"
    assert result["classification"] == "PAGE_RENDER_ERROR"


def test_explicit_route_coverage_reports_complete_and_partial_scans():
    complete_results = []
    for index in range(44):
        result = classify_page_result(
            url=f"https://portal.example.com/{index}", status=200, error=None,
            missing_security_headers=[], console_errors=[], failed_resources=[],
            security_headers_tested=True,
        )
        result["load_ms"] = 1
        complete_results.append(result)
    complete = aggregate_report(
        complete_results,
        routes_discovered=44,
        routes_eligible=44,
        routes_queued=44,
        routes_remaining=0,
        termination_reason="DISCOVERY_EXHAUSTED",
    )
    assert complete["routes_validated"] == 44
    assert complete["scan_completeness"] == "COMPLETE"

    partial = aggregate_report(
        complete_results + complete_results[:6],
        routes_discovered=100,
        routes_eligible=100,
        routes_queued=100,
        routes_remaining=50,
        termination_reason="MAX_ROUTES_REACHED",
    )
    assert partial["routes_validated"] == 50
    assert partial["routes_remaining"] == 50
    assert partial["scan_completeness"] == "PARTIAL"
    assert partial["termination_reason"] == "MAX_ROUTES_REACHED"


@pytest.mark.parametrize(("validated", "healthy", "failed", "not_tested"), [
    (10, 9, 1, 34),
    (40, 38, 2, 4),
])
def test_terminal_route_counters_use_one_canonical_invariant(
    validated, healthy, failed, not_tested,
):
    results = []
    for index in range(validated):
        result = classify_page_result(
            url=f"https://portal.example.com/{index}",
            status=500 if index >= healthy else 200,
            error=None,
            missing_security_headers=[],
            console_errors=[],
            failed_resources=[],
            security_headers_tested=True,
        )
        result["load_ms"] = 1
        results.append(result)
    summary = aggregate_report(
        results,
        routes_discovered=44,
        routes_eligible=44,
        routes_queued=44,
        routes_remaining=not_tested,
        termination_reason="MAX_ROUTES_REACHED",
    )
    assert summary["routes_discovered"] == 44
    assert summary["routes_validated"] == validated
    assert summary["healthy_routes"] == healthy
    assert summary["failed_pages"] == failed
    assert summary["routes_not_tested"] == not_tested
    assert summary["not_tested"] == not_tested
    assert summary["routes_discovered"] == (
        summary["routes_validated"]
        + summary["routes_not_tested"]
        + summary["routes_skipped"]
    )
    assert summary["not_tested_reason_counts"] == {
        "NOT_TESTED_MAX_ROUTES": not_tested,
    }


def test_api_inventory_correlates_routes_and_classifies_401_without_auth_failure():
    results = [
        {
            "normalized_route_identity": "https://portal.example.com/home",
            "api_requests": [
                {"url": "https://api.example.net/profile?token=REDACTED", "method": "GET", "protocol": "REST", "status": 401, "error": None, "duration_ms": 20},
                {"url": "https://api.example.net/profile", "method": "GET", "protocol": "REST", "status": 200, "error": None, "duration_ms": 10},
            ],
        },
        {
            "normalized_route_identity": "https://portal.example.com/settings",
            "api_requests": [
                {"url": "https://api.example.net/profile", "method": "GET", "protocol": "REST", "status": 200, "error": None, "duration_ms": 30},
            ],
        },
    ]
    inventory = aggregate_api_inventory(results)
    assert len(inventory) == 1
    endpoint = inventory[0]
    assert endpoint["calls"] == 3
    assert endpoint["status_2xx"] == 2
    assert endpoint["status_4xx"] == 1
    assert endpoint["failure_classifications"] == {"API_AUTHENTICATION_FAILURE": 1}
    assert endpoint["route_count"] == 2
    assert endpoint["average_duration_ms"] == 20
    assert endpoint["health"] == "DEGRADED"


def test_scan_wide_api_events_preserve_early_and_route_correlated_requests():
    inventory = aggregate_api_events([
        {
            "url": "https://identity.example.net/session?code=REDACTED",
            "method": "POST",
            "protocol": "REST",
            "status": 200,
            "error": None,
            "phase": "AUTHENTICATION",
            "importance": "AUTHENTICATION",
            "observed_at": "2026-01-01T00:00:00+00:00",
            "initiating_route": None,
        },
        {
            "url": "https://api.example.net/items?token=REDACTED",
            "method": "GET",
            "protocol": "REST",
            "status": 200,
            "error": None,
            "phase": "VALIDATION",
            "importance": "REQUIRED",
            "observed_at": "2026-01-01T00:00:01+00:00",
            "initiating_route": "https://portal.example.com/items",
        },
    ])
    assert [(item["host"], item["endpoint"]) for item in inventory] == [
        ("api.example.net", "/items"),
        ("identity.example.net", "/session"),
    ]
    assert inventory[0]["routes_using_endpoint"] == [
        "https://portal.example.com/items",
    ]
    auth_item = inventory[1]
    assert auth_item["method"] == "POST"
    assert auth_item["authentication_phase_count"] == 1
    assert auth_item["validation_phase_count"] == 0
    assert auth_item["first_seen"] == "2026-01-01T00:00:00+00:00"
    assert "REDACTED" not in str(inventory)


def test_validator_blocks_are_auditable_but_not_target_api_failures():
    inventory = aggregate_api_events([{
        "url": "https://portal.example.com/update",
        "method": "POST",
        "protocol": "REST",
        "status": None,
        "error": "net::ERR_BLOCKED_BY_CLIENT",
        "blocked_by_validator": True,
        "initiating_route": "https://portal.example.com/settings",
    }])
    assert inventory[0]["calls"] == 1
    assert inventory[0]["validator_blocks"] == 1
    assert inventory[0]["blocked_count"] == 1
    assert inventory[0]["network_failures"] == 0
    assert inventory[0]["health"] == "HEALTHY"


def test_inherited_spa_security_recommendations_are_not_repeated_as_findings():
    document = classify_page_result(
        url="https://portal.example.com/", status=200, error=None,
        missing_security_headers=["content-security-policy"], console_errors=[],
        failed_resources=[], security_headers_tested=True,
    )
    document.update({
        "normalized_route_identity": "https://portal.example.com/",
        "missing_security_headers": ["content-security-policy"],
    })
    spa = classify_page_result(
        url="https://portal.example.com/#/reports", status=None, error=None,
        missing_security_headers=["content-security-policy"], console_errors=[],
        failed_resources=[], security_headers_tested=True,
        route_transition_succeeded=True, inherited_strict_tls=True,
        security_headers_inherited=True, include_security_header_findings=False,
    )
    spa.update({
        "normalized_route_identity": "https://portal.example.com/#/reports",
        "missing_security_headers": ["content-security-policy"],
    })
    assert document["classification"] == "PASS_WITH_WARNINGS"
    assert spa["classification"] == "PASS"
    assert spa["security_headers_status"] == "WARNING"
    recommendations = aggregate_security_recommendations([document, spa])
    assert len(recommendations) == 1
    assert recommendations[0]["affected_document_count"] == 1


def test_resource_inventory_keeps_resources_separate_from_routes_and_apis():
    inventory = aggregate_resource_inventory([{
        "normalized_route_identity": "https://portal.example.com/home",
        "resources": [
            {"url": "https://cdn.example.net/app.js", "resource_type": "script", "status": 200, "error": None},
            {"url": "https://cdn.example.net/app.js", "resource_type": "script", "status": 503, "error": None},
        ],
    }])
    assert inventory == [{
        "host": "cdn.example.net",
        "path": "/app.js",
        "type": "SCRIPT",
        "calls": 2,
        "failures": 1,
        "routes_using_resource": ["https://portal.example.com/home"],
        "route_count": 1,
        "health": "DEGRADED",
    }]
