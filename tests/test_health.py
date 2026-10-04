from app.health import api_health_findings, assess_page_health
from app.reporting import aggregate_report, classify_page_result


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
    assert [item["type"] for item in findings] == ["API_SERVER_ERROR", "API_CLIENT_ERROR"]
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
