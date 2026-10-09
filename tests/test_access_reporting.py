"""Access barriers are not evidence that a generic portal needs credentials."""

import json

import pytest

from app.navigation import classify_authentication
from app.reporting import aggregate_report, classify_page_result


def result(status=200, **overrides):
    settings = dict(
        url="https://portal.example/", status=status, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True,
    )
    settings.update(overrides)
    return classify_page_result(**settings)


@pytest.mark.parametrize("status,code", [(403, "HTTP_ACCESS_RESTRICTED"), (429, "HTTP_RATE_LIMITED")])
@pytest.mark.parametrize("mode", ["none", "basic", "bearer", "storage_state"])
def test_http_access_barriers_never_imply_credentials_or_application_failure(status, code, mode):
    classification = classify_authentication(
        authentication_mode=mode, status=status, final_url="https://portal.example/",
        target_in_scope=True, error_classification=None,
    )
    page = result(status, authentication_classification=classification)
    assert page["classification"] == page["access_status"] == "ACCESS_RESTRICTED"
    assert page["page_load_status"] == "LOADED"
    assert page["tls_status"] == "TRUSTED" and not page["tls"]["bypass_used"]
    assert page["authentication_status"] == page["validation_status"] == "NOT_TESTED"
    assert {finding["type"] for finding in page["finding_details"]} == {code}
    assert "AUTHENTICATION_REQUIRED" not in json.dumps(page)
    summary = aggregate_report([page])
    assert summary["auth_issues"] == summary["failed_pages"] == summary["healthy_routes"] == 0
    assert summary["access_issues"] == summary["access_restricted_pages"] == 1
    assert summary["coverage_status"] == "NONE"
    assert summary["coverage_reasons"] == [
        {"code": "ACCESS_RESTRICTED", "count": 1}, {"code": "NO_APPLICATION_ROUTES", "count": 1},
    ]
    assert page["api_status"] == "NOT_TESTED"


@pytest.mark.parametrize("status", [403, 429])
def test_report_fallback_uses_same_access_classification(status):
    assert result(status)["classification"] == "ACCESS_RESTRICTED"


def test_browser_challenge_is_limited_coverage_not_failed_or_authentication():
    page = result(render_classification="CHALLENGE_REQUIRED")
    assert page["access_status"] == "CHALLENGE_REQUIRED"
    assert page["authentication_status"] == page["validation_status"] == "NOT_TESTED"
    assert any(finding["type"] == "ACCESS_CHALLENGE" for finding in page["finding_details"])
    summary = aggregate_report([page])
    assert summary["challenge_required_pages"] == summary["access_issues"] == 1
    assert summary["auth_issues"] == summary["failed_pages"] == summary["healthy_routes"] == 0
    assert summary["coverage_status"] == "NONE"


def test_mixed_public_auth_and_access_results_have_independent_counts():
    pages = [result(), result(missing_security_headers=["referrer-policy"]),
             result(401), result(403), result(render_classification="CHALLENGE_REQUIRED"), result(500)]
    summary = aggregate_report(pages)
    assert summary["healthy_routes"] == 2
    assert summary["routes_with_warnings"] == 1
    assert summary["auth_issues"] == 1 and summary["access_issues"] == 2
    assert summary["failed_pages"] == 1
    assert summary["coverage_status"] == "PARTIAL"


@pytest.mark.parametrize("status", [404, 500, 503])
def test_actual_http_failures_remain_failures(status):
    page = result(status)
    assert page["classification"] == "HTTP_ERROR"
    assert page["validation_status"] == "FAIL"
    assert aggregate_report([page])["failed_pages"] == 1
