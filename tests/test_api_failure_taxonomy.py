"""Browser TLS/timeout diagnostics remain distinct from cancellations and policy."""

import pytest

from app.health import api_health_findings
from app.network import PassiveNetworkObserver
from app.reporting import aggregate_api_events, classify_api_status


class Request:
    method = "GET"
    url = "https://portal.example/api/read?token=fixture-secret"
    resource_type = "fetch"


@pytest.mark.parametrize(("error", "classification"), [
    ("net::ERR_TIMED_OUT", "API_TIMEOUT"),
    ("The connection timed out", "API_TIMEOUT"),
    ("Timeout 30000ms exceeded", "API_TIMEOUT"),
    ("net::ERR_SSL_PROTOCOL_ERROR", "API_TLS_FAILURE"),
])
def test_browser_failure_matches_route_findings_and_endpoint_classification(error, classification):
    observer = PassiveNetworkObserver([])
    request = Request()
    event = observer.observe_request(
        request, phase="ROUTE_VALIDATION", importance="REQUIRED",
        initiating_route="https://portal.example/#/reports", main_document=False,
    )
    observer.mark_allowed(request, "SAFE_METHOD")
    observer.mark_dispatched(request)
    observer.record_failure(request, error)
    observer.finalize_pending()

    item = aggregate_api_events([event])[0]
    findings = api_health_findings([event])
    assert classify_api_status(None, error) == classification
    assert item["failure_classifications"] == {classification: 1}
    assert item["failure_count"] == item["network_failures"] == 1
    assert [finding["type"] for finding in findings] == [classification]
    assert event["lifecycle_status"] == "FAILED"
    assert item["completed_calls"] == item["incomplete_calls"] == item["canceled_calls"] == 0


@pytest.mark.parametrize("blocked", [False, True])
def test_browser_abort_does_not_imply_a_target_timeout(blocked):
    observer = PassiveNetworkObserver([])
    request = Request()
    event = observer.observe_request(
        request, phase="ROUTE_VALIDATION", importance="REQUIRED",
        initiating_route="https://portal.example/#/reports", main_document=False,
    )
    if blocked:
        observer.mark_blocked(request, "NETWORK_POLICY")
    observer.record_failure(request, "net::ERR_ABORTED")
    observer.finalize_pending()

    item = aggregate_api_events([event])[0]
    findings = api_health_findings([event])
    assert item["failure_count"] == item["network_failures"] == 0
    assert "API_TIMEOUT" not in item["failure_classifications"]
    assert all(finding["type"] != "API_TIMEOUT" for finding in findings)
    assert item["blocked_calls"] == int(blocked)
    assert item["canceled_calls"] == int(not blocked)
