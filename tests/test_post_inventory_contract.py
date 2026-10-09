"""The observed inventory exposes decisions without changing execution policy."""

import json

from app.reporting import aggregate_api_events, aggregate_report


def event(request_id, *, method="POST", endpoint="/api/read", **metadata):
    return {
        "request_id": request_id,
        "method": method,
        "url": f"https://portal.example{endpoint}?token=fixture-query-secret",
        "initiating_route": "UI_VIEW_fixture_reports",
        "phase": "ROUTE_VALIDATION",
        **metadata,
    }


def test_inventory_post_evidence_reconciles_multiple_natural_calls_and_blocked_attempts():
    events = [
        event("read-1", request_classification="APPROVED_READ_POST", policy_decision="ALLOW",
              request_dispatched=True, response_seen=True, response_completed=True, status=200, duration_ms=20),
        event("read-2", request_classification="APPROVED_READ_POST", policy_decision="ALLOW",
              request_dispatched=True, response_seen=True, response_completed=True, status=503, duration_ms=40),
        event("read-3", request_classification="BLOCKED_MUTATION", policy_decision="BLOCK",
              blocked_by_validator=True, block_reason="READ_ONLY_MUTATION_BLOCKED", lifecycle_status="BLOCKED"),
    ]
    item = aggregate_api_events(events)[0]
    assert item["calls"] == item["observed_calls"] == 3
    assert item["allowed_calls"] == 2 and item["blocked_calls"] == 1
    assert item["response_status_counts"] == {"200": 1, "503": 1}
    assert item["failure_count"] == item["target_failure_count"] == 1
    assert item["average_duration_ms"] == 30 and item["worst_duration_ms"] == 40
    assert item["routes_using_endpoint"] == ["UI_VIEW_fixture_reports"]
    assert item["post_classification_counts"] == {
        "POST_OBSERVED": 3,
        "POST_READ_ONLY_APPROVED": 2,
        "POST_READ_ONLY_UNVERIFIED": 1,
        "POST_BLOCKED_BY_POLICY": 1,
        "POST_MUTATION_RESTRICTED": 1,
    }
    assert item["post_classifications"] == sorted(item["post_classification_counts"])
    assert item["authentication_classifications"] == ["NOT_AUTHENTICATION"]
    assert item["authentication_classification_counts"] == {"NOT_AUTHENTICATION": 3}
    assert "fixture-query-secret" not in json.dumps(item)


def test_blocked_post_is_visible_with_explicit_policy_status_and_not_target_failure():
    item = aggregate_api_events([
        event("blocked", endpoint="/api/unapproved", blocked_by_validator=True,
              request_classification="BLOCKED_MUTATION", policy_decision="BLOCK",
              block_reason="READ_ONLY_MUTATION_BLOCKED", lifecycle_status="BLOCKED"),
    ])[0]
    assert item["method"] == "POST" and item["calls"] == 1
    assert item["observation_status"] == "BLOCKED_BY_POLICY"
    assert item["observation_outcome"] == "BLOCKED_BY_VALIDATOR"  # Legacy compatibility.
    assert item["health"] == "NOT_EXECUTED"
    assert item["failure_count"] == item["sent_calls"] == 0
    assert item["response_status_counts"] == {}
    assert item["block_reasons"] == {"READ_ONLY_MUTATION_BLOCKED": 1}


def test_authentication_and_network_failure_classifications_are_independent_of_read_only():
    inventory = aggregate_api_events([
        event("auth", endpoint="/saml/consume", request_classification="AUTH_FLOW",
              policy_decision="ALLOW", phase="AUTHENTICATION", status=302,
              response_seen=True, response_completed=True),
        event("refresh", endpoint="/oauth/refresh", request_classification="SESSION_REFRESH",
              policy_decision="ALLOW", phase="SESSION_REFRESH", status=200,
              response_seen=True, response_completed=True),
        event("failed", endpoint="/api/read", request_classification="APPROVED_READ_POST",
              policy_decision="ALLOW", error="net::ERR_CONNECTION_RESET",
              request_failed=True, failure_category="NETWORK_FAILURE", request_dispatched=True),
        event("pending", endpoint="/api/pending", request_classification="APPLICATION_REQUEST",
              policy_decision="PENDING", lifecycle_status="INCOMPLETE"),
    ])
    items = {item["endpoint"]: item for item in inventory}
    assert items["/saml/consume"]["post_classifications"] == ["POST_AUTH_BOOTSTRAP", "POST_OBSERVED"]
    assert items["/saml/consume"]["authentication_classifications"] == ["AUTH_BOOTSTRAP"]
    assert items["/oauth/refresh"]["authentication_classifications"] == ["SESSION_REFRESH"]
    assert items["/api/read"]["post_classifications"] == [
        "POST_NETWORK_FAILED", "POST_OBSERVED", "POST_READ_ONLY_APPROVED",
    ]
    assert items["/api/read"]["failure_count"] == 1
    assert items["/api/pending"]["observation_status"] == "INCOMPLETE"
    assert items["/api/pending"]["calls"] == 1
    assert items["/api/pending"]["post_classifications"] == ["POST_OBSERVED", "POST_READ_ONLY_UNVERIFIED"]


def test_all_observed_http_methods_survive_aggregation_including_options():
    methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    inventory = aggregate_api_events([
        event(method, method=method, endpoint=f"/api/{method.lower()}",
              blocked_by_validator=method in {"PUT", "PATCH", "DELETE"},
              status=None if method in {"PUT", "PATCH", "DELETE"} else 200)
        for method in methods
    ])
    assert sorted(item["method"] for item in inventory) == sorted(methods)
    assert sum(item["calls"] for item in inventory) == len(methods)
    assert all(item["post_classifications"] == [] for item in inventory if item["method"] != "POST")


def test_failure_count_counts_calls_not_multiple_failure_dimensions():
    item = aggregate_api_events([
        event("failed-response", status=503, error="net::ERR_CONNECTION_RESET", request_failed=True),
        event("canceled-response", status=200, error="net::ERR_ABORTED", request_failed=True, request_canceled=True),
    ])[0]
    assert item["calls"] == 2
    assert item["failure_count"] == 1
    assert item["target_failure_count"] == 2  # Existing dimension-based field remains unchanged.


def test_report_adds_eight_diagnostics_without_changing_legacy_post_summary():
    events = [
        event("read-1", request_classification="APPROVED_READ_POST", policy_decision="ALLOW",
              request_dispatched=True, response_seen=True, response_completed=True, status=200),
        event("read-2", request_classification="APPROVED_READ_POST", policy_decision="ALLOW",
              request_dispatched=True, lifecycle_status="INCOMPLETE"),
        event("blocked", endpoint="/api/unapproved", request_classification="BLOCKED_MUTATION",
              policy_decision="BLOCK", blocked_by_validator=True, lifecycle_status="BLOCKED"),
    ]
    result = {
        "classification": "PASS", "page_load_status": "LOADED", "validation_status": "PASS",
        "api_requests": [dict(events[0]), dict(events[0])],
    }
    summary = aggregate_report([result], api_events=events)
    assert summary["post_summary"] == {
        "observed_calls": 3, "approved_read_only_calls": 2, "executed_approved_calls": 2,
    }
    assert summary["post_diagnostics"] == {
        "total_http_requests_observed": None,
        "post_requests_observed": 3,
        "post_requests_allowed": 2,
        "post_requests_blocked": 1,
        "approved_read_only_post_endpoints": 1,
        "unverified_post_endpoints": 1,
        "post_requests_without_completed_responses": 2,
        "unique_post_endpoints_reported": 2,
    }
    assert summary["post_diagnostics"] == json.loads(json.dumps(summary))["post_diagnostics"]
