"""POST evidence is visible without deriving execution permission from names."""

import json

import pytest

from app.network import (
    PassiveNetworkObserver,
    classify_post_observation,
    summarize_post_diagnostics,
    summarize_post_observation,
)


def post_event(**updates):
    event = {
        "method": "POST",
        "url": "https://portal.example/api/items/17/query?token=fixture-private-query",
        "policy_decision": "PENDING",
        "request_classification": "UNKNOWN",
        "allowed_by_policy": False,
        "response_completed": False,
    }
    event.update(updates)
    return event


@pytest.mark.parametrize("method", ["GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_post_classification_does_not_relabel_other_methods(method):
    assert classify_post_observation(post_event(method=method)) == []


@pytest.mark.parametrize("classification", ["APPROVED_READ_POST", "APPROVED_READ_REQUEST", "APPROVED_READ_ONLY"])
def test_only_explicit_approved_policy_establishes_read_only(classification):
    event = post_event(request_classification=classification, policy_decision="ALLOW")
    assert classify_post_observation(event) == ["POST_OBSERVED", "POST_READ_ONLY_APPROVED"]
    event["policy_decision"] = "PENDING"
    assert classify_post_observation(event) == ["POST_OBSERVED", "POST_READ_ONLY_UNVERIFIED"]


def test_policy_approval_never_comes_from_success_name_or_authentication_phase():
    event = post_event(
        url="https://portal.example/api/read-only-search",
        phase="AUTHENTICATION", status=200, response_seen=True, response_completed=True,
    )
    assert classify_post_observation(event) == ["POST_OBSERVED", "POST_READ_ONLY_UNVERIFIED"]
    summary = summarize_post_diagnostics([event])
    assert summary["post_requests_allowed"] == summary["approved_read_only_post_endpoints"] == 0
    assert summary["unverified_post_endpoints"] == 1


@pytest.mark.parametrize("classification", ["AUTH_FLOW", "SESSION_REFRESH"])
def test_explicit_authentication_is_separate_from_read_only_approval(classification):
    event = post_event(request_classification=classification, policy_decision="ALLOW")
    assert classify_post_observation(event) == ["POST_OBSERVED", "POST_AUTH_BOOTSTRAP"]
    summary = summarize_post_diagnostics([event])
    assert summary["post_requests_allowed"] == 1
    assert summary["approved_read_only_post_endpoints"] == summary["unverified_post_endpoints"] == 0
    event["policy_decision"] = "PENDING"
    assert "POST_AUTH_BOOTSTRAP" not in classify_post_observation(event)


def test_blocked_mutation_has_orthogonal_explainable_labels():
    event = post_event(
        blocked_by_validator=True, policy_decision="BLOCK",
        policy_classification="READ_ONLY_BLOCKED", block_reason="READ_ONLY_MUTATION_BLOCKED",
        request_failed=True, error="net::ERR_BLOCKED_BY_CLIENT",
    )
    assert classify_post_observation(event) == [
        "POST_OBSERVED", "POST_READ_ONLY_UNVERIFIED", "POST_BLOCKED_BY_POLICY", "POST_MUTATION_RESTRICTED",
    ]
    summary = summarize_post_diagnostics([event])
    assert summary["post_requests_observed"] == summary["post_requests_blocked"] == 1
    assert summary["post_requests_allowed"] == 0
    assert summary["post_requests_without_completed_responses"] == 1


def test_network_policy_block_is_not_automatically_a_mutation_or_network_failure():
    event = post_event(
        blocked_by_validator=True, policy_decision="BLOCK",
        request_classification="BLOCKED_BY_NETWORK_POLICY", block_reason="NETWORK_POLICY",
        request_failed=True, error="net::ERR_BLOCKED_BY_CLIENT",
    )
    assert classify_post_observation(event) == [
        "POST_OBSERVED", "POST_READ_ONLY_UNVERIFIED", "POST_BLOCKED_BY_POLICY",
    ]


def test_mutation_word_in_url_does_not_overrule_explicit_policy():
    event = post_event(
        url="https://portal.example/api/delete-history/query",
        policy_classification="APPROVED_READ_ONLY", policy_decision="ALLOW",
    )
    assert classify_post_observation(event) == ["POST_OBSERVED", "POST_READ_ONLY_APPROVED"]


def test_genuine_network_failure_preserves_explicit_read_only_approval():
    event = post_event(
        request_classification="APPROVED_READ_POST", policy_decision="ALLOW",
        request_failed=True, failure_category="NETWORK_FAILURE", error="net::ERR_CONNECTION_RESET",
    )
    assert classify_post_observation(event) == [
        "POST_OBSERVED", "POST_READ_ONLY_APPROVED", "POST_NETWORK_FAILED",
    ]


@pytest.mark.parametrize("updates", [
    {"request_failed": True, "request_canceled": True, "error": "net::ERR_ABORTED"},
    {"request_failed": True, "lifecycle_status": "CANCELED", "error": "Request canceled"},
    {"error": "net::ERR_ABORTED"},
    {"error": "AbortError: operation aborted"},
    {"request_failed": True, "status": 200, "response_seen": True,
     "failure_category": "RESPONSE_BODY_FAILURE", "error": "net::ERR_CONNECTION_RESET"},
    {"status": 500, "response_seen": True, "response_completed": True},
    {"status": 200, "response_seen": True, "lifecycle_status": "INCOMPLETE"},
    {"lifecycle_status": "INCOMPLETE"},
])
def test_policy_cancellation_http_and_incomplete_results_are_not_network_failure(updates):
    assert "POST_NETWORK_FAILED" not in classify_post_observation(post_event(**updates))


def test_diagnostics_reconcile_calls_and_sanitized_endpoint_groups():
    events = [
        post_event(request_classification="APPROVED_READ_POST", policy_decision="ALLOW",
                   status=200, response_completed=True),
        post_event(url="https://portal.example/api/items/18/query?token=another-private-query",
                   policy_classification="APPROVED_READ_ONLY", policy_decision="ALLOW",
                   status=200, response_completed=True, protocol="GRAPHQL"),
        post_event(blocked_by_validator=True, policy_decision="BLOCK", block_reason="READ_ONLY_MUTATION_BLOCKED"),
        post_event(),
        post_event(url="https://identity.example/oauth/callback",
                   request_classification="AUTH_FLOW", policy_decision="ALLOW", status=200, response_completed=True),
        post_event(url="https://portal.example/api/lookup", request_classification="APPROVED_READ_POST",
                   policy_decision="ALLOW", request_failed=True, error="net::ERR_CONNECTION_RESET"),
        post_event(method="GET", url="https://portal.example/api/items/17/query"),
    ]
    assert summarize_post_diagnostics(events, total_http_requests=22) == {
        "total_http_requests_observed": 22,
        "post_requests_observed": 6,
        "post_requests_allowed": 4,
        "post_requests_blocked": 1,
        "approved_read_only_post_endpoints": 2,
        "unverified_post_endpoints": 1,
        "post_requests_without_completed_responses": 3,
        "unique_post_endpoints_reported": 3,
    }
    # The old three-field contract remains untouched for stored reports/UI.
    assert summarize_post_observation(events) == {
        "observed_calls": 6, "approved_read_only_calls": 3, "executed_approved_calls": 2,
    }
    assert "fixture-private-query" not in json.dumps(summarize_post_diagnostics(events))


def test_total_http_is_unknown_when_only_api_records_are_available():
    summary = summarize_post_diagnostics([post_event()])
    assert summary["total_http_requests_observed"] is None
    assert summary["post_requests_observed"] == 1


@pytest.mark.parametrize("total", [-1, True, 1.5, "12"])
def test_http_counter_rejects_untrustworthy_values(total):
    with pytest.raises(ValueError, match="non-negative integer"):
        summarize_post_diagnostics([], total_http_requests=total)


class MetadataOnlyRequest:
    method = "POST"
    url = "https://portal.example/api/query?token=fixture-private-query"
    resource_type = "fetch"

    @property
    def headers(self):
        raise AssertionError("Passive metadata observation must not inspect headers")

    @property
    def post_data(self):
        raise AssertionError("Passive metadata observation must not inspect payloads")


def observe_request(observer, request):
    return observer.observe_request(
        request, phase="ROUTE_VALIDATION", importance="REQUIRED",
        initiating_route="https://portal.example/dashboard", main_document=False,
    )


def test_observer_updates_classifications_without_accessing_payload_or_headers():
    events = []
    observer = PassiveNetworkObserver(events)
    request = MetadataOnlyRequest()
    event = observe_request(observer, request)
    assert event["post_classifications"] == ["POST_OBSERVED", "POST_READ_ONLY_UNVERIFIED"]
    observer.mark_allowed(request, "APPROVED_READ_POST")
    assert event["post_classifications"] == ["POST_OBSERVED", "POST_READ_ONLY_APPROVED"]
    observer.mark_dispatched(request)
    observer.record_failure(request, "net::ERR_CONNECTION_RESET")
    assert event["post_classifications"] == [
        "POST_OBSERVED", "POST_READ_ONLY_APPROVED", "POST_NETWORK_FAILED",
    ]
    observer.finalize_pending()
    assert event["post_classifications"] == classify_post_observation(event)
    assert len(events) == 1
    assert "fixture-private-query" not in json.dumps(events)


def test_native_response_does_not_fabricate_read_only_or_authentication_approval():
    observer = PassiveNetworkObserver([])
    request = MetadataOnlyRequest()
    event = observe_request(observer, request)
    observer.record_response(request, 200)
    observer.record_finished(request)
    observer.finalize_pending()
    assert event["post_classifications"] == ["POST_OBSERVED", "POST_READ_ONLY_UNVERIFIED"]
    assert event["policy_decision"] == "PENDING"


def test_finalized_observer_does_not_reclassify_cleanup_as_target_failure():
    observer = PassiveNetworkObserver([])
    request = MetadataOnlyRequest()
    event = observe_request(observer, request)
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.mark_dispatched(request)
    observer.finalize_pending()
    labels = list(event["post_classifications"])
    observer.record_failure(request, "net::ERR_ABORTED")
    observer.mark_blocked(request, "CONTEXT_CLOSED")
    assert event["post_classifications"] == labels == ["POST_OBSERVED", "POST_READ_ONLY_APPROVED"]
