"""POST observation, network dispatch and read-only approval remain separate."""

import asyncio
import json

import pytest

from app.network import (
    PassiveNetworkObserver,
    drain_pending_api_observations,
    summarize_post_observation,
)
from app.reporting import aggregate_api_events, aggregate_report


class Request:
    method = "POST"
    resource_type = "fetch"
    url = "https://portal.example/api/query?token=fixture-private-query"


def observe(observer, request):
    return observer.observe_request(
        request,
        phase="ROUTE_VALIDATION",
        importance="REQUIRED",
        initiating_route="https://portal.example/dashboard",
        main_document=False,
        route_activation_id="route-1",
    )


def test_native_redirect_response_proves_dispatch_but_not_read_only_approval():
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    event = observe(observer, request)
    # Native HTTP redirect requests are observed, but Playwright deliberately
    # does not invoke context.route() again for their intermediate hops.
    observer.record_response(request, 200)
    observer.record_finished(request)
    observer.finalize_pending()

    item = aggregate_api_events(events)[0]
    assert item["observed_calls"] == item["sent_calls"] == 1
    assert item["responded_calls"] == item["completed_calls"] == 1
    assert event["request_reached_network"] is True
    assert event["route_handler_seen"] is False
    assert event["policy_evaluated"] is False
    assert event["policy_decision"] == "PENDING"
    assert item["allowed_calls"] == 0
    assert item["approved_read_only_calls"] == item["executed_approved_calls"] == 0
    assert summarize_post_observation(events) == {
        "observed_calls": 1, "approved_read_only_calls": 0, "executed_approved_calls": 0,
    }
    assert "fixture-private-query" not in json.dumps(events)


@pytest.mark.parametrize("classification", ["APPROVED_READ_POST", "APPROVED_READ_REQUEST"])
@pytest.mark.parametrize("stage", ["allowed", "sent", "responded", "completed", "failed", "canceled"])
def test_approved_post_execution_uses_actual_dispatch_evidence(classification, stage):
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    observe(observer, request)
    observer.mark_allowed(request, classification)
    if stage in {"sent", "failed", "canceled"}:
        observer.mark_dispatched(request)
    if stage in {"responded", "completed"}:
        observer.record_response(request, 200)
    if stage == "completed":
        observer.record_finished(request)
    elif stage in {"failed", "canceled"}:
        observer.record_failure(
            request, "net::ERR_ABORTED" if stage == "canceled" else "net::ERR_CONNECTION_RESET",
        )
    observer.finalize_pending()

    summary = summarize_post_observation(events)
    assert summary == {
        "observed_calls": 1,
        "approved_read_only_calls": 1,
        "executed_approved_calls": int(stage != "allowed"),
    }
    item = aggregate_api_events(events)[0]
    assert item["approved_read_only_calls"] == summary["approved_read_only_calls"]
    assert item["executed_approved_calls"] == summary["executed_approved_calls"]
    assert item["completed_calls"] == int(stage == "completed")


@pytest.mark.parametrize("classification", ["AUTH_FLOW", "SESSION_REFRESH", "ACCESS_GATE", "APPLICATION_REQUEST"])
def test_successful_non_read_only_post_does_not_become_approved(classification):
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    observe(observer, request)
    observer.mark_allowed(request, classification)
    observer.record_response(request, 200)
    observer.record_finished(request)
    assert summarize_post_observation(events) == {
        "observed_calls": 1, "approved_read_only_calls": 0, "executed_approved_calls": 0,
    }


def test_blocked_post_remains_observed_not_executed_or_approved():
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    observe(observer, request)
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.mark_blocked(request, "NETWORK_POLICY", classification="BLOCKED_BY_NETWORK_POLICY")
    observer.record_failure(request, "net::ERR_BLOCKED_BY_CLIENT")
    observer.finalize_pending()
    assert summarize_post_observation(events) == {
        "observed_calls": 1, "approved_read_only_calls": 0, "executed_approved_calls": 0,
    }
    item = aggregate_api_events(events)[0]
    assert item["blocked_calls"] == 1
    assert item["sent_calls"] == item["failed_calls"] == 0


def test_report_post_summary_reconciles_authoritative_scan_events_and_inventory():
    events = [
        {"request_id": "request-1", "method": "POST", "url": "https://portal.example/api/query",
         "request_classification": "APPROVED_READ_POST", "policy_decision": "ALLOW",
         "request_dispatched": True, "response_seen": True, "response_completed": True, "status": 200},
        {"request_id": "request-2", "method": "POST", "url": "https://portal.example/api/query",
         "request_classification": "APPROVED_READ_POST", "policy_decision": "ALLOW",
         "request_dispatched": False, "response_seen": False, "lifecycle_status": "INCOMPLETE"},
        {"request_id": "request-3", "method": "POST", "url": "https://portal.example/api/write",
         "blocked_by_validator": True, "policy_decision": "BLOCK"},
        {"request_id": "request-4", "method": "GET", "url": "https://portal.example/config.json",
         "status": 200, "response_seen": True, "response_completed": True},
    ]
    # A route snapshot may repeat the scan-wide event. It must not double-count.
    route = {
        "classification": "PASS", "page_load_status": "LOADED", "validation_status": "PASS",
        "api_requests": [dict(events[0]), dict(events[0])],
    }
    summary = aggregate_report([route], api_events=events)
    inventory = aggregate_api_events(events)
    assert summary["post_summary"] == {
        "observed_calls": 3, "approved_read_only_calls": 2, "executed_approved_calls": 1,
    }
    assert summary["post_summary"]["observed_calls"] == sum(
        item["observed_calls"] for item in inventory if item["method"] == "POST"
    )
    for key in ("approved_read_only_calls", "executed_approved_calls"):
        assert summary["post_summary"][key] == sum(item[key] for item in inventory)
    assert summary["post_summary"] == json.loads(json.dumps(summary))["post_summary"]


@pytest.mark.parametrize("headers_received", [False, True])
def test_finalized_incomplete_is_not_reclassified_by_context_cleanup(headers_received):
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    event = observe(observer, request)
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.mark_dispatched(request)
    if headers_received:
        observer.record_response(request, 200)
    observer.finalize_pending()
    original = dict(event)
    assert event["lifecycle_status"] == "INCOMPLETE"
    assert observer.finalized is True

    observer.record_failure(request, "net::ERR_ABORTED")
    observer.record_response(request, 503)
    observer.record_finished(request)
    observer.mark_allowed(request, "AUTH_FLOW")
    observer.mark_blocked(request, "CONTEXT_CLOSED")
    observer.mark_route_handler(request)
    observer.mark_dispatched(request)
    observer.finalize_pending()
    assert event == original
    assert observe(observer, request) is event
    with pytest.raises(RuntimeError, match="Network observation has been finalized"):
        observe(observer, Request())
    assert len(events) == 1
    item = aggregate_api_events(events)[0]
    assert item["incomplete_calls"] == 1
    assert item["canceled_calls"] == item["failed_calls"] == 0


@pytest.mark.asyncio
async def test_finalization_observes_optional_discovery_post_until_body_completes():
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    observer.observe_request(
        request, phase="DISCOVERY", importance="BACKGROUND",
        initiating_route="https://portal.example/dashboard", main_document=False,
    )
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.mark_dispatched(request)
    observer.record_response(request, 200)

    async def complete_body():
        await asyncio.sleep(0.02)
        observer.record_finished(request)

    completion = asyncio.create_task(complete_body())
    outcome = await drain_pending_api_observations(observer, maximum_ms=1000, quiet_ms=10)
    await completion
    observer.finalize_pending()
    assert outcome["reason"] == "API_QUIET"
    assert outcome["pending"] == 0 and outcome["timed_out"] is False
    assert events[0]["lifecycle_status"] == "COMPLETED"
    assert aggregate_api_events(events)[0]["completed_calls"] == 1


@pytest.mark.asyncio
async def test_finalization_tracks_a_new_post_during_the_quiet_window():
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()

    async def late_application_work():
        await asyncio.sleep(0)
        observe(observer, request)
        observer.mark_allowed(request, "APPROVED_READ_POST")
        observer.mark_dispatched(request)
        observer.record_response(request, 200)
        await asyncio.sleep(0.02)
        observer.record_finished(request)

    late = asyncio.create_task(late_application_work())
    outcome = await drain_pending_api_observations(observer, maximum_ms=1000, quiet_ms=50)
    await late
    assert outcome["reason"] == "API_QUIET"
    assert outcome["observed_requests"] == 1 and outcome["pending"] == 0
    assert events[0]["response_completed"] is True


@pytest.mark.asyncio
async def test_finalization_timeout_keeps_no_response_request_incomplete():
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    observe(observer, request)
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.mark_dispatched(request)
    outcome = await drain_pending_api_observations(observer, maximum_ms=20, quiet_ms=10)
    observer.finalize_pending()
    assert outcome["reason"] == "FINALIZATION_TIMEOUT"
    assert outcome["timed_out"] is True and outcome["pending"] == 1
    assert events[0]["lifecycle_status"] == "INCOMPLETE"
    assert events[0]["incomplete_reason"] == "NO_RESPONSE_BEFORE_SCAN_END"


@pytest.mark.asyncio
async def test_finalization_cancellation_is_prompt_and_does_not_replay_requests():
    events = []
    observer = PassiveNetworkObserver(events)
    request = Request()
    observe(observer, request)
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.mark_dispatched(request)
    cancellation = asyncio.Event()
    cancellation.set()
    outcome = await drain_pending_api_observations(
        observer, maximum_ms=1000, quiet_ms=100, cancel_event=cancellation,
    )
    observer.finalize_pending()
    assert outcome["reason"] == "CANCELLED" and outcome["cancelled"] is True
    assert outcome["pending"] == outcome["observed_requests"] == len(events) == 1
    assert events[0]["lifecycle_status"] == "INCOMPLETE"


@pytest.mark.asyncio
async def test_finalization_does_not_wait_for_blocked_or_naturally_failed_requests():
    events = []
    observer = PassiveNetworkObserver(events)
    blocked, failed = Request(), Request()
    observe(observer, blocked)
    observer.mark_blocked(blocked, "READ_ONLY_MUTATION_BLOCKED")
    observe(observer, failed)
    observer.record_failure(failed, "net::ERR_CONNECTION_RESET")
    outcome = await drain_pending_api_observations(observer, maximum_ms=1000, quiet_ms=0)
    assert outcome["reason"] == "API_QUIET"
    assert outcome["pending"] == 0 and outcome["observed_requests"] == 2
