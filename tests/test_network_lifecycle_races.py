"""Out-of-order callbacks must enrich evidence without undoing terminal states."""

import json

import pytest

from app.network import PassiveNetworkObserver, RouteNetworkActivity
from app.reporting import aggregate_api_events


class Source:
    pass


class Request:
    method = "POST"
    resource_type = "fetch"
    url = "https://portal.example/api/read-query?code=private-query"
    timing = {"responseEnd": 37}

    def __init__(self, *, page=None, frame=None):
        self.frame = frame or Source()
        self.frame.page = page or Source()
        self.frame.parent_frame = None
        self.frame.url = "https://portal.example/#/view?token=private-token"


def observed():
    request = Request()
    observer = PassiveNetworkObserver([])
    event = observer.observe_request(
        request, phase="ROUTE_VALIDATION", importance="REQUIRED",
        initiating_route="https://portal.example/#/view", main_document=False,
        route_activation_id="activation-1",
    )
    return request, observer, event


@pytest.mark.parametrize("terminal", ["RESPONDED", "COMPLETED", "FAILED", "CANCELED"])
def test_late_policy_approval_does_not_regress_received_or_terminal_evidence(terminal):
    request, observer, event = observed()
    observer.record_response(request, 502 if terminal == "FAILED" else 200)
    if terminal == "COMPLETED":
        observer.record_finished(request)
    elif terminal in {"FAILED", "CANCELED"}:
        observer.record_failure(request, "net::ERR_ABORTED" if terminal == "CANCELED" else "net::ERR_CONNECTION_RESET")

    observer.mark_allowed(request, "APPROVED_READ_POST")

    assert event["lifecycle_status"] == terminal
    assert event["response_seen"] is True
    assert event["policy_decision"] == "ALLOW"
    assert event["response_completed"] is (terminal == "COMPLETED")


def test_late_policy_approval_cannot_undo_a_blocked_operation():
    request, observer, event = observed()
    observer.mark_blocked(request, "READ_ONLY_MUTATION_BLOCKED")
    observer.mark_allowed(request, "APPROVED_READ_POST")
    assert event["policy_decision"] == "BLOCK"
    assert event["allowed_by_policy"] is False
    assert event["request_classification"] == "BLOCKED_MUTATION"
    assert event["lifecycle_status"] == "BLOCKED"


def test_late_response_enriches_failed_request_without_erasing_transfer_failure():
    request, observer, event = observed()
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.record_failure(request, "net::ERR_CONNECTION_RESET")
    observer.record_response(request, 502)
    assert event["status"] == 502
    assert event["lifecycle_status"] == "FAILED"
    assert event["failure_category"] == "RESPONSE_BODY_FAILURE"
    endpoint = aggregate_api_events([event])[0]
    assert endpoint["target_failure_count"] == endpoint["status_5xx"] == 1
    assert endpoint["response_body_failures"] == 1
    assert endpoint["network_failures"] == 0


def test_finished_before_response_keeps_completion_without_inventing_http_status():
    request, observer, event = observed()
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.record_finished(request)
    assert event["status"] is None
    assert event["response_completed"] is False
    assert event["request_dispatched"] is True
    observer.record_response(request, 200)
    assert event["lifecycle_status"] == "COMPLETED"
    assert event["response_completed"] is True
    assert event["duration_ms"] == 37
    observer.finalize_pending()
    endpoint = aggregate_api_events([event])[0]
    assert endpoint["completed_calls"] == 1
    assert endpoint["incomplete_calls"] == 0


def test_source_page_and_frame_identity_distinguish_popup_and_child_frame_safely():
    observer = PassiveNetworkObserver([])
    primary_page, popup_page = Source(), Source()
    main_frame, child_frame = Source(), Source()
    requests = [
        Request(page=primary_page, frame=main_frame),
        Request(page=primary_page, frame=main_frame),
        Request(page=primary_page, frame=child_frame),
        Request(page=popup_page),
    ]
    for request in requests:
        observer.observe_request(
            request, phase="DISCOVERY", importance="BACKGROUND",
            initiating_route="UI_VIEW_" + "a" * 24, main_document=False,
        )
    first, second, child, popup = observer.events
    assert first["source_page_id"] == second["source_page_id"] == child["source_page_id"]
    assert first["source_frame_id"] == second["source_frame_id"]
    assert child["source_frame_id"] != first["source_frame_id"]
    assert popup["source_page_id"] != first["source_page_id"]
    assert "private-" not in json.dumps(observer.events)
    assert all(event["source_page_id"].startswith("page-") for event in observer.events)


def test_initial_popup_source_is_enriched_after_its_frame_becomes_available():
    request = Request()
    frame = request.frame
    del request.frame
    observer = PassiveNetworkObserver([])
    event = observer.observe_request(
        request, phase="DISCOVERY", importance="BACKGROUND", initiating_route="https://portal.example/",
        main_document=True,
    )
    assert event["source_page_id"] is event["source_frame_id"] is None
    assert event["frame_identity"] == "UNKNOWN_FRAME"
    request.frame = frame
    observer.record_response(request, 200)
    assert event["source_page_id"] == "page-1"
    assert event["source_frame_id"] == "frame-1"
    assert event["frame_identity"] == "MAIN_FRAME"


def test_reobserving_initially_frameless_popup_only_enriches_missing_source_metadata():
    request = Request()
    frame = request.frame
    frame.url = "https://user:private-password@portal.example/private-view?token=private-token#/private-tab"
    del request.frame
    observer = PassiveNetworkObserver([])
    event = observer.observe_request(
        request, phase="APPLICATION_BOOTSTRAP", importance="BACKGROUND",
        initiating_route="https://portal.example/", main_document=True,
        route_activation_id="opener-activation",
    )
    observer.mark_allowed(request, "APPROVED_READ_POST")
    observer.record_response(request, 200)
    observer.record_finished(request)
    before = dict(event)
    request.frame = frame
    existing = observer.observe_request(
        request, phase="ROUTE_VALIDATION", importance="REQUIRED",
        initiating_route="https://portal.example/popup", main_document=True,
        route_activation_id="popup-activation",
    )
    assert existing is event
    assert len(observer.events) == 1
    assert event["source_page_id"] == "page-1"
    assert event["source_frame_id"] == "frame-1"
    assert event["frame_identity"] == "MAIN_FRAME"
    assert event["initiator"] == {"kind": "BROWSER_FRAME", "origin": "https://portal.example"}
    for key in before.keys() - {"source_page_id", "source_frame_id", "frame_identity", "initiator"}:
        assert event[key] == before[key]
    assert "private-" not in json.dumps(event)


@pytest.mark.parametrize("dispatched", [False, True])
def test_incomplete_api_reports_distinguish_unconfirmed_transmission_and_missing_response(dispatched):
    request, observer, event = observed()
    observer.mark_allowed(request, "APPROVED_READ_POST")
    if dispatched:
        observer.mark_dispatched(request)
    event["incomplete_reason"] = "private-untrusted-do-not-report"
    observer.finalize_pending()
    endpoint = aggregate_api_events([event])[0]
    assert endpoint["validation_reasons"][0]["code"] == (
        "NO_RESPONSE_BEFORE_SCAN_END" if dispatched else "NOT_DISPATCHED_BEFORE_SCAN_END"
    )
    assert "private-untrusted" not in json.dumps(endpoint)
    assert endpoint["average_duration_ms"] is None
    assert endpoint["response_status_counts"] == {}


def test_pending_popup_activity_transfers_only_its_request_and_finishes_on_its_view():
    activity = RouteNetworkActivity()
    popup_request, primary_request = Request(), Request()
    activity.request_started(popup_request, "opener")
    activity.request_started(primary_request, "opener")
    assert activity.snapshot("opener")["pending"] == 2
    assert activity.reassign_request(popup_request, "popup-view") is True
    assert activity.snapshot("opener")["pending"] == activity.snapshot("popup-view")["pending"] == 1
    activity.request_finished(popup_request)
    assert activity.snapshot("popup-view")["pending"] == 0
    assert activity.snapshot("opener")["pending"] == 1
    assert activity.reassign_request(popup_request, "other-view") is False


def test_late_source_enrichment_cannot_mutate_frozen_report():
    request = Request()
    frame = request.frame
    del request.frame
    observer = PassiveNetworkObserver([])
    event = observer.observe_request(
        request, phase="APPLICATION_BOOTSTRAP", importance="BACKGROUND",
        initiating_route="https://portal.example/", main_document=True,
    )
    observer.finalize_pending()
    snapshot = json.dumps(event, sort_keys=True)
    request.frame = frame
    assert observer.observe_request(
        request, phase="ROUTE_VALIDATION", importance="REQUIRED",
        initiating_route="https://portal.example/popup", main_document=True,
    ) is event
    assert json.dumps(event, sort_keys=True) == snapshot
