import asyncio

import pytest
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from app.navigation import (
    AuthenticationNavigationPolicy,
    auth_protocol_signal,
    classify_authentication,
    settle_authentication_navigation,
)
from app.reporting import aggregate_report, classify_page_result


@pytest.mark.parametrize("body", ["state=ready", "error=business-error", "state=x&error=bad", "RelayState=x", "SAMLRequest="])
def test_business_fields_cannot_authorize_authentication_post(body):
    policy = AuthenticationNavigationPolicy(approved_hosts=frozenset({"identity.example"}))
    assert not policy.allows_main_frame_method("POST", "https://identity.example/api/change", body)
    assert not policy.active


def test_authentication_post_requires_explicit_destination_and_protocol():
    policy = AuthenticationNavigationPolicy(approved_hosts=frozenset({"identity.example"}))
    policy.observe("https://identity.example/oauth/authorize?client_id=portal")
    assert not policy.allows_main_frame_method("POST", "https://attacker.example/sso", "SAMLRequest=opaque")
    assert not policy.allows_main_frame_method("POST", "https://identity.example/account/delete", "state=x")
    assert not policy.allows_main_frame_method("POST", "https://identity.example/account/delete", "state=x&error=bad")
    assert policy.allows_main_frame_method("POST", "https://identity.example/saml/sso", "SAMLRequest=opaque")
    assert policy.allows_main_frame_method(
        "POST", "https://portal.example/oauth/callback", "code=opaque&state=opaque", portal_scoped=True,
    )
    assert policy.allows_main_frame_method(
        "POST", "https://portal.example/consume", "SAMLResponse=opaque", portal_scoped=True,
    )
    assert not policy.allows_main_frame_method("PUT", "https://identity.example/sso", "SAMLRequest=opaque")


def test_denied_post_cannot_activate_authentication_chain():
    policy = AuthenticationNavigationPolicy(approved_hosts=frozenset({"identity.example"}))
    policy.observe("https://attacker.example/oauth", "POST")
    assert not policy.active
    assert not policy.allows_main_frame_method(
        "POST", "https://portal.example/oauth/callback", "code=x&state=x", portal_scoped=True,
    )
    assert not policy.allows_main_frame_method(
        "POST", "https://identity.example/oauth/callback", "code=x&state=x",
    )
    assert not policy.allows_main_frame_method(
        "POST", "https://identity.example/saml/consume", "SAMLResponse=opaque",
    )


def test_explicit_identity_host_can_begin_nonstandard_authentication_endpoint_flow():
    policy = AuthenticationNavigationPolicy(approved_hosts=frozenset({"identity.example"}))
    policy.observe("https://identity.example/consume", "GET")
    assert policy.active
    assert policy.allows_main_frame_method("POST", "https://identity.example/consume", "SAMLResponse=opaque")


@pytest.mark.parametrize("url", [
    "https://portal.example/login", "https://portal.example/oauth/callback?code=secret&state=secret",
    "https://portal.example/#/callback?code=secret&state=secret",
])
def test_same_scope_authentication_surface_is_not_application_pass(url):
    assert auth_protocol_signal(url)
    assert classify_authentication(
        authentication_mode="storage_state", status=200, final_url=url,
        target_in_scope=True, error_classification=None,
    ) == "SESSION_EXPIRED"


def test_same_scope_password_page_requires_authentication():
    assert classify_authentication(
        authentication_mode="none", status=200, final_url="https://portal.example/account",
        target_in_scope=True, error_classification=None, password_form=True,
    ) == "AUTH_REQUIRED"
    assert not auth_protocol_signal("https://portal.example/report?scope=team&state=ready")
    assert not auth_protocol_signal("https://portal.example/report?client_id=account")
    assert not auth_protocol_signal("https://portal.example/report?redirect_uri=next")
    assert not auth_protocol_signal("https://portal.example/report?SAMLRequest=")


def test_unrelated_non_authentication_destination_is_not_application_pass():
    assert classify_authentication(
        authentication_mode="none", status=200, final_url="https://unrelated.example/dashboard",
        target_in_scope=False, error_classification=None,
    ) == "NAVIGATION_ERROR"


@pytest.mark.parametrize("path", ["/docs/oauth/getting-started", "/reference/saml", "/login-history"])
def test_public_protocol_documentation_is_not_an_authentication_boundary(path):
    url = "https://portal.example" + path
    assert auth_protocol_signal(url)  # Still a conservative SSO navigation hint.
    assert not auth_protocol_signal(url, boundary_only=True)
    assert classify_authentication(
        authentication_mode="none", status=200, final_url=url,
        target_in_scope=True, error_classification=None,
    ) == "PASS"


class RedirectPage:
    def __init__(self, urls):
        self.urls = list(urls)
        self.url = self.urls.pop(0)
        self.waits = 0

    async def evaluate(self, script):
        return False

    async def wait_for_url(self, predicate, *, wait_until, timeout):
        self.waits += 1
        if self.urls:
            self.url = self.urls.pop(0)
            assert predicate(self.url)
            return
        await asyncio.sleep(timeout / 1000)
        raise PlaywrightTimeoutError("bounded test observation")


async def no_forms(page):
    return False, False


@pytest.mark.asyncio
async def test_public_documentation_does_not_consume_authentication_timeout():
    page = RedirectPage(["https://portal.example/docs/oauth/getting-started"])
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: True, detect_signals=no_forms, timeout_ms=60000,
        flow_active=True,
    )
    assert result["completed"] and result["stage"] == "APPLICATION"
    assert page.waits == 0


@pytest.mark.asyncio
async def test_same_scope_protocol_auto_post_bridge_is_not_public_application_content():
    page = RedirectPage(["https://portal.example/saml/consume", "https://portal.example/dashboard"])

    async def protocol_form(script):
        return page.url.endswith("/saml/consume")

    page.evaluate = protocol_form
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: True, detect_signals=no_forms,
        timeout_ms=1000, flow_active=True,
    )
    assert result["completed"] and result["stage"] == "APPLICATION"
    assert page.waits == 1


@pytest.mark.asyncio
async def test_auto_post_and_callback_naturally_settle_to_application_without_replay():
    page = RedirectPage([
        "https://identity.example/oauth/authorize?client_id=portal&state=secret",
        "https://federation.example/saml/consume",
        "https://portal.example/oauth/callback?code=secret&state=secret",
        "https://portal.example/dashboard",
    ])
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: url.startswith("https://portal.example/"),
        detect_signals=no_forms, timeout_ms=1000, flow_active=True,
    )
    assert result["completed"]
    assert result["stage"] == "APPLICATION"
    assert result["final_host"] == "portal.example"
    assert page.waits == 3
    assert "secret" not in str(result)


@pytest.mark.asyncio
async def test_public_application_does_not_receive_artificial_authentication_wait():
    page = RedirectPage(["https://portal.example/dashboard"])
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: True, detect_signals=no_forms, timeout_ms=60000,
    )
    assert result["completed"] and page.waits == 0


@pytest.mark.asyncio
async def test_interactive_login_stops_without_waiting_or_submitting():
    page = RedirectPage(["https://identity.example/login"])

    async def password_form(page):
        return {"password_form": True, "mfa_form": False}

    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: False, detect_signals=password_form,
        timeout_ms=60000, flow_active=True,
    )
    assert result["stage"] == "LOGIN_REQUIRED"
    assert result["password_form"] and not result["completed"] and page.waits == 0


@pytest.mark.asyncio
async def test_callback_wait_is_bounded_and_incomplete_not_application_pass():
    page = RedirectPage(["https://portal.example/oauth/callback?code=secret&state=secret"])
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: True, detect_signals=no_forms, timeout_ms=10,
    )
    assert result["timed_out"] and not result["completed"]
    assert result["stage"] == "AUTHENTICATION_PENDING"
    assert result["elapsed_ms"] < 500


@pytest.mark.asyncio
async def test_terminal_unrelated_page_does_not_consume_authentication_timeout():
    page = RedirectPage(["https://unrelated.example/welcome"])
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: False, detect_signals=no_forms,
        timeout_ms=60000, flow_active=True,
    )
    assert result["stage"] == "OUTSIDE_PORTAL"
    assert page.waits == 0 and not result["timed_out"]


@pytest.mark.asyncio
async def test_explicit_approved_identity_bridge_can_finish_delayed_callback_without_url_markers():
    page = RedirectPage([
        "https://identity.example/bridge", "https://portal.example/oauth/callback?code=secret&state=secret",
        "https://portal.example/dashboard",
    ])
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: url.startswith("https://portal.example/"),
        detect_signals=no_forms, timeout_ms=1000, flow_active=True,
        is_approved_authentication_host=lambda host: host == "identity.example",
    )
    assert result["stage"] == "APPLICATION" and result["completed"]
    assert page.waits == 2 and "secret" not in str(result)


@pytest.mark.asyncio
async def test_explicit_approved_identity_bridge_remains_bounded_and_cannot_be_application_pass():
    page = RedirectPage(["https://identity.example/bridge"])
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: False, detect_signals=no_forms,
        timeout_ms=10, flow_active=True,
        is_approved_authentication_host=lambda host: host == "identity.example",
    )
    assert result["stage"] == "AUTHENTICATION_PENDING" and result["timed_out"]
    assert not result["completed"] and page.waits == 1


@pytest.mark.asyncio
async def test_latest_document_status_stops_pending_authentication_on_denied_page():
    page = RedirectPage([
        "https://identity.example/oauth/authorize", "https://identity.example/login",
    ])
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: False, detect_signals=no_forms,
        timeout_ms=60000, status=200,
        current_status=lambda: 403 if page.waits else 200,
    )
    assert result["stage"] == "HTTP_ERROR" and page.waits == 1


@pytest.mark.asyncio
async def test_unmarked_saml_auto_post_bridge_is_observed_without_submission():
    page = RedirectPage(["https://identity.example/consume", "https://portal.example/dashboard"])

    async def protocol_form(script):
        return page.url.startswith("https://identity.example/")

    page.evaluate = protocol_form
    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: url.startswith("https://portal.example/"),
        detect_signals=no_forms, timeout_ms=1000, flow_active=True,
    )
    assert result["completed"] and page.waits == 1


def page_result(classification="PASS", *, status=200, error=None):
    return classify_page_result(
        url="https://portal.example/", status=status, error=error,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, authentication_classification=classification,
    )


@pytest.mark.parametrize("classification", ["AUTH_REQUIRED", "SESSION_EXPIRED", "ACCESS_RESTRICTED", "CHALLENGE_REQUIRED"])
def test_exhausted_authentication_or_challenge_page_does_not_prove_portal_coverage(classification):
    summary = aggregate_report([page_result(classification)])
    assert summary["execution_status"] == "COMPLETE"
    assert summary["execution_complete"]
    assert summary["coverage_status"] == "NONE"
    assert not summary["coverage_complete"]
    assert summary["scan_completeness"] == "PARTIAL"
    assert summary["application_routes_validated"] == 0
    assert summary["coverage_reasons"]


def test_mixed_application_and_authentication_results_have_partial_coverage():
    summary = aggregate_report([page_result(), page_result("AUTH_REQUIRED")])
    assert summary["coverage_status"] == "PARTIAL"
    assert summary["application_routes_validated"] == 1
    assert {reason["code"] for reason in summary["coverage_reasons"]} == {"AUTHENTICATION_INCOMPLETE"}


def test_warnings_remain_healthy_and_do_not_invalidate_coverage():
    result = page_result()
    result.update(classification="PASS_WITH_WARNINGS", passed=True, validation_status="WARNING")
    summary = aggregate_report([result])
    assert summary["coverage_complete"] and summary["coverage_status"] == "COMPLETE"
    assert summary["healthy_routes"] == 1 and summary["failed_pages"] == 0
    assert summary["coverage_reasons"] == []


def test_empty_finished_job_does_not_claim_portal_coverage():
    summary = aggregate_report([])
    assert summary["execution_complete"]
    assert not summary["coverage_complete"]
    assert summary["coverage_status"] == "NONE"


def test_navigation_failure_and_remaining_routes_explain_incomplete_coverage():
    summary = aggregate_report(
        [page_result("TIMEOUT", status=None, error="Timeout")],
        routes_discovered=3, termination_reason="SCAN_TIMEOUT",
    )
    assert summary["execution_status"] == "TIMED_OUT"
    assert not summary["execution_complete"]
    assert {reason["code"] for reason in summary["coverage_reasons"]} >= {
        "NAVIGATION_FAILED", "NO_APPLICATION_ROUTES", "ROUTES_NOT_TESTED", "SCAN_TIMEOUT",
    }


def test_incomplete_api_observation_limits_coverage_without_failing_loaded_route():
    first, second = page_result(), page_result()
    event = {"request_id": "request-1", "lifecycle_status": "INCOMPLETE"}
    first["api_requests"] = [event]
    second["api_requests"] = [dict(event)]
    summary = aggregate_report([first, second])
    assert summary["healthy_routes"] == 2 and summary["failed_pages"] == 0
    assert summary["coverage_status"] == "PARTIAL"
    assert summary["coverage_reasons"] == [{"code": "API_OBSERVATION_INCOMPLETE", "count": 1}]


def test_final_completed_api_observation_replaces_older_incomplete_snapshot():
    first, second = page_result(), page_result()
    first["api_requests"] = [{"request_id": "request-1", "lifecycle_status": "INCOMPLETE"}]
    second["api_requests"] = [{"request_id": "request-1", "lifecycle_status": "COMPLETED"}]
    assert aggregate_report([first, second])["coverage_complete"]
    assert aggregate_report([second, first])["coverage_complete"]


def test_scan_wide_late_pending_observation_limits_coverage_without_losing_route_health():
    summary = aggregate_report(
        [page_result()], api_events=[{"request_id": "late-request", "lifecycle_status": "INCOMPLETE"}],
    )
    assert summary["healthy_routes"] == 1 and summary["failed_pages"] == 0
    assert summary["coverage_status"] == "PARTIAL"
    assert summary["coverage_reasons"] == [{"code": "API_OBSERVATION_INCOMPLETE", "count": 1}]


def test_scan_wide_final_response_supersedes_route_snapshot():
    result = page_result()
    result["api_requests"] = [{"request_id": "request-1", "lifecycle_status": "INCOMPLETE"}]
    summary = aggregate_report(
        [result], api_events=[{"request_id": "request-1", "lifecycle_status": "COMPLETED"}],
    )
    assert summary["coverage_complete"]
