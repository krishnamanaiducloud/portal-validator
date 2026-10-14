"""Protocol denial diagnosis is independent of request authorization."""

import json

import pytest

from app.navigation import AuthenticationNavigationPolicy


def diagnose(policy, *, destination="https://identity.example/oauth/token", source="https://portal.example/", body="grant_type=authorization_code&code=fixture-private-code"):
    return policy.diagnose_blocked_request(
        "POST", destination, body, resource_type="fetch", document_navigation=False,
        portal_scoped=False, source_url=source,
        source_portal_scoped=source == "https://portal.example/",
    )


@pytest.mark.parametrize("hosts,active,expected", [
    (frozenset(), False, "AUTHENTICATION_HOSTS_REQUIRED"),
    (frozenset({"other.example"}), True, "AUTHENTICATION_HOST_NOT_APPROVED"),
    (frozenset({"identity.example"}), False, "AUTHENTICATION_FLOW_NOT_ACTIVE"),
    (frozenset({"identity.example"}), True, "AUTHENTICATION_POLICY_BLOCKED"),
])
def test_denied_oauth_reports_missing_policy_evidence_without_activating_flow(hosts, active, expected):
    policy = AuthenticationNavigationPolicy(hosts, active=active)
    diagnostic = diagnose(policy)
    assert diagnostic["reason"] == expected
    assert diagnostic["affects_authentication"]
    assert diagnostic["destination_host"] == "identity.example"
    assert diagnostic["source_host"] == "portal.example"
    assert policy.active is active
    assert "fixture-private" not in json.dumps(diagnostic)


def test_untrusted_source_cannot_invalidate_portal_authentication():
    diagnostic = diagnose(
        AuthenticationNavigationPolicy(frozenset({"identity.example"}), active=True),
        source="https://unrelated.example/embedded",
    )
    assert diagnostic["reason"] == "AUTHENTICATION_SOURCE_NOT_APPROVED"
    assert not diagnostic["affects_authentication"]


def test_protocol_mismatch_is_diagnostic_only_and_does_not_authorize_request():
    policy = AuthenticationNavigationPolicy(frozenset({"identity.example"}), active=True)
    diagnostic = diagnose(policy, destination="https://identity.example/api/delete")
    assert diagnostic["reason"] == "AUTHENTICATION_PROTOCOL_MISMATCH"
    assert not diagnostic["affects_authentication"]
    assert not policy.allows_browser_request(
        "POST", "https://identity.example/api/delete", "grant_type=authorization_code&code=fixture-private-code",
        resource_type="fetch", document_navigation=False,
        source_url="https://portal.example/", source_portal_scoped=True,
    )


@pytest.mark.parametrize("body", ["{}", "state=ready&error=business", "operation=delete"])
def test_business_post_with_authentication_words_has_no_authentication_diagnostic(body):
    policy = AuthenticationNavigationPolicy(frozenset({"identity.example"}), active=True)
    assert diagnose(policy, destination="https://portal.example/api/oauth/report", body=body) is None


def test_saml_denial_is_sanitized_and_requires_approved_source_for_coverage():
    policy = AuthenticationNavigationPolicy(frozenset({"identity.example"}), active=True)
    diagnostic = policy.diagnose_blocked_request(
        "POST", "https://federation.example/saml/consume?state=fixture-private-state",
        "SAMLRequest=fixture-private-saml", resource_type="document", document_navigation=True,
        portal_scoped=False, source_url="https://identity.example/authorize?code=fixture-private-code",
    )
    assert diagnostic["reason"] == "AUTHENTICATION_HOST_NOT_APPROVED"
    assert diagnostic["affects_authentication"]
    assert "fixture-private" not in json.dumps(diagnostic)
