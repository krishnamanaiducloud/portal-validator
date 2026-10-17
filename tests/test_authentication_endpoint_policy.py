"""Host approval cannot turn a business mutation into authentication traffic."""

import pytest

from app.navigation import AuthenticationNavigationPolicy, authentication_endpoint_signal


def active_policy(**options):
    return AuthenticationNavigationPolicy(
        approved_hosts=frozenset({"identity.example", "federation.example"}), active=True, **options,
    )


@pytest.mark.parametrize("path", [
    "/saml/sso", "/oauth/callback", "/oauth2/token", "/as/token.oauth2", "/token",
    "/idp/SSO.saml2", "/authorization", "/acs", "/tenant/acs", "/signin-oidc",
    "/oauth/authorization.oauth2", "/tenant/saml-acs", "/saml/sso.aspx",
    "/saml/consume", "/saml2/resume", "/oauth/resume", "/saml/consume.html",
])
def test_default_authentication_endpoint_recognition_is_generic(path):
    assert authentication_endpoint_signal("https://identity.example" + path)
    policy = active_policy()
    assert policy.allows_main_frame_method(
        "POST", "https://identity.example" + path, "SAMLResponse=private-fixture-value",
        source_url="https://federation.example/saml/sso",
    )


@pytest.mark.parametrize("path", [
    "/account/delete", "/account/delete?SAMLRequest=private-fixture-value",
    "/report?client_id=fixture&redirect_uri=https://portal.example/callback",
    "/api/change?code=private-fixture-code&state=private-fixture-state",
    "/oauth/account/delete", "/saml/account/%64elete", "/oauth/account/update",
    "/sso/export", "/oauth/submit", "/custom/relay", "/oauth/business/allocate",
    "/saml/api/startWork", "/oauth/business/allocate.oauth2", "/saml/api/startWork.saml2",
    "/oauth-allocate", "/business/saml-allocate", "/business/token-allocate",
    "/oauth/business/consume", "/saml/api/resume", "/business/consume",
    "/consume", "/resume", "/saml/sso;allocate", "/saml/sso.allocate",
])
def test_protocol_query_or_parent_path_does_not_authorize_mutation_endpoint(path):
    policy = active_policy()
    destination = "https://identity.example" + path
    assert not authentication_endpoint_signal(destination)
    assert not policy.allows_main_frame_method("POST", destination, "SAMLRequest=private-fixture-value")
    assert not policy.allows_browser_request(
        "POST", destination, "SAMLResponse=private-fixture-value", resource_type="document",
        document_navigation=True, source_url="https://portal.example/", source_portal_scoped=True,
    )
    assert not policy.allows_redirect(
        "POST", "https://federation.example/saml/sso", destination,
        document_navigation=True, authentication_form=True,
    )
    assert not policy.allows_browser_request(
        "POST", destination, "grant_type=authorization_code&code=private-fixture-code",
        resource_type="fetch", document_navigation=False,
        source_url="https://portal.example/", source_portal_scoped=True,
    )
    assert not policy.allows_redirect(
        "POST", "https://federation.example/oauth/token", destination,
        document_navigation=False, oauth_token_form=True,
    )


def test_nonstandard_callback_requires_exact_explicit_endpoint_approval():
    endpoint = "https://identity.example/custom/relay"
    assert not active_policy().allows_main_frame_method("POST", endpoint, "SAMLResponse=private-fixture-value")
    policy = active_policy(approved_endpoints=frozenset({endpoint}))
    assert policy.allows_main_frame_method("POST", endpoint, "SAMLResponse=private-fixture-value")
    assert policy.allows_browser_request(
        "POST", endpoint, "SAMLResponse=private-fixture-value", resource_type="document",
        document_navigation=True, source_url="https://portal.example/", source_portal_scoped=True,
    )
    assert policy.allows_redirect(
        "POST", "https://federation.example/saml/sso", endpoint,
        document_navigation=True, authentication_form=True,
    )
    for unrelated in (endpoint + "/extra", endpoint + "-other", "https://identity.example:444/custom/relay"):
        assert not policy.allows_main_frame_method("POST", unrelated, "SAMLResponse=private-fixture-value")


def test_custom_oauth_exchange_endpoint_remains_separate_from_business_posts():
    endpoint = "https://identity.example/protocol/exchange"
    policy = active_policy(approved_endpoints=frozenset({endpoint}))
    arguments = dict(resource_type="fetch", document_navigation=False,
                     source_url="https://portal.example/", source_portal_scoped=True)
    assert policy.allows_browser_request(
        "POST", endpoint, "grant_type=authorization_code&code=private-fixture-code", **arguments,
    )
    assert policy.allows_redirect(
        "POST", "https://federation.example/oauth/token", endpoint,
        document_navigation=False, oauth_token_form=True,
    )
    assert not policy.allows_browser_request("POST", endpoint, "action=delete", **arguments)
    assert not policy.allows_browser_request(
        "POST", endpoint, "grant_type=password&username=private-user&password=private-password", **arguments,
    )


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE", "TRACE", "CONNECT"])
def test_explicit_endpoint_never_authorizes_unapproved_method(method):
    endpoint = "https://identity.example/custom/relay"
    policy = active_policy(approved_endpoints=frozenset({endpoint}))
    assert not policy.allows_main_frame_method(method, endpoint, "SAMLResponse=private-fixture-value")
    assert not policy.allows_browser_request(
        method, endpoint, "SAMLResponse=private-fixture-value", resource_type="document",
        document_navigation=True, source_url="https://portal.example/", source_portal_scoped=True,
    )
    assert not policy.allows_redirect(
        method, "https://federation.example/saml/sso", endpoint,
        document_navigation=True, authentication_form=True,
    )


def test_endpoint_approval_cannot_approve_a_host_or_source_or_activate_a_flow():
    endpoint = "https://unapproved.example/custom/relay"
    policy = active_policy(approved_endpoints=frozenset({endpoint}))
    assert not policy.allows_main_frame_method("POST", endpoint, "SAMLResponse=private-fixture-value")
    approved_endpoint = "https://identity.example/custom/relay"
    policy = active_policy(approved_endpoints=frozenset({approved_endpoint}))
    assert not policy.allows_browser_request(
        "POST", approved_endpoint, "SAMLResponse=private-fixture-value", resource_type="document",
        document_navigation=True, source_url="https://unapproved.example/",
    )
    policy.active = False
    assert not policy.allows_main_frame_method("POST", approved_endpoint, "SAMLResponse=private-fixture-value")
    assert not policy.active


@pytest.mark.parametrize("endpoint", [
    "https://identity.example/custom/*", "https://identity.example/custom/relay?SAMLRequest=private-fixture-value",
    "https://identity.example/custom/relay#fragment", "https://user:password@identity.example/relay",
    "https://identity.example/custom/../relay", "https://identity.example/custom/%2frelay",
])
def test_invalid_explicit_endpoint_configuration_is_rejected(endpoint):
    with pytest.raises(ValueError):
        active_policy(approved_endpoints=frozenset({endpoint}))


def test_blocked_business_endpoint_diagnosis_does_not_invalidate_authentication():
    policy = active_policy()
    diagnostic = policy.diagnose_blocked_request(
        "POST", "https://identity.example/oauth/account/delete", "SAMLRequest=private-fixture-value",
        resource_type="document", document_navigation=True, portal_scoped=False,
        source_url="https://portal.example/", source_portal_scoped=True,
    )
    assert diagnostic["reason"] == "AUTHENTICATION_PROTOCOL_MISMATCH"
    assert diagnostic["affects_authentication"] is False
    assert "private-fixture" not in str(diagnostic)


@pytest.mark.parametrize("source", [
    "https://unapproved.example/oauth/authorize?client_id=fixture&response_type=code",
    "https://identity.example.attacker.example/saml/sso", "https://evilidentity.example/login",
    "", "about:blank", "https://[invalid",
])
def test_supplied_unapproved_main_frame_source_cannot_post_to_approved_identity_host(source):
    policy = active_policy()
    assert not policy.allows_main_frame_method(
        "POST", "https://identity.example/saml/sso", "SAMLRequest=private-fixture-value",
        source_url=source,
    )


def test_auth_looking_get_source_does_not_become_an_approved_post_source():
    policy = AuthenticationNavigationPolicy(approved_hosts=frozenset({"identity.example"}))
    source = "https://unapproved.example/oauth/authorize?client_id=fixture&response_type=code"
    assert policy.allows_main_frame_method("GET", source)
    assert policy.active
    destination = "https://identity.example/saml/sso"
    assert not policy.allows_main_frame_method(
        "POST", destination, "SAMLRequest=private-fixture-value", source_url=source,
    )
    assert not policy.allows_browser_request(
        "POST", destination, "SAMLRequest=private-fixture-value", resource_type="document",
        document_navigation=True, source_url=source,
    )
    assert not policy.allows_redirect(
        "POST", source, destination, document_navigation=True, authentication_form=True,
    )


@pytest.mark.parametrize("source,portal_scoped", [
    ("https://portal.example/workspace", True),
    ("https://identity.example/oauth/authorize", False),
    ("https://federation.example/saml/sso", False),
])
def test_supplied_portal_or_exact_identity_source_can_finish_approved_authentication(source, portal_scoped):
    policy = active_policy()
    assert policy.allows_main_frame_method(
        "POST", "https://identity.example/saml/sso", "SAMLRequest=private-fixture-value",
        source_url=source, source_portal_scoped=portal_scoped,
    )
    assert policy.allows_browser_request(
        "POST", "https://identity.example/saml/sso", "SAMLRequest=private-fixture-value",
        source_url=source, source_portal_scoped=portal_scoped,
        resource_type="document", document_navigation=True,
    )
    assert policy.allows_redirect(
        "POST", source, "https://identity.example/saml/sso", source_portal_scoped=portal_scoped,
        document_navigation=True, authentication_form=True,
    )


def test_approved_source_does_not_replace_endpoint_destination_method_or_form_approval():
    policy = active_policy()
    source = "https://federation.example/saml/sso"
    for method, destination, body in (
        ("POST", "https://identity.example/account/delete", "SAMLRequest=private-fixture-value"),
        ("POST", "https://unapproved.example/saml/sso", "SAMLRequest=private-fixture-value"),
        ("POST", "https://identity.example/saml/sso", "operation=delete"),
        ("PUT", "https://identity.example/saml/sso", "SAMLRequest=private-fixture-value"),
    ):
        assert not policy.allows_main_frame_method(method, destination, body, source_url=source)


def test_unsupplied_source_preserves_direct_policy_api_but_empty_supplied_source_fails_closed():
    policy = active_policy()
    assert policy.allows_main_frame_method(
        "POST", "https://identity.example/saml/sso", "SAMLRequest=private-fixture-value",
    )
    assert not policy.allows_main_frame_method(
        "POST", "https://identity.example/saml/sso", "SAMLRequest=private-fixture-value", source_url="",
    )


@pytest.mark.parametrize("source", [
    "ftp://identity.example/saml/sso", "javascript://identity.example/saml/sso",
    "//identity.example/saml/sso", "https://identity.example:invalid/saml/sso",
    "https://identity.example:0/saml/sso", "https://identity.example:65536/saml/sso",
    "https://user:private-fixture-password@identity.example/saml/sso",
])
@pytest.mark.parametrize("portal_scoped", [False, True])
def test_non_http_or_malformed_source_cannot_gain_approval_from_its_hostname(source, portal_scoped):
    policy = active_policy()
    destination = "https://identity.example/saml/sso"
    assert not policy.is_approved_authentication_source(source, portal_scoped=portal_scoped)
    assert not policy.allows_main_frame_method(
        "POST", destination, "SAMLRequest=private-fixture-value",
        source_url=source, source_portal_scoped=portal_scoped,
    )
    assert not policy.allows_browser_request(
        "POST", destination, "SAMLRequest=private-fixture-value", resource_type="document",
        document_navigation=True, source_url=source, source_portal_scoped=portal_scoped,
    )
    assert not policy.allows_browser_request(
        "POST", "https://identity.example/oauth/token", "grant_type=authorization_code&code=private-fixture-code",
        resource_type="fetch", document_navigation=False, source_url=source, source_portal_scoped=portal_scoped,
    )
    assert not policy.allows_redirect(
        "POST", source, destination, source_portal_scoped=portal_scoped,
        document_navigation=True, authentication_form=True,
    )
