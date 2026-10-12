"""Generic enterprise authentication boundaries; no real portal or credentials."""

import copy
import json

import pytest
from playwright.async_api import Error as PlaywrightError

from app.navigation import (
    AuthenticationNavigationPolicy,
    oauth_token_form_signal,
    settle_authentication_navigation,
)
from app.session import RuntimeSessionStore, scope_storage_state


def active_policy():
    policy = AuthenticationNavigationPolicy(frozenset({"identity.example", "federation.example"}))
    policy.observe("https://identity.example/oauth/authorize?client_id=portal&response_type=code")
    return policy


@pytest.mark.parametrize("body", [
    "grant_type=authorization_code&code=private-value&code_verifier=private-verifier",
    "grant_type=refresh_token&refresh_token=private-value",
])
def test_explicit_auth_host_oauth_fetch_is_separate_from_business_post(body):
    policy = active_policy()
    assert policy.allows_browser_request(
        "POST", "https://identity.example/oauth/token", body, resource_type="fetch",
        document_navigation=False, source_url="https://portal.example/",
        source_portal_scoped=True,
    )


@pytest.mark.parametrize("destination,source,body,active", [
    ("https://unapproved.example/oauth/token", "https://portal.example/", "grant_type=authorization_code&code=x", True),
    ("https://identity.example/oauth/token", "https://attacker.example/", "grant_type=authorization_code&code=x", True),
    ("https://identity.example/oauth/token", "https://portal.example/", "grant_type=authorization_code&code=x", False),
    ("https://identity.example/api/delete", "https://portal.example/", "grant_type=authorization_code&code=x", True),
    ("https://identity.example/oauth/token", "https://portal.example/", "grant_type=password&username=x&password=x", True),
    ("https://identity.example/oauth/token", "https://portal.example/", "operation=delete", True),
    ("https://identity.example/oauth/token", "https://portal.example/", "grant_type=refresh_token&refresh_token=", True),
    ("https://identity.example/oauth/token", "https://portal.example/", "grant_type=authorization_code&grant_type=password&code=x", True),
])
def test_auth_fetch_approval_is_narrow(destination, source, body, active):
    policy = active_policy()
    policy.active = active
    assert not policy.allows_browser_request(
        "POST", destination, body, resource_type="fetch", document_navigation=False,
        source_url=source, source_portal_scoped=source == "https://portal.example/",
    )


def test_saml_iframe_navigation_can_finish_only_approved_authentication_chain():
    policy = active_policy()
    assert policy.allows_browser_request(
        "POST", "https://federation.example/saml/consume", "SAMLRequest=private-value",
        resource_type="document", document_navigation=True,
        source_url="https://identity.example/oauth/authorize",
    )
    assert policy.allows_browser_request(
        "POST", "https://portal.example/callback", "SAMLResponse=private-value",
        resource_type="document", document_navigation=True,
        source_url="https://federation.example/saml/consume", portal_scoped=True,
    )
    assert not policy.allows_browser_request(
        "POST", "https://identity.example/api/delete", "action=delete",
        resource_type="document", document_navigation=True,
        source_url="https://identity.example/oauth/authorize",
    )
    assert not policy.allows_browser_request(
        "POST", "https://unapproved.example/saml/consume", "SAMLRequest=private-value",
        resource_type="document", document_navigation=True,
        source_url="https://identity.example/oauth/authorize",
    )


def test_auth_host_is_not_a_general_resource_or_iframe_allowlist():
    policy = active_policy()
    arguments = dict(source_url="https://portal.example/", source_portal_scoped=True)
    assert policy.allows_browser_request(
        "GET", "https://identity.example/oauth/authorize", resource_type="document",
        document_navigation=True, **arguments,
    )
    for resource_type, document_navigation in (("image", False), ("script", False), ("document", True)):
        assert not policy.allows_browser_request(
            "GET", "https://identity.example/account/settings", resource_type=resource_type,
            document_navigation=document_navigation, **arguments,
        )


def test_explicit_identity_get_iframe_may_begin_flow_but_post_cannot():
    policy = AuthenticationNavigationPolicy(frozenset({"identity.example"}))
    arguments = dict(
        resource_type="document", document_navigation=True,
        source_url="https://portal.example/", source_portal_scoped=True,
    )
    assert not policy.allows_browser_request(
        "POST", "https://identity.example/saml/consume", "SAMLRequest=private-value", **arguments,
    )
    assert not policy.active
    assert policy.allows_browser_request("GET", "https://identity.example/oauth/authorize", **arguments)
    assert policy.active
    assert policy.allows_browser_request(
        "POST", "https://identity.example/saml/consume", "SAMLRequest=private-value", **arguments,
    )


def test_token_protocol_parser_does_not_accept_json_or_excessive_payload():
    assert not oauth_token_form_signal('{"grant_type":"authorization_code","code":"private"}')
    assert not oauth_token_form_signal("grant_type=authorization_code&code=" + "x" * 65536)


@pytest.mark.parametrize("path", ["/oauth2/token", "/as/token.oauth2", "/token"])
def test_standard_token_endpoint_spellings_work_under_explicit_policy(path):
    assert active_policy().allows_browser_request(
        "POST", "https://identity.example" + path, "grant_type=authorization_code&code=private-value",
        resource_type="fetch", document_navigation=False, source_url="https://portal.example/",
        source_portal_scoped=True,
    )


def test_auth_redirect_protocol_evidence_does_not_broaden_post_destinations():
    policy = active_policy()
    assert policy.allows_redirect(
        "POST", "https://identity.example/consume", "https://portal.example/callback",
        document_navigation=True, authentication_form=True, destination_portal_scoped=True,
    )
    assert policy.allows_redirect(
        "POST", "https://identity.example/oauth/token", "https://federation.example/oauth2/token",
        document_navigation=False, oauth_token_form=True,
    )
    assert not policy.allows_redirect(
        "POST", "https://identity.example/oauth/token", "https://federation.example/oauth2/token",
        document_navigation=False,
    )
    assert not policy.allows_redirect(
        "POST", "https://identity.example/oauth/token", "https://federation.example/api/delete",
        document_navigation=False, oauth_token_form=True,
    )
    assert not policy.allows_redirect(
        "POST", "https://identity.example/consume", "https://attacker.example/callback",
        document_navigation=True, authentication_form=True,
    )
    assert not policy.allows_redirect(
        "POST", "https://attacker.example/consume", "https://portal.example/callback",
        document_navigation=True, authentication_form=True, destination_portal_scoped=True,
    )
    assert not policy.allows_redirect(
        "POST", "https://portal.example/api/oauth/report", "https://identity.example/account/delete",
        document_navigation=True, source_portal_scoped=True,
    )


@pytest.mark.parametrize("method,url,body,resource_type,document_navigation,portal_scoped,expected", [
    ("POST", "https://portal.example/api/oauth/report", "{}", "fetch", False, True, False),
    ("POST", "https://portal.example/api/saml/report", "state=ready&error=business", "fetch", False, True, False),
    ("GET", "https://identity.example/analytics/sso.gif", None, "image", False, False, False),
    ("GET", "https://identity.example/docs/oauth-helper.js", None, "script", False, False, False),
    ("GET", "https://portal.example/docs/oauth", None, "document", True, True, False),
    ("GET", "https://portal.example/login", None, "document", True, True, True),
    ("POST", "https://unapproved.example/saml/consume", "SAMLRequest=private-value", "document", True, False, True),
    ("POST", "https://identity.example/oauth/token", "grant_type=authorization_code&code=private-value", "fetch", False, False, True),
    ("POST", "https://identity.example/oauth/token", "state=ready&error=business", "fetch", False, False, False),
    ("PUT", "https://portal.example/oauth/report", "{}", "fetch", False, True, False),
])
def test_blocked_business_requests_do_not_manufacture_authentication_failure(
    method, url, body, resource_type, document_navigation, portal_scoped, expected,
):
    policy = active_policy()
    assert policy.identifies_authentication_attempt(
        method, url, body, resource_type=resource_type,
        document_navigation=document_navigation, portal_scoped=portal_scoped,
    ) is expected
    policy.active = False
    assert not policy.identifies_authentication_attempt(
        method, url, body, resource_type=resource_type,
        document_navigation=document_navigation, portal_scoped=portal_scoped,
    )
    assert not policy.active


def cookie(domain, value="private-value"):
    return {
        "name": "session", "value": value, "domain": domain, "path": "/", "expires": -1,
        "httpOnly": True, "secure": True, "sameSite": "Lax",
    }


def test_storage_profile_is_scoped_without_modifying_mounted_state():
    state = {
        "cookies": [cookie("portal.example"), cookie("identity.example"), cookie("unrelated.example")],
        "origins": [
            {"origin": "https://portal.example", "localStorage": [{"name": "session", "value": "private"}]},
            {"origin": "https://identity.example", "localStorage": [], "indexedDB": [{"name": "approved"}]},
            {"origin": "https://unrelated.example", "localStorage": [{"name": "session", "value": "private"}]},
        ],
    }
    original = copy.deepcopy(state)
    scoped = scope_storage_state(state, {"portal.example", "identity.example"})
    assert state == original
    assert {item["domain"] for item in scoped["cookies"]} == {"portal.example", "identity.example"}
    assert {item["origin"] for item in scoped["origins"]} == {"https://portal.example", "https://identity.example"}
    assert scoped["origins"][1]["indexedDB"] == [{"name": "approved"}]
    scoped["origins"][0]["localStorage"][0]["value"] = "changed-private-copy"
    assert state == original


def test_domain_cookies_are_narrowed_to_explicit_hosts_with_dns_label_boundary():
    state = {"cookies": [cookie(".example.com")], "origins": []}
    scoped = scope_storage_state(state, {"app.example.com", "id.example.com", "evilexample.com", "example.com.evil"})
    assert {item["domain"] for item in scoped["cookies"]} == {"app.example.com", "id.example.com"}
    assert all(not item["domain"].startswith(".") for item in scoped["cookies"])
    assert all(item["secure"] and item["httpOnly"] and item["sameSite"] == "Lax" for item in scoped["cookies"])


def test_host_cookie_never_broadens_to_subdomain_and_specific_cookie_wins():
    assert not scope_storage_state({"cookies": [cookie("example.com")], "origins": []}, {"app.example.com"})["cookies"]
    scoped = scope_storage_state(
        {"cookies": [cookie("app.example.com", "host-only"), cookie(".example.com", "domain")], "origins": []},
        {"app.example.com"},
    )
    assert len(scoped["cookies"]) == 1 and scoped["cookies"][0]["value"] == "host-only"
    scoped = scope_storage_state(
        {"cookies": [cookie("app.example.com", "host-only"), cookie(".app.example.com", "domain")], "origins": []},
        {"app.example.com"},
    )
    assert len(scoped["cookies"]) == 1 and scoped["cookies"][0]["value"] == "host-only"


@pytest.mark.asyncio
async def test_refreshing_one_portal_preserves_another_portal_and_profile(tmp_path):
    original = {
        "cookies": [cookie(".example.com", "shared-original"), cookie("other.example.net", "other-original")],
        "origins": [
            {"origin": "https://app.example.com", "localStorage": [{"name": "state", "value": "old"}]},
            {"origin": "https://other.example.net", "localStorage": [{"name": "state", "value": "unrelated"}]},
        ],
    }
    mounted = tmp_path / "mounted.json"
    mounted.write_text(json.dumps(original), encoding="utf-8")
    store = RuntimeSessionStore(tmp_path / "runtime")
    runtime = store.seed("shared", mounted)
    other_profile = store.seed("independent", mounted)
    original_other = other_profile.read_bytes()

    class Context:
        async def storage_state(self):
            return {
                "cookies": [cookie(".example.com", "rotated-selected")],
                "origins": [{"origin": "https://app.example.com", "localStorage": [{"name": "state", "value": "new"}]}],
            }

    await store.persist("shared", Context(), approved_hosts={"app.example.com"})
    updated = json.loads(runtime.read_text(encoding="utf-8"))
    selected = scope_storage_state(updated, {"app.example.com"})
    assert selected["cookies"][0]["value"] == "rotated-selected"
    assert selected["origins"][0]["localStorage"][0]["value"] == "new"
    unrelated = scope_storage_state(updated, {"other.example.net", "second.example.com"})
    assert {item["value"] for item in unrelated["cookies"]} == {"other-original", "shared-original"}
    assert unrelated["origins"][0]["localStorage"][0]["value"] == "unrelated"
    assert all(not key.startswith("_portal_validator") for key in selected)
    assert mounted.read_text(encoding="utf-8") == json.dumps(original)
    assert other_profile.read_bytes() == original_other


@pytest.mark.asyncio
async def test_expired_scoped_cookie_is_not_resurrected_from_original_domain_cookie(tmp_path):
    mounted = tmp_path / "mounted.json"
    mounted.write_text(json.dumps({"cookies": [cookie(".example.com")], "origins": []}), encoding="utf-8")
    store = RuntimeSessionStore(tmp_path / "runtime")
    runtime = store.seed("shared", mounted)

    class ExpiredContext:
        async def storage_state(self):
            return {"cookies": [], "origins": []}

    await store.persist("shared", ExpiredContext(), approved_hosts={"app.example.com"})
    updated = json.loads(runtime.read_text(encoding="utf-8"))
    assert not scope_storage_state(updated, {"app.example.com"})["cookies"]
    assert scope_storage_state(updated, {"another.example.com"})["cookies"]


class ReplacingDocument:
    def __init__(self):
        self.url = "https://portal.example/dashboard"
        self.readiness_waits = 0

    async def wait_for_load_state(self, state, *, timeout):
        assert state == "domcontentloaded" and timeout > 0
        self.readiness_waits += 1

    async def evaluate(self, script):
        return False


@pytest.mark.asyncio
async def test_auth_observation_retries_transient_replaced_document_read_only():
    page = ReplacingDocument()
    calls = 0

    async def signals(page):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PlaywrightError("Page.evaluate: Execution context was destroyed, most likely because of a navigation")
        return False, False

    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: True, detect_signals=signals, timeout_ms=1000,
    )
    assert result["completed"] and calls == 2 and page.readiness_waits == 1


@pytest.mark.asyncio
async def test_auth_observation_does_not_swallow_persistent_or_unrelated_dom_failure():
    page = ReplacingDocument()
    for message, expected_waits in (("Execution context was destroyed", 2), ("unexpected evaluation failure", 0)):
        page.readiness_waits = 0

        async def signals(page):
            raise PlaywrightError(message)

        with pytest.raises(PlaywrightError, match=message):
            await settle_authentication_navigation(
                page, in_portal_scope=lambda url: True, detect_signals=signals, timeout_ms=1000,
            )
        assert page.readiness_waits == expected_waits


@pytest.mark.asyncio
async def test_auth_observation_never_classifies_old_login_dom_as_new_application():
    page = ReplacingDocument()
    page.url = "https://identity.example/login"
    calls = 0

    async def signals(page):
        nonlocal calls
        calls += 1
        if calls == 1:
            page.url = "https://portal.example/dashboard"
            return True, False
        return False, False

    result = await settle_authentication_navigation(
        page, in_portal_scope=lambda url: url.startswith("https://portal.example/"),
        detect_signals=signals, timeout_ms=1000, flow_active=True,
    )
    assert result["completed"] and result["stage"] == "APPLICATION"
    assert calls == 2 and page.readiness_waits == 1
