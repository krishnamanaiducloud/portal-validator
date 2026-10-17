"""Authentication approval uses the initiator, not a stale/destination frame."""

from types import SimpleNamespace

from playwright.async_api import Error as PlaywrightError

from app.main import authentication_request_source
from app.navigation import AuthenticationNavigationPolicy


def test_new_document_uses_its_initiating_frame():
    request = SimpleNamespace(redirected_from=None, frame=SimpleNamespace(
        url="https://portal.example/", parent_frame=None,
    ))
    assert authentication_request_source(request) == "https://portal.example/"


def test_preserved_post_redirect_uses_previous_hop_not_stale_approved_frame():
    request = SimpleNamespace(
        redirected_from=SimpleNamespace(url="https://unapproved.example/saml/sso"),
        frame=SimpleNamespace(url="https://identity.example/saml/sso", parent_frame=None),
    )
    source = authentication_request_source(request)
    assert source == "https://unapproved.example/saml/sso"
    policy = AuthenticationNavigationPolicy(
        approved_hosts=frozenset({"identity.example"}), active=True,
    )
    assert not policy.allows_main_frame_method(
        "POST", "https://identity.example/saml/acs", "SAMLResponse=private-fixture",
        source_url=source,
    )


def test_inherited_blank_iframe_uses_existing_parent_document():
    parent = SimpleNamespace(url="https://portal.example/", parent_frame=None)
    request = SimpleNamespace(redirected_from=None, frame=SimpleNamespace(
        url="about:blank", parent_frame=parent,
    ))
    assert authentication_request_source(request) == parent.url


def test_missing_frame_evidence_fails_closed():
    class MissingFrame:
        redirected_from = None

        @property
        def frame(self):
            raise PlaywrightError("No frame exists for this request")

    source = authentication_request_source(MissingFrame())
    assert source == ""
    policy = AuthenticationNavigationPolicy(
        approved_hosts=frozenset({"identity.example"}), active=True,
    )
    assert not policy.allows_main_frame_method(
        "POST", "https://identity.example/saml/acs", "SAMLResponse=private-fixture",
        source_url=source,
    )
