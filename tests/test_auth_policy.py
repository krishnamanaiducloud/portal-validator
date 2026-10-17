"""Authentication approvals come from operator configuration, never cookies."""

import copy
import json
from dataclasses import FrozenInstanceError

import pytest

from app.auth_policy import (
    AUTH_POLICIES_FILE_ENV,
    CONFIGURATION_ERROR,
    MAX_HOSTS_PER_POLICY,
    MAX_ENDPOINTS_PER_POLICY,
    MAX_POLICIES,
    MAX_POLICY_FILE_BYTES,
    AuthenticationPolicyConfigurationError,
    approved_authentication_hosts_for_target,
    approved_authentication_endpoints_for_target,
    canonical_authentication_endpoint,
    load_authentication_policies,
)


def document(entries=None):
    return {"version": 1, "policies": entries if entries is not None else [{
        "id": "approved-sso",
        "portal_hosts": ["portal.example"],
        "authentication_hosts": ["identity.example"],
    }]}


def write_policy(tmp_path, value):
    path = tmp_path / "authentication-policies.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_unconfigured_policy_preserves_empty_approvals(monkeypatch):
    monkeypatch.delenv(AUTH_POLICIES_FILE_ENV, raising=False)
    assert load_authentication_policies() == ()
    assert approved_authentication_hosts_for_target("portal.example", ()) == (frozenset(), ())


def test_explicit_operator_file_and_environment_have_same_immutable_result(tmp_path, monkeypatch):
    value = document([{
        "id": "approved-sso",
        "portal_hosts": ["PORTAL.EXAMPLE.", "portal.example"],
        "authentication_hosts": ["IDENTITY.EXAMPLE.", "identity.example", "127.0.0.1"],
    }])
    original = copy.deepcopy(value)
    path = write_policy(tmp_path, value)
    before = path.read_bytes()
    monkeypatch.setenv(AUTH_POLICIES_FILE_ENV, str(path))
    first = load_authentication_policies()
    second = load_authentication_policies(path)
    assert first == second
    assert value == original and path.read_bytes() == before
    assert first[0].portal_hosts == frozenset({"portal.example"})
    assert first[0].authentication_hosts == frozenset({"identity.example", "127.0.0.1"})
    assert approved_authentication_hosts_for_target("PORTAL.EXAMPLE.", first) == (
        frozenset({"identity.example", "127.0.0.1"}), ("approved-sso",),
    )
    with pytest.raises(FrozenInstanceError):
        first[0].id = "changed"


@pytest.mark.parametrize("target", [
    "unrelated.example", "child.portal.example", "evilportal.example", "portal.example.evil",
])
def test_policy_scope_never_uses_suffix_or_child_host_matching(tmp_path, target):
    policies = load_authentication_policies(write_policy(tmp_path, document()))
    assert approved_authentication_hosts_for_target(target, policies) == (frozenset(), ())


def test_matching_policy_union_is_deterministic_and_does_not_mutate_policies(tmp_path):
    policies = load_authentication_policies(write_policy(tmp_path, document([
        {"id": "z-policy", "portal_hosts": ["portal.example"], "authentication_hosts": ["identity.example"]},
        {"id": "a-policy", "portal_hosts": ["portal.example"], "authentication_hosts": ["federation.example"]},
        {"id": "other", "portal_hosts": ["other.example"], "authentication_hosts": ["unrelated.example"]},
    ])))
    before = copy.deepcopy(policies)
    expected = (frozenset({"identity.example", "federation.example"}), ("a-policy", "z-policy"))
    assert approved_authentication_hosts_for_target("portal.example", policies) == expected
    assert approved_authentication_hosts_for_target("portal.example", policies) == expected
    assert policies == before


@pytest.mark.parametrize("value", [
    {}, [], {"version": 1}, {"version": 1, "policies": [], "cookies": []},
    {"version": True, "policies": []}, {"version": "1", "policies": []},
    {"version": 2, "policies": []}, {"version": 1, "policies": {}},
    document([None]), document([{"id": "approved-sso", "portal_hosts": ["portal.example"]}]),
    document([{"id": "approved-sso", "portal_hosts": ["portal.example"], "authentication_hosts": ["identity.example"], "auto_infer": True}]),
    document([{"id": "approved-sso", "portal_hosts": [], "authentication_hosts": ["identity.example"]}]),
    document([{"id": "approved-sso", "portal_hosts": ["portal.example"], "authentication_hosts": []}]),
    document([{"id": "approved-sso", "portal_hosts": "portal.example", "authentication_hosts": ["identity.example"]}]),
    document([{"id": "approved-sso", "portal_hosts": [None], "authentication_hosts": ["identity.example"]}]),
])
def test_invalid_schema_fails_closed_without_echoing_document(tmp_path, value):
    with pytest.raises(AuthenticationPolicyConfigurationError) as error:
        load_authentication_policies(write_policy(tmp_path, value))
    assert str(error.value) == CONFIGURATION_ERROR


@pytest.mark.parametrize("identifier", ["", "../secret", "contains space", "*", "x" * 65, 123, None])
def test_policy_identifiers_are_safe_bounded_strings(tmp_path, identifier):
    value = document()
    value["policies"][0]["id"] = identifier
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(write_policy(tmp_path, value))


def test_duplicate_identifiers_and_json_fields_are_rejected(tmp_path):
    entry = document()["policies"][0]
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(write_policy(tmp_path, document([entry, copy.deepcopy(entry)])))
    path = tmp_path / "duplicate.json"
    path.write_text('{"version":1,"version":2,"policies":[]}', encoding="utf-8")
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(path)


@pytest.mark.parametrize("host", ["*.identity.example", ".identity.example", "https://identity.example/auth", "identity.example:443", "user@identity.example", "", "bad host", True])
@pytest.mark.parametrize("field", ["portal_hosts", "authentication_hosts"])
def test_configured_hosts_must_be_exact_hostnames(tmp_path, host, field):
    value = document()
    value["policies"][0][field] = [host]
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(write_policy(tmp_path, value))


def test_configuration_counts_and_size_are_bounded(tmp_path):
    entries = [{"id": f"policy-{index}", "portal_hosts": ["portal.example"], "authentication_hosts": ["identity.example"]} for index in range(MAX_POLICIES + 1)]
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(write_policy(tmp_path, document(entries)))
    value = document()
    value["policies"][0]["authentication_hosts"] = [f"identity-{index}.example" for index in range(MAX_HOSTS_PER_POLICY + 1)]
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(write_policy(tmp_path, value))
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (MAX_POLICY_FILE_BYTES + 1))
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(path)


@pytest.mark.parametrize("contents", [b"", b"not JSON", b"\xff", b'{"version":1,"policies":[],"token":"do-not-echo-secret"}'])
def test_malformed_file_errors_never_expose_path_or_contents(tmp_path, contents):
    path = tmp_path / "do-not-echo-secret.json"
    path.write_bytes(contents)
    with pytest.raises(AuthenticationPolicyConfigurationError) as error:
        load_authentication_policies(path)
    assert str(error.value) == CONFIGURATION_ERROR
    assert "do-not-echo-secret" not in str(error.value)


def test_configured_missing_file_directory_and_blank_path_fail_closed(tmp_path, monkeypatch):
    for configured in (tmp_path / "missing.json", tmp_path, " "):
        monkeypatch.setenv(AUTH_POLICIES_FILE_ENV, str(configured))
        with pytest.raises(AuthenticationPolicyConfigurationError):
            load_authentication_policies()


def test_empty_policy_file_is_valid_but_never_authorizes_hosts(tmp_path):
    policies = load_authentication_policies(write_policy(tmp_path, document([])))
    assert policies == ()
    assert approved_authentication_hosts_for_target("identity.example", policies) == (frozenset(), ())


def test_configmap_style_symlink_within_mount_is_supported(tmp_path):
    backing = tmp_path / "..timestamped"
    backing.mkdir()
    path = write_policy(backing, document())
    data = tmp_path / "..data"
    mounted = tmp_path / "authentication-policies.json"
    try:
        data.symlink_to(backing, target_is_directory=True)
        mounted.symlink_to(data / path.name)
    except OSError:
        pytest.skip("creating symlinks requires OS privileges")
    policies = load_authentication_policies(mounted)
    assert approved_authentication_hosts_for_target("portal.example", policies) == (
        frozenset({"identity.example"}), ("approved-sso",),
    )


def test_policy_file_symlink_cannot_escape_its_mount(tmp_path):
    mount = tmp_path / "mount"
    mount.mkdir()
    outside = write_policy(tmp_path, document())
    mounted = mount / "authentication-policies.json"
    try:
        mounted.symlink_to(outside)
    except OSError:
        pytest.skip("creating symlinks requires OS privileges")
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(mounted)


@pytest.mark.parametrize("value,expected", [
    ("HTTPS://IDENTITY.EXAMPLE.:443/saml/%61cs", "https://identity.example/saml/acs"),
    ("http://identity.example:80", "http://identity.example/"),
    ("https://identity.example:8443/tenant/callback", "https://identity.example:8443/tenant/callback"),
    ("http://[2001:0db8::1]:80/acs", "http://[2001:db8::1]/acs"),
    ("https://b\u00fccher.example/saml/caf\u00e9", "https://xn--bcher-kva.example/saml/caf%C3%A9"),
    ("https://identity.example/acs%3aprimary", "https://identity.example/acs%3Aprimary"),
    ("https://identity.example/%7etenant/acs/", "https://identity.example/~tenant/acs/"),
])
def test_endpoint_canonicalization_is_exact_and_idempotent(value, expected):
    assert canonical_authentication_endpoint(value) == expected
    assert canonical_authentication_endpoint(expected) == expected


@pytest.mark.parametrize("value", [
    None, 123, "", "//identity.example/acs", "ftp://identity.example/acs",
    "https:///acs", "https://user:do-not-echo-secret@identity.example/acs",
    "https://identity.example/acs?state=do-not-echo-secret", "https://identity.example/acs?",
    "https://identity.example/acs#", "https://identity.example/acs#state=do-not-echo-secret",
    "https://*.identity.example/acs", "https://identity.example:/acs",
    "https://identity.example:0/acs", "https://identity.example:65536/acs",
    "https://identity.example:bad/acs", "https://[fe80::1%25scope]/acs",
    "https://identity.example/../acs", "https://identity.example/./acs",
    "https://identity.example/%2e%2e/acs", "https://identity.example/.%2e/acs",
    "https://identity.example/saml%2facs", "https://identity.example/saml%5cacs",
    "https://identity.example/saml%252facs", "https://identity.example/saml%255cacs",
    "https://identity.example/acs%3fstate=private", "https://identity.example/acs%23private",
    "https://identity.example\\acs", "https://identity.example/saml//acs",
    "https://identity.example/acs\n", "https://identity.example/acs%00",
    "https://identity.example/acs%20", "https://identity.example/acs%09",
    "https://identity.example/acs%", "https://identity.example/acs%2",
    "https://identity.example/acs%GG", "https://identity.example/acs%FF",
    "https://identity.example/*", "https://identity.example/%2a",
    "https://identity.example/{tenant}/acs", "https://identity.example/%7btenant%7d/acs",
])
def test_ambiguous_or_nonexact_endpoints_fail_closed_without_echoing_url(value):
    with pytest.raises(AuthenticationPolicyConfigurationError) as error:
        canonical_authentication_endpoint(value)
    assert str(error.value) == CONFIGURATION_ERROR
    assert "do-not-echo-secret" not in str(error.value)


def test_operator_endpoint_approvals_are_separate_exact_and_target_scoped(tmp_path):
    value = document([
        {"id": "primary", "portal_hosts": ["portal.example"], "authentication_hosts": ["identity.example"],
         "authentication_endpoints": ["HTTPS://IDENTITY.EXAMPLE:443/tenant/acs", "https://portal.example/custom-callback"]},
        {"id": "secondary", "portal_hosts": ["other.example"], "authentication_hosts": ["identity.example"],
         "authentication_endpoints": ["https://identity.example/other/acs"]},
    ])
    policies = load_authentication_policies(write_policy(tmp_path, value))
    before = copy.deepcopy(policies)
    assert approved_authentication_hosts_for_target("portal.example", policies) == (
        frozenset({"identity.example"}), ("primary",),
    )
    expected = frozenset({"https://identity.example/tenant/acs", "https://portal.example/custom-callback"})
    assert approved_authentication_endpoints_for_target("PORTAL.EXAMPLE.", policies) == expected
    assert approved_authentication_endpoints_for_target("portal.example", policies) == expected
    assert approved_authentication_endpoints_for_target("child.portal.example", policies) == frozenset()
    assert approved_authentication_endpoints_for_target("unrelated.example", policies) == frozenset()
    assert policies == before


def test_endpoint_host_cannot_authorize_itself_outside_policy_hosts(tmp_path):
    value = document()
    value["policies"][0]["authentication_endpoints"] = ["https://unapproved.example/acs"]
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(write_policy(tmp_path, value))


@pytest.mark.parametrize("endpoints", [None, "https://identity.example/acs", [None], ["https://identity.example/acs"] * (MAX_ENDPOINTS_PER_POLICY + 1)])
def test_operator_endpoint_list_is_strict_and_bounded(tmp_path, endpoints):
    value = document()
    value["policies"][0]["authentication_endpoints"] = endpoints
    with pytest.raises(AuthenticationPolicyConfigurationError):
        load_authentication_policies(write_policy(tmp_path, value))


def test_absent_endpoint_list_preserves_existing_host_policy_contract(tmp_path):
    policies = load_authentication_policies(write_policy(tmp_path, document()))
    assert policies[0].authentication_endpoints == frozenset()
    assert approved_authentication_endpoints_for_target("portal.example", policies) == frozenset()
    assert approved_authentication_hosts_for_target("portal.example", policies) == (
        frozenset({"identity.example"}), ("approved-sso",),
    )


def test_storage_state_cookie_metadata_cannot_be_used_as_approval_configuration(tmp_path):
    storage_state = {
        "cookies": [{"domain": "unapproved.example", "name": "session", "value": "do-not-echo-secret"}],
        "origins": [{"origin": "https://unapproved.example", "localStorage": []}],
    }
    with pytest.raises(AuthenticationPolicyConfigurationError) as error:
        load_authentication_policies(write_policy(tmp_path, storage_state))
    assert str(error.value) == CONFIGURATION_ERROR
    assert "unapproved.example" not in str(error.value)
    assert "do-not-echo-secret" not in str(error.value)
