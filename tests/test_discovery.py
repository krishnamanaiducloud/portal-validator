import pytest

from app.discovery import normalize_route_url, safe_navigation_control
from app.main import partition_links, url_in_scan_scope


@pytest.mark.parametrize(("value", "policy", "allowed", "expected"), [
    (
        "HTTPS://EXAMPLE.COM:443/products?utm_source=x&token=secret#section",
        "preserve",
        set(),
        "https://example.com/products",
    ),
    (
        "https://example.com/view?tab=health&id=123",
        "allowlist",
        {"tab"},
        "https://example.com/view?tab=health",
    ),
    (
        "https://example.com/app#/dashboard",
        "ignore",
        set(),
        "https://example.com/app#/dashboard",
    ),
    (
        "https://example.com/app#heading",
        "ignore",
        set(),
        "https://example.com/app",
    ),
])
def test_route_identity_normalization(value, policy, allowed, expected):
    assert normalize_route_url(
        value,
        query_policy=policy,
        allowed_query_parameters=allowed,
    ) == expected


def test_relative_and_invalid_route_normalization():
    assert normalize_route_url("../health", base_url="https://example.com/app/") == (
        "https://example.com/health"
    )
    assert normalize_route_url("javascript:alert(1)", base_url="https://example.com") is None
    assert normalize_route_url("file:///etc/passwd") is None
    assert normalize_route_url("https://user:secret@example.com/private") is None
    assert normalize_route_url("https://example.com/#/callback?code=secret") == "https://example.com/"


def test_duplicate_and_query_loop_routes_collapse():
    crawl, external = partition_links(
        [
            "https://example.com/items?page=1&utm_source=a",
            "https://example.com/items?page=2&utm_source=b",
            "https://example.com/items?page=3",
            "https://outside.example.net/",
        ],
        "example.com",
        False,
        query_parameter_policy="ignore",
    )
    assert crawl == ["https://example.com/items"]
    assert external == ["https://outside.example.net/"]


def test_explicit_portal_hosts_are_crawlable_without_broadening_subdomains():
    approved = {"app.example.net"}
    assert url_in_scan_scope("https://app.example.net/home", "example.com", False, approved)
    assert not url_in_scan_scope("https://api.example.net/home", "example.com", False, approved)
    assert not url_in_scan_scope("https://app.example.net.evil.test", "example.com", True, approved)


def test_only_semantic_non_form_controls_are_safe_to_expand():
    assert safe_navigation_control({
        "role": "button", "aria_expanded": "false", "aria_controls": "menu",
        "text": "Services", "inside_form": "false", "disabled": "false", "href": None,
    })
    assert safe_navigation_control({
        "role": "tab", "aria_selected": "false", "aria_controls": "panel",
        "text": "Health", "inside_form": "false", "disabled": "false", "href": None,
    })
    assert not safe_navigation_control({
        "role": "button", "aria_expanded": "false", "aria_controls": "menu",
        "text": "Delete account", "inside_form": "false", "disabled": "false", "href": None,
    })
    assert not safe_navigation_control({
        "role": "button", "aria_expanded": "false", "aria_controls": "menu",
        "text": "Menu", "inside_form": "true", "disabled": "false", "href": None,
    })
