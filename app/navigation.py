from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qs, urlparse, urldefrag

from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from app.security import DestinationError, normalized_host, sanitize_url


AUTH_PATH_MARKERS = frozenset({
    "auth", "authorize", "authorization", "oauth", "oidc", "saml", "sso", "signin", "login", "idp",
})


def origin_for_url(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    default_port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
    return parsed.scheme.lower(), normalized_host(parsed.hostname or ""), parsed.port or default_port


@dataclass
class NavigationDestination:
    raw_url: str
    started_at: float
    status: int | None = None

    @property
    def host(self) -> str:
        return normalized_host(urlparse(self.raw_url).hostname or "")


class NavigationTracker:
    def __init__(self, max_redirects: int):
        self.max_redirects = max_redirects
        self.destinations: list[NavigationDestination] = []
        self._seen: set[str] = set()

    def record_destination(
        self,
        url: str,
        *,
        now: float | None = None,
        allow_revisit: bool = False,
    ) -> None:
        normalized = urldefrag(url).url
        if normalized in self._seen and (
            not allow_revisit
            or not self.destinations
            or self.destinations[-1].raw_url == normalized
            or sum(destination.raw_url == normalized for destination in self.destinations) >= 2
        ):
            raise DestinationError("NAVIGATION_ERROR", "Redirect loop detected")
        if len(self.destinations) >= self.max_redirects + 1:
            raise DestinationError("NAVIGATION_ERROR", "Maximum redirect count exceeded")
        self._seen.add(normalized)
        self.destinations.append(NavigationDestination(normalized, now or time.perf_counter()))

    def record_response(self, url: str, status: int) -> None:
        normalized = urldefrag(url).url
        for destination in reversed(self.destinations):
            if destination.raw_url == normalized:
                destination.status = status
                return

    def reconcile_http_chain(self, chain: list[tuple[str, int | None]]) -> None:
        """Use Playwright's authoritative HTTP redirect chain when routing missed a hop."""
        normalized_chain = [(urldefrag(url).url, status) for url, status in chain]
        if len(normalized_chain) > len(self.destinations):
            now = time.perf_counter()
            self.destinations = [
                NavigationDestination(url, now + (index / 1000), status)
                for index, (url, status) in enumerate(normalized_chain)
            ]
            self._seen = {destination.raw_url for destination in self.destinations}
            return
        statuses = {url: status for url, status in normalized_chain}
        for destination in self.destinations:
            if destination.raw_url in statuses:
                destination.status = statuses[destination.raw_url]

    @property
    def redirect_count(self) -> int:
        return max(0, len(self.destinations) - 1)

    def redirects(self) -> list[dict]:
        redirects: list[dict] = []
        for index, (source, destination) in enumerate(
            zip(self.destinations, self.destinations[1:]),
            start=1,
        ):
            source_origin = origin_for_url(source.raw_url)
            destination_origin = origin_for_url(destination.raw_url)
            redirects.append({
                "redirect_number": index,
                "source_url": sanitize_url(source.raw_url),
                "destination_url": sanitize_url(destination.raw_url),
                "status": source.status,
                "source_host": source.host,
                "destination_host": destination.host,
                "redirect_type": "SAME_ORIGIN" if source_origin == destination_origin else "CROSS_ORIGIN",
                "same_origin": source_origin == destination_origin,
                "elapsed_ms": max(0, round((destination.started_at - source.started_at) * 1000)),
            })
        return redirects


def auth_protocol_signal(url: str) -> bool:
    parsed = urlparse(url)

    def populated_keys(query: str) -> set[str]:
        return {
            key.lower() for key, values in parse_qs(query, keep_blank_values=True).items()
            if any(value.strip() for value in values)
        }

    keys = populated_keys(parsed.query)
    fragment_path, _, fragment_query = parsed.fragment.partition("?")
    keys.update(populated_keys(fragment_query))
    # OAuth implicit callbacks may carry their parameters directly in the fragment.
    if "=" in parsed.fragment and not fragment_query:
        keys.update(populated_keys(parsed.fragment))
    path_tokens = {
        token for token in re.split(r"[^a-z0-9]+", f"{parsed.path}/{fragment_path}".lower()) if token
    }
    callback = bool({"code", "id_token", "error"} & keys and "state" in keys)
    authorization = "client_id" in keys and bool({"redirect_uri", "response_type"} & keys)
    return bool(
        {"samlrequest", "samlresponse"} & keys or path_tokens & AUTH_PATH_MARKERS
        or authorization or callback
    )


def authentication_form_signal(post_data: str | None) -> bool:
    if not post_data:
        return False
    try:
        values = {
            key.lower(): value for key, value in parse_qs(post_data, keep_blank_values=True).items()
            if any(item.strip() for item in value)
        }
    except (TypeError, ValueError):
        return False
    keys = set(values)
    # Generic business forms frequently contain state/error. Neither is proof of SSO.
    return bool(
        {"samlrequest", "samlresponse"} & keys
        or ("state" in keys and {"code", "id_token", "error"} & keys)
    )


@dataclass
class AuthenticationNavigationPolicy:
    """Track an SSO navigation chain without broadening crawler or resource scope."""

    approved_hosts: frozenset[str] = frozenset()
    active: bool = False

    def __post_init__(self) -> None:
        self.approved_hosts = frozenset(normalized_host(host) for host in self.approved_hosts)

    def observe(self, url: str, method: str = "GET") -> None:
        # A denied mutation must not manufacture an active authentication chain.
        if method.upper() in {"GET", "HEAD"}:
            host = normalized_host(urlparse(url).hostname or "")
            self.active = self.active or auth_protocol_signal(url) or host in self.approved_hosts

    def allows_main_frame_method(
        self, method: str, url: str, post_data: str | None = None, *, portal_scoped: bool = False,
    ) -> bool:
        normalized_method = method.upper()
        url_signal = auth_protocol_signal(url)
        if normalized_method in {"GET", "HEAD", "OPTIONS"}:
            self.observe(url, normalized_method)
            return True
        if normalized_method != "POST":
            return False
        form_signal = authentication_form_signal(post_data)
        host_approved = normalized_host(urlparse(url).hostname or "") in self.approved_hosts
        # IdP POSTs require explicit host approval AND protocol evidence. Portal
        # callbacks may finish an already observed flow, never initiate arbitrary POSTs.
        error_response = bool(
            post_data and "error" in {key.lower() for key in parse_qs(post_data)}
        )
        allowed = self.active and form_signal and (not error_response or url_signal) and (
            host_approved or portal_scoped
        )
        if allowed:
            self.active = True
        return allowed


async def settle_authentication_navigation(
    page: Any,
    *,
    in_portal_scope: Callable[[str], bool],
    detect_signals: Callable[[Any], Awaitable[Any]],
    timeout_ms: int,
    flow_active: bool = False,
    status: int | None = None,
    current_status: Callable[[], int | None] | None = None,
    is_approved_authentication_host: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """Observe natural SSO redirects; never submit forms or alter browser security.

    DOMContentLoaded is not authentication completion: auto-post and callback
    scripts can still be running. Only an application surface ends that wait.
    Interactive login/MFA pages stop immediately for honest classification.
    """
    started = time.perf_counter()
    deadline = started + max(0, timeout_ms) / 1000
    active = flow_active

    def result(stage: str, *, completed: bool = False, timed_out: bool = False,
               password: bool = False, mfa: bool = False) -> dict[str, Any]:
        return {
            "stage": stage, "completed": completed, "timed_out": timed_out,
            "password_form": password, "mfa_form": mfa,
            "elapsed_ms": round((time.perf_counter() - started) * 1000),
            "final_host": normalized_host(urlparse(page.url).hostname or ""),
        }

    while True:
        current_url = page.url
        signals = await detect_signals(page)
        if isinstance(signals, dict):
            password = bool(signals.get("password_form"))
            mfa = bool(signals.get("mfa_form"))
        else:
            password, mfa = map(bool, signals)
        if mfa:
            return result("MFA_REQUIRED", mfa=True, password=password)
        if password:
            return result("LOGIN_REQUIRED", password=True)
        effective_status = current_status() if current_status is not None else status
        if effective_status is not None and effective_status >= 400:
            return result("HTTP_ERROR")
        portal_scoped = in_portal_scope(current_url)
        approved_external_identity = bool(
            not portal_scoped and is_approved_authentication_host is not None
            and is_approved_authentication_host(normalized_host(urlparse(current_url).hostname or ""))
        )
        auth_surface = auth_protocol_signal(current_url) or approved_external_identity
        active = active or auth_surface
        if portal_scoped and not auth_surface:
            return result("APPLICATION", completed=True)
        if not auth_surface and not portal_scoped:
            # An active chain is not permission to treat every unrelated page as
            # authentication. A protocol auto-post form is concrete bridge evidence.
            protocol_form = active and await page.evaluate("""() => Array.from(document.forms).some(form => {
                if (form.method.toUpperCase() !== 'POST') return false;
                const fields = new Map(Array.from(form.elements)
                    .filter(field => field.name && typeof field.value === 'string' && field.value.trim())
                    .map(field => [field.name.toLowerCase(), true]));
                return fields.has('samlrequest') || fields.has('samlresponse') ||
                    (fields.has('state') && (fields.has('code') || fields.has('id_token')));
            })""")
            if not protocol_form:
                return result("OUTSIDE_PORTAL")
        if not active:
            return result("OUTSIDE_PORTAL")
        remaining_ms = (deadline - time.perf_counter()) * 1000
        if remaining_ms <= 0:
            return result("AUTHENTICATION_PENDING", timed_out=True)
        try:
            # The short observation bound also notices a login form that appears
            # without a URL change. It is not a target-performance measurement.
            await page.wait_for_url(
                lambda url: str(url) != current_url,
                wait_until="domcontentloaded", timeout=max(1, min(250, remaining_ms)),
            )
        except PlaywrightTimeoutError:
            continue


def classify_authentication(
    *,
    authentication_mode: str,
    status: int | None,
    final_url: str,
    target_in_scope: bool,
    error_classification: str | None,
    password_form: bool = False,
    mfa_form: bool = False,
    access_restricted: bool = False,
) -> str:
    auth_surface = password_form or auth_protocol_signal(final_url)
    if error_classification:
        if error_classification == "TIMEOUT" and auth_surface:
            return "AUTH_TIMEOUT"
        return error_classification
    if status == 401:
        return "AUTH_REQUIRED" if authentication_mode == "none" else "AUTH_FAILED"
    if status == 403 or access_restricted:
        return "ACCESS_RESTRICTED"
    if mfa_form:
        return "MFA_REQUIRED"
    if auth_surface:
        if authentication_mode == "storage_state":
            return "SESSION_EXPIRED"
        if authentication_mode == "none":
            return "AUTH_REQUIRED"
        return "AUTH_FAILED"
    if status is not None and status >= 400:
        return "HTTP_ERROR"
    if not target_in_scope:
        return "NAVIGATION_ERROR"
    return "PASS"


def classify_navigation_error(error: str) -> str:
    upper = error.upper()
    if "ERR_CERT_" in upper or "ERR_SSL_" in upper:
        return "TLS_ERROR"
    if "ERR_NAME_NOT_RESOLVED" in upper or "COULD NOT BE RESOLVED" in upper:
        return "DNS_ERROR"
    if "TIMEOUT" in upper or "TIMED OUT" in upper:
        return "TIMEOUT"
    if any(marker in upper for marker in (
        "ERR_CONNECTION_",
        "ERR_NETWORK_",
        "ERR_INTERNET_DISCONNECTED",
        "NETWORK POLICY",
    )):
        return "NETWORK_ERROR"
    return "NAVIGATION_ERROR"
