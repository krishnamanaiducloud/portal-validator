from __future__ import annotations

import re
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse, urldefrag

from app.security import DestinationError, normalized_host, sanitize_url


AUTH_QUERY_KEYS = frozenset({
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "samlrequest",
    "samlresponse",
    "relaystate",
})
AUTH_FORM_KEYS = frozenset({
    "samlrequest", "samlresponse", "relaystate", "code", "id_token", "state", "error",
})
AUTH_PATH_MARKERS = frozenset({
    "authorize", "authorization", "oauth", "oidc", "saml", "sso", "signin", "login", "idp",
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
    keys = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True)}
    path_tokens = {token for token in re.split(r"[^a-z0-9]+", parsed.path.lower()) if token}
    return bool(keys & AUTH_QUERY_KEYS or path_tokens & AUTH_PATH_MARKERS)


def authentication_form_signal(post_data: str | None) -> bool:
    if not post_data:
        return False
    try:
        keys = {key.lower() for key in parse_qs(post_data, keep_blank_values=True)}
    except (TypeError, ValueError):
        return False
    return bool(keys & AUTH_FORM_KEYS)


@dataclass
class AuthenticationNavigationPolicy:
    """Track an SSO navigation chain without broadening crawler or resource scope."""

    active: bool = False

    def observe(self, url: str) -> None:
        self.active = self.active or auth_protocol_signal(url)

    def allows_main_frame_method(self, method: str, url: str, post_data: str | None = None) -> bool:
        normalized_method = method.upper()
        url_signal = auth_protocol_signal(url)
        self.observe(url)
        if normalized_method in {"GET", "HEAD", "OPTIONS"}:
            return True
        if normalized_method != "POST":
            return False
        form_signal = authentication_form_signal(post_data)
        allowed = form_signal or (self.active and url_signal)
        self.active = self.active or form_signal
        return allowed


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
    if auth_surface and not target_in_scope:
        if authentication_mode == "storage_state":
            return "SESSION_EXPIRED"
        if authentication_mode == "none":
            return "AUTH_REQUIRED"
        return "AUTH_FAILED"
    if status is not None and status >= 400:
        return "HTTP_ERROR"
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
