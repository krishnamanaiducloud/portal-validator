from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qs, urlparse, urldefrag

from playwright.async_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError

from app.discovery import retry_dom_operation
from app.security import DestinationError, normalized_host, sanitize_url


AUTH_PATH_MARKERS = frozenset({
    "auth", "authorize", "authorization", "oauth", "oauth2", "oidc", "saml", "sso", "signin", "login", "idp",
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


def auth_protocol_signal(url: str, *, boundary_only: bool = False) -> bool:
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
    path_signal = bool(path_tokens & AUTH_PATH_MARKERS)
    if boundary_only:
        # Protocol words inside a public documentation/audit route are weak
        # navigation hints, not evidence that the application requires login.
        # Keep explicit login endpoints and populated protocol parameters.
        login_endpoints = {"login", "signin", "sign-in", "log-in"}
        path_signal = any(
            path.rstrip("/").rsplit("/", 1)[-1].lower() in login_endpoints
            for path in (parsed.path, fragment_path)
        )
    return bool(
        {"samlrequest", "samlresponse"} & keys or path_signal
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


def oauth_token_form_signal(post_data: str | None) -> bool:
    """Recognize browser OAuth code/refresh exchanges, never password grants.

    This is only protocol evidence, not authorization. The caller must still
    require an active flow, explicitly approved destination, trusted initiating
    frame, and independent network/TLS validation. Payloads are never retained.
    """
    if not post_data or len(post_data) > 64 * 1024:
        return False
    try:
        values = parse_qs(post_data, keep_blank_values=True, max_num_fields=100)
    except (TypeError, ValueError):
        return False
    # Duplicate protocol fields are ambiguous; do not choose one silently.
    if any(len(items) != 1 for items in values.values()):
        return False
    grant = values.get("grant_type", [""])[0]
    required = {"authorization_code": "code", "refresh_token": "refresh_token"}.get(grant)
    return bool(required and values.get(required, [""])[0].strip())


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


    def allows_browser_request(
        self,
        method: str,
        url: str,
        post_data: str | None = None,
        *,
        resource_type: str,
        document_navigation: bool,
        source_url: str,
        source_portal_scoped: bool = False,
        portal_scoped: bool = False,
    ) -> bool:
        """Supplement top-level navigation policy for explicit SSO bridges.

        Auth iframe navigations and OAuth fetches are not business resources.
        They are nevertheless *not* a blanket resource-host exception: require
        an already observed flow, approved source/destination and concrete
        protocol evidence. Independent destination/redirect SSRF checks remain
        mandatory before dispatch. This function never sends/replays requests.
        """
        source_host = normalized_host(urlparse(source_url).hostname or "")
        if not source_portal_scoped and source_host not in self.approved_hosts:
            return False
        destination_host = normalized_host(urlparse(url).hostname or "")
        host_approved = destination_host in self.approved_hosts
        normalized_method = method.upper()
        url_signal = auth_protocol_signal(url)
        if document_navigation:
            if normalized_method in {"GET", "HEAD", "OPTIONS"}:
                allowed = bool(url_signal and (host_approved or self.active and portal_scoped))
                if allowed:
                    # An explicitly approved GET identity iframe can begin the
                    # flow. A mutating request can never manufacture that state.
                    self.observe(url, normalized_method)
                return allowed
            return self.allows_main_frame_method(
                normalized_method, url, post_data, portal_scoped=portal_scoped,
            )
        token_endpoint = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1].lower() == "token"
        if not self.active or resource_type.lower() not in {"xhr", "fetch"} or not host_approved:
            return False
        if normalized_method in {"GET", "HEAD", "OPTIONS"}:
            return url_signal
        return normalized_method == "POST" and (url_signal or token_endpoint) and oauth_token_form_signal(post_data)


    def allows_redirect(
        self, method: str, source_url: str, destination_url: str, *,
        document_navigation: bool, authentication_form: bool = False,
        oauth_token_form: bool = False, source_portal_scoped: bool = False,
        destination_portal_scoped: bool = False,
    ) -> bool:
        """Validate a naturally followed auth redirect using safe protocol facts.

        CDP supplies only booleans derived from the browser's existing request
        body. Absent token-body evidence fails closed for preserved POSTs; no
        source URL alone can authorize an OAuth fetch mutation. Destination
        URL/port/DNS validation is still performed by the redirect guard caller.
        """
        if not self.active:
            return False
        source_host = normalized_host(urlparse(source_url).hostname or "")
        destination_host = normalized_host(urlparse(destination_url).hostname or "")
        if not source_portal_scoped and source_host not in self.approved_hosts:
            return False
        normalized_method = method.upper()
        if document_navigation:
            return bool(
                normalized_method in {"GET", "HEAD", "OPTIONS", "POST"}
                and (
                    authentication_form if normalized_method == "POST"
                    else authentication_form or auth_protocol_signal(source_url)
                )
                and (destination_portal_scoped or destination_host in self.approved_hosts)
            )
        if source_host not in self.approved_hosts or destination_host not in self.approved_hosts:
            return False
        destination_token = urlparse(destination_url).path.rstrip("/").rsplit("/", 1)[-1].lower() == "token"
        if not (auth_protocol_signal(destination_url) or destination_token):
            return False
        if normalized_method in {"GET", "HEAD", "OPTIONS"}:
            return bool(oauth_token_form or auth_protocol_signal(source_url))
        return normalized_method == "POST" and oauth_token_form


    def identifies_authentication_attempt(
        self, method: str, url: str, post_data: str | None, *,
        resource_type: str, document_navigation: bool, portal_scoped: bool,
    ) -> bool:
        """Classify a denied SSO request, not authorize or activate its flow.

        Protocol words on assets/business endpoints are insufficient evidence
        that authentication failed. POST navigation needs an actual protocol
        form; API exchanges additionally require explicit identity-host scope.
        """
        if not self.active:
            return False
        normalized_method = method.upper()
        if document_navigation:
            if normalized_method == "POST":
                return authentication_form_signal(post_data)
            return bool(
                normalized_method in {"GET", "HEAD", "OPTIONS"}
                and auth_protocol_signal(url, boundary_only=portal_scoped)
            )
        if normalized_method != "POST" or resource_type.lower() not in {"xhr", "fetch"}:
            return False
        host = normalized_host(urlparse(url).hostname or "")
        token_endpoint = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1].lower() == "token"
        return bool(
            host in self.approved_hosts and (auth_protocol_signal(url) or token_endpoint)
            and oauth_token_form_signal(post_data)
        )


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

    async def observe_document() -> tuple[str, bool, bool, int | None, bool, bool]:
        """Read one consistent document snapshot; an auth bridge may replace it."""
        current_url = page.url
        signals = await detect_signals(page)
        if isinstance(signals, dict):
            password = bool(signals.get("password_form"))
            mfa = bool(signals.get("mfa_form"))
        else:
            password, mfa = map(bool, signals)
        effective_status = current_status() if current_status is not None else status
        portal_scoped = in_portal_scope(current_url)
        approved_external_identity = bool(
            not portal_scoped and is_approved_authentication_host is not None
            and is_approved_authentication_host(normalized_host(urlparse(current_url).hostname or ""))
        )
        auth_surface = auth_protocol_signal(current_url, boundary_only=portal_scoped) or approved_external_identity
        if active and not auth_surface and not password and not mfa:
            # A protocol auto-post form is concrete bridge evidence both inside
            # and outside portal scope. Observe it; never submit it ourselves.
            auth_surface = await page.evaluate("""() => Array.from(document.forms).some(form => {
                if (form.method.toUpperCase() !== 'POST') return false;
                const fields = new Map(Array.from(form.elements)
                    .filter(field => field.name && typeof field.value === 'string' && field.value.trim())
                    .map(field => [field.name.toLowerCase(), true]));
                return fields.has('samlrequest') || fields.has('samlresponse') ||
                    (fields.has('state') && (fields.has('code') || fields.has('id_token')));
            })""")
        if page.url != current_url:
            # A frame's URL and DOM evidence must describe the same document.
            # Retrying this read-only snapshot cannot replay an SSO submission.
            raise PlaywrightError("Execution context was destroyed during authentication observation")
        return current_url, password, mfa, effective_status, portal_scoped, bool(auth_surface)

    while True:
        try:
            current_url, password, mfa, effective_status, portal_scoped, auth_surface = await retry_dom_operation(
                page, observe_document,
                timeout_ms=max(1, round((deadline - time.perf_counter()) * 1000)),
            )
        except asyncio.TimeoutError:
            return result("AUTHENTICATION_PENDING", timed_out=True)
        if mfa:
            return result("MFA_REQUIRED", mfa=True, password=password)
        if password:
            return result("LOGIN_REQUIRED", password=True)
        if effective_status is not None and effective_status >= 400:
            return result("HTTP_ERROR")
        active = active or auth_surface
        if portal_scoped and not auth_surface:
            return result("APPLICATION", completed=True)
        if not auth_surface and not portal_scoped:
            # An active chain alone does not authorize an unrelated destination.
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
    auth_surface = password_form or auth_protocol_signal(final_url, boundary_only=target_in_scope)
    if error_classification:
        if error_classification == "TIMEOUT" and auth_surface:
            return "AUTH_TIMEOUT"
        return error_classification
    if status == 401:
        return "AUTH_REQUIRED" if authentication_mode == "none" else "AUTH_FAILED"
    if status in {403, 429} or access_restricted:
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
