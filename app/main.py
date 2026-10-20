from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import time
import uuid
import weakref
from collections import Counter, defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Awaitable, Callable, Literal
from urllib.parse import parse_qsl, urldefrag, urlparse, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from playwright.async_api import BrowserContext, Error as PlaywrightError, Request as BrowserRequest, Route, async_playwright

from app.authentication import (
    AuthenticationConfigurationError,
    build_authentication_manager,
)
from app.auth_policy import (
    AuthenticationPolicyConfigurationError,
    approved_authentication_endpoints_for_target,
    approved_authentication_hosts_for_target,
    load_authentication_policies,
)
from app.logging_config import LOGGER, log_event
from app.browser_lifecycle import BrowserLifecycle
from app.discovery import (
    DOCUMENT_NAVIGATION,
    DOWNLOAD_OBSERVED,
    POPUP_NAVIGATION,
    ROUTE_OBSERVER_SCRIPT,
    SAME_DOCUMENT_NAVIGATIONS,
    UI_VIEW_ACTIVATION,
    DiscoveredRoute,
    evaluate_dom,
    retry_dom_operation,
    collect_route_name_evidence,
    discover_page_routes,
    discovered_route_key,
    expand_safe_navigation,
    finalize_duplicate_route_names,
    is_document_route_candidate,
    normalize_route_url,
    perform_route_navigation,
    resolve_route_name,
    resolve_view_target,
    route_identity_fields,
)
from app.health import (
    api_health_findings,
    assess_page_health,
    application_shell_ready,
    configured_readiness_satisfied,
    capture_render_health,
    configured_readiness_conditions,
    document_navigation_timing,
    readiness_event_init_script,
    realtime_health_findings,
    route_performance_timing,
    wait_for_render_settle,
)
from app.navigation import (
    AuthenticationObservationCancelled,
    AuthenticationNavigationPolicy,
    NavigationTracker,
    classify_authentication,
    classify_navigation_error,
    origin_for_url,
    settle_authentication_navigation,
    auth_protocol_signal,
    authentication_form_signal,
    oauth_refresh_grant_signal,
)
from app.navigation_guard import RedirectResponseGuard
from app.network import (
    BROWSER_TIMER_LIMIT_MS,
    SAFE_HTTP_METHODS,
    PassiveNetworkObserver,
    ReadOnlyPolicy,
    RouteNetworkActivity,
    is_read_only_graphql_body,
    load_read_only_policy,
    request_identity,
    safe_api_identity,
    summarize_post_diagnostics,
    summarize_route_api_coverage,
    api_timeout_init_script,
    drain_pending_api_observations,
    policy_hostname,
)
from app.reporting import (
    _safe_authentication_diagnostics,
    group_authentication_diagnostics,
    suggested_authentication_hosts,
    traffic_class,
    aggregate_api_events,
    aggregate_api_inventory,
    aggregate_report,
    aggregate_resource_events,
    aggregate_resource_inventory,
    aggregate_security_recommendations,
    apply_global_authentication_failure,
    build_coverage_dimensions,
    classify_page_result,
    create_authentication_error,
    finding,
    refresh_route_api_health,
    navigation_coverage,
    unvisited_route_reason,
)
from app.session import RuntimeSessionStore, load_refresh_config, refresh_browser_session, scope_storage_state
from app.resources import build_resource_report, enrich_resource_timings, large_resource_findings, resource_timing_key, safe_content_type
from app.scans import ScanAdmissionCancelled, ScanCapacityError, ScanConcurrencyLimiter, ScanJob, ScanRegistry, TERMINAL_STATES
from app.security import (
    DestinationError,
    normalized_host,
    resolve_and_validate,
    sanitize_text,
    sanitize_url,
    validate_http_url,
)
from app.trust import TrustStatus, inspect_trust_status
from app.build_info import build_diagnostics, frontend_identity
from app.version import VALIDATOR_VERSION


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
AUTH_STATE_DIR = Path(os.getenv("SESSION_STATE_DIR", "/auth"))
MAX_CONCURRENT_SCANS = max(1, int(os.getenv("MAX_CONCURRENT_SCANS", "2")))
SCAN_LIMITER = ScanConcurrencyLimiter(MAX_CONCURRENT_SCANS)
SCAN_REGISTRY = ScanRegistry(maximum_jobs=max(10, int(os.getenv("MAX_SCAN_JOBS", "100"))))
ProgressCallback = Callable[..., Awaitable[None]]

SAFE_READ_ONLY_METHODS = set(SAFE_HTTP_METHODS)
DANGEROUS_PATH_WORDS = (
    "delete", "destroy", "restart", "reboot", "deploy", "approve",
    "terminate", "logout", "remove", "signout",
)
FORBIDDEN_AUTH_HEADERS = {"host", "content-length", "connection", "cookie"}
PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SECURITY_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-content-type-options",
    "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
)
COMMON_COUNTRY_CODE_SECOND_LEVEL_LABELS = frozenset({
    "ac", "co", "com", "edu", "gov", "net", "org",
})
REPORT_SCHEMA_VERSION = "2.6"


@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.trust_status = inspect_trust_status()
    application.state.read_only_policy = load_read_only_policy()
    # Operator approvals are a separate, read-only configuration contract.
    # Invalid configured policy fails startup; browser profiles never grant it.
    load_authentication_policies()
    try:
        yield
    finally:
        await SCAN_REGISTRY.shutdown()


app = FastAPI(
    title="Portal Validator",
    version=VALIDATOR_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.exception_handler(RequestValidationError)
async def invalid_scan_configuration(request: Request, exc: RequestValidationError):
    # FastAPI's default response includes rejected input, which may contain
    # credentials. Return schema metadata only, never values or exception text.
    known_fields = set(ScanRequest.model_fields) | set(Authentication.model_fields) | set(CookieInput.model_fields)
    errors = []
    for error in exc.errors():
        location = error.get("loc", ())
        field = ".".join(
            str(part) if part == "body" or isinstance(part, int) or part in known_fields else "[field]"
            for part in location
        )
        code = error.get("type", "invalid_configuration")
        message = (
            "Unrecognized configuration field; use the documented request fields."
            if code == "extra_forbidden" else
            "Use exact authentication hostnames or IP addresses, without URLs, ports or wildcards."
            if "authentication_hosts" in location else
            "Required configuration field is missing."
            if code == "missing" else
            "Configuration value is invalid or outside its allowed limits."
        )
        errors.append({"field": field, "code": code, "message": message})
    log_event(logging.WARNING, "SCAN_CONFIGURATION_REJECTED", error_count=len(errors))
    return JSONResponse(status_code=422, content={
        "detail": "Invalid scan configuration. Check the indicated fields.", "errors": errors,
    })


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        ),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
    })
    return response


class CookieInput(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    value: SecretStr
    domain: str | None = Field(default=None, max_length=253)
    path: str = Field(default="/", max_length=2048)
    secure: bool = True
    http_only: bool = True
    same_site: Literal["Strict", "Lax", "None"] = "Lax"


class Authentication(BaseModel):
    model_config = {"extra": "forbid"}
    mode: Literal["none", "basic", "bearer", "headers", "cookies", "storage_state"] = "none"
    username: str | None = Field(default=None, max_length=512)
    password: SecretStr | None = None
    token: SecretStr | None = None
    headers: dict[str, SecretStr] = Field(default_factory=dict)
    cookies: list[CookieInput] = Field(default_factory=list, max_length=50)
    storage_profile: str | None = None

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, headers: dict[str, SecretStr]):
        if len(headers) > 25:
            raise ValueError("No more than 25 custom headers are allowed")
        for name in headers:
            normalized = name.strip().lower()
            if normalized in FORBIDDEN_AUTH_HEADERS or not re.fullmatch(r"[A-Za-z0-9-]+", name):
                raise ValueError(f"Header is not allowed: {name}")
        return headers


class ApprovedReadPostOperation(BaseModel):
    model_config = {"extra": "forbid"}
    method: Literal["POST"] = "POST"
    host: str = Field(min_length=1, max_length=253)
    path: str | None = Field(default=None, max_length=2048)
    path_pattern: str | None = Field(default=None, max_length=2048)
    description: str | None = Field(default=None, max_length=256)
    graphql_queries_only: bool = False

    @model_validator(mode="after")
    def validate_explicit_operation(self):
        # Use the same strict policy parser for UI and deployment rules.
        rule = load_read_only_policy(raw=json.dumps({
            "safe_application_requests": [self.model_dump(exclude_none=True)],
        })).safe_application_requests[0]
        self.host = rule.host
        return self


class ScanRequest(BaseModel):
    model_config = {"frozen": True, "extra": "forbid"}
    target: str = Field(min_length=1, max_length=4096)
    # Every scan setting is operator-configurable from the UI/API. Only
    # technical bounds apply: millisecond values must fit browser timers.
    max_pages: int = Field(500, ge=1)
    max_depth: int = Field(10, ge=0)
    max_redirects: int = Field(10, ge=0)
    timeout_ms: int = Field(15000, ge=1000, le=BROWSER_TIMER_LIMIT_MS)
    per_route_timeout_ms: int | None = Field(None, ge=1000, le=BROWSER_TIMER_LIMIT_MS)
    total_timeout_ms: int = Field(1800000, ge=1000, le=BROWSER_TIMER_LIMIT_MS)
    navigation_timeout_ms: int | None = Field(None, ge=1000, le=BROWSER_TIMER_LIMIT_MS)
    authentication_timeout_ms: int | None = Field(None, ge=1000, le=BROWSER_TIMER_LIMIT_MS)
    readiness_timeout_ms: int | None = Field(None, ge=1000, le=BROWSER_TIMER_LIMIT_MS)
    api_timeout_ms: int | None = Field(None, ge=1000, le=BROWSER_TIMER_LIMIT_MS)
    # Discovery runs after a route is validated and has its own budget, so a
    # large menu tree cannot turn a healthy route into a route timeout.
    discovery_timeout_ms: int | None = Field(None, ge=1000, le=BROWSER_TIMER_LIMIT_MS)
    readiness_selector: str | None = Field(None, max_length=512)
    readiness_event: str | None = Field(None, max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    concurrency_limit: int = Field(MAX_CONCURRENT_SCANS, ge=1, le=MAX_CONCURRENT_SCANS)
    check_links: bool = True
    check_console: bool = True
    check_resources: bool = True
    check_performance: bool = True
    check_security_headers: bool = True
    allow_subdomains: bool = False
    allow_private_networks: bool = False
    resource_hosts: list[str] = Field(default_factory=list)
    approved_read_post_operations: list[ApprovedReadPostOperation] = Field(default_factory=list)
    portal_hosts: list[str] = Field(default_factory=list)
    credential_hosts: list[str] = Field(default_factory=list)
    authentication_hosts: list[str] = Field(default_factory=list)
    query_parameter_policy: Literal["ignore", "allowlist", "preserve"] = "ignore"
    allowed_query_parameters: list[str] = Field(default_factory=list)
    slow_page_threshold_ms: int = Field(5000, ge=500, le=BROWSER_TIMER_LIMIT_MS)
    large_resource_threshold_bytes: int = Field(1048576, ge=1024)
    large_image_threshold_bytes: int = Field(524288, ge=1024)
    large_js_threshold_bytes: int = Field(1048576, ge=1024)
    large_css_font_threshold_bytes: int = Field(524288, ge=1024)
    render_settle_ms: int = Field(400, ge=0, le=BROWSER_TIMER_LIMIT_MS)
    min_observation_ms: int = Field(300, ge=0, le=BROWSER_TIMER_LIMIT_MS)
    network_quiet_ms: int = Field(300, ge=0, le=BROWSER_TIMER_LIMIT_MS)
    # Once the view is rendered and its DOM is stable, stop waiting for
    # network quiet after this long. Polling applications never go quiet;
    # 0 waits for quiet until the readiness budget is exhausted.
    network_settle_cap_ms: int = Field(2000, ge=0, le=BROWSER_TIMER_LIMIT_MS)
    # A separately loaded document (a hyperlink to a help, documentation or
    # other non-application page) never shows the application shell's
    # readiness selector/event. Once it has rendered stable content for this
    # long without it, validate it as a linked document instead of waiting
    # for the route timeout. 0 always requires the configured condition.
    shell_marker_grace_ms: int = Field(2000, ge=0, le=BROWSER_TIMER_LIMIT_MS)
    # Observation after opening a menu during discovery (not route validation).
    menu_settle_ms: int = Field(250, ge=0, le=BROWSER_TIMER_LIMIT_MS)
    max_navigation_actions: int = Field(200, ge=0)
    max_discovery_scrolls: int = Field(3, ge=0)
    # Re-run a profile's configured silent session refresh during the scan this
    # often, on a separate tab. Overrides the profile's refresh interval_ms.
    session_refresh_interval_ms: int | None = Field(None, ge=1000, le=BROWSER_TIMER_LIMIT_MS)
    # When the session expires after the application was ready, re-establish
    # it (profile refresh + silent SSO) and retry the route this many times
    # before stopping with the routes validated so far.
    session_recovery_attempts: int = Field(3, ge=0)
    # Shared header/navigation/sidebar menus are explored once per scan.
    # Enable to re-explore them on every route (slower; for menus whose
    # content differs per route).
    reexplore_navigation_each_route: bool = False
    authentication: Authentication = Field(default_factory=Authentication)
    allow_mutations: bool = False
    mutation_acknowledged: bool = False
    mutation_endpoint_allowlist: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("target", mode="before")
    @classmethod
    def normalize_target(cls, target):
        if not isinstance(target, str):
            return target
        value = target.strip()
        if value.startswith("//"):
            return "https:" + value
        if "://" not in value:
            return "https://" + value
        return value

    @field_validator("resource_hosts", "portal_hosts", "credential_hosts")
    @classmethod
    def validate_host_lists(cls, hosts: list[str]):
        cleaned = []
        for host in hosts:
            value = normalized_host(host)
            if not value or "/" in value or "://" in value:
                raise ValueError(f"Configured host must be a hostname: {host}")
            cleaned.append(value)
        return list(dict.fromkeys(cleaned))

    @field_validator("authentication_hosts")
    @classmethod
    def validate_authentication_hosts(cls, hosts: list[str]):
        return list(dict.fromkeys(policy_hostname(host) for host in hosts))

    @field_validator("allowed_query_parameters")
    @classmethod
    def validate_query_parameters(cls, parameters: list[str]):
        cleaned: list[str] = []
        for parameter in parameters:
            value = parameter.strip().lower()
            if not re.fullmatch(r"[a-z0-9_.-]{1,64}", value):
                raise ValueError(f"Query parameter name is invalid: {parameter}")
            cleaned.append(value)
        return list(dict.fromkeys(cleaned))


def portal_boundary_host(host: str) -> str:
    normalized = normalized_host(host)
    return normalized[4:] if normalized.startswith("www.") else normalized


def can_expand_subdomains(host: str) -> bool:
    boundary = portal_boundary_host(host)
    try:
        ipaddress.ip_address(boundary)
        return False
    except ValueError:
        pass
    labels = boundary.split(".")
    if len(labels) < 2:
        return False
    return not (
        len(labels) == 2
        and len(labels[1]) == 2
        and labels[0] in COMMON_COUNTRY_CODE_SECOND_LEVEL_LABELS
    )


def host_in_scope(host: str, root_host: str, allow_subdomains: bool) -> bool:
    candidate = normalized_host(host)
    boundary = portal_boundary_host(root_host)
    if not candidate or not boundary:
        return False
    if candidate in {boundary, "www." + boundary}:
        return True
    return bool(
        allow_subdomains
        and can_expand_subdomains(boundary)
        and candidate.endswith("." + boundary)
    )


def url_in_scope(candidate: str, root_host: str, allow_subdomains: bool) -> bool:
    parsed = urlparse(candidate)
    return bool(
        parsed.scheme in {"http", "https"}
        and parsed.hostname
        and host_in_scope(parsed.hostname, root_host, allow_subdomains)
    )


def host_in_scan_scope(
    host: str,
    root_host: str,
    allow_subdomains: bool,
    approved_portal_hosts: set[str] | None = None,
) -> bool:
    candidate = normalized_host(host)
    return host_in_scope(candidate, root_host, allow_subdomains) or candidate in (
        approved_portal_hosts or set()
    )


def url_in_scan_scope(
    candidate: str,
    root_host: str,
    allow_subdomains: bool,
    approved_portal_hosts: set[str] | None = None,
) -> bool:
    parsed = urlparse(candidate)
    return bool(
        parsed.scheme in {"http", "https"}
        and parsed.hostname
        and host_in_scan_scope(
            parsed.hostname,
            root_host,
            allow_subdomains,
            approved_portal_hosts,
        )
    )


def evaluate_navigation_scope(
    requested_url: str,
    final_url: str,
    root_host: str,
    allow_subdomains: bool,
) -> tuple[str, str, bool]:
    """Backward-compatible helper that now describes crawler scope only."""
    requested = urlparse(requested_url)
    final = urlparse(final_url)
    requested_host = normalized_host(requested.hostname or "")
    final_host = normalized_host(final.hostname or "")
    return (
        requested_host,
        final_host,
        bool(final_host and url_in_scope(final_url, root_host, allow_subdomains)),
    )


def sanitized_url(value: str, *, include_path: bool = True) -> str:
    return sanitize_url(value, include_path=include_path)


def sanitized_diagnostic(value: str) -> str:
    first_line = value.splitlines()[0] if value else "Unknown navigation error"
    return sanitize_text(first_line, limit=1000)


async def validate_destination(host: str, allow_private: bool) -> None:
    try:
        await resolve_and_validate(host, allow_private)
    except DestinationError as exc:
        raise HTTPException(400, exc.public_message) from exc


def storage_state_path(profile: str | None) -> Path:
    if not profile or not PROFILE_RE.fullmatch(profile):
        raise HTTPException(400, "Storage-state profile name is invalid")
    path = (AUTH_STATE_DIR / f"{profile}.json").resolve()
    root = AUTH_STATE_DIR.resolve()
    if root not in path.parents or not path.is_file():
        raise HTTPException(400, "Storage-state profile was not found")
    try:
        validate_storage_state_file(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(400, "Storage-state profile is not valid Playwright JSON") from exc
    return path


def validate_storage_state_file(path: Path) -> None:
    """Validate Playwright storage state without returning or logging its secrets."""
    size = path.stat().st_size
    if size <= 0 or size > 10 * 1024 * 1024:
        raise ValueError("Storage-state file size is invalid")
    with path.open("r", encoding="utf-8") as handle:
        state = json.load(handle)
    if not isinstance(state, dict):
        raise ValueError("Storage state must be an object")
    cookies = state.get("cookies", [])
    origins = state.get("origins", [])
    if not isinstance(cookies, list) or not isinstance(origins, list):
        raise ValueError("Storage state cookies and origins must be arrays")
    for cookie in cookies:
        if (
            not isinstance(cookie, dict)
            or not all(isinstance(cookie.get(key), str) for key in ("name", "value", "domain", "path"))
            or not all(cookie.get(key) for key in ("name", "domain", "path"))
        ):
            raise ValueError("Storage state contains an invalid cookie")
    for origin_state in origins:
        if not isinstance(origin_state, dict) or not isinstance(origin_state.get("origin"), str):
            raise ValueError("Storage state contains an invalid origin")
        validate_http_url(origin_state["origin"])
        local_storage = origin_state.get("localStorage", [])
        if not isinstance(local_storage, list) or not all(
            isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and isinstance(item.get("value"), str)
            for item in local_storage
        ):
            raise ValueError("Storage state contains invalid local storage")


def discover_storage_profiles() -> list[str]:
    if not AUTH_STATE_DIR.is_dir():
        return []
    profiles: list[str] = []
    for path in AUTH_STATE_DIR.glob("*.json"):
        if not PROFILE_RE.fullmatch(path.stem):
            continue
        try:
            resolved = path.resolve(strict=True)
            if AUTH_STATE_DIR.resolve() not in resolved.parents:
                continue
            validate_storage_state_file(resolved)
        except (OSError, ValueError, json.JSONDecodeError, DestinationError):
            continue
        profiles.append(path.stem)
    return sorted(profiles)


def discover_refresh_profiles(profiles: list[str]) -> list[str]:
    enabled: list[str] = []
    for profile in profiles:
        try:
            if load_refresh_config(profile, AUTH_STATE_DIR) is not None:
                enabled.append(profile)
        except (OSError, ValueError, json.JSONDecodeError, DestinationError):
            continue
    return sorted(enabled)


def browser_context_options(state_path: Path | None, approved_storage_hosts: set[str] | None = None) -> dict[str, object]:
    options: dict[str, object] = {
        "ignore_https_errors": False,
        "service_workers": "block",
    }
    if state_path is not None:
        options["storage_state"] = (
            scope_storage_state(json.loads(state_path.read_text(encoding="utf-8")), approved_storage_hosts)
            if approved_storage_hosts is not None else str(state_path)
        )
    return options


def authentication_approvals_for_scan(req: ScanRequest, root_host: str):
    """Resolve explicit approvals without consulting or mutating session state."""
    try:
        policies = load_authentication_policies()
        operator_hosts, matched_policies = approved_authentication_hosts_for_target(root_host, policies)
        operator_endpoints = approved_authentication_endpoints_for_target(root_host, policies)
    except AuthenticationPolicyConfigurationError as exc:
        raise HTTPException(503, "Administrator authentication policy is invalid") from exc
    hosts = list(dict.fromkeys([*req.authentication_hosts, *sorted(operator_hosts)]))
    if len(hosts) > 25:
        raise HTTPException(400, "Combined authentication-host approvals exceed the maximum of 25")
    return hosts, operator_endpoints, {
        "submitted_authentication_host_count": len(req.authentication_hosts),
        "operator_authentication_host_count": len(operator_hosts),
        "operator_authentication_policy_count": len(matched_policies),
        "operator_authentication_endpoint_count": len(operator_endpoints),
    }


def authentication_request_source(request: BrowserRequest) -> str:
    """Use the previous HTTP hop, or initiating frame, never the destination."""
    try:
        previous = request.redirected_from
        if previous is not None:
            return previous.url
        frame = request.frame
        while frame.parent_frame is not None and not frame.url.startswith(("http://", "https://")):
            frame = frame.parent_frame
        return frame.url
    except PlaywrightError:
        # Unavailable source evidence must fail closed for authentication POSTs.
        return ""


def auth_headers(authentication: Authentication) -> dict[str, str]:
    try:
        manager = build_authentication_manager(
            mode=authentication.mode,
            credential_hosts=set(),
            username=authentication.username,
            password=(
                authentication.password.get_secret_value()
                if authentication.password is not None else None
            ),
            token=(
                authentication.token.get_secret_value()
                if authentication.token is not None else None
            ),
            headers={
                name: value.get_secret_value()
                for name, value in authentication.headers.items()
            },
        )
        return manager.configured_headers()
    except AuthenticationConfigurationError as exc:
        raise HTTPException(400, str(exc)) from exc


def headers_for_destination(
    request_headers: dict[str, str],
    sensitive_headers: dict[str, str],
    destination_host: str,
    credential_hosts: set[str],
) -> dict[str, str]:
    """Attach scan credentials only to explicitly approved destination hosts."""
    manager = build_authentication_manager(
        mode="headers" if sensitive_headers else "none",
        credential_hosts=credential_hosts,
        headers=sensitive_headers,
    )
    return manager.headers_for_request(request_headers, normalized_host(destination_host))


async def configure_cookies(
    context: BrowserContext,
    req: ScanRequest,
    root_host: str,
    approved_portal_hosts: set[str] | None = None,
) -> None:
    if req.authentication.mode != "cookies":
        return
    if not req.authentication.cookies:
        raise HTTPException(400, "Cookie authentication requires at least one cookie")
    cookies = []
    for cookie in req.authentication.cookies:
        domain = normalized_host(cookie.domain or root_host)
        if not host_in_scan_scope(
            domain.lstrip("."),
            root_host,
            req.allow_subdomains,
            approved_portal_hosts,
        ):
            raise HTTPException(400, f"Cookie domain is outside the approved portal scope: {domain}")
        cookies.append({
            "name": cookie.name,
            "value": cookie.value.get_secret_value(),
            "domain": domain,
            "path": cookie.path,
            "secure": cookie.secure,
            "httpOnly": cookie.http_only,
            "sameSite": cookie.same_site,
        })
    await context.add_cookies(cookies)


async def detect_auth_signals(page) -> tuple[bool, bool]:
    # A replaced execution context is not evidence that login/MFA is absent.
    # Retry read-only observation within a bound; persistent failures propagate.
    # Hidden login templates and numeric business filters are common in
    # hydrated portals. Neither proves that the visible route is a login
    # or MFA challenge, and a false positive prevents all route discovery.
    signals = await evaluate_dom(page, """() => {
          const visible = input => {
            const style = getComputedStyle(input);
            const rect = input.getBoundingClientRect();
            return !input.disabled && input.type !== 'hidden' &&
              !input.closest('[hidden], [inert], [aria-hidden="true"]') &&
              style.visibility !== 'hidden' && style.display !== 'none' &&
              rect.width > 0 && rect.height > 0;
          };
          const inputs = Array.from(document.querySelectorAll('input')).filter(visible);
          // An optional header/sidebar sign-in widget must not hide an already
          // available public main surface. Be conservative: require visible
          // content with multiple main-area navigation links, outside the form.
          const publicMain = Array.from(document.querySelectorAll('main, [role="main"]'))
            .filter(main => visible(main) && (main.innerText || '').trim().length >= 40 &&
              Array.from(main.querySelectorAll('a[href]')).filter(visible).length >= 2);
          const optionalWidget = input => input.closest('header, nav, aside, footer') &&
            !input.closest('dialog, [role="dialog"], [aria-modal="true"]') &&
            !document.querySelector('dialog[open], [aria-modal="true"]') &&
            publicMain.some(main => !main.contains(input));
          const codeLabel = input => [input.name, input.id, input.getAttribute('aria-label'),
            ...Array.from(input.labels || [], label => label.textContent),
            ...(input.getAttribute('aria-labelledby') || '').split(/\\s+/)
              .map(id => document.getElementById(id)?.textContent || '')
          ].filter(Boolean).join(' ');
          return {
            password: inputs.some(input => input.type === 'password' && !optionalWidget(input)),
            mfa: inputs.some(input => input.autocomplete === 'one-time-code' || (
              /(?:^|[^a-z])(?:otp|mfa|totp|one[ -]?time[ -]?(?:code|password)|verification[ -]?code|authentication[ -]?code)(?:$|[^a-z])/i
                .test(codeLabel(input))
            ))
          };
        }""")
    return bool(signals["password"]), bool(signals["mfa"])


async def acknowledge_configured_access_gate(
    page,
    policy: ReadOnlyPolicy,
    current_url: str,
    acknowledged: set[tuple[str, str]],
    timeout_ms: int = 5000,
) -> bool:
    """Activate one exact administrator-approved gate without inspecting content."""
    rule = policy.access_gate_for(current_url)
    if rule is None:
        return False
    key = (rule.host, rule.selector)
    if key in acknowledged:
        return False
    control = page.locator(rule.selector)
    count = await control.count()
    if count == 0:
        return False
    if count != 1:
        raise RuntimeError("Configured access gate selector is ambiguous")
    if not await control.is_visible():
        return False
    await control.click(timeout=max(1, timeout_ms))
    acknowledged.add(key)
    return True


def partition_links(
    links: list[str],
    root_host: str,
    allow_subdomains: bool,
    approved_portal_hosts: set[str] | None = None,
    query_parameter_policy: str = "preserve",
    allowed_query_parameters: set[str] | None = None,
) -> tuple[list[str], list[str]]:
    crawl_links: list[str] = []
    external_links: list[str] = []
    seen_crawl: set[str] = set()
    seen_external: set[str] = set()
    for link in links:
        clean = normalize_route_url(
            link,
            query_policy=query_parameter_policy,
            allowed_query_parameters=allowed_query_parameters,
        )
        if clean is None:
            continue
        if not is_document_route_candidate(clean):
            continue
        parsed = urlparse(clean)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        if url_in_scan_scope(clean, root_host, allow_subdomains, approved_portal_hosts):
            if clean not in seen_crawl:
                crawl_links.append(clean)
                seen_crawl.add(clean)
        else:
            safe_link = sanitized_url(clean)
            if safe_link not in seen_external:
                external_links.append(safe_link)
                seen_external.add(safe_link)
    return crawl_links, external_links


@app.get("/", include_in_schema=False)
async def home():
    frontend_sha256, integrity = frontend_identity()
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    script = '<script src="/static/app.js" defer></script>'
    if script not in html:
        raise RuntimeError("Dashboard script identity marker is missing")
    return HTMLResponse(html.replace(
        script,
        f'<script src="/static/app.js?v={frontend_sha256}" integrity="{integrity}" '
        f'crossorigin="anonymous" data-frontend-sha256="{frontend_sha256}" defer></script>',
        1,
    ))


@app.get("/api/diagnostics/build")
async def application_build():
    return build_diagnostics()


@app.get("/api/scan-settings")
async def scan_settings():
    """Defaults and technical bounds of every numeric/boolean scan setting.

    The dashboard reads this instead of hard-coding limits, so the request
    model stays the single source of truth for what an operator may configure.
    """
    settings = {}
    for name, field in ScanRequest.model_fields.items():
        if field.annotation not in (int, bool, int | None):
            continue
        entry: dict[str, object] = {"default": field.default}
        for constraint in field.metadata:
            for attribute, key in (("ge", "minimum"), ("le", "maximum")):
                value = getattr(constraint, attribute, None)
                if value is not None:
                    entry[key] = value
        settings[name] = entry
    return {"settings": settings, "deployment": {"max_concurrent_scans": MAX_CONCURRENT_SCANS}}


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok", "version": app.version}


@app.get("/api/auth-profiles")
async def auth_profiles():
    profiles = discover_storage_profiles()
    return {
        "profiles": profiles,
        "maximum_concurrent_scans": MAX_CONCURRENT_SCANS,
        "refresh_enabled_profiles": discover_refresh_profiles(profiles),
        "message": None if profiles else (
            "No valid SSO session profiles are mounted. A desktop browser session is separate "
            "from Chromium running in this container."
        ),
    }


async def reconcile_http_redirect_chain(response, tracker: NavigationTracker) -> None:
    requests = []
    request = response.request
    while request is not None:
        requests.append(request)
        request = request.redirected_from
    chain: list[tuple[str, int | None]] = []
    for redirected_request in reversed(requests):
        redirected_response = await redirected_request.response()
        chain.append((
            redirected_request.url,
            redirected_response.status if redirected_response is not None else None,
        ))
    tracker.reconcile_http_chain(chain)


async def _resolve_with_logging(host: str, req: ScanRequest, scan_id: str) -> list[str]:
    log_event(logging.INFO, "DNS_RESOLUTION_STARTED", scan_id=scan_id, hostname=host)
    addresses = await resolve_and_validate(host, req.allow_private_networks)
    log_event(
        logging.INFO,
        "DNS_RESOLUTION_COMPLETED",
        scan_id=scan_id,
        hostname=host,
        address_count=len(addresses),
    )
    return addresses


class _AuthenticationGateFailure(Exception):
    """Unwind browser work without treating bootstrap as an application route."""


class _SessionExpiredDuringScan(_AuthenticationGateFailure):
    """The session was rejected after the scan-wide gate had passed."""


# Policy/configuration denials are not session loss: re-authenticating cannot
# fix them, so they keep failing the whole scan closed.
POLICY_AUTHENTICATION_FAILURES = frozenset({"AUTHENTICATION_BLOCKED", "AUTHENTICATION_CONFIGURATION_ERROR"})


async def execute_scan(
    req: ScanRequest,
    *,
    scan_id: str | None = None,
    progress_callback: ProgressCallback | None = None,
    cancel_event: asyncio.Event | None = None,
):
    # Each scan receives its own effective configuration. Do not write policy
    # approvals into a caller's request, mounted profile, or another session.
    req = req.model_copy(deep=True)
    scan_id = scan_id or str(uuid.uuid4())
    scan_started = time.perf_counter()
    deadline = scan_started + req.total_timeout_ms / 1000
    preflight_timeout_reached = False
    application_gate_confirmed = False
    authentication_error: dict | None = None
    authentication_approval_counts: dict[str, int] = {}
    browser_context_count = 0
    browser_page_count = 0
    scan_lifecycle: dict[str, object] = {"state": "INITIALIZING", "events": []}
    lifecycle_order = (
        "INITIALIZING", "AUTHENTICATING", "AUTHENTICATED", "APPLICATION_READY",
        "DISCOVERING_ROUTES", "VALIDATING_ROUTES", "COMPLETED",
    )

    async def publish_progress(state: str, **values) -> None:
        if scan_lifecycle["state"] == "FAILED" and state != "FAILED":
            return
        if state in {"FAILED", "CANCELLED", "PARTIAL"} or (
            state in lifecycle_order and (
                not scan_lifecycle["events"]
                or lifecycle_order.index(state) > lifecycle_order.index(str(scan_lifecycle["state"]))
            )
        ):
            scan_lifecycle["state"] = state
            scan_lifecycle["events"].append({
                "state": state, "elapsed_ms": max(0, round((time.perf_counter() - scan_started) * 1000)),
            })
        if state in {"DISCOVERING_ROUTES", "VALIDATING_ROUTES"} and not application_gate_confirmed:
            raise RuntimeError("Application work cannot start before authentication/readiness")
        if not application_gate_confirmed or state == "FAILED":
            values.update(discovered=0, queued=0, validated=0, healthy=0, failed=0, warnings=0, current_route=None)
        if progress_callback is None:
            return
        values.setdefault("remaining_budget_ms", max(
            0,
            req.total_timeout_ms - round((time.perf_counter() - scan_started) * 1000),
        ))
        # Observability callbacks cannot extend the configured scan budget.
        # Final report assembly still runs after expiry to preserve coverage.
        if time.perf_counter() >= deadline:
            return
        budget = asyncio.timeout_at(deadline)
        try:
            async with budget:
                await progress_callback(state, **values)
        except TimeoutError:
            if not budget.expired():
                raise
            log_event(logging.WARNING, "SCAN_PROGRESS_DEADLINE_REACHED", scan_id=scan_id)

    async def failed_authentication_report(error: dict, diagnostics: list[dict] | None = None) -> dict:
        await publish_progress("FAILED")
        elapsed = max(0, round((time.perf_counter() - scan_started) * 1000))
        report = apply_global_authentication_failure({
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "validator_version": VALIDATOR_VERSION,
            "build_identity": build_diagnostics(), "scan_id": scan_id, "run_id": scan_id,
            "target": sanitized_url(req.target), "scan_lifecycle": scan_lifecycle,
            "scan_configuration": {
                "authentication_mode": req.authentication.mode,
                "authentication_host_count": len(req.authentication_hosts),
                "readiness_selector_configured": bool(req.readiness_selector),
                "readiness_event_configured": bool(req.readiness_event),
                **authentication_approval_counts,
            },
            "scan_timing": {"total_scan_ms": elapsed, "browser_contexts": browser_context_count,
                            "pages": browser_page_count},
            "timings": {"browser_contexts": browser_context_count, "pages": browser_page_count},
            "summary": {"total_scan_duration_ms": elapsed},
            "safety": {"read_only_enforced": True, "mutations_enabled": False},
        }, error, diagnostics=diagnostics or [])
        log_event(logging.ERROR, "SCAN_AUTHENTICATION_FAILED", scan_id=scan_id,
                  classification=error["category"], stage=error["stage"],
                  http_status=error.get("http_status"))
        return report

    async def configuration_failure() -> dict:
        return await failed_authentication_report(create_authentication_error(
            "AUTHENTICATION_CONFIGURATION_ERROR", stage="INITIALIZING",
            duration_ms=round((time.perf_counter() - scan_started) * 1000),
        ))

    async def resolve_preflight(host: str) -> None:
        nonlocal preflight_timeout_reached
        if preflight_timeout_reached or time.perf_counter() >= deadline:
            preflight_timeout_reached = True
            return
        budget = asyncio.timeout_at(deadline)
        try:
            async with budget:
                await _resolve_with_logging(host, req, scan_id)
        except TimeoutError:
            if not budget.expired():
                raise
            # No browser is started after this. The normal deadline/report
            # path below records PARTIAL / SCAN_TIMEOUT, not a target failure.
            preflight_timeout_reached = True
            log_event(logging.WARNING, "SCAN_PREFLIGHT_DEADLINE_REACHED", scan_id=scan_id)

    await publish_progress("INITIALIZING")
    requested_target = req.target.strip()
    log_event(logging.INFO, "SCAN_STARTED", scan_id=scan_id, requested_url=requested_target)
    try:
        root_host, _port = validate_http_url(requested_target)
    except DestinationError as exc:
        log_event(logging.ERROR, "SCAN_FAILED", scan_id=scan_id, classification=exc.classification, error=exc.public_message)
        raise HTTPException(400, exc.public_message) from exc
    log_event(logging.INFO, "URL_VALIDATED", scan_id=scan_id, requested_url=requested_target, hostname=root_host)
    try:
        effective_authentication_hosts, operator_authentication_endpoints, authentication_approval_counts = (
            authentication_approvals_for_scan(req, root_host)
        )
    except HTTPException:
        return await configuration_failure()
    req = req.model_copy(update={"authentication_hosts": effective_authentication_hosts})
    # Query parameters observed to distinguish sibling tab/menu destinations
    # (e.g. ?tab=daily vs ?tab=monthly). They become part of route identity
    # even under the default "ignore" policy; tracking and secret parameters
    # remain excluded by normalize_route_url.
    view_query_parameters: set[str] = set()

    def route_query_policy() -> str:
        if req.query_parameter_policy == "ignore" and view_query_parameters:
            return "allowlist"
        return req.query_parameter_policy

    def route_query_allowlist() -> set[str]:
        return set(req.allowed_query_parameters) | view_query_parameters

    def learn_view_query_parameters(routes) -> None:
        groups: dict[tuple[str, str, str], list[dict[str, str]]] = {}
        for route in routes:
            if route.view_control or not (
                route.source in {"tab", "menuitem", "option"} or route.navigation_hierarchy
            ):
                continue
            try:
                parsed = urlsplit(route.url)
            except ValueError:
                continue
            if not parsed.query:
                continue
            groups.setdefault((parsed.scheme, parsed.netloc, parsed.path), []).append(
                {key.lower(): value for key, value in parse_qsl(parsed.query, keep_blank_values=True)}
            )
        for queries in groups.values():
            if len(queries) < 2:
                continue
            for key in set().union(*queries):
                if len({query.get(key) for query in queries}) > 1:
                    view_query_parameters.add(key)
    log_event(
        logging.INFO, "AUTHENTICATION_APPROVALS_APPLIED", scan_id=scan_id,
        effective_host_count=len(effective_authentication_hosts), **authentication_approval_counts,
    )
    try:
        await resolve_preflight(root_host)
    except DestinationError as exc:
        log_event(logging.ERROR, exc.classification, scan_id=scan_id, hostname=root_host, error=exc.public_message)
        raise HTTPException(400, exc.public_message) from exc

    if req.allow_mutations:
        raise HTTPException(400, "Portal health validation is read-only; mutations cannot be enabled")

    try:
        read_only_policy: ReadOnlyPolicy = app.state.read_only_policy
    except AttributeError:
        try:
            read_only_policy = load_read_only_policy()
        except (OSError, ValueError) as exc:
            raise HTTPException(500, "Administrator read-only policy is invalid") from exc
    if req.approved_read_post_operations:
        scan_policy = load_read_only_policy(raw=json.dumps({
            "safe_application_requests": [
                operation.model_dump(exclude_none=True)
                for operation in req.approved_read_post_operations
            ],
        }))
        read_only_policy = ReadOnlyPolicy(
            tuple(dict.fromkeys(read_only_policy.safe_application_requests + scan_policy.safe_application_requests)),
            read_only_policy.access_gates,
        )
    # Explicit operation approval never exempts its destination from SSRF checks
    # and does not generally allow that host's unrelated assets or APIs.
    for policy_host in {rule.host for rule in read_only_policy.safe_application_requests}:
        try:
            await resolve_preflight(policy_host)
        except DestinationError as exc:
            raise HTTPException(400, exc.public_message) from exc
    log_event(
        logging.INFO,
        "READ_ONLY_POLICY_LOADED",
        scan_id=scan_id,
        safe_request_rules=len(read_only_policy.safe_application_requests),
        access_gate_rules=len(read_only_policy.access_gates),
    )

    approved_resource_hosts = {normalized_host(host) for host in req.resource_hosts}
    for host in approved_resource_hosts:
        try:
            await resolve_preflight(host)
        except DestinationError as exc:
            raise HTTPException(400, exc.public_message) from exc

    approved_portal_hosts = {normalized_host(host) for host in req.portal_hosts}
    for host in approved_portal_hosts:
        try:
            await resolve_preflight(host)
        except DestinationError as exc:
            raise HTTPException(400, exc.public_message) from exc

    # Crawl scope and credential scope are intentionally independent. By default,
    # validator-managed credentials are sent only to the exact target host.
    credential_hosts = {normalized_host(root_host)}
    for host in req.credential_hosts:
        if not (
            host_in_scan_scope(
                host,
                root_host,
                req.allow_subdomains,
                approved_portal_hosts,
            )
            or host in approved_resource_hosts
        ):
            raise HTTPException(
                400,
                "Credential host must be an approved portal or resource/API host",
            )
        try:
            await resolve_preflight(host)
        except DestinationError as exc:
            raise HTTPException(400, exc.public_message) from exc
        credential_hosts.add(host)

    # Anonymous validation does not imply that the destination needs credentials.
    # Actual login/SSO evidence is still evaluated after browser navigation.
    await publish_progress("AUTHENTICATING")
    try:
        authentication_manager = build_authentication_manager(
            mode=req.authentication.mode,
            credential_hosts=credential_hosts,
            username=req.authentication.username,
            password=(
                req.authentication.password.get_secret_value()
                if req.authentication.password is not None else None
            ),
            token=(
                req.authentication.token.get_secret_value()
                if req.authentication.token is not None else None
            ),
            headers={
                name: value.get_secret_value()
                for name, value in req.authentication.headers.items()
            },
        )
        # Force configuration validation before Chromium starts.
        authentication_manager.configured_headers()
    except AuthenticationConfigurationError:
        return await configuration_failure()
    if req.authentication.mode == "bearer":
        log_event(
            logging.INFO,
            "BEARER_AUTH_CONFIGURED",
            scan_id=scan_id,
            credential_scope_host_count=authentication_manager.credential_host_count,
        )
    try:
        mounted_state_path = (
            storage_state_path(req.authentication.storage_profile)
            if req.authentication.mode == "storage_state" else None
        )
        runtime_session_store = RuntimeSessionStore()
        state_path = (
            runtime_session_store.seed(req.authentication.storage_profile, mounted_state_path)
            if mounted_state_path is not None and req.authentication.storage_profile else None
        )
        state_generation = state_path.stat().st_mtime_ns if state_path is not None else None
        refresh_config = (
            load_refresh_config(req.authentication.storage_profile, AUTH_STATE_DIR)
            if req.authentication.mode == "storage_state" and req.authentication.storage_profile
            else None
        )
    except (HTTPException, OSError, ValueError, json.JSONDecodeError, DestinationError):
        return await configuration_failure()
    preflight_duration_ms = round((time.perf_counter() - scan_started) * 1000)
    authentication_duration_ms = 0
    browser_startup_duration_ms = 0
    readiness_duration_ms = 0
    navigation_duration_ms = 0
    network_observation_started: float | None = None
    network_observation_duration_ms = 0
    discovery_duration_ms = 0
    validation_duration_ms = 0
    results: list[dict] = []
    authentication_diagnostics: list[dict] = []
    requested_route = normalize_route_url(
        requested_target,
        query_policy=route_query_policy(),
        allowed_query_parameters=route_query_allowlist(),
    ) or requested_target
    queue = deque([(
        requested_target,
        0,
        "Requested route",
        "target",
        DOCUMENT_NAVIGATION,
        None,
        "DOCUMENT_NAVIGATION",
        "target",
        None,
        None,
        None,
    )])
    seen: set[str] = set()
    # A bootstrap target is not discovered/tested application coverage yet.
    discovered_routes: set[str] = set()
    queued_routes: set[str] = set()
    # (label, menu hierarchy) of entries discovered as real links.
    linked_menu_entries: set[tuple[str, tuple[str, ...]]] = set()
    # Shared header popovers (notifications, profile, help) appear on every
    # route; like shared menus they are validated once per scan.
    queued_popover_views: set[tuple[str, str, str]] = set()
    # Signatures of shared navigation controls already explored in this scan.
    explored_navigation_controls: set[str] | None = (
        None if req.reexplore_navigation_each_route else set()
    )
    depth_limited_routes: set[str] = set()
    queued_view_keys: dict[str, set[str]] = defaultdict(set)
    action_limited_routes: set[str] = set()
    route_locations: dict[str, str] = {requested_route: requested_route}
    route_page_keys: dict[str, str] = {}
    route_document_sources: dict[str, str | None] = {}
    active_browser_page_key: str | None = None
    route_parent_ids: dict[str, str | None] = {requested_route: None}
    route_name_by_id: dict[str, str] = {requested_route: "Requested route"}
    route_metadata: dict[str, dict[str, object]] = {
        requested_route: {
            "route_label": "Requested route", "route_source": "target",
            "navigation_type": DOCUMENT_NAVIGATION,
            "discovery_type": "DOCUMENT_NAVIGATION", "depth": 0,
        },
    }
    view_navigation_aliases: dict[str, str] = {}
    document_navigation_aliases: dict[str, str] = {}
    active_view_source: str | None = None
    route_provenance: dict[str, dict[str, object]] = {
        requested_route: {
            "observations": 1,
            "sources": [{
                "source": "target",
                "discovery_type": "DOCUMENT_NAVIGATION",
                "label": "Requested route",
                "label_source": "target",
                "discovered_from": None,
            }],
        },
    }

    def remember_route_discovery(
        identity: str,
        route: DiscoveredRoute,
        discovered_from: str | None,
        discovered_from_route_id: str | None = None,
    ) -> None:
        entry = route_provenance.setdefault(identity, {"observations": 0, "sources": []})
        entry["observations"] = int(entry["observations"]) + 1
        source = {
            "source": route.source,
            "discovery_type": route.discovery_type,
            "label": sanitize_text(route.label, limit=160) if route.label else None,
            "label_source": route.label_source,
            "discovered_from": sanitized_url(discovered_from) if discovered_from else None,
            "discovered_from_route_id": discovered_from_route_id,
        }
        sources = entry["sources"]
        if source not in sources:
            sources.append(source)

    def menu_entry_signature(label: str | None, hierarchy) -> tuple[str, tuple[str, ...]] | None:
        text = " ".join(str(label or "").split()).lower()
        return (text, tuple(hierarchy or ())) if text else None

    def enqueue_discovered_routes(
        routes: list[DiscoveredRoute], depth: int, source_url: str,
    ) -> list[str]:
        """Retain actual panel observations before another panel or a timeout.

        One scope/identity/depth policy applies to incremental menu observations
        and the final document/frame/popup collection alike.
        """
        if not application_gate_confirmed or authentication_error is not None:
            return []
        learn_view_query_parameters(routes)
        external_urls: set[str] = set()
        # A menu entry rendered both as a link and as a clickable menu item is
        # one destination: validate it once through its link.
        for route in routes:
            signature = None if route.view_control else menu_entry_signature(route.label, route.navigation_hierarchy)
            if signature is not None:
                linked_menu_entries.add(signature)
        for route in routes:
            # Only panel-less menu items duplicate a link; tabs that control a
            # panel are distinct views even when they also carry an href.
            if route.view_control and route.view_control.get("kind") == "navigation" and menu_entry_signature(
                route.label, route.navigation_hierarchy,
            ) in linked_menu_entries:
                continue
            if (route.view_control and active_view_source
                    and normalize_route_url(route.url) == normalize_route_url(source_url)):
                # History updates caused by a tab do not create fresh copies
                # of every sibling tab under the new URL. Preserve the source
                # context of the controls already being validated.
                route = replace(route, url=active_view_source)
            identity = normalize_route_url(
                route.url,
                query_policy=route_query_policy(),
                allowed_query_parameters=route_query_allowlist(),
            )
            if identity is None or route.navigation_mode == DOWNLOAD_OBSERVED:
                continue
            if not is_document_route_candidate(identity):
                continue
            if not url_in_scan_scope(identity, root_host, req.allow_subdomains, approved_portal_hosts):
                external_urls.add(sanitized_url(identity))
                continue
            if any(word in urlparse(identity).path.lower() for word in DANGEROUS_PATH_WORDS):
                continue
            if not route.view_control and identity in view_navigation_aliases:
                remember_route_discovery(
                    view_navigation_aliases[identity], route, source_url, active_route_id,
                )
                continue
            if not route.view_control and identity in document_navigation_aliases:
                remember_route_discovery(
                    document_navigation_aliases[identity], route, source_url, active_route_id,
                )
                continue
            route_key = discovered_route_key(route, identity)
            page_key = route.browser_page_key or active_browser_page_key
            if page_key is not None:
                route_page_keys.setdefault(route_key, page_key)
            if route.navigation_mode in SAME_DOCUMENT_NAVIGATIONS:
                source_page = browser_pages.get(page_key)
                source_response = document_response_for(source_page) if source_page is not None else None
                # A history URL may have no server document route. Retain the
                # actual document GET separately; never replay a POST that
                # established an authentication/application document.
                route_document_sources.setdefault(
                    route_key,
                    source_response.url
                    if source_response is not None and source_response.request.method.upper() == "GET"
                    else None,
                )
            route_locations[route_key] = identity
            parent_route_id = route.opener_route_id or active_route_id
            route_parent_ids.setdefault(route_key, parent_route_id)
            route_metadata.setdefault(route_key, {
                "route_label": sanitize_text(route.label, limit=160) if route.label else "Discovered route",
                "route_source": route.source,
                "navigation_type": route.navigation_mode,
                "discovery_type": route.discovery_type,
                "navigation_hierarchy": [
                    sanitize_text(label, limit=160) for label in route.navigation_hierarchy
                ],
                "depth": depth + 1,
            })
            if len(route.navigation_hierarchy) > len(route_metadata[route_key].get("navigation_hierarchy", [])):
                route_metadata[route_key]["navigation_hierarchy"] = [
                    sanitize_text(label, limit=160) for label in route.navigation_hierarchy
                ]
            remember_route_discovery(route_key, route, source_url, parent_route_id)
            if route.view_control:
                # UI controls have their own bounded action budget. URLs still
                # pass the exact existing portal/SSRF/read-only policies.
                view_keys = queued_view_keys[identity]
                if route_key not in view_keys and len(view_keys) >= req.max_navigation_actions:
                    discovered_routes.add(route_key)
                    action_limited_routes.add(route_key)
                    continue
                view_keys.add(route_key)
            if route_key in discovered_routes:
                continue
            popover_key = None
            if (route.view_control and route.view_control.get("presentation") == "popover"
                    and not req.reexplore_navigation_each_route):
                popover_key = (
                    str(route.view_control.get("scope", "")),
                    str(route.view_control.get("identity") or route.view_control.get("panel")),
                    str(route.view_control.get("label", "")),
                )
                if popover_key in queued_popover_views:
                    continue
            discovered_routes.add(route_key)
            if depth >= req.max_depth:
                depth_limited_routes.add(route_key)
                log_event(logging.INFO, "ROUTE_SKIPPED", scan_id=scan_id,
                          current_url=identity, reason="MAX_DEPTH_REACHED")
                continue
            queue.append((
                identity, depth + 1,
                sanitize_text(route.label, limit=160) if route.label else "Discovered route",
                route.source, route.navigation_mode, source_url, route.discovery_type,
                route.label_source,
                sanitize_text(route.accessible_name, limit=160) if route.accessible_name else None,
                route.view_control,
                parent_route_id,
            ))
            queued_routes.add(route_key)
            if popover_key is not None:
                queued_popover_views.add(popover_key)
            log_event(logging.DEBUG, "LINK_DISCOVERED", scan_id=scan_id,
                      current_url=identity, crawl_depth=depth + 1,
                      navigation_type=route.navigation_mode)
        if external_urls:
            log_event(logging.INFO, "EXTERNAL_LINK_SKIPPED", scan_id=scan_id, count=len(external_urls))
        return sorted(external_urls)

    total_timeout_reached = False
    cancellation_requested = False
    late_navigation_observed = False
    document_evidence: dict[tuple[str, str, int | None], dict[str, object]] = {}
    scan_api_events: list[dict] = []
    scan_http_method_counts: Counter[str] = Counter()
    scan_resource_events: list[dict] = []
    network_drain: dict[str, object] | None = None
    session_expired = False
    discovery_stop_reason: str | None = None
    active_route_identity: str | None = None
    network_observer: PassiveNetworkObserver | None = None
    popup_tasks: set[asyncio.Task] = set()
    browser_context_count = 0
    browser_page_count = 0
    session_refresh: dict[str, object] = {"attempted": False}
    # True only while the validator opens its own (non-application) tab.
    internal_page_requested = False
    # Evidence recorded before a successful session recovery is history, not
    # proof that the recovered session is rejected.
    session_evidence_start = 0
    diagnostic_evidence_start = 0
    session_recovery_attempts_used = 0
    session_interruption: dict | None = None
    # The activation whose readiness passed the scan-wide gate. Only blocked
    # authentication evidence belonging to it (or seen before the gate)
    # invalidates the whole scan; later blocks affect their own route only.
    bootstrap_activation_id: str | None = None
    redirect_guards: list[RedirectResponseGuard] = []
    guard_install_tasks = weakref.WeakKeyDictionary()

    def reject_global_authentication(
        classification: str | None, *, status: int | None, endpoint: str,
        stage: str = "AUTHENTICATING", duration_ms: int | None = None,
        method: str | None = None, policy_decision: str | None = None,
    ) -> None:
        nonlocal authentication_error
        category = classification or "APPLICATION_NOT_READY"
        if category in {"PASS", "APPLICATION_BOOTSTRAP_PENDING"}:
            category = "APPLICATION_NOT_READY"
        elif category == "MFA_REQUIRED":
            pass
        elif category in {"AUTH_REQUIRED", "AUTHENTICATION_REQUIRED", "AUTH_FAILED"}:
            category = (
                "SESSION_EXPIRED" if application_gate_confirmed and req.authentication.mode != "none"
                else "AUTHENTICATION_FAILED"
            )
        elif category in {"AUTH_TIMEOUT", "TIMEOUT"}:
            category = "AUTHENTICATION_TIMEOUT"
        destination_host = normalized_host(urlparse(endpoint).hostname or "")
        if (
            destination_host in req.authentication_hosts
            and not url_in_scan_scope(endpoint, root_host, req.allow_subdomains, approved_portal_hosts)
            and (
                status is not None and status >= 500
                or category in {"HTTP_ERROR", "DNS_ERROR", "NETWORK_ERROR", "NAVIGATION_ERROR"}
            )
            and category not in {"AUTHENTICATION_BLOCKED", "TLS_ERROR", "AUTHENTICATION_CONFIGURATION_ERROR"}
            and (status is None or status >= 500)
        ):
            category = "IDENTITY_PROVIDER_UNAVAILABLE"
        evidence = next((
            item for item in reversed(authentication_diagnostics)
            if item.get("affects_authentication")
        ), {}) if category == "AUTHENTICATION_BLOCKED" else {}
        authentication_error = create_authentication_error(
            category, stage=stage, http_status=evidence.get("http_status", status),
            method=evidence.get("method") or method or "GET", endpoint=evidence.get("endpoint") or endpoint,
            policy_decision=evidence.get("policy_decision") or evidence.get("policy_reason") or policy_decision,
            duration_ms=duration_ms if duration_ms is not None else round((time.perf_counter() - scan_started) * 1000),
        )
        if application_gate_confirmed and authentication_error["category"] not in POLICY_AUTHENTICATION_FAILURES:
            raise _SessionExpiredDuringScan
        raise _AuthenticationGateFailure

    def rejected_session_response() -> dict | None:
        # The application must accept the session, not merely return a static
        # HTML shell. Optional/public peripheral 401s are not proof of expiry;
        # explicit session-required APIs and scoped auth exchanges are evidence.
        # A public scan has no session to expire once the site is ready: a 401
        # there belongs to its route, not to the whole scan.
        if application_gate_confirmed and req.authentication.mode == "none":
            return None
        return next((event for event in reversed(scan_api_events[session_evidence_start:]) if (
            event.get("status") == 401 and not event.get("blocked_by_validator")
            and event.get("phase") != "SESSION_REFRESH"
            and (
                event.get("importance") == "AUTHENTICATION"
                or req.authentication.mode != "none" and event.get("importance") == "REQUIRED"
            )
        )), None)

    def scan_blocking_denials() -> list[dict]:
        return [
            item for item in authentication_diagnostics[diagnostic_evidence_start:]
            if item.get("affects_authentication") and (
                not application_gate_confirmed or item.get("route_activation_id") == bootstrap_activation_id
            )
        ]

    def require_current_session() -> None:
        """Stop further application work as soon as auth evidence is rejected."""
        denied = next(reversed(scan_blocking_denials()), None)
        if denied is not None:
            reject_global_authentication(
                "AUTHENTICATION_BLOCKED", status=denied.get("http_status"),
                endpoint=denied.get("endpoint") or requested_target,
            )
        rejected = rejected_session_response()
        if rejected is not None:
            reject_global_authentication(
                "SESSION_EXPIRED" if application_gate_confirmed or req.authentication.mode == "storage_state"
                else "AUTHENTICATION_FAILED",
                status=401, endpoint=rejected.get("url") or requested_target,
                method=rejected.get("method"), policy_decision=rejected.get("policy_decision"),
            )

    def authentication_request_diagnostics() -> list[dict]:
        def request_identity(item: dict) -> tuple[str, str, str]:
            parsed = urlparse(str(item.get("url") or item.get("endpoint") or ""))
            return (
                str(item.get("method") or "").upper(),
                normalized_host(parsed.hostname or str(item.get("destination_host") or item.get("host") or "")),
                parsed.path,
            )

        scan_category = (authentication_error or {}).get("category")
        evidence = [
            {**item, "category": scan_category} if scan_category and not item.get("category") else dict(item)
            for item in authentication_diagnostics
        ]
        # A policy decision and the browser request it blocked describe one
        # transition; report it once, with the richer policy evidence.
        recorded = {request_identity(item) for item in evidence}
        for event in scan_api_events:
            if request_identity(event) in recorded:
                continue
            if (
                event.get("importance") == "AUTHENTICATION"
                or event.get("phase") in {"AUTHENTICATION", "SESSION_REFRESH"}
            ):
                evidence.append({
                    "category": (authentication_error or {}).get("category", "AUTHENTICATION_FAILED"),
                    "stage": (authentication_error or {}).get("stage", "AUTHENTICATING"),
                    "http_status": event.get("status"), "method": event.get("method"),
                    "endpoint": event.get("url") or event.get("endpoint"),
                    "policy_decision": event.get("policy_decision") or event.get("block_reason"),
                    "duration_ms": event.get("duration_ms"),
                })
        return evidence

    @asynccontextmanager
    async def scan_deadline_scope():
        nonlocal total_timeout_reached, cancellation_requested
        budget = asyncio.timeout_at(deadline)
        try:
            async with budget:
                yield
        except ScanAdmissionCancelled:
            cancellation_requested = True
            log_event(logging.INFO, "SCAN_CANCELLED_WHILE_QUEUED", scan_id=scan_id)
        except AuthenticationObservationCancelled:
            cancellation_requested = True
            if active_route_identity is not None:
                seen.discard(active_route_identity)
            log_event(logging.INFO, "SCAN_CANCELLED_DURING_BOOTSTRAP", scan_id=scan_id)
        except _AuthenticationGateFailure:
            # Browser/context cleanup completes before the failed, empty report.
            pass
        except TimeoutError:
            if not budget.expired() and time.perf_counter() < deadline:
                raise
            total_timeout_reached = True
            if active_route_identity is not None:
                seen.discard(active_route_identity)
            log_event(logging.WARNING, "SCAN_DEADLINE_REACHED", scan_id=scan_id)
        finally:
            for task in tuple(popup_tasks):
                task.cancel()
            if popup_tasks:
                await asyncio.gather(*tuple(popup_tasks), return_exceptions=True)
            if network_observer is not None:
                network_observer.finalize_pending()


    async with scan_deadline_scope(), SCAN_LIMITER.slot(req.concurrency_limit, cancel_event):
        if time.perf_counter() >= deadline:
            raise TimeoutError("Total scan budget expired before browser startup")
        async with async_playwright() as playwright:
            browser_started = time.perf_counter()
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage"],
            )
            log_event(logging.INFO, "BROWSER_LAUNCHED", scan_id=scan_id)
            try:
                storage_hosts = {root_host, *approved_portal_hosts, *credential_hosts, *req.authentication_hosts}
                if root_host.startswith("www."):
                    storage_hosts.add(root_host[4:])
                elif "." in root_host and not re.fullmatch(r"[0-9.]+", root_host):
                    storage_hosts.add("www." + root_host)
                context_options = browser_context_options(state_path, storage_hosts)
                scoped_state = context_options.get("storage_state")
                approved_session = bool(
                    req.authentication_hosts and isinstance(scoped_state, dict)
                    and (scoped_state.get("cookies") or scoped_state.get("origins"))
                )
                context = await browser.new_context(**context_options)
                browser_startup_duration_ms = round((time.perf_counter() - browser_started) * 1000)
                browser_context_count += 1
                await context.add_init_script(script=ROUTE_OBSERVER_SCRIPT)
                if req.readiness_event:
                    await context.add_init_script(script=readiness_event_init_script(req.readiness_event))
                if req.api_timeout_ms is not None:
                    await context.add_init_script(script=api_timeout_init_script(req.api_timeout_ms))
                await configure_cookies(context, req, root_host, approved_portal_hosts)
                page = None
                console_errors: list[dict] = []
                page_errors: list[dict] = []
                failed_resources: list[dict] = []
                api_events: list[dict] = []
                network_observer = PassiveNetworkObserver(api_events)
                route_network_activity = RouteNetworkActivity()
                resource_events: list[dict] = []
                scan_api_events = api_events
                scan_resource_events = resource_events
                websocket_events: list[dict] = []
                event_streams: list[dict] = []
                download_events: list[dict] = []
                frame_events: list[dict] = []
                popup_routes: list[DiscoveredRoute] = []
                request_started = weakref.WeakKeyDictionary()
                observed_http_requests = weakref.WeakSet()
                request_routes = weakref.WeakKeyDictionary()
                request_observation = weakref.WeakKeyDictionary()
                request_owners = weakref.WeakKeyDictionary()
                resource_observations = weakref.WeakKeyDictionary()
                resource_failure_observations = weakref.WeakKeyDictionary()
                authentication_denials: set[str | None] = set()
                active_route_id: str | None = None
                active_route_activation_id: str | None = None
                current_tracker: NavigationTracker | None = None
                navigation_policy_error: DestinationError | None = None
                navigation_hosts: set[str] = set()
                authentication_navigation = AuthenticationNavigationPolicy(
                    approved_hosts=frozenset(req.authentication_hosts), active=approved_session,
                    approved_endpoints=operator_authentication_endpoints,
                )
                latest_document_response = None
                validator_blocks: dict[tuple[str, str, str, bool], deque[str]] = defaultdict(deque)
                redirect_response_statuses: dict[tuple[str, str, str, bool], deque[int]] = defaultdict(deque)
                acknowledged_access_gates: set[tuple[str, str]] = set()
                navigation_policy_intervals: list[tuple[float, float]] = []
                observation_phase = "AUTHENTICATION"
                popup_origins = weakref.WeakKeyDictionary()
                browser_pages: dict[str, object] = {}
                browser_page_keys = weakref.WeakKeyDictionary()
                page_document_responses = weakref.WeakKeyDictionary()
                observed_document_responses = []
                page_observations: dict[str, list[dict]] = defaultdict(list)
                observation_page_keys: dict[int, str] = {}
                request_page_keys = weakref.WeakKeyDictionary()
                adopted_page_keys: set[str] = set()
                popup_observation_failures = 0
                accounted_popup_observation_failures = 0
                primary_page = None

                def remember_page_observation(owner_page, event):
                    if owner_page is None:
                        return
                    register_browser_page(owner_page)
                    page_key = browser_page_keys.get(request_identity(owner_page))
                    if page_key is not None and id(event) not in observation_page_keys:
                        observation_page_keys[id(event)] = page_key
                        page_observations[page_key].append(event)

                def remember_request_observation(request, event):
                    try:
                        owner_page = request.frame.page
                    except PlaywrightError:
                        return
                    remember_page_observation(owner_page, event)
                    request_page_keys[request_identity(request)] = browser_page_keys.get(request_identity(owner_page))

                def adopt_page_observations(owner_page):
                    """Assign a popup's own bootstrap to its independently validated view.

                    Never match URLs: two windows can share an origin/URL but
                    own different state. Later background requests retain the
                    last actual activation of their source page.
                    """
                    page_key = browser_page_keys.get(request_identity(owner_page))
                    if page_key is None or page_key in adopted_page_keys:
                        return
                    adopted_page_keys.add(page_key)
                    for event in page_observations.get(page_key, []):
                        event.setdefault("opener_route", event.get("initiating_route"))
                        event.setdefault("opener_route_activation_id", event.get("route_activation_id"))
                        event["initiating_route"] = active_route_id
                        event["route_activation_id"] = active_route_activation_id
                        if event.get("phase") not in {None, "AUTHENTICATION", "SESSION_REFRESH"}:
                            event["phase"] = "APPLICATION_BOOTSTRAP"
                            if event.get("importance") == "BACKGROUND":
                                event["importance"] = "REQUIRED"
                        if event.get("top_level_navigation"):
                            event["main_document"] = True
                    for key, source_page_key in tuple(request_page_keys.items()):
                        if source_page_key != page_key:
                            continue
                        if key in request_routes:
                            request_routes[key] = active_route_id
                        if key in request_owners:
                            request_owners[key] = (active_route_id, active_route_activation_id)
                        if key in request_observation:
                            prior_phase, prior_importance = request_observation[key]
                            if prior_phase not in {"AUTHENTICATION", "SESSION_REFRESH"}:
                                request_observation[key] = (
                                    "APPLICATION_BOOTSTRAP", "REQUIRED" if prior_importance == "BACKGROUND" else prior_importance,
                                )
                        route_network_activity.reassign_request(key, active_route_id)

                def document_response_for(owner_page):
                    # Playwright may emit an initial popup Response before its
                    # Frame has a Page. Correlate that same captured Response
                    # after the frame is attached, never by URL alone.
                    latest_response = None
                    for response in reversed(observed_document_responses):
                        try:
                            if response.request.frame.page == owner_page:
                                # The initial popup POST can be observed before
                                # its Frame/Page exists. Retry that same request
                                # identity now so its API occurrence participates
                                # in this page's bootstrap adoption as well.
                                ensure_api_observed(response.request)
                                # Bind earlier redirecting POST documents too;
                                # the final document may itself be a plain GET.
                                if latest_response is None:
                                    latest_response = response
                        except PlaywrightError:
                            continue
                    if latest_response is not None:
                        page_document_responses[request_identity(owner_page)] = latest_response
                    return page_document_responses.get(request_identity(owner_page))

                def route_activity_snapshot():
                    activity = route_network_activity.snapshot(active_route_id)
                    # A popup's response can precede its DOM/title observation.
                    # Do not finish discovery between those browser events.
                    activity["pending"] += sum(not task.done() for task in popup_tasks)
                    return activity

                def record_console_error(message, owner_page):
                    if message.type in {"error", "warning"}:
                        owner = ((active_route_id, active_route_activation_id, observation_phase)
                                 if owner_page == page else popup_origins.get(request_identity(owner_page), (None, None, None)))
                        event = {"message": sanitized_diagnostic(message.text), "initiating_route": owner[0], "route_activation_id": owner[1]}
                        console_errors.append(event)
                        remember_page_observation(owner_page, event)

                def record_page_error(error, owner_page):
                    owner = ((active_route_id, active_route_activation_id, observation_phase)
                             if owner_page == page else popup_origins.get(request_identity(owner_page), (None, None, None)))
                    event = {"message": sanitized_diagnostic(str(error)), "initiating_route": owner[0], "route_activation_id": owner[1]}
                    page_errors.append(event)
                    remember_page_observation(owner_page, event)

                def is_api_observation(request) -> bool:
                    return (
                        request.resource_type in {"xhr", "fetch"}
                        or request.method.upper() not in SAFE_READ_ONLY_METHODS
                    )

                def request_origin(request):
                    try:
                        source_page = request.frame.page
                        if source_page == page:
                            return active_route_id, active_route_activation_id, observation_phase
                        owner = popup_origins.get(request_identity(source_page))
                    except Exception:
                        owner = None
                    return owner or (active_route_id, active_route_activation_id, observation_phase)

                def api_importance(request) -> str:
                    phase = request_origin(request)[2]
                    if phase == "AUTHENTICATION" or (
                        authentication_navigation.active and (
                            (request.method.upper() not in SAFE_READ_ONLY_METHODS and is_main_navigation(request))
                            or auth_protocol_signal(request.url)
                        )
                    ):
                        return "AUTHENTICATION"
                    path = urlparse(request.url).path.lower()
                    if any(marker in path for marker in (
                        "/analytics", "/beacon", "/collect", "/metrics", "/telemetry",
                    )):
                        return "OPTIONAL"
                    return (
                        "REQUIRED"
                        if phase in {"APPLICATION_BOOTSTRAP", "ROUTE_VALIDATION", "VALIDATION"}
                        else "BACKGROUND"
                    )

                def request_phase(request) -> str:
                    if api_importance(request) == "AUTHENTICATION":
                        return "AUTHENTICATION"
                    return request_origin(request)[2]

                def is_main_navigation(request) -> bool:
                    try:
                        return bool(request.is_navigation_request() and request.frame.parent_frame is None)
                    except PlaywrightError as exc:
                        # Chromium can emit a popup's initial document request
                        # before Playwright has created its Frame. It is still
                        # navigation, not an asset; validate its destination and
                        # authentication method through the navigation policy.
                        return bool(
                            request.is_navigation_request() and request.resource_type == "document"
                            and "before the frame is created" in str(exc)
                        )
                    except Exception:
                        return False

                def is_primary_navigation(request) -> bool:
                    try:
                        return bool(
                            page is not None
                            and is_main_navigation(request)
                            and request.frame == page.main_frame
                        )
                    except Exception:
                        return False

                def block_resource_kind(resource_type: str) -> str:
                    # CDP reports browser fetch responses as XHR; Playwright
                    # distinguishes fetch from XMLHttpRequest. Correlate both
                    # without changing their reported resource types.
                    return "api" if resource_type.lower() in {"fetch", "xhr"} else resource_type.lower()

                def request_event_key(request) -> tuple[str, str, str, bool]:
                    return (
                        sanitized_url(request.url),
                        request.method.upper(),
                        block_resource_kind(request.resource_type),
                        is_primary_navigation(request),
                    )

                def ensure_api_observed(request) -> dict | None:
                    if network_observer.finalized or not is_api_observation(request):
                        return None
                    event = network_observer.observe_request(
                        request,
                        phase=request_phase(request),
                        importance=api_importance(request),
                        initiating_route=request_origin(request)[0],
                        main_document=is_main_navigation(request),
                        route_activation_id=request_origin(request)[1],
                    )
                    if "_resource_timing_key" not in event:
                        event["_resource_timing_key"] = resource_timing_key(request.url)
                    remember_request_observation(request, event)
                    return event

                def record_request(request):
                    if network_observer.finalized:
                        return
                    key = request_identity(request)
                    # API inventory intentionally excludes ordinary documents/assets.
                    # Count all HTTP activity separately, once per live browser request,
                    # including requests intercepted before their request event arrives.
                    if (
                        not network_observer.finalized
                        and key not in observed_http_requests
                        and urlparse(request.url).scheme in {"http", "https"}
                    ):
                        observed_http_requests.add(key)
                        scan_http_method_counts[request.method.upper()] += 1
                    if key in request_started:
                        ensure_api_observed(request)
                        return
                    request_started[key] = time.perf_counter()
                    request_routes[key] = request_origin(request)[0]
                    request_owners[key] = request_origin(request)[:2]
                    route_network_activity.request_started(
                        request, request_origin(request)[0],
                        # A menu's lazy microfrontend requests are discovery
                        # work even though their failures are not required API
                        # failures. Keep readiness independent of that label.
                        relevant=(
                            is_main_navigation(request)
                            or api_importance(request) == "REQUIRED"
                            or (request_origin(request)[2] == "DISCOVERY"
                                and api_importance(request) == "BACKGROUND")
                        ) and request.resource_type not in {"websocket", "eventsource"},
                    )
                    request_observation[key] = (
                        request_phase(request),
                        api_importance(request),
                    )
                    api_event = ensure_api_observed(request)
                    if api_event is None and request.resource_type not in {"document", "eventsource"}:
                        resource_event = {
                            "url": sanitized_url(request.url),
                            "method": request.method.upper(),
                            "observed_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
                            "_resource_timing_key": resource_timing_key(request.url),
                            "resource_type": request.resource_type,
                            "status": None, "error": None,
                            "phase": request_phase(request),
                            "initiating_route": request_origin(request)[0],
                            "route_activation_id": request_origin(request)[1],
                            "response_seen": False, "response_completed": False,
                            "lifecycle_status": "REQUESTED",
                        }
                        resource_events.append(resource_event)
                        resource_observations[key] = resource_event
                        remember_request_observation(request, resource_event)
                    if api_event is not None:
                        log_event(
                            logging.DEBUG,
                            "API_REQUEST_OBSERVED",
                            scan_id=scan_id,
                            request_id=api_event["request_id"],
                            route_activation_id=api_event["route_activation_id"],
                            method=api_event["method"],
                            hostname=api_event["host"],
                            endpoint=api_event["endpoint"],
                            phase=api_event["phase"],
                            resource_type=api_event["resource_type"],
                        )

                def request_timing(
                    request,
                ) -> tuple[int | None, str | None, str, str]:
                    key = request_identity(request)
                    started_at = request_started.pop(key, None)
                    route_id = request_routes.pop(key, None)
                    phase, importance = request_observation.pop(
                        key,
                        (request_phase(request), api_importance(request)),
                    )
                    duration = (
                        round((time.perf_counter() - started_at) * 1000)
                        if started_at is not None else None
                    )
                    return duration, route_id, phase, importance

                async def abort_by_validator(route: Route, reason: str) -> None:
                    request = route.request
                    validator_blocks[request_event_key(request)].append(reason)
                    api_event = ensure_api_observed(request)
                    try:
                        auth_body = request.post_data
                    except PlaywrightError:
                        auth_body = None
                    source_url = authentication_request_source(request)
                    # Diagnose concrete protocol attempts even when the missing
                    # identity-host approval prevented an active flow. Diagnosis
                    # cannot authorize a request or retain credential payloads.
                    auth_diagnostic = authentication_navigation.diagnose_blocked_request(
                        request.method, request.url, auth_body,
                        resource_type=request.resource_type,
                        document_navigation=request.is_navigation_request(),
                        portal_scoped=url_in_scan_scope(
                            request.url, root_host, req.allow_subdomains, approved_portal_hosts,
                        ),
                        source_url=source_url,
                        source_portal_scoped=url_in_scan_scope(
                            source_url, root_host, req.allow_subdomains, approved_portal_hosts,
                        ),
                        main_frame=is_main_navigation(request),
                    )
                    if auth_diagnostic is not None:
                        route_id, activation_id, phase = request_origin(request)
                        auth_diagnostic.update({
                            "route_id": route_id, "route_activation_id": activation_id,
                            "phase": phase, "policy_reason": reason.upper(),
                            "method": request.method, "endpoint": safe_api_identity(request.url)[0],
                            "policy_decision": "BLOCK",
                            "duration_ms": (api_event or {}).get("duration_ms", 0),
                        })
                        if auth_diagnostic not in authentication_diagnostics:
                            authentication_diagnostics.append(auth_diagnostic)
                        if auth_diagnostic["affects_authentication"]:
                            authentication_denials.add(activation_id)
                        if api_event is not None:
                            api_event["authentication_diagnostic"] = dict(auth_diagnostic)
                        log_event(logging.WARNING, "AUTHENTICATION_REQUEST_BLOCKED", scan_id=scan_id,
                                  hostname=auth_diagnostic["destination_host"],
                                  classification=auth_diagnostic["reason"],
                                  route_activation_id=activation_id)
                    if api_event is not None:
                        public_reason = (
                            "READ_ONLY_MUTATION_BLOCKED"
                            if reason == "read_only_mutation_policy"
                            else reason.upper()
                        )
                        network_observer.mark_blocked(
                            request,
                            public_reason,
                            classification=(
                                "BLOCKED_MUTATION"
                                if reason == "read_only_mutation_policy"
                                else "BLOCKED_BY_NETWORK_POLICY"
                            ),
                        )
                        log_event(
                            logging.WARNING,
                            "API_REQUEST_BLOCKED",
                            scan_id=scan_id,
                            request_id=api_event["request_id"],
                            route_activation_id=api_event["route_activation_id"],
                            method=api_event["method"],
                            hostname=api_event["host"],
                            endpoint=api_event["endpoint"],
                            block_reason=public_reason,
                        )
                    log_event(
                        logging.DEBUG,
                        "REQUEST_BLOCKED_BY_VALIDATOR",
                        scan_id=scan_id,
                        hostname=normalized_host(urlparse(request.url).hostname or ""),
                        resource_type=request.resource_type,
                        main_document=is_main_navigation(request),
                        block_reason=reason,
                    )
                    await route.abort("blockedbyclient")

                def record_resource_failure(request, details):
                    """One request occurrence can have HTTP and transfer failure evidence."""
                    key = request_identity(request)
                    observed = resource_observations.get(key)
                    if observed is not None:
                        details.setdefault("status", observed.get("status"))
                        details.setdefault("response_seen", observed.get("response_seen", False))
                    existing = resource_failure_observations.get(key)
                    if existing is None:
                        failed_resources.append(details)
                        resource_failure_observations[key] = details
                        remember_request_observation(request, details)
                    else:
                        existing.update(details)

                def finalize_resource_observations():
                    # Stop at the same cutoff as API observation. Browser cleanup
                    # must not turn pending transfers into target-side failures.
                    for event in resource_events:
                        if event.get("lifecycle_status") not in {"COMPLETED", "FAILED", "BLOCKED", "CANCELED"}:
                            event["lifecycle_status"] = "INCOMPLETE"
                            event["incomplete_reason"] = (
                                "RESPONSE_BODY_NOT_COMPLETED" if event.get("response_seen")
                                else "NO_RESPONSE_BEFORE_SCAN_END"
                            )

                def record_failed_request(request):
                    if network_observer.finalized:
                        return
                    route_network_activity.request_finished(request)
                    duration_ms, initiating_route, phase, importance = request_timing(request)
                    owner = request_owners.pop(
                        request_identity(request), request_origin(request)[:2],
                    )
                    initiating_route = owner[0]
                    key = request_event_key(request)
                    reasons = validator_blocks.get(key)
                    block_reason = reasons.popleft() if reasons else None
                    if reasons is not None and not reasons:
                        validator_blocks.pop(key, None)
                    statuses = redirect_response_statuses.get(key)
                    redirect_status = statuses.popleft() if statuses else None
                    if statuses is not None and not statuses:
                        redirect_response_statuses.pop(key, None)
                    record_resource_failure(request, {
                        "url": sanitized_url(request.url),
                        "error": sanitized_diagnostic(request.failure or "Request failed"),
                        "resource_type": request.resource_type,
                        "main_document": is_primary_navigation(request),
                        "top_level_navigation": is_main_navigation(request),
                        "blocked_by_validator": block_reason is not None,
                        "block_reason": block_reason,
                        "duration_ms": duration_ms,
                        "initiating_route": initiating_route,
                        "route_activation_id": owner[1],
                    })
                    if is_api_observation(request):
                        api_event = ensure_api_observed(request)
                        if block_reason and api_event is not None and not api_event.get("blocked_by_validator"):
                            network_observer.mark_blocked(request, block_reason.upper(), classification="BLOCKED_BY_NETWORK_POLICY")
                            if redirect_status is not None:
                                api_event.update(
                                    redirect_blocked=True, status=redirect_status, response_status=redirect_status,
                                    response_seen=True, target_reached=True, request_reached_network=True,
                                )
                        api_event = network_observer.record_failure(
                            request,
                            sanitized_diagnostic(request.failure or "Request failed"),
                        )
                        if api_event is not None and not api_event.get("blocked_by_validator"):
                            log_event(
                                logging.WARNING,
                                "API_REQUEST_FAILED",
                                scan_id=scan_id,
                                request_id=api_event["request_id"],
                                route_activation_id=api_event["route_activation_id"],
                                method=api_event["method"],
                                hostname=api_event["host"],
                                endpoint=api_event["endpoint"],
                                phase=api_event["phase"],
                            )
                    elif request.resource_type not in {"document", "eventsource"}:
                        resource_event = resource_observations.get(request_identity(request))
                        failure = {
                            "url": sanitized_url(request.url),
                            "_resource_timing_key": resource_timing_key(request.url),
                            "resource_type": request.resource_type,
                            "status": resource_event.get("status") if resource_event else None,
                            "error": sanitized_diagnostic(request.failure or "Request failed"),
                            "blocked_by_validator": block_reason is not None,
                            "block_reason": block_reason,
                            "phase": phase,
                            "duration_ms": duration_ms,
                            "initiating_route": initiating_route,
                            "route_activation_id": owner[1],
                            "response_completed": False,
                            "lifecycle_status": "BLOCKED" if block_reason else "FAILED",
                        }
                        if resource_event is not None:
                            # One occurrence keeps its definitive HTTP status
                            # even if Chromium subsequently fails the body.
                            resource_event.update(failure)
                        else:
                            resource_events.append(failure)
                            resource_observations[request_identity(request)] = failure
                    if request.resource_type == "eventsource":
                        event_streams.append({
                            "url": sanitized_url(request.url),
                            "status": None,
                            "error": sanitized_diagnostic(request.failure or "Request failed"),
                        })

                def record_request_finished(request):
                    if network_observer.finalized:
                        return
                    route_network_activity.request_finished(request)
                    network_observer.record_finished(request)
                    resource_event = resource_observations.get(request_identity(request))
                    if resource_event is not None:
                        resource_event.update(response_completed=True, lifecycle_status="COMPLETED")
                    request_owners.pop(request_identity(request), None)

                def record_response(response):
                    nonlocal latest_document_response
                    if network_observer.finalized:
                        return
                    if is_main_navigation(response.request):
                        observed_document_responses.append(response)
                        try:
                            page_document_responses[request_identity(response.request.frame.page)] = response
                        except PlaywrightError:
                            # The initial popup document can precede Frame
                            # creation; record_popup resolves it after commit.
                            pass
                    if is_primary_navigation(response.request):
                        latest_document_response = response
                        authentication_navigation.observe(response.url, method=response.request.method)
                    duration_ms, initiating_route, phase, importance = request_timing(response.request)
                    content_type = safe_content_type(response.headers.get("content-type"))
                    owner = request_owners.get(
                        request_identity(response.request), request_origin(response.request)[:2],
                    )
                    initiating_route = owner[0]
                    if is_api_observation(response.request):
                        api_event = network_observer.record_response(
                            response.request,
                            response.status,
                        )
                        if api_event is not None:
                            remember_request_observation(response.request, api_event)
                            api_event["content_type"] = content_type
                            log_event(
                                logging.DEBUG,
                                "API_RESPONSE_OBSERVED",
                                scan_id=scan_id,
                                request_id=api_event["request_id"],
                                route_activation_id=api_event["route_activation_id"],
                                method=api_event["method"],
                                hostname=api_event["host"],
                                endpoint=api_event["endpoint"],
                                http_status=response.status,
                                phase=api_event["phase"],
                            )
                            if (
                                api_event.get("request_classification") == "SESSION_REFRESH"
                                and 200 <= response.status < 400
                            ):
                                log_event(
                                    logging.INFO,
                                    "SESSION_REFRESH_SUCCEEDED",
                                    scan_id=scan_id,
                                    hostname=api_event["host"],
                                    endpoint=api_event["endpoint"],
                                    http_status=response.status,
                                )
                    elif response.request.resource_type not in {"document", "eventsource"}:
                        resource_event = {
                            "url": sanitized_url(response.url),
                            "_resource_timing_key": resource_timing_key(response.url),
                            "resource_type": response.request.resource_type,
                            "status": response.status,
                            "content_type": content_type,
                            "error": None,
                            "phase": phase,
                            "duration_ms": duration_ms,
                            "initiating_route": initiating_route,
                            "route_activation_id": owner[1],
                            "response_seen": True,
                            "response_completed": False,
                            "lifecycle_status": "RESPONDED",
                        }
                        key = request_identity(response.request)
                        existing_resource = resource_observations.get(key)
                        if existing_resource is None:
                            resource_events.append(resource_event)
                            resource_observations[key] = resource_event
                        else:
                            existing_resource.update(resource_event)
                        if response.status >= 400:
                            record_resource_failure(response.request, {
                                "url": sanitized_url(response.url),
                                "status": response.status,
                                "response_seen": True,
                                "error": f"Resource returned HTTP {response.status}",
                                "resource_type": response.request.resource_type,
                                "main_document": False,
                                "top_level_navigation": False,
                                "blocked_by_validator": False,
                                "block_reason": None,
                                "duration_ms": duration_ms,
                                "initiating_route": initiating_route,
                                "route_activation_id": owner[1],
                            })
                    if response.request.resource_type == "eventsource" or content_type == "text/event-stream":
                        event_streams.append({
                            "url": sanitized_url(response.url),
                            "status": response.status,
                            "error": None,
                        })
                    if current_tracker is not None and is_primary_navigation(response.request):
                        current_tracker.record_response(response.url, response.status)
                        log_event(
                            logging.INFO,
                            "HTTP_RESPONSE",
                            scan_id=scan_id,
                            current_url=response.url,
                            http_status=response.status,
                        )

                def record_websocket(socket):
                    item = {"url": sanitized_url(socket.url), "status": "OPEN"}
                    websocket_events.append(item)
                    socket.on("close", lambda: item.update(status="CLOSED"))
                    socket.on(
                        "socketerror",
                        lambda error: item.update(
                            status="ERROR",
                            error=sanitized_diagnostic(str(error)),
                        ),
                    )

                def record_download(download):
                    download_events.append({
                        "url": sanitized_url(download.url),
                        "suggested_filename": sanitize_text(download.suggested_filename, limit=160),
                    })

                def record_frame_navigation(frame):
                    if frame.url.startswith(("http://", "https://")):
                        owner = ((active_route_id, active_route_activation_id, observation_phase)
                                 if frame.page == page else popup_origins.get(request_identity(frame.page), (None, None, None)))
                        event = {
                            "url": sanitized_url(frame.url),
                            "main_frame": frame == frame.page.main_frame,
                            "initiating_route": owner[0], "route_activation_id": owner[1],
                        }
                        frame_events.append(event)
                        remember_page_observation(frame.page, event)

                async def record_popup(popup):
                    nonlocal popup_observation_failures
                    try:
                        await popup.wait_for_load_state("domcontentloaded", timeout=max(1, min(req.timeout_ms, round((deadline - time.perf_counter()) * 1000))))
                        await settle_authentication_navigation(
                            popup,
                            in_portal_scope=lambda candidate: url_in_scan_scope(
                                candidate, root_host, req.allow_subdomains, approved_portal_hosts,
                            ),
                            is_approved_authentication_host=lambda host: host in req.authentication_hosts,
                            detect_signals=detect_auth_signals,
                            timeout_ms=max(1, min(
                                req.authentication_timeout_ms or req.timeout_ms,
                                round((deadline - time.perf_counter()) * 1000),
                            )),
                            flow_active=authentication_navigation.active,
                            current_status=lambda: (
                                document_response_for(popup).status
                                if document_response_for(popup) is not None else None
                            ),
                        )
                        if popup.url.startswith(("http://", "https://")):
                            popup_routes.append(DiscoveredRoute(
                                url=popup.url,
                                label=sanitize_text(await retry_dom_operation(popup, popup.title), limit=160) or "New window",
                                source="popup",
                                navigation_mode=POPUP_NAVIGATION,
                                browser_page_key=browser_page_keys.get(request_identity(popup)),
                                opener_route_id=popup_origins.get(request_identity(popup), (None, None, None))[0],
                            ))
                    except Exception as exc:
                        popup_observation_failures += 1
                        log_event(
                            logging.INFO,
                            "POPUP_OBSERVATION_FAILED",
                            scan_id=scan_id,
                            error=sanitized_diagnostic(str(exc)),
                        )
                    # Keep the naturally opened page alive until context cleanup:
                    # closing on DOMContentLoaded cancels lazy APIs and auth work.

                async def ensure_redirect_guard(owner_page):
                    key = request_identity(owner_page)
                    task = guard_install_tasks.get(key)
                    if task is None:
                        async def validate_redirect_policy(destination, source, metadata):
                            destination_host, _ = validate_http_url(destination)
                            await _resolve_with_logging(destination_host, req, scan_id)
                            source_host = normalized_host(urlparse(source).hostname or "")
                            # Playwright header overrides are inherited by native
                            # redirects. Fail closed rather than leak credentials.
                            if (
                                authentication_manager.configured_headers()
                                and source_host in credential_hosts
                                and destination_host not in credential_hosts
                            ):
                                raise DestinationError(
                                    "NAVIGATION_ERROR",
                                    "Redirect outside approved credential scope was blocked; use a scoped SSO session or review destination approval",
                                )
                            destination_scoped = host_in_scan_scope(
                                destination_host, root_host, req.allow_subdomains, approved_portal_hosts,
                            )
                            method = metadata["method"]
                            if metadata["response_status"] == 303 and method != "HEAD" or metadata["response_status"] in {301, 302} and method == "POST":
                                method = "GET"
                            approved_redirect = read_only_policy.match(method, destination)
                            auth_redirect = authentication_navigation.allows_redirect(
                                method, source, destination,
                                document_navigation=bool(metadata.get("document_navigation")),
                                authentication_form=bool(metadata.get("authentication_form")),
                                oauth_token_form=bool(metadata.get("oauth_token_form")),
                                source_portal_scoped=host_in_scan_scope(
                                    source_host, root_host, req.allow_subdomains, approved_portal_hosts,
                                ),
                                destination_portal_scoped=destination_scoped,
                            )
                            if method not in SAFE_READ_ONLY_METHODS:
                                source_rule = read_only_policy.match(method, source)
                                if not auth_redirect and approved_redirect is None:
                                    raise DestinationError("NAVIGATION_ERROR", "Redirected POST destination lacks explicit read-only or authentication approval")
                                if approved_redirect is not None and approved_redirect.graphql_queries_only and not (
                                    source_rule is not None and source_rule.graphql_queries_only
                                ):
                                    raise DestinationError("NAVIGATION_ERROR", "Redirect cannot establish a previously unverified GraphQL query-only operation")
                            if metadata["main_document"]:
                                navigation_hosts.add(destination_host)
                                authentication_navigation.observe(source, metadata["method"])
                                if owner_page == page and current_tracker is not None:
                                    for hop in (source, destination):
                                        if not current_tracker.destinations or current_tracker.destinations[-1].raw_url != urldefrag(hop).url:
                                            current_tracker.record_destination(hop, allow_revisit=authentication_navigation.active)
                            elif not (
                                destination_scoped or destination_host in approved_resource_hosts
                                or destination_host in navigation_hosts or approved_redirect is not None
                                or auth_redirect
                            ):
                                raise DestinationError("NETWORK_ERROR", "Resource redirect destination is outside approved resource scope")

                        async def validate_redirect(destination, source, metadata):
                            policy_started = time.perf_counter()
                            try:
                                await validate_redirect_policy(destination, source, metadata)
                            finally:
                                if owner_page == page and metadata["main_document"]:
                                    navigation_policy_intervals.append((policy_started, time.perf_counter()))

                        def redirect_denied(exc, metadata):
                            nonlocal navigation_policy_error
                            if metadata["main_document"] and owner_page == page:
                                navigation_policy_error = exc
                            event_key = (
                                sanitized_url(metadata["url"]), metadata["method"],
                                block_resource_kind(metadata["resource_type"]), metadata["main_document"],
                            )
                            validator_blocks[event_key].append("redirect_network_policy")
                            if isinstance(metadata.get("response_status"), int):
                                redirect_response_statuses[event_key].append(metadata["response_status"])
                            log_event(
                                logging.WARNING, "REDIRECT_BLOCKED_BY_POLICY", scan_id=scan_id,
                                hostname=normalized_host(urlparse(metadata["url"]).hostname or ""),
                                method=metadata["method"], main_document=metadata["main_document"],
                                resource_type=metadata["resource_type"],
                                classification=exc.classification, error=exc.public_message,
                            )

                        async def install():
                            guard = await RedirectResponseGuard.install_browser(
                                browser, validate_destination=validate_redirect,
                                on_policy_error=redirect_denied,
                                validation_timeout_ms=req.navigation_timeout_ms or req.timeout_ms,
                            )
                            redirect_guards.append(guard)
                            await guard.bind_primary_page(context, owner_page)
                            return guard
                        task = asyncio.create_task(install())
                        guard_install_tasks[key] = task
                    return await task

                def navigation_policy_time_ms(begin: float, end: float) -> int:
                    intervals = sorted(
                        (max(start, begin), min(stop, end))
                        for start, stop in navigation_policy_intervals
                        if start < end and stop > begin
                    )
                    elapsed = 0.0
                    cursor = begin
                    for start, stop in intervals:
                        elapsed += max(0.0, stop - max(cursor, start))
                        cursor = max(cursor, stop)
                    return round(elapsed * 1000)

                async def route_guard_policy(route: Route):
                    nonlocal navigation_policy_error
                    request = route.request
                    # Observation is intentionally first and idempotent. Context listeners
                    # normally arrive first; this guarantees policy never makes an attempt
                    # invisible if Playwright schedules interception before the event callback.
                    if request_identity(request) not in request_started:
                        record_request(request)
                    api_event = ensure_api_observed(request)
                    network_observer.mark_route_handler(request)
                    request_url = urlparse(request.url)
                    host = normalized_host(request_url.hostname or "")
                    portal_scoped = bool(host and host_in_scan_scope(
                        host,
                        root_host,
                        req.allow_subdomains,
                        approved_portal_hosts,
                    ))
                    resource_scoped = host in approved_resource_hosts
                    approved_operation = read_only_policy.match(request.method, request.url)
                    main_navigation = is_main_navigation(request)
                    source_url = authentication_request_source(request)
                    try:
                        auth_body = request.post_data
                    except PlaywrightError:
                        auth_body = None
                    auth_request_allowed = (
                        not main_navigation and authentication_navigation.allows_browser_request(
                            request.method, request.url, auth_body,
                            resource_type=request.resource_type,
                            document_navigation=request.is_navigation_request(),
                            source_url=source_url,
                            source_portal_scoped=url_in_scan_scope(
                                source_url, root_host, req.allow_subdomains, approved_portal_hosts,
                            ),
                            portal_scoped=portal_scoped,
                        )
                    )
                    if main_navigation:
                        try:
                            validated_host, _ = validate_http_url(request.url)
                            await _resolve_with_logging(validated_host, req, scan_id)
                            if is_primary_navigation(request) and current_tracker is None:
                                raise DestinationError("NAVIGATION_ERROR", "Navigation tracker is unavailable")
                            authentication_navigation.observe(request.url, method=request.method)
                            if is_primary_navigation(request) and current_tracker is not None:
                                if not current_tracker.destinations or current_tracker.destinations[-1].raw_url != urldefrag(request.url).url:
                                    current_tracker.record_destination(
                                        request.url,
                                        allow_revisit=authentication_navigation.active,
                                    )
                            navigation_hosts.add(validated_host)
                        except DestinationError as exc:
                            if is_primary_navigation(request):
                                navigation_policy_error = exc
                            log_event(
                                logging.ERROR,
                                exc.classification,
                                scan_id=scan_id,
                                current_url=request.url,
                                hostname=host,
                                error=exc.public_message,
                            )
                            await abort_by_validator(route, "network_policy")
                            return
                    elif auth_request_allowed:
                        # Explicit protocol-specific authentication approval is
                        # separate from assets, crawling and business POST rules.
                        # It never exempts the actual destination from SSRF.
                        try:
                            validated_host, _ = validate_http_url(request.url)
                            await _resolve_with_logging(validated_host, req, scan_id)
                        except DestinationError:
                            await abort_by_validator(route, "network_policy")
                            return
                    elif request_url.scheme not in {"http", "https"} or not (
                        portal_scoped or resource_scoped or host in navigation_hosts or approved_operation is not None
                    ):
                        await abort_by_validator(route, "third_party_resource_policy")
                        return
                    elif approved_operation is not None and not (
                        portal_scoped or resource_scoped or host in navigation_hosts
                    ):
                        # An operation exception is narrower than a resource
                        # host allowlist and must independently validate the
                        # actual URL's port and current DNS destination.
                        try:
                            validated_host, _ = validate_http_url(request.url)
                            await _resolve_with_logging(validated_host, req, scan_id)
                        except DestinationError:
                            await abort_by_validator(route, "network_policy")
                            return

                    method = request.method.upper()
                    if method not in SAFE_READ_ONLY_METHODS:
                        auth_navigation_allowed = auth_request_allowed
                        if main_navigation:
                            try:
                                post_data = request.post_data
                            except PlaywrightError:
                                post_data = None
                            auth_navigation_allowed = authentication_navigation.allows_main_frame_method(
                                request.method,
                                request.url,
                                post_data,
                                portal_scoped=portal_scoped,
                                source_url=source_url,
                                source_portal_scoped=url_in_scan_scope(
                                    source_url, root_host, req.allow_subdomains, approved_portal_hosts,
                                ),
                            )
                        approved_rule = approved_operation
                        if approved_rule is not None and approved_rule.graphql_queries_only:
                            # An OAuth-looking URL must not override an explicit
                            # endpoint restriction on the submitted operation.
                            if api_event is not None:
                                api_event["protocol"] = "GRAPHQL"
                            try:
                                graphql_body = request.post_data
                            except PlaywrightError:
                                graphql_body = None
                            if not is_read_only_graphql_body(graphql_body):
                                await abort_by_validator(route, "read_only_mutation_policy")
                                return
                            auth_navigation_allowed = False
                        if not auth_navigation_allowed and approved_rule is None:
                            await abort_by_validator(route, "read_only_mutation_policy")
                            return
                        if auth_navigation_allowed:
                            session_renewal = (
                                not main_navigation and method == "POST"
                                and oauth_refresh_grant_signal(auth_body)
                            )
                            request_phase_name = "SESSION_REFRESH" if session_renewal else "AUTHENTICATION"
                            request_observation[request_identity(request)] = (
                                request_phase_name,
                                "AUTHENTICATION",
                            )
                            network_observer.mark_allowed(
                                request,
                                "SESSION_REFRESH" if session_renewal else "AUTH_FLOW",
                                phase=request_phase_name,
                                importance="AUTHENTICATION",
                            )
                            log_event(
                                logging.INFO,
                                "SESSION_REFRESH_OBSERVED" if session_renewal else "AUTH_FLOW_POST_ALLOWED",
                                scan_id=scan_id,
                                hostname=host,
                                method=method,
                            )
                        elif approved_rule is not None:
                            classification = approved_rule.classification
                            policy_phase = (
                                "SESSION_REFRESH"
                                if classification == "SESSION_REFRESH"
                                else request_phase(request)
                            )
                            policy_importance = (
                                "AUTHENTICATION"
                                if classification == "SESSION_REFRESH"
                                else api_importance(request)
                            )
                            request_observation[request_identity(request)] = (
                                policy_phase,
                                policy_importance,
                            )
                            network_observer.mark_allowed(
                                request,
                                classification,
                                phase=policy_phase,
                                importance=policy_importance,
                            )
                            log_event(
                                logging.INFO,
                                (
                                    "SESSION_REFRESH_OBSERVED"
                                    if classification == "SESSION_REFRESH"
                                    else "SAFE_APPLICATION_POST_ALLOWED"
                                    if method == "POST"
                                    else "SAFE_APPLICATION_REQUEST_ALLOWED"
                                ),
                                scan_id=scan_id,
                                hostname=host,
                                endpoint=api_event.get("endpoint") if api_event else "/",
                                method=method,
                                classification=classification,
                                request_id=api_event.get("request_id") if api_event else None,
                                route_activation_id=api_event.get("route_activation_id") if api_event else None,
                            )
                    elif auth_request_allowed and api_event is not None:
                        network_observer.mark_allowed(request, "AUTH_FLOW", phase="AUTHENTICATION", importance="AUTHENTICATION")
                    elif api_event is not None:
                        network_observer.mark_allowed(request, "SAFE_METHOD")

                    if authentication_manager.configured_headers():
                        headers = authentication_manager.headers_for_request(request.headers, host)
                        await route.continue_(headers=headers)
                    else:
                        # Avoid converting browser-managed credentials into
                        # explicit overrides that persist across native redirects.
                        await route.continue_()
                    network_observer.mark_dispatched(request)

                async def route_guard(route: Route):
                    policy_started = time.perf_counter()
                    primary_navigation = is_primary_navigation(route.request)
                    try:
                        await route_guard_policy(route)
                    finally:
                        if primary_navigation:
                            navigation_policy_intervals.append((policy_started, time.perf_counter()))

                context.on("request", record_request)
                context.on("requestfailed", record_failed_request)
                context.on("requestfinished", record_request_finished)
                context.on("response", record_response)
                def register_browser_page(owner_page):
                    nonlocal browser_page_count
                    key = request_identity(owner_page)
                    if key in browser_page_keys:
                        return
                    browser_page_count += 1
                    page_key = f"page-{browser_page_count}"
                    browser_page_keys[key] = page_key
                    browser_pages[page_key] = owner_page
                    popup_origins[key] = (active_route_id, active_route_activation_id, observation_phase)
                    owner_page.on("websocket", record_websocket)
                    owner_page.on("download", record_download)
                    owner_page.on("framenavigated", record_frame_navigation)

                def schedule_popup(popup, owner=None):
                    if getattr(popup, "_portal_validator_page_limit_blocked", False):
                        return
                    register_browser_page(popup)
                    key = request_identity(popup)
                    if getattr(popup, "_portal_validator_observed_popup", False):
                        if owner is not None:
                            popup_origins[key] = owner
                        return
                    popup._portal_validator_observed_popup = True
                    popup_origins[key] = owner or (active_route_id, active_route_activation_id, observation_phase)
                    task = asyncio.create_task(record_popup(popup))
                    popup_tasks.add(task)
                    task.add_done_callback(popup_tasks.discard)

                def observe_context_page(owner_page):
                    nonlocal popup_observation_failures
                    if internal_page_requested:
                        # A validator-owned tab (session refresh) is observed for
                        # network policy but is never an application popup/route.
                        owner_page._portal_validator_internal = True
                        register_browser_page(owner_page)
                        return
                    if primary_page is not None and browser_page_count >= max(4, req.max_pages + 1):
                        # Keep independent windows bounded by the configured
                        # route ceiling, with minimal authentication headroom.
                        owner_page._portal_validator_page_limit_blocked = True
                        popup_observation_failures += 1
                        task = asyncio.create_task(owner_page.close())
                        popup_tasks.add(task)
                        task.add_done_callback(popup_tasks.discard)
                        log_event(logging.WARNING, "BROWSER_PAGE_LIMIT_REACHED", scan_id=scan_id,
                                  maximum=max(4, req.max_pages + 1))
                        return
                    register_browser_page(owner_page)
                    owner_page.on("popup", lambda child: schedule_popup(
                        child, popup_origins.get(request_identity(owner_page)),
                    ))
                    # The very first context page is primary. Every later page
                    # is discovered even when its opener event is unavailable.
                    if primary_page is not None:
                        schedule_popup(owner_page)

                context.on("page", observe_context_page)
                refresh_interval_s = (
                    (req.session_refresh_interval_ms or refresh_config.interval_ms or 0) / 1000
                    if refresh_config is not None else 0
                )
                last_session_refresh = time.perf_counter()

                async def run_periodic_session_refresh():
                    """Let the IdP renew the session on a separate validator tab."""
                    nonlocal internal_page_requested, observation_phase, last_session_refresh
                    nonlocal authentication_duration_ms
                    previous_phase = observation_phase
                    started_refresh = time.perf_counter()
                    internal_page_requested = True
                    try:
                        refresh_page = await context.new_page()
                    finally:
                        internal_page_requested = False
                    try:
                        await ensure_redirect_guard(refresh_page)
                        observation_phase = "SESSION_REFRESH"
                        log_event(
                            logging.INFO, "SESSION_REFRESH_STARTED", scan_id=scan_id, periodic=True,
                            hostname=normalized_host(urlparse(refresh_config.refresh_url).hostname or ""),
                        )
                        outcome = await refresh_browser_session(refresh_page, refresh_config)
                        log_event(
                            logging.INFO if not outcome.get("error") else logging.WARNING,
                            "SESSION_REFRESH_COMPLETED", scan_id=scan_id, periodic=True, **outcome,
                        )
                        session_refresh["periodic_refreshes"] = int(session_refresh.get("periodic_refreshes", 0)) + 1
                        if outcome.get("error"):
                            session_refresh["periodic_refresh_failures"] = int(
                                session_refresh.get("periodic_refresh_failures", 0)
                            ) + 1
                    finally:
                        observation_phase = previous_phase
                        try:
                            await refresh_page.close()
                        except PlaywrightError:
                            pass
                        last_session_refresh = time.perf_counter()
                        authentication_duration_ms += round((last_session_refresh - started_refresh) * 1000)

                async def recover_expired_session() -> bool:
                    """Re-establish an expired session through the approved SSO flow.

                    Runs the profile's silent refresh (if configured), then reopens the
                    portal so the identity provider can silently re-issue tokens from
                    its own session. Credentials are never entered or replayed.
                    """
                    nonlocal session_recovery_attempts_used, authentication_error, session_expired
                    nonlocal session_evidence_start, diagnostic_evidence_start, session_interruption
                    nonlocal observation_phase, current_tracker, navigation_policy_error
                    session_interruption = authentication_error or session_interruption
                    if session_recovery_attempts_used >= req.session_recovery_attempts or time.perf_counter() >= deadline:
                        return False
                    session_recovery_attempts_used += 1
                    log_event(
                        logging.WARNING, "SESSION_RECOVERY_STARTED", scan_id=scan_id,
                        attempt=session_recovery_attempts_used,
                        category=(authentication_error or {}).get("category"),
                    )
                    if refresh_config is not None:
                        await run_periodic_session_refresh()
                    previous_phase = observation_phase
                    observation_phase = "SESSION_REFRESH"
                    recovered = False
                    try:
                        budget_ms = max(1, min(
                            req.authentication_timeout_ms or req.timeout_ms,
                            round((deadline - time.perf_counter()) * 1000),
                        ))
                        current_tracker = NavigationTracker(req.max_redirects)
                        navigation_policy_error = None
                        response = await primary_page.goto(
                            requested_target, wait_until="domcontentloaded", timeout=budget_ms,
                        )
                        settled = await settle_authentication_navigation(
                            primary_page,
                            in_portal_scope=lambda candidate: url_in_scan_scope(
                                candidate, root_host, req.allow_subdomains, approved_portal_hosts,
                            ),
                            is_approved_authentication_host=lambda host: host in req.authentication_hosts,
                            detect_signals=detect_auth_signals,
                            timeout_ms=budget_ms,
                            flow_active=authentication_navigation.active,
                            status=response.status if response is not None else None,
                        )
                        if settled.get("stage") == "APPLICATION" and settled.get("completed"):
                            readiness = await wait_for_render_settle(
                                primary_page,
                                settle_ms=req.render_settle_ms,
                                maximum_ms=max(0, min(
                                    req.readiness_timeout_ms or req.timeout_ms,
                                    round((deadline - time.perf_counter()) * 1000),
                                )),
                                minimum_observation_ms=req.min_observation_ms,
                                network_quiet_ms=req.network_quiet_ms,
                                readiness_selector=req.readiness_selector,
                                readiness_event=req.readiness_event,
                                network_settle_cap_ms=req.network_settle_cap_ms,
                            )
                            password_form, mfa_form = await detect_auth_signals(primary_page)
                            recovered = bool(
                                application_shell_ready(readiness) and not password_form and not mfa_form
                                and url_in_scan_scope(
                                    primary_page.url, root_host, req.allow_subdomains, approved_portal_hosts,
                                )
                            )
                    except (PlaywrightError, TimeoutError, DestinationError) as exc:
                        log_event(logging.WARNING, "SESSION_RECOVERY_ERROR", scan_id=scan_id,
                                  error=sanitized_diagnostic(str(exc)))
                    finally:
                        observation_phase = previous_phase
                    if recovered:
                        session_evidence_start = len(scan_api_events)
                        diagnostic_evidence_start = len(authentication_diagnostics)
                        authentication_error = None
                        session_expired = False
                        session_refresh["recoveries"] = int(session_refresh.get("recoveries", 0)) + 1
                        log_event(logging.INFO, "SESSION_RECOVERED", scan_id=scan_id,
                                  attempt=session_recovery_attempts_used)
                    else:
                        log_event(logging.WARNING, "SESSION_RECOVERY_FAILED", scan_id=scan_id,
                                  attempt=session_recovery_attempts_used)
                    return recovered
                # Context observers see initial inline popup diagnostics before
                # Playwright emits the Page event; per-page listeners are too late.
                context.on("console", lambda message: record_console_error(message, message.page))
                context.on("weberror", lambda error: record_page_error(error.error, error.page))
                network_observation_started = time.perf_counter()
                await context.route("**/*", route_guard)
                page = await context.new_page()
                primary_page = page
                # CDP interception must be active before Chromium starts the
                # first request. Installing it in a paused route misses that
                # request's response and can deadlock frame-tree discovery.
                await ensure_redirect_guard(page)
                if refresh_config is not None:
                    refresh_started = time.perf_counter()
                    current_tracker = NavigationTracker(req.max_redirects)
                    navigation_policy_error = None
                    navigation_hosts.clear()
                    # Keep context-wide approved authentication evidence while
                    # refreshing; each request still needs protocol/host/source approval.
                    observation_phase = "SESSION_REFRESH"
                    log_event(
                        logging.INFO,
                        "SESSION_REFRESH_STARTED",
                        scan_id=scan_id,
                        hostname=normalized_host(urlparse(refresh_config.refresh_url).hostname or ""),
                    )
                    session_refresh = await refresh_browser_session(page, refresh_config)
                    log_event(
                        logging.INFO if not session_refresh.get("error") else logging.WARNING,
                        "SESSION_REFRESH_COMPLETED",
                        scan_id=scan_id,
                        **session_refresh,
                    )
                    observation_phase = "AUTHENTICATION"
                    authentication_duration_ms += round((time.perf_counter() - refresh_started) * 1000)
                while queue and len(results) < req.max_pages:
                    try:
                        if cancel_event is not None and cancel_event.is_set():
                            cancellation_requested = True
                            break
                        if time.perf_counter() >= deadline:
                            total_timeout_reached = True
                            break
                        if (
                            refresh_interval_s and application_gate_confirmed
                            and time.perf_counter() - last_session_refresh >= refresh_interval_s
                        ):
                            await run_periodic_session_refresh()
                        (
                            url,
                            depth,
                            route_label,
                            route_source,
                            navigation_mode,
                            discovered_from,
                            discovery_type,
                            route_label_source,
                            route_accessible_name,
                            view_control,
                            parent_route_id,
                        ) = current_queue_entry = queue.popleft()
                        route_identity = normalize_route_url(
                            url,
                            query_policy=route_query_policy(),
                            allowed_query_parameters=route_query_allowlist(),
                        ) or url
                        route_key = discovered_route_key(DiscoveredRoute(
                            url=url, label=route_label, source=route_source, view_control=view_control,
                        ), route_identity)
                        if route_key in seen or depth > req.max_depth:
                            continue
                        if view_control and view_control.get("kind") == "navigation" and menu_entry_signature(
                            route_label, route_metadata.get(route_key, {}).get("navigation_hierarchy", ()),
                        ) in linked_menu_entries:
                            # Its link was discovered after this menu item was queued.
                            discovered_routes.discard(route_key)
                            continue
                        seen.add(route_key)
                        active_route_identity = route_key
                        active_route_id = route_key if view_control else sanitized_url(route_identity)
                        active_view_source = url if view_control else None
                        active_route_activation_id = f"activation-{len(results) + 1}"
                        selected_page_key = route_page_keys.get(route_key)
                        page = browser_pages.get(selected_page_key, primary_page)
                        active_browser_page_key = browser_page_keys.get(request_identity(page))
                        await publish_progress(
                            "VALIDATING_ROUTES" if application_gate_confirmed else "AUTHENTICATING",
                            discovered=len(discovered_routes),
                            queued=len(queue) + 1,
                            validated=len(results),
                            healthy=sum(bool(item.get("passed")) for item in results),
                            failed=sum(
                                item.get("validation_status") == "FAIL"
                                or item.get("page_load_status") == "FAILED_TO_LOAD"
                                for item in results
                            ),
                            warnings=sum(
                                item.get("classification") == "PASS_WITH_WARNINGS"
                                for item in results
                            ),
                            current_route=active_route_id,
                        )
                        current_tracker = NavigationTracker(req.max_redirects)
                        navigation_policy_error = None
                        navigation_hosts.clear()
                        # Session/authentication evidence belongs to the shared browser
                        # context, not a single tab. Do not erase it between SPA routes.
                        latest_document_response = (
                            document_response_for(page)
                            if navigation_mode == POPUP_NAVIGATION else None
                        )
                        # Passive bootstrap observation is not an API health check.
                        # Only protocol-approved traffic is authentication traffic;
                        # ordinary application calls retain their owning view when
                        # the gate succeeds, and are withheld entirely if it fails.
                        observation_phase = "ROUTE_VALIDATION" if application_gate_confirmed else "APPLICATION_BOOTSTRAP"
                        popup_origins[request_identity(page)] = (
                            active_route_id, active_route_activation_id, observation_phase,
                        )
                        adopt_page_observations(page)
                        requested_url = sanitized_url(url)
                        requested_host = normalized_host(urlparse(url).hostname or "")
                        final_url: str | None = None
                        final_raw_url = url
                        websocket_start = len(websocket_events)
                        event_stream_start = len(event_streams)
                        download_start = len(download_events)
                        started = time.perf_counter()
                        route_deadline = min(deadline, started + (req.per_route_timeout_ms or req.timeout_ms) / 1000)
                        status: int | None = None
                        title: str | None = None
                        error: str | None = None
                        error_classification: str | None = None
                        authentication_classification: str | None = None
                        response_headers: dict[str, str] = {}
                        route_transition_succeeded = False
                        inherited_strict_tls = False
                        security_headers_inherited = False
                        links: list[str] = []
                        discovered: list[DiscoveredRoute] = []
                        external_links: list[str] = []
                        redirects: list[dict] = []
                        render_health: dict[str, object] | None = None
                        application_ready = False
                        dom_target = page
                        auth_settle: dict[str, object] = {"stage": "NOT_TESTED", "completed": False}
                        browser_lifecycle = BrowserLifecycle()
                        browser_lifecycle.advance("INITIAL_NAVIGATION")
                        name_evidence = {"primary_heading": "", "breadcrumb": ""}
                        navigation_actions = {"activated": 0, "skipped": 0}
                        route_discovery_ms = 0
                        navigation_ms = 0
                        navigation_policy_ms = 0
                        navigation_policy_intervals.clear()
                        render_start_ms = None
                        frame_observations: list[dict[str, object]] = []
                        final_in_scope = False
                        remaining_ms = max(0, round((deadline - time.perf_counter()) * 1000))
                        if remaining_ms == 0:
                            error = "Total scan timeout exceeded"
                            error_classification = "TIMEOUT"
                            browser_lifecycle.fail("TIMEOUT")
                        else:
                            log_event(
                                logging.INFO,
                                (
                                    "SPA_ROUTE_TRANSITION_STARTED"
                                    if navigation_mode in SAME_DOCUMENT_NAVIGATIONS
                                    else "DOCUMENT_NAVIGATION_STARTED"
                                ),
                                scan_id=scan_id,
                                requested_url=url,
                                hostname=requested_host,
                                page_number=len(results) + 1,
                                crawl_depth=depth,
                                navigation_type=navigation_mode,
                            )
                            try:
                                async with asyncio.timeout_at(route_deadline) as route_scope:
                                    dom_target = resolve_view_target(page, view_control)
                                    semantic_popup = None

                                    async def select_semantic_popup(popup):
                                        nonlocal semantic_popup
                                        semantic_popup = popup

                                    response, route_transition_succeeded, activation_method = await perform_route_navigation(
                                        page,
                                        url,
                                        navigation_mode,
                                        min(req.navigation_timeout_ms or req.timeout_ms, remaining_ms),
                                        label=route_label,
                                        source=route_source,
                                        view_control=view_control,
                                        source_document_url=route_document_sources.get(route_key),
                                        source_route_url=discovered_from,
                                        navigation_hierarchy=tuple(
                                            route_metadata.get(route_key, {}).get("navigation_hierarchy", ())
                                        ),
                                        on_popup=select_semantic_popup,
                                    )
                                    if semantic_popup is not None:
                                        page = semantic_popup
                                        dom_target = page
                                        active_browser_page_key = browser_page_keys.get(request_identity(page))
                                        route_page_keys[route_key] = active_browser_page_key
                                        popup_origins[request_identity(page)] = (
                                            active_route_id, active_route_activation_id, observation_phase,
                                        )
                                        latest_document_response = document_response_for(page)
                                        adopt_page_observations(page)
                                    if navigation_mode == POPUP_NAVIGATION or semantic_popup is not None:
                                        response = latest_document_response
                                        if response is None:
                                            raise RuntimeError("Observed popup has no captured main-document HTTP response")
                                    navigation_ms = round((time.perf_counter() - started) * 1000)
                                    navigation_policy_ms = navigation_policy_time_ms(started, time.perf_counter())
                                    navigation_duration_ms += navigation_ms
                                    browser_lifecycle.advance("AUTHENTICATING")
                                    require_bootstrap_readiness = bool(
                                        not results and (
                                            req.authentication.mode != "none" or req.readiness_selector
                                            or req.readiness_event or authentication_navigation.active
                                        )
                                    )

                                    async def bootstrap_application_ready(target):
                                        snapshot = await capture_render_health(target)
                                        snapshot.update(await configured_readiness_conditions(
                                            target, readiness_selector=req.readiness_selector,
                                            readiness_event=req.readiness_event,
                                        ))
                                        return application_shell_ready(snapshot)

                                    auth_settle = await settle_authentication_navigation(
                                        page,
                                        in_portal_scope=lambda candidate: url_in_scan_scope(
                                            candidate, root_host, req.allow_subdomains, approved_portal_hosts,
                                        ),
                                        is_approved_authentication_host=lambda host: host in req.authentication_hosts,
                                        detect_signals=detect_auth_signals,
                                        timeout_ms=max(1, min(
                                            req.authentication_timeout_ms or req.timeout_ms,
                                            round((route_deadline - time.perf_counter()) * 1000),
                                        )),
                                        flow_active=authentication_navigation.active,
                                        status=response.status if response is not None else None,
                                        current_status=lambda: (
                                            latest_document_response.status if latest_document_response is not None
                                            else response.status if response is not None else None
                                        ),
                                        application_ready=(
                                            bootstrap_application_ready if require_bootstrap_readiness else None
                                        ),
                                        application_readiness_timeout_ms=req.readiness_timeout_ms,
                                        cancel_event=cancel_event,
                                    )
                                    authentication_duration_ms += int(auth_settle["elapsed_ms"])
                                    # This policy records authentication evidence for
                                    # the shared browser context, not just this page.
                                    # The main application can settle while a popup's
                                    # approved SSO POST/callback is still in flight.
                                    # Every POST still requires protocol evidence,
                                    # approved destination and normal network checks.
                                    # goto() may return an intermediate auto-post/callback
                                    # document. Use the actual final main-document evidence.
                                    if latest_document_response is not None and navigation_mode not in SAME_DOCUMENT_NAVIGATIONS:
                                        response = latest_document_response
                                    if not route_transition_succeeded and auth_settle["completed"]:
                                        # The final application's own Navigation Timing
                                        # includes a slow document reached after SSO,
                                        # but not our auth polling/diagnostic overhead.
                                        document_timing = await document_navigation_timing(page)
                                        if document_timing:
                                            navigation_ms, document_start, document_end = document_timing
                                            navigation_policy_ms = navigation_policy_time_ms(document_start, document_end)
                                    log_event(
                                        logging.INFO, "AUTHENTICATION_OBSERVATION_COMPLETED",
                                        scan_id=scan_id, stage=auth_settle["stage"],
                                        hostname=auth_settle["final_host"],
                                        elapsed_ms=auth_settle["elapsed_ms"],
                                    )
                                    log_event(
                                        logging.INFO,
                                        "ROUTE_ACTIVATION_COMPLETED",
                                        scan_id=scan_id,
                                        current_route=active_route_id,
                                        activation_method=activation_method,
                                    )
                                    final_raw_url = dom_target.url
                                    final_url = sanitized_url(final_raw_url)
                                    if response is not None:
                                        await reconcile_http_redirect_chain(response, current_tracker)
                                    redirects = current_tracker.redirects()
                                    for redirect in redirects:
                                        log_event(logging.INFO, "REDIRECT_DETECTED", scan_id=scan_id, **redirect)
                                        if not redirect["same_origin"]:
                                            log_event(logging.INFO, "CROSS_ORIGIN_REDIRECT", scan_id=scan_id, **redirect)
                                    if response is not None:
                                        status = response.status
                                        response_headers = {
                                            name.lower(): value
                                            for name, value in (await response.all_headers()).items()
                                        }
                                        document_evidence[origin_for_url(final_raw_url)] = {
                                            "response_headers": response_headers.copy(),
                                            "strict_tls": urlparse(final_raw_url).scheme == "https",
                                        }
                                    else:
                                        evidence = document_evidence.get(origin_for_url(final_raw_url))
                                        if evidence is None:
                                            raise RuntimeError(
                                                "Same-document route has no validated document context"
                                            )
                                        response_headers = dict(evidence["response_headers"])
                                        inherited_strict_tls = bool(evidence["strict_tls"])
                                        security_headers_inherited = True
                                    if (
                                        url_in_scan_scope(
                                            final_raw_url,
                                            root_host,
                                            req.allow_subdomains,
                                            approved_portal_hosts,
                                        )
                                        and await acknowledge_configured_access_gate(
                                            page,
                                            read_only_policy,
                                            final_raw_url,
                                            acknowledged_access_gates,
                                            timeout_ms=max(1, round((route_deadline - time.perf_counter()) * 1000)),
                                        )
                                    ):
                                        final_raw_url = page.url
                                        final_url = sanitized_url(final_raw_url)
                                        log_event(
                                            logging.INFO,
                                            "ACCESS_GATE_ACKNOWLEDGED",
                                            scan_id=scan_id,
                                            hostname=normalized_host(
                                                urlparse(final_raw_url).hostname or ""
                                            ),
                                        )
                                    final_in_scope = url_in_scan_scope(
                                        final_raw_url,
                                        root_host,
                                        req.allow_subdomains,
                                        approved_portal_hosts,
                                    )
                                    if view_control and final_in_scope:
                                        observed_view_url = normalize_route_url(
                                            final_raw_url, query_policy=route_query_policy(),
                                            allowed_query_parameters=route_query_allowlist(),
                                        )
                                        if observed_view_url and observed_view_url != route_identity:
                                            view_navigation_aliases[observed_view_url] = route_key
                                    password_form, mfa_form = await detect_auth_signals(dom_target)
                                    authentication_classification = classify_authentication(
                                        authentication_mode=req.authentication.mode,
                                        status=status,
                                        final_url=final_raw_url,
                                        target_in_scope=final_in_scope,
                                        error_classification=None,
                                        password_form=password_form,
                                        mfa_form=mfa_form,
                                    )
                                    if auth_settle["timed_out"] and auth_settle["stage"] != "APPLICATION_BOOTSTRAP_PENDING":
                                        authentication_classification = "AUTH_TIMEOUT"
                                    if active_route_activation_id in authentication_denials:
                                        authentication_classification = "AUTHENTICATION_BLOCKED"
                                    if (
                                        application_gate_confirmed and status == 403 and final_in_scope
                                        and not password_form and not mfa_form
                                        and authentication_classification != "AUTHENTICATION_BLOCKED"
                                        and not auth_protocol_signal(final_raw_url, boundary_only=True)
                                    ):
                                        authentication_classification = "AUTHORIZATION_DENIED"
                                    log_event(
                                        logging.INFO,
                                        (
                                            "SPA_ROUTE_TRANSITIONED"
                                            if route_transition_succeeded
                                            else "DOCUMENT_NAVIGATION_COMPLETED"
                                        ),
                                        scan_id=scan_id,
                                        final_url=final_raw_url,
                                        hostname=normalized_host(urlparse(final_raw_url).hostname or ""),
                                        http_status=status,
                                        redirect_count=len(redirects),
                                        classification=authentication_classification,
                                        navigation_type=navigation_mode,
                                    )
                                    if authentication_classification != "PASS":
                                        log_event(
                                            logging.WARNING,
                                            authentication_classification,
                                            scan_id=scan_id,
                                            final_url=final_raw_url,
                                        )
                                    log_event(logging.INFO, "PAGE_VALIDATION_STARTED", scan_id=scan_id, final_url=final_raw_url)
                                    if authentication_classification == "PASS":
                                        # A stable scoped document plus absence of
                                        # login/MFA evidence establishes the session;
                                        # rendered application readiness is separate.
                                        browser_lifecycle.advance("SESSION_ESTABLISHED")
                                        browser_lifecycle.advance("APPLICATION_BOOTSTRAP")
                                    else:
                                        browser_lifecycle.fail(
                                            authentication_classification or "AUTHENTICATION_INCOMPLETE",
                                            stage="ROUTE_VALIDATION" if authentication_classification == "AUTHORIZATION_DENIED" else None,
                                        )
                                    render_start_ms = round((time.perf_counter() - started) * 1000)
                                    readiness_started = time.perf_counter()
                                    # At bootstrap a never-settling resource (pixel, long
                                    # poll) must not consume the whole route budget: keep
                                    # headroom so the scan-wide gate decides on observed
                                    # readiness instead of failing on a route timeout.
                                    route_budget_s = (req.per_route_timeout_ms or req.timeout_ms) / 1000
                                    gate_reserve_s = 0.0 if application_gate_confirmed else min(
                                        2.0, max(0.25, route_budget_s * 0.2),
                                    )
                                    readiness_deadline = max(readiness_started, min(
                                        route_deadline - gate_reserve_s,
                                        readiness_started + (req.readiness_timeout_ms or req.timeout_ms) / 1000,
                                    ))
                                    render_health = await wait_for_render_settle(
                                        dom_target,
                                        settle_ms=req.render_settle_ms,
                                        maximum_ms=max(0, round((readiness_deadline - time.perf_counter()) * 1000)),
                                        network_activity=route_activity_snapshot,
                                        minimum_observation_ms=req.min_observation_ms,
                                        network_quiet_ms=req.network_quiet_ms,
                                        readiness_selector=req.readiness_selector if dom_target == page else None,
                                        readiness_event=req.readiness_event if dom_target == page else None,
                                        view_control=view_control,
                                        network_settle_cap_ms=req.network_settle_cap_ms,
                                        # Only a newly loaded document after the
                                        # shell was proven may lack the shell marker.
                                        shell_marker_grace_ms=(
                                            req.shell_marker_grace_ms
                                            if application_gate_confirmed and dom_target == page and status is not None
                                            and (req.readiness_selector or req.readiness_event) else 0
                                        ),
                                    ) if authentication_classification == "PASS" else None
                                    if dom_target != page and render_health is not None and (req.readiness_selector or req.readiness_event):
                                        # The configured application-shell selector lives
                                        # in the parent; child views must additionally
                                        # satisfy their own visible render readiness.
                                        render_health["configured_readiness_met"] = False
                                        parent_readiness_ms = max(0, round((readiness_deadline - time.perf_counter()) * 1000))
                                        if parent_readiness_ms:
                                            try:
                                                render_health.update(await configured_readiness_conditions(
                                                    page, readiness_selector=req.readiness_selector,
                                                    readiness_event=req.readiness_event,
                                                    timeout_ms=parent_readiness_ms,
                                                    wait_until_met=True,
                                                ))
                                            except TimeoutError:
                                                # Exhausting a readiness observation does
                                                # not turn a completed view activation into
                                                # an invented document-navigation timeout.
                                                pass
                                    readiness_duration_ms += round((time.perf_counter() - readiness_started) * 1000)
                                    # Authentication observation precedes render settling.
                                    # A delayed client redirect/login must not be mistaken
                                    # for an authenticated application shell afterwards.
                                    if authentication_classification == "PASS":
                                        final_raw_url = dom_target.url
                                        final_url = sanitized_url(final_raw_url)
                                        final_in_scope = url_in_scan_scope(
                                            final_raw_url, root_host, req.allow_subdomains, approved_portal_hosts,
                                        )
                                        password_form, mfa_form = await detect_auth_signals(dom_target)
                                        authentication_classification = classify_authentication(
                                            authentication_mode=req.authentication.mode, status=status,
                                            final_url=final_raw_url, target_in_scope=final_in_scope,
                                            error_classification=None, password_form=password_form, mfa_form=mfa_form,
                                        )
                                    if active_route_activation_id in authentication_denials:
                                        authentication_classification = "AUTHENTICATION_BLOCKED"
                                    application_ready = bool(
                                        authentication_classification == "PASS" and final_in_scope
                                        and application_shell_ready(render_health)
                                    )
                                    if application_ready:
                                        browser_lifecycle.advance("APPLICATION_READY")
                                        # Bootstrap headings/titles may still describe a
                                        # loading surface immediately after navigation.
                                        # Name the rendered destination, not that placeholder.
                                        title = sanitize_text(
                                            await retry_dom_operation(dom_target, dom_target.title), limit=512,
                                        )
                                        name_evidence = await collect_route_name_evidence(dom_target)
                                    elif authentication_classification != "PASS":
                                        browser_lifecycle.fail(
                                            authentication_classification or "AUTHENTICATION_INCOMPLETE", stage="AUTHENTICATING",
                                        )
                                    else:
                                        browser_lifecycle.fail("APPLICATION_NOT_READY")
                                    log_event(
                                        logging.INFO if application_ready else logging.WARNING,
                                        "APPLICATION_SHELL_READY" if application_ready else "APPLICATION_SHELL_NOT_READY",
                                        scan_id=scan_id, hostname=normalized_host(urlparse(final_raw_url).hostname or ""),
                                        configured_readiness=bool(req.readiness_selector or req.readiness_event),
                                        authentication_status=authentication_classification,
                                    )
                                    rejected_session = rejected_session_response()
                                    if rejected_session is not None:
                                        reject_global_authentication(
                                            "SESSION_EXPIRED" if application_gate_confirmed or req.authentication.mode == "storage_state"
                                            else "AUTHENTICATION_FAILED",
                                            status=401, endpoint=rejected_session.get("url") or final_raw_url,
                                            method=rejected_session.get("method"),
                                            policy_decision=rejected_session.get("policy_decision"),
                                            duration_ms=round((time.perf_counter() - started) * 1000),
                                        )
                                    if not application_gate_confirmed:
                                        if not application_ready:
                                            reject_global_authentication(
                                                authentication_classification, status=status, endpoint=final_raw_url,
                                                stage="APPLICATION_BOOTSTRAP" if authentication_classification == "PASS" else "AUTHENTICATING",
                                                duration_ms=round((time.perf_counter() - started) * 1000),
                                            )
                                        await publish_progress("AUTHENTICATED")
                                        await publish_progress("APPLICATION_READY")
                                        application_gate_confirmed = True
                                        bootstrap_activation_id = active_route_activation_id
                                        discovered_routes.add(route_key)
                                        queued_routes.add(route_key)
                                        await publish_progress("DISCOVERING_ROUTES", discovered=len(discovered_routes), queued=len(queue))
                                    elif req.authentication.mode != "none" and authentication_classification in {
                                        "AUTH_REQUIRED", "AUTHENTICATION_REQUIRED", "AUTH_FAILED", "AUTH_TIMEOUT",
                                        "SESSION_EXPIRED", "MFA_REQUIRED",
                                    }:
                                        reject_global_authentication(
                                            authentication_classification, status=status, endpoint=final_raw_url,
                                            duration_ms=round((time.perf_counter() - started) * 1000),
                                        )
                                    if application_ready and navigation_mode == DOCUMENT_NAVIGATION:
                                        # Only alias an actually observed successful document
                                        # redirect, never infer that '/' and 'index.html' are
                                        # equivalent for every application.
                                        actual_document = normalize_route_url(
                                            final_raw_url, query_policy=route_query_policy(),
                                            allowed_query_parameters=route_query_allowlist(),
                                        )
                                        if actual_document and actual_document != route_identity:
                                            document_navigation_aliases[actual_document] = route_key
                                    log_event(
                                        logging.INFO,
                                        "ROUTE_SETTLE_COMPLETED",
                                        scan_id=scan_id,
                                        current_route=active_route_id,
                                        settle_reason=(render_health or {}).get("settle_reason"),
                                        settle_elapsed_ms=(render_health or {}).get("settle_elapsed_ms"),
                                        network_pending=(render_health or {}).get("network_pending"),
                                    )
                                    frame_observations = [
                                        {
                                            "url": sanitized_url(frame.url),
                                            "main_frame": frame == page.main_frame,
                                            "same_origin": origin_for_url(frame.url) == origin_for_url(final_raw_url),
                                            "observation": (
                                                "MAIN_DOCUMENT" if frame == page.main_frame else
                                                "SAME_ORIGIN_FRAME" if origin_for_url(frame.url) == origin_for_url(final_raw_url) else
                                                "CROSS_ORIGIN_FRAME_OBSERVED"
                                            ),
                                            "in_portal_scope": url_in_scan_scope(
                                                frame.url,
                                                root_host,
                                                req.allow_subdomains,
                                                approved_portal_hosts,
                                            ),
                                        }
                                        for frame in page.frames
                                        if frame.url.startswith(("http://", "https://"))
                                    ]
                                    if (
                                        req.check_links
                                        and final_in_scope
                                        and authentication_classification == "PASS"
                                        and application_ready
                                    ):
                                        observation_phase = "DISCOVERY"
                                        browser_lifecycle.advance("ROUTE_DISCOVERY")
                                        discovery_started = time.perf_counter()
                                        # Validation is complete; discovery gets its own
                                        # budget instead of the route's remaining time.
                                        route_deadline = min(deadline, discovery_started + (
                                            req.discovery_timeout_ms or req.navigation_timeout_ms or req.timeout_ms
                                        ) / 1000)
                                        route_scope.reschedule(route_deadline)
                                        await publish_progress(
                                            "DISCOVERING_ROUTES",
                                            discovered=len(discovered_routes),
                                            queued=len(queue),
                                            validated=len(results),
                                            current_route=active_route_id,
                                        )
                                        async def retain_panel_routes(routes):
                                            require_current_session()
                                            external_links[:] = sorted(set(external_links).union(
                                                enqueue_discovered_routes(routes, depth, final_raw_url),
                                            ))

                                        async def observe_discovery_panel(target=page):
                                            require_current_session()
                                            snapshot = await wait_for_render_settle(
                                                target,
                                                settle_ms=req.menu_settle_ms,
                                                maximum_ms=max(0, round((route_deadline - time.perf_counter()) * 1000)),
                                                network_activity=route_activity_snapshot,
                                                minimum_observation_ms=min(req.min_observation_ms, req.menu_settle_ms),
                                                network_quiet_ms=min(req.network_quiet_ms, req.menu_settle_ms),
                                                network_settle_cap_ms=req.network_settle_cap_ms,
                                            )
                                            require_current_session()
                                            return snapshot

                                        # A zero action budget forbids activation, not
                                        # observation or accounting of unvisited controls.
                                        navigation_actions = await expand_safe_navigation(
                                            page,
                                            req.max_navigation_actions,
                                            timeout_ms=max(1, min(
                                                req.navigation_timeout_ms or req.timeout_ms,
                                                round((route_deadline - time.perf_counter()) * 1000),
                                            )),
                                            wait_after_action=observe_discovery_panel,
                                            maximum_scrolls=req.max_discovery_scrolls,
                                            on_routes_discovered=retain_panel_routes,
                                            explored_controls=explored_navigation_controls,
                                        )
                                        safe_routes = list(navigation_actions.pop("routes", []))
                                        if navigation_actions["activated"]:
                                            log_event(
                                                logging.INFO,
                                                "NAVIGATION_MENU_EXPANDED",
                                                scan_id=scan_id,
                                                count=navigation_actions["activated"],
                                            )
                                        if navigation_actions["skipped"]:
                                            log_event(
                                                logging.INFO,
                                                "UNSAFE_CONTROL_SKIPPED",
                                                scan_id=scan_id,
                                                count=navigation_actions["skipped"],
                                            )
                                        discovered = safe_routes + await discover_page_routes(
                                            page,
                                            req.max_discovery_scrolls,
                                        )
                                        for frame in page.frames:
                                            if (frame == page.main_frame
                                                or origin_for_url(frame.url) != origin_for_url(final_raw_url)
                                                or not url_in_scan_scope(
                                                frame.url, root_host, req.allow_subdomains,
                                                approved_portal_hosts,
                                            )):
                                                continue
                                            try:
                                                frame_actions = await expand_safe_navigation(
                                                    frame,
                                                    max(0, req.max_navigation_actions - int(navigation_actions["activated"])),
                                                    timeout_ms=max(1, min(
                                                        req.navigation_timeout_ms or req.timeout_ms,
                                                        round((route_deadline - time.perf_counter()) * 1000),
                                                    )),
                                                    maximum_scrolls=req.max_discovery_scrolls,
                                                    wait_after_action=lambda target=frame: observe_discovery_panel(target),
                                                    on_routes_discovered=retain_panel_routes,
                                                    explored_controls=explored_navigation_controls,
                                                )
                                                frame_routes = list(frame_actions.pop("routes", []))
                                                for metric in ("activated", "skipped", "inspected", "remaining", "discovered", "unresolved", "view_controls", "menus_expanded"):
                                                    navigation_actions[metric] = int(navigation_actions.get(metric, 0)) + int(frame_actions.get(metric, 0))
                                                navigation_actions["limit_reached"] = bool(
                                                    navigation_actions.get("limit_reached") or frame_actions.get("limit_reached")
                                                )
                                            except PlaywrightError:
                                                # A detached frame must not discard routes already
                                                # discovered in healthy documents.
                                                log_event(logging.INFO, "FRAME_DISCOVERY_UNAVAILABLE", scan_id=scan_id)
                                                navigation_actions["unresolved"] = int(navigation_actions.get("unresolved", 0)) + 1
                                                continue
                                            discovered.extend(frame_routes)
                                        # A popup may finish after a route's early
                                        # collection window. Retain every observed
                                        # page; ordinary route deduplication applies.
                                        if popup_tasks:
                                            _, pending_popups = await asyncio.wait(
                                                tuple(popup_tasks), timeout=max(0, route_deadline - time.perf_counter()),
                                            )
                                            if pending_popups:
                                                navigation_actions["unresolved"] = int(navigation_actions.get("unresolved", 0)) + len(pending_popups)
                                        discovered.extend(popup_routes)
                                        new_popup_failures = popup_observation_failures - accounted_popup_observation_failures
                                        accounted_popup_observation_failures = popup_observation_failures
                                        navigation_actions["popup_observation_failures"] = new_popup_failures
                                        navigation_actions["unresolved"] = int(navigation_actions.get("unresolved", 0)) + new_popup_failures
                                        unique_discovered: dict[str, DiscoveredRoute] = {}
                                        for route in discovered:
                                            identity = normalize_route_url(
                                                route.url,
                                                query_policy=route_query_policy(),
                                                allowed_query_parameters=route_query_allowlist(),
                                            )
                                            if identity is not None:
                                                key = discovered_route_key(route, identity)
                                                existing = unique_discovered.get(key)
                                                if (existing is None or (not existing.label and route.label)
                                                        or len(route.navigation_hierarchy) > len(existing.navigation_hierarchy)):
                                                    unique_discovered[key] = route
                                        discovered = list(unique_discovered.values())
                                        download_routes = [
                                            route for route in discovered
                                            if route.navigation_mode == DOWNLOAD_OBSERVED
                                        ]
                                        navigation_actions["downloads_observed"] = len(download_routes)
                                        if final_in_scope:
                                            external_links[:] = sorted(set(external_links).union(
                                                enqueue_discovered_routes(discovered, depth, final_raw_url),
                                            ))
                                        route_discovery_ms = round(
                                            (time.perf_counter() - discovery_started) * 1000
                                        )
                                        discovery_duration_ms += route_discovery_ms
                                        observation_phase = "ROUTE_VALIDATION"
                            except _AuthenticationGateFailure:
                                raise
                            except Exception as exc:
                                if isinstance(exc, TimeoutError) and observation_phase == "DISCOVERY":
                                    browser_lifecycle.fail("DISCOVERY_TIMEOUT")
                                    # The document already loaded. Exhausting a
                                    # menu's observation budget is incomplete
                                    # discovery, not a main-document load failure.
                                    # Earlier panel observations are already queued.
                                    navigation_actions["timed_out"] = True
                                    route_discovery_ms = round((time.perf_counter() - discovery_started) * 1000)
                                    discovery_duration_ms += route_discovery_ms
                                    observation_phase = "ROUTE_VALIDATION"
                                    log_event(logging.WARNING, "ROUTE_DISCOVERY_TIMEOUT", scan_id=scan_id,
                                              current_route=active_route_id, queued=len(queue))
                                elif isinstance(exc, PlaywrightError) and observation_phase == "DISCOVERY":
                                    browser_lifecycle.fail("DISCOVERY_FAILED")
                                    # The document loaded successfully. A persistent
                                    # browser/DOM discovery failure must be visible,
                                    # not silently healthy or a fabricated load failure.
                                    navigation_actions["error"] = sanitized_diagnostic(str(exc))
                                    navigation_actions["unresolved"] = int(navigation_actions.get("unresolved", 0)) + 1
                                    route_discovery_ms = round((time.perf_counter() - discovery_started) * 1000)
                                    discovery_duration_ms += route_discovery_ms
                                    observation_phase = "ROUTE_VALIDATION"
                                    log_event(logging.ERROR, "ROUTE_DISCOVERY_FAILED", scan_id=scan_id,
                                              current_route=active_route_id, error=navigation_actions["error"])
                                else:
                                    if isinstance(exc, TimeoutError):
                                        error = "Configured maximum time per route exceeded"
                                        error_classification = "TIMEOUT"
                                    elif navigation_policy_error is not None:
                                        error = navigation_policy_error.public_message
                                        error_classification = navigation_policy_error.classification
                                    else:
                                        error = sanitized_diagnostic(str(exc))
                                        error_classification = classify_navigation_error(error)
                                    final_raw_url = page.url if page.url.startswith(("http://", "https://")) else url
                                    final_url = sanitized_url(final_raw_url)
                                    redirects = current_tracker.redirects()
                                    authentication_classification = classify_authentication(
                                        authentication_mode=req.authentication.mode,
                                        status=status,
                                        final_url=final_raw_url,
                                        target_in_scope=url_in_scan_scope(
                                            final_raw_url,
                                            root_host,
                                            req.allow_subdomains,
                                            approved_portal_hosts,
                                        ),
                                        error_classification=error_classification,
                                    )
                                    if active_route_activation_id in authentication_denials:
                                        authentication_classification = "AUTHENTICATION_BLOCKED"
                                        # The route's own sign-in handshake was blocked; that is
                                        # the cause, not a generic navigation failure.
                                        blocked = next((
                                            item for item in reversed(authentication_diagnostics)
                                            if item.get("route_activation_id") == active_route_activation_id
                                            and item.get("affects_authentication")
                                        ), {})
                                        error_classification = "AUTHENTICATION_BLOCKED"
                                        error = (
                                            "The route's sign-in request to "
                                            f"{blocked.get('destination_host') or 'its identity provider'} was blocked "
                                            f"({blocked.get('reason') or 'AUTHENTICATION_POLICY_BLOCKED'}). "
                                            "Add the identity provider host to Authentication hosts to validate this route."
                                        )
                                    browser_lifecycle.fail(
                                        authentication_classification
                                        if authentication_classification not in {None, "PASS"}
                                        else error_classification or "NAVIGATION_ERROR",
                                    )
                                    log_event(
                                        logging.ERROR,
                                        error_classification,
                                        scan_id=scan_id,
                                        requested_url=url,
                                        final_url=final_raw_url,
                                        error=error,
                                    )

                        # Discovery may itself reveal a delayed sign-in exchange.
                        # Reconcile that evidence before classifying this route.
                        require_current_session()
                        if active_route_activation_id in authentication_denials:
                            authentication_classification = "AUTHENTICATION_BLOCKED"
                            application_ready = False
                            browser_lifecycle.fail("AUTHENTICATION_BLOCKED", stage="AUTHENTICATING")
                        if (
                            authentication_classification == "AUTH_REQUIRED"
                            and req.authentication.mode != "none"
                            and any(item.get("authentication_status") == "PASS" for item in results)
                        ):
                            authentication_classification = "SESSION_EXPIRED"
                        if authentication_classification == "SESSION_EXPIRED":
                            session_expired = True
                            log_event(
                                logging.WARNING,
                                "SESSION_EXPIRED",
                                scan_id=scan_id,
                                hostname=normalized_host(urlparse(final_raw_url).hostname or ""),
                            )

                        if not application_gate_confirmed or req.authentication.mode != "none" and authentication_classification in {
                            "AUTH_REQUIRED", "AUTHENTICATION_REQUIRED", "AUTH_FAILED", "AUTH_TIMEOUT",
                            "SESSION_EXPIRED", "MFA_REQUIRED",
                        }:
                            reject_global_authentication(
                                authentication_classification or error_classification,
                                status=status, endpoint=final_raw_url,
                                stage="APPLICATION_BOOTSTRAP" if authentication_classification == "PASS" else "AUTHENTICATING",
                                duration_ms=round((time.perf_counter() - started) * 1000),
                            )

                        health_validation_started = time.perf_counter()
                        await publish_progress("VALIDATING_ROUTES", discovered=len(discovered_routes), validated=len(results))
                        if browser_lifecycle.failed_stage is None:
                            browser_lifecycle.advance("ROUTE_VALIDATION")
                        elapsed = round((time.perf_counter() - started) * 1000)
                        route_validation_ms = max(0, elapsed - route_discovery_ms)
                        performance_timing = route_performance_timing(
                            navigation_ms=navigation_ms,
                            navigation_policy_ms=navigation_policy_ms,
                            render_health=render_health,
                            total_validation_ms=route_validation_ms,
                            render_start_ms=render_start_ms,
                        )
                        page_console = list(dict.fromkeys(
                            event["message"] for event in console_errors
                            if event.get("route_activation_id") == active_route_activation_id
                        )) if req.check_console else []
                        page_script_errors = list(dict.fromkeys(
                            event["message"] for event in page_errors
                            if event.get("route_activation_id") == active_route_activation_id
                        )) if req.check_console else []
                        page_failures = [
                            failure for failure in failed_resources
                            if failure.get("route_activation_id") == active_route_activation_id
                        ] if req.check_resources else []
                        page_api_events = [
                            event for event in api_events
                            if event.get("route_activation_id") == active_route_activation_id
                        ]
                        page_resource_events = [
                            event for event in resource_events
                            if event.get("route_activation_id") == active_route_activation_id
                        ] if req.check_resources else []
                        if render_health is not None and req.check_resources and time.perf_counter() < route_deadline:
                            timing_budget = asyncio.timeout_at(route_deadline)
                            try:
                                async with timing_budget:
                                    await enrich_resource_timings(page, page_resource_events + page_api_events)
                            except TimeoutError:
                                if not timing_budget.expired():
                                    raise
                                # Optional size diagnostics cannot extend a route's
                                # work budget or invent a main-document failure.
                                log_event(logging.INFO, "RESOURCE_TIMING_BUDGET_EXHAUSTED", scan_id=scan_id)
                        page_resource_details, _ = build_resource_report(
                            page_resource_events + page_api_events,
                            large_resource_threshold_bytes=req.large_resource_threshold_bytes,
                            large_image_threshold_bytes=req.large_image_threshold_bytes,
                            large_js_threshold_bytes=req.large_js_threshold_bytes,
                            large_css_font_threshold_bytes=req.large_css_font_threshold_bytes,
                        )
                        page_websockets = websocket_events[websocket_start:] if req.check_resources else []
                        page_event_streams = event_streams[event_stream_start:] if req.check_resources else []
                        page_downloads = download_events[download_start:]
                        page_frame_events = [event for event in frame_events if event.get("route_activation_id") == active_route_activation_id]
                        subresource_failures = sum(not failure["main_document"] for failure in page_failures)
                        unexpected_subresource_failures = sum(
                            not failure["main_document"] and not failure.get("blocked_by_validator")
                            for failure in page_failures
                        )
                        if unexpected_subresource_failures:
                            log_event(
                                logging.WARNING,
                                "SUBRESOURCE_FAILURES",
                                scan_id=scan_id,
                                hostname=requested_host,
                                count=unexpected_subresource_failures,
                            )
                        validator_skips = subresource_failures - unexpected_subresource_failures
                        if validator_skips:
                            log_event(
                                logging.INFO,
                                "VALIDATOR_RESOURCE_SKIPS",
                                scan_id=scan_id,
                                hostname=requested_host,
                                count=validator_skips,
                            )
                        header_names = SECURITY_HEADERS
                        if urlparse(final_url or requested_url).scheme != "https":
                            header_names = tuple(name for name in SECURITY_HEADERS if name != "strict-transport-security")
                        security_headers_tested = bool(
                            req.check_security_headers
                            and (status is not None or security_headers_inherited)
                        )
                        header_report = {
                            name: response_headers.get(name) for name in header_names
                        } if security_headers_tested else {}
                        missing_headers = [name for name, value in header_report.items() if not value]
                        render_classification: str | None = None
                        health_findings: list[dict] = []
                        if render_health is not None:
                            render_classification, health_findings = assess_page_health(
                                render_health,
                                load_ms=int(performance_timing["application_load_ms"]),
                                slow_page_threshold_ms=req.slow_page_threshold_ms,
                                performance_enabled=req.check_performance,
                            )
                            if not configured_readiness_satisfied(render_health):
                                health_findings.append(finding(
                                    "READINESS_NOT_REACHED", "ERROR",
                                    "The configured readiness selector or event was not reached within its budget.",
                                    blocking=True,
                                ))
                            elif not application_ready and authentication_classification == "PASS":
                                health_findings.append(finding(
                                    "APPLICATION_VIEW_NOT_READY", "ERROR",
                                    "The application view did not reach observable rendered readiness; navigation discovery was not performed.",
                                    blocking=True,
                                ))
                        health_findings.extend(api_health_findings([
                            event for event in page_api_events
                            if not event.get("blocked_by_validator")
                        ]))
                        health_findings.extend(realtime_health_findings(
                            page_websockets,
                            page_event_streams,
                        ))
                        health_findings.extend(large_resource_findings(page_resource_details))
                        if navigation_actions.get("skipped", 0):
                            limitation = finding(
                                "DISCOVERED_BUT_NOT_SAFELY_ACTIVATABLE",
                                "INFO",
                                "Navigation-like controls were not activated because they could not be proven safe.",
                            )
                            limitation["count"] = int(navigation_actions["skipped"])
                            health_findings.append(limitation)
                        if navigation_actions.get("timed_out"):
                            health_findings.append(finding(
                                "DISCOVERY_TIMEOUT", "WARNING",
                                "Navigation discovery reached the configured route budget; earlier observed routes were retained.",
                            ))
                        if navigation_actions.get("error"):
                            health_findings.append(finding(
                                "DISCOVERY_FAILED", "WARNING",
                                "Navigation discovery failed after bounded browser-context recovery; coverage is incomplete.",
                                reason=navigation_actions["error"],
                            ))
                        if navigation_actions.get("remaining", 0):
                            limitation = finding(
                                "NAVIGATION_ACTION_LIMIT", "WARNING",
                                "Visible navigation controls remain unexplored within the configured action budget.",
                            )
                            limitation["count"] = int(navigation_actions["remaining"])
                            health_findings.append(limitation)
                        if navigation_actions.get("downloads_observed", 0) or page_downloads:
                            observed_download = finding(
                                "DOWNLOAD_OBSERVED",
                                "INFO",
                                "A download destination was observed and was not opened or processed.",
                            )
                            observed_download["count"] = (
                                int(navigation_actions.get("downloads_observed", 0))
                                + len(page_downloads)
                            )
                            health_findings.append(observed_download)
                        cross_origin_frames = sum(
                            observation.get("observation") == "CROSS_ORIGIN_FRAME_OBSERVED"
                            for observation in frame_observations
                        )
                        if cross_origin_frames:
                            frame_finding = finding(
                                "CROSS_ORIGIN_FRAME_OBSERVED",
                                "INFO",
                                "A cross-origin frame loaded; its document is reported separately from portal crawl scope.",
                            )
                            frame_finding["count"] = cross_origin_frames
                            health_findings.append(frame_finding)
                        classification = classify_page_result(
                            url=final_url or requested_url,
                            status=status,
                            error=error,
                            missing_security_headers=missing_headers,
                            console_errors=page_console,
                            page_errors=page_script_errors,
                            failed_resources=page_failures,
                            security_headers_tested=security_headers_tested,
                            authentication_classification=authentication_classification or error_classification,
                            render_classification=render_classification,
                            additional_findings=health_findings,
                            route_transition_succeeded=route_transition_succeeded,
                            navigation_mode=navigation_mode,
                            inherited_strict_tls=inherited_strict_tls,
                            security_headers_inherited=security_headers_inherited,
                            include_security_header_findings=not security_headers_inherited,
                        )
                        api_failure_count = sum(
                            bool(event.get("error"))
                            or (isinstance(event.get("status"), int) and event["status"] >= 400)
                            for event in page_api_events
                            if not event.get("blocked_by_validator")
                        )
                        failed_api_events = [
                            event for event in page_api_events
                            if not event.get("blocked_by_validator") and (
                                bool(event.get("error"))
                                or (isinstance(event.get("status"), int) and event["status"] >= 400)
                            )
                        ]
                        failed_required_api_count = sum(
                            event.get("importance") == "REQUIRED" for event in failed_api_events
                        )
                        failed_optional_api_count = len(failed_api_events) - failed_required_api_count
                        api_network_failure_count = sum(
                            bool(event.get("error")) for event in failed_api_events
                        )
                        read_only_blocks = sum(
                            bool(event.get("blocked_by_validator"))
                            and event.get("block_reason") == "READ_ONLY_MUTATION_BLOCKED"
                            for event in page_api_events
                        )
                        api_coverage = summarize_route_api_coverage(page_api_events)
                        final_identity = normalize_route_url(
                            final_raw_url,
                            query_policy=route_query_policy(),
                            allowed_query_parameters=route_query_allowlist(),
                        ) or route_identity
                        identity = route_identity_fields(
                            final_identity,
                            query_policy=route_query_policy(),
                            allowed_query_parameters=route_query_allowlist(),
                        )
                        requested_identity = route_identity_fields(
                            route_identity,
                            query_policy=route_query_policy(),
                            allowed_query_parameters=route_query_allowlist(),
                        )
                        display_url = sanitized_url(final_identity)
                        route_name, route_name_source, route_name_confidence = resolve_route_name(
                            navigation_label=route_label,
                            accessible_name=route_accessible_name,
                            primary_heading=name_evidence.get("primary_heading"),
                            breadcrumb=name_evidence.get("breadcrumb"),
                            metadata_name=None,
                            document_title=title,
                            display_path=identity["display_path"],
                        )
                        route_name_by_id[active_route_id] = route_name
                        navigation_hierarchy: list[str] = []
                        hierarchy_cursor = parent_route_id
                        hierarchy_seen: set[str] = set()
                        while hierarchy_cursor and hierarchy_cursor not in hierarchy_seen:
                            hierarchy_seen.add(hierarchy_cursor)
                            navigation_hierarchy.insert(
                                0,
                                route_name_by_id.get(hierarchy_cursor, hierarchy_cursor),
                            )
                            hierarchy_cursor = route_parent_ids.get(hierarchy_cursor)
                        menu_hierarchy = route_metadata.get(route_key, {}).get("navigation_hierarchy", [])
                        for menu_label in menu_hierarchy:
                            if not navigation_hierarchy or navigation_hierarchy[-1] != menu_label:
                                navigation_hierarchy.append(menu_label)
                        navigation_hierarchy.append(route_name)
                        provenance = route_provenance.get(route_key, {"observations": 1, "sources": []})
                        health_validation_ms = round((time.perf_counter() - health_validation_started) * 1000)
                        route_validation_ms = max(0, round((time.perf_counter() - started) * 1000) - route_discovery_ms)
                        performance_timing = route_performance_timing(
                            navigation_ms=navigation_ms,
                            navigation_policy_ms=navigation_policy_ms,
                            render_health=render_health,
                            total_validation_ms=route_validation_ms,
                            render_start_ms=render_start_ms,
                        )
                        performance_timing["route_transition_ms"] = navigation_ms if route_transition_succeeded else 0
                        performance_timing["health_validation_ms"] = health_validation_ms
                        performance_timing["discovery_ms"] = route_discovery_ms
                        validation_duration_ms += route_validation_ms
                        browser_lifecycle.advance("REPORT")
                        result = {
                            "route_id": active_route_id,
                            "view_type": "UI_TAB" if view_control else "URL_ROUTE",
                            "route_activation_id": active_route_activation_id,
                            "url": display_url,
                            "requested_url": requested_url,
                            "discovered_url": sanitized_url(route_identity),
                            "final_url": final_url,
                            "origin": identity["origin"],
                            "host": identity["host"],
                            "hostname": identity["host"],
                            "pathname": identity["pathname"],
                            "query_sanitized": identity["query_sanitized"],
                            "search": identity["query_sanitized"],
                            "fragment": identity["fragment"],
                            "hash": identity["fragment"],
                            "spa_route": identity["spa_route"],
                            "canonical_route": requested_identity["canonical_route"],
                            "display_path": identity["display_path"],
                            "route_display_path": identity["display_path"],
                            "depth": depth,
                            "crawl_depth": depth,
                            "navigation_depth": depth,
                            "route_label": route_label,
                            "navigation_label": route_label,
                            "accessible_name": route_accessible_name,
                            "route_label_source": route_label_source,
                            "route_name": route_name,
                            "route_name_source": route_name_source,
                            "route_name_confidence": route_name_confidence,
                            "document_title": title,
                            "route_source": route_source,
                            "discovery_type": discovery_type,
                            "discovery_sources": provenance.get("sources", []),
                            "duplicate_discovery_count": max(
                                0, int(provenance.get("observations", 1)) - 1
                            ),
                            "discovered_from": sanitized_url(discovered_from) if discovered_from else None,
                            "parent_route_id": parent_route_id,
                            "parent_route_name": menu_hierarchy[-1] if menu_hierarchy else route_name_by_id.get(parent_route_id) if parent_route_id else None,
                            "navigation_hierarchy": navigation_hierarchy,
                            "expected_origin": sanitized_url(url, include_path=False),
                            "normalized_route_identity": active_route_id,
                            "navigation_type": navigation_mode,
                            "status": status,
                            "same_document_transition": route_transition_succeeded,
                            "http_status_display": "N/A (UI view)" if view_control else "N/A (SPA)" if route_transition_succeeded else status,
                            "title": title,
                            "load_ms": performance_timing["application_load_ms"] if req.check_performance else None,
                            **performance_timing,
                            "timings": dict(performance_timing),
                            "error": error,
                            "redirect_count": len(redirects),
                            "redirects": redirects,
                            "links_found": len(links),
                            "routes_discovered": len(discovered),
                            "external_links_found": len(external_links),
                            "external_links": external_links[:100],
                            "console_errors": page_console,
                            "page_errors": page_script_errors,
                            "failed_resources": page_failures,
                            "resource_failure_count": unexpected_subresource_failures,
                            "api_requests": page_api_events,
                            "api_failures": api_failure_count,
                            "failed_api_count": api_failure_count,
                            "failed_required_api_count": failed_required_api_count,
                            "failed_optional_api_count": failed_optional_api_count,
                            "api_network_failure_count": api_network_failure_count,
                            **api_coverage,
                            "route_render_coverage": (
                                "ROUTE_RENDERED" if render_health is not None else "NOT_RENDERED"
                            ),
                            "resources": page_resource_events,
                            "websockets": page_websockets,
                            "event_streams": page_event_streams,
                            "downloads": page_downloads,
                            "frames": frame_observations,
                            "frame_navigations": page_frame_events,
                            "render_health": render_health,
                            "application_ready": application_ready,
                            "application_readiness": (
                                "LINKED_DOCUMENT" if application_ready and render_health.get("configured_readiness_applicable") is False
                                else "READY" if application_ready else "NOT_TESTED" if render_health is None
                                else "CONFIGURED_CONDITION_NOT_REACHED" if not configured_readiness_satisfied(render_health)
                                else "RENDER_NOT_READY"
                            ),
                            "authentication_observation": auth_settle,
                            "authentication_diagnostics": [
                                item for item in authentication_diagnostics
                                if item.get("route_activation_id") == active_route_activation_id
                            ],
                            "browser_lifecycle": browser_lifecycle.snapshot(),
                            "failed_lifecycle_stage": browser_lifecycle.failed_stage,
                            "lifecycle_failure_reason": browser_lifecycle.failure_reason,
                            "slow": req.check_performance and int(performance_timing["application_load_ms"]) > req.slow_page_threshold_ms,
                            "discovery_ms": route_discovery_ms,
                            "validation_ms": route_validation_ms,
                            "navigation_actions": navigation_actions,
                            "navigation_controls_discovered": int(navigation_actions.get("discovered", navigation_actions.get("inspected", 0))),
                            "navigation_controls_activated": int(navigation_actions.get("activated", 0)),
                            "navigation_controls_unresolved": (
                                int(navigation_actions.get("unresolved", navigation_actions.get("skipped", 0)))
                                + int(bool(navigation_actions.get("timed_out")))
                            ),
                            "unsafe_actions_skipped": navigation_actions["skipped"],
                            "discovery_limitations": (
                                int(navigation_actions.get("unresolved", navigation_actions.get("skipped", 0)))
                                + int(bool(navigation_actions.get("timed_out")))
                            ),
                            "read_only_blocks": read_only_blocks,
                            "security_headers": header_report,
                            "missing_security_headers": missing_headers,
                            **classification,
                        }
                        results.append(result)
                        active_route_identity = None
                        await publish_progress(
                            "VALIDATING_ROUTES",
                            discovered=len(discovered_routes),
                            queued=len(queue),
                            validated=len(results),
                            healthy=sum(bool(item.get("passed")) for item in results),
                            failed=sum(
                                item.get("validation_status") == "FAIL"
                                or item.get("page_load_status") == "FAILED_TO_LOAD"
                                for item in results
                            ),
                            warnings=sum(
                                item.get("classification") == "PASS_WITH_WARNINGS"
                                for item in results
                            ),
                            current_route=active_route_id,
                        )
                        log_event(
                            logging.INFO,
                            (
                                "ROUTE_VALIDATED" if result["page_load_status"] == "LOADED" else
                                "ROUTE_SKIPPED" if result["page_load_status"] == "NOT_TESTED" else
                                "ROUTE_FAILED"
                            ),
                            scan_id=scan_id,
                            final_url=final_raw_url,
                            classification=result["classification"],
                            elapsed_ms=elapsed,
                        )
                        # A blocked authentication request on a later route affects
                        # that route only; bootstrap blocks fail through the gate.
                        # On a public scan a login-required page is one route's result.
                        if (session_expired or req.authentication.mode != "none" and authentication_classification in {
                            "AUTHENTICATION_REQUIRED", "AUTH_REQUIRED",
                            "AUTH_FAILED", "AUTH_TIMEOUT", "MFA_REQUIRED",
                        } or (len(results) == 1 and not application_ready)):
                            discovery_stop_reason = (
                                "SESSION_EXPIRED" if session_expired else
                                authentication_classification if authentication_classification not in {None, "PASS"} else
                                browser_lifecycle.failure_reason or error_classification or "APPLICATION_NOT_READY"
                            )
                            break
                        if not queue and popup_tasks and req.check_links:
                            _, pending_popups = await asyncio.wait(
                                tuple(popup_tasks), timeout=max(0, min(
                                    (req.authentication_timeout_ms or req.timeout_ms) / 1000,
                                    deadline - time.perf_counter(),
                                )),
                            )
                            enqueue_discovered_routes(popup_routes, depth, final_raw_url)
                            if pending_popups:
                                navigation_actions["unresolved"] = int(navigation_actions.get("unresolved", 0)) + len(pending_popups)
                                navigation_actions["popup_observation_pending"] = len(pending_popups)
                                result["navigation_controls_unresolved"] += len(pending_popups)
                                result["discovery_limitations"] += len(pending_popups)
                        if time.perf_counter() >= deadline:
                            total_timeout_reached = bool(queue)
                            break
                    except _SessionExpiredDuringScan:
                        # The route was interrupted by session loss; it is retried
                        # after recovery or reported as not tested, never as health.
                        seen.discard(route_key)
                        if await recover_expired_session():
                            queue.appendleft(current_queue_entry)
                            continue
                        session_expired = True
                        break
                if (
                    req.authentication.mode == "storage_state"
                    and req.authentication.storage_profile
                    and any(result.get("passed") for result in results)
                ):
                    updated_state = await runtime_session_store.persist(
                        req.authentication.storage_profile,
                        context,
                        expected_mtime_ns=state_generation,
                        approved_hosts=storage_hosts,
                    )
                    session_refresh["runtime_state_updated"] = updated_state is not None
                    session_refresh["concurrent_update_preserved"] = updated_state is None
                network_drain = await drain_pending_api_observations(
                    network_observer,
                    maximum_ms=max(0, min(
                        req.api_timeout_ms or req.readiness_timeout_ms or req.timeout_ms,
                        round((deadline - time.perf_counter()) * 1000),
                    )),
                    quiet_ms=req.network_quiet_ms,
                    cancel_event=cancel_event,
                )
                if network_drain["cancelled"]:
                    cancellation_requested = True
                log_event(logging.INFO, "NETWORK_OBSERVATION_DRAIN_COMPLETED",
                          scan_id=scan_id, **network_drain)
                # Pages created by a late background response must not be
                # cancelled by teardown and then silently called full coverage.
                # This bounded final window records real unvisited destinations;
                # it does not extend the scan or replay their requests.
                pending_popups = set()
                if popup_tasks:
                    _, pending_popups = await asyncio.wait(
                        tuple(popup_tasks), timeout=max(0, min(
                            (req.authentication_timeout_ms or req.timeout_ms) / 1000,
                            deadline - time.perf_counter(),
                        )),
                    )
                before_late_routes = len(discovered_routes)
                if req.check_links and results:
                    enqueue_discovered_routes(popup_routes, depth, final_raw_url)
                late_count = len(discovered_routes) - before_late_routes
                new_popup_failures = popup_observation_failures - accounted_popup_observation_failures
                if pending_popups or late_count or new_popup_failures:
                    late_navigation_observed = True
                    if results:
                        missing = len(pending_popups) + late_count + new_popup_failures
                        results[-1]["navigation_controls_unresolved"] += missing
                        results[-1]["discovery_limitations"] += missing
                        results[-1]["navigation_actions"]["late_popup_observations"] = missing
                        results[-1]["navigation_actions"]["popup_observation_failures"] = (
                            int(results[-1]["navigation_actions"].get("popup_observation_failures", 0)) + new_popup_failures
                        )
                # Freeze before closing: context.close() aborts outstanding
                # requests, which is not evidence of a target-side failure.
                finalize_resource_observations()
                network_observer.finalize_pending()
                await context.close()
            finally:
                if network_observer is not None:
                    finalize_resource_observations()
                    network_observer.finalize_pending()
                await browser.close()
                if network_observation_started is not None:
                    network_observation_duration_ms = round(
                        (time.perf_counter() - network_observation_started) * 1000
                    )
                for task in tuple(guard_install_tasks.values()):
                    if not task.done():
                        task.cancel()
                if guard_install_tasks:
                    await asyncio.gather(*tuple(guard_install_tasks.values()), return_exceptions=True)
                for guard in redirect_guards:
                    await guard.close()

    if authentication_error is None and scan_blocking_denials():
        evidence = scan_blocking_denials()[-1]
        authentication_error = create_authentication_error(
            "AUTHENTICATION_BLOCKED", stage="AUTHENTICATING", method=evidence.get("method"),
            endpoint=evidence.get("endpoint"), policy_decision=evidence.get("policy_decision") or evidence.get("policy_reason"),
            duration_ms=round((time.perf_counter() - scan_started) * 1000),
        )
    if authentication_error is None and not application_gate_confirmed and not cancellation_requested:
        authentication_error = create_authentication_error(
            "AUTHENTICATION_TIMEOUT" if total_timeout_reached or preflight_timeout_reached else "APPLICATION_NOT_READY",
            stage="AUTHENTICATING", endpoint=requested_target,
            duration_ms=round((time.perf_counter() - scan_started) * 1000),
        )
    rejected_session = rejected_session_response()
    if authentication_error is None and rejected_session is not None:
        authentication_error = create_authentication_error(
            "SESSION_EXPIRED" if application_gate_confirmed or req.authentication.mode == "storage_state"
            else "AUTHENTICATION_FAILED",
            stage="AUTHENTICATING", http_status=401, method=rejected_session.get("method"),
            endpoint=rejected_session.get("url"), policy_decision=rejected_session.get("policy_decision"),
            duration_ms=round((time.perf_counter() - scan_started) * 1000),
        )
    if (
        authentication_error is not None and application_gate_confirmed
        and authentication_error["category"] not in POLICY_AUTHENTICATION_FAILURES
        and any(result.get("authentication_status") == "PASS" for result in results)
    ):
        # The session was lost after the application was ready and could not
        # be recovered. Routes validated while it was valid remain accurate;
        # the rest are NOT_TESTED_SESSION_EXPIRED, never silently dropped.
        session_interruption = session_interruption or authentication_error
        session_expired = True
        authentication_error = None
        log_event(logging.WARNING, "SCAN_STOPPED_SESSION_EXPIRED", scan_id=scan_id,
                  validated_routes=len(results), category=session_interruption.get("category"))
    if authentication_error is not None:
        return await failed_authentication_report(authentication_error, authentication_request_diagnostics())

    await publish_progress(
        "FINALIZING",
        discovered=len(discovered_routes),
        queued=len(queue),
        validated=len(results),
        current_route=None,
    )
    finalization_started = time.perf_counter()
    for result in results:
        result["authentication_diagnostics"] = [
            item for item in authentication_diagnostics
            if item.get("route_activation_id") == result.get("route_activation_id")
        ]
        if (
            any(item["affects_authentication"] for item in result["authentication_diagnostics"])
            and result.get("authentication_status") == "PASS"
        ):
            # A late protocol denial belongs to its initiating activation even
            # after the page snapshot. Final drain evidence cannot leave an
            # anonymous shell counted as authenticated application coverage.
            result["authentication_status"] = "AUTHENTICATION_BLOCKED"
            result["application_ready"] = False
            if result.get("classification") in {"PASS", "PASS_WITH_WARNINGS"}:
                result["classification"] = "AUTHENTICATION_BLOCKED"
                result["render_status"] = "NOT_TESTED"
                result["failed_lifecycle_stage"] = "AUTHENTICATING"
                result["lifecycle_failure_reason"] = "AUTHENTICATION_BLOCKED"
                result["browser_lifecycle"].update({
                    "failed_stage": "AUTHENTICATING", "failure_reason": "AUTHENTICATION_BLOCKED",
                })
                result["finding_details"].append(finding(
                    "AUTHENTICATION_BLOCKED", "INFO",
                    "A required authentication request was blocked during browser observation. "
                    "Review the authentication diagnostics before evaluating protected application coverage.",
                    user_action_required=True,
                ))
        # Continuous observation can complete a request after its initiating
        # route snapshot. Reconcile that route, never the currently active one.
        route_events = [event for event in scan_api_events
                        if event.get("route_activation_id") == result.get("route_activation_id")]
        if req.check_resources:
            result["resources"] = [event for event in scan_resource_events
                                   if event.get("route_activation_id") == result.get("route_activation_id")]
        result.update(refresh_route_api_health(
            result, route_events,
            resource_failures=[failure for failure in failed_resources
                               if failure.get("route_activation_id") == result.get("route_activation_id")]
            if req.check_resources else None,
            console_errors=list(dict.fromkeys(
                event["message"] for event in console_errors
                if event.get("route_activation_id") == result.get("route_activation_id")
            )) if req.check_console else None,
            page_errors=list(dict.fromkeys(
                event["message"] for event in page_errors
                if event.get("route_activation_id") == result.get("route_activation_id")
            )) if req.check_console else None,
        ))
        result["frame_navigations"] = [event for event in frame_events
                                       if event.get("route_activation_id") == result.get("route_activation_id")]
        canonical = str(result.get("route_id") or result.get("canonical_route") or "")
        provenance = route_provenance.get(canonical)
        if provenance:
            result["discovery_sources"] = provenance.get("sources", [])
            result["duplicate_discovery_count"] = max(
                0, int(provenance.get("observations", 1)) - 1
            )
    finalize_duplicate_route_names(results)
    remaining_routes = (discovered_routes - seen) - depth_limited_routes - action_limited_routes
    if cancellation_requested:
        termination_reason = "USER_CANCELLED"
    elif session_expired:
        termination_reason = "SESSION_EXPIRED"
    elif total_timeout_reached:
        termination_reason = "SCAN_TIMEOUT"
    elif discovery_stop_reason:
        termination_reason = discovery_stop_reason
    elif remaining_routes and len(results) >= req.max_pages:
        termination_reason = "MAX_ROUTES_REACHED"
    elif depth_limited_routes:
        termination_reason = "MAX_DEPTH_REACHED"
    elif action_limited_routes:
        termination_reason = "MAX_NAVIGATION_ACTIONS_REACHED"
    elif late_navigation_observed:
        termination_reason = "LATE_NAVIGATION_OBSERVED"
    else:
        termination_reason = "DISCOVERY_EXHAUSTED"
    if termination_reason != "DISCOVERY_EXHAUSTED":
        log_event(
            logging.WARNING,
            "SCAN_LIMIT_REACHED",
            scan_id=scan_id,
            reason=termination_reason,
            routes_remaining=len(remaining_routes),
        )
    summary = aggregate_report(
        results,
        routes_discovered=len(discovered_routes),
        routes_eligible=len(discovered_routes),
        routes_queued=len(queued_routes),
        routes_remaining=len(remaining_routes),
        routes_skipped=len(depth_limited_routes | action_limited_routes),
        termination_reason=termination_reason,
        api_events=scan_api_events,
    )
    # Reporting may determine that exhausted navigation stopped at an auth or
    # access boundary. Execution completion is not proof of complete coverage.
    termination_reason = str(summary.get("termination_reason") or termination_reason)
    # Menu-expansion observations and uniquely queued UI views are separate:
    # views activate during validation, never as speculative discovery clicks.
    for metric in ("discovered", "activated", "unresolved"):
        summary[f"menu_controls_{metric}"] = summary[f"navigation_controls_{metric}"]
    discovered_views = {key for key in discovered_routes if key.startswith("UI_VIEW_")}
    activated_views = {
        str(result["route_id"]) for result in results
        if result.get("view_type") == "UI_TAB" and result.get("same_document_transition")
    }
    summary["view_controls_discovered"] = len(discovered_views)
    summary["view_controls_activated"] = len(activated_views)
    summary["view_controls_unresolved"] = len(discovered_views - activated_views)
    for metric in ("discovered", "activated", "unresolved"):
        summary[f"navigation_controls_{metric}"] += summary[f"view_controls_{metric}"]
    # Results remain the validation-only stream for existing API consumers.
    # The inventory also retains every evidenced route that a configured limit
    # prevented us from visiting, with its real URL and explicit reason.
    route_inventory = list(results)
    for result in results:
        route_name_by_id[str(result["route_id"])] = str(result["route_name"])
    unvisited_reason = unvisited_route_reason(termination_reason)
    for route_key in sorted(remaining_routes | depth_limited_routes | action_limited_routes):
        route_url = sanitized_url(route_locations[route_key])
        route_fields = route_identity_fields(
            route_url,
            query_policy=route_query_policy(),
            allowed_query_parameters=route_query_allowlist(),
        )
        metadata = route_metadata[route_key]
        name, name_source, name_confidence = resolve_route_name(
            navigation_label=str(metadata["route_label"]),
            accessible_name=None,
            primary_heading=None,
            breadcrumb=None,
            metadata_name=None,
            document_title=None,
            display_path=route_fields["display_path"],
        )
        parent_id = route_parent_ids.get(route_key)
        parent_name = route_name_by_id.get(parent_id) if parent_id else None
        hierarchy: list[str] = [name]
        cursor = parent_id
        ancestors: set[str] = {route_key}
        while cursor and cursor not in ancestors:
            ancestors.add(cursor)
            hierarchy.insert(0, route_name_by_id.get(cursor, "Discovered route"))
            cursor = route_parent_ids.get(cursor)
        menu_hierarchy = metadata.get("navigation_hierarchy", [])
        if menu_hierarchy:
            hierarchy[-1:-1] = menu_hierarchy
            parent_name = menu_hierarchy[-1]
        skipped = route_key in depth_limited_routes | action_limited_routes
        reason = (
            "SKIPPED_MAX_DEPTH" if route_key in depth_limited_routes else
            "SKIPPED_MAX_NAVIGATION_ACTIONS" if route_key in action_limited_routes else
            unvisited_reason
        )
        route_inventory.append({
            **route_fields, **metadata,
            "route_id": route_key if route_key.startswith("UI_VIEW_") else sanitized_url(route_key),
            "normalized_route_identity": route_key if route_key.startswith("UI_VIEW_") else sanitized_url(route_key),
            "url": route_url, "requested_url": route_url, "discovered_url": route_url,
            "final_url": None, "route_name": name, "route_name_source": name_source,
            "route_name_confidence": name_confidence,
            "parent_route_id": parent_id, "parent_route_name": parent_name,
            "navigation_hierarchy": hierarchy,
            "view_type": "UI_TAB" if route_key.startswith("UI_VIEW_") else "URL_ROUTE",
            "discovery_sources": route_provenance[route_key]["sources"],
            "classification": "SKIPPED" if skipped else "NOT_TESTED",
            "page_load_status": "NOT_TESTED", "validation_status": "NOT_TESTED",
            "navigation_status": "NOT_TESTED", "render_status": "NOT_TESTED",
            "authentication_status": "NOT_TESTED", "tls_status": "NOT_TESTED",
            "api_status": "NOT_TESTED", "resource_status": "NOT_TESTED", "console_status": "NOT_TESTED",
            "failure_dimension": "COVERAGE", "failure_reason": reason,
            "coverage_reason": reason, "passed": False, "status": None,
            "warning_reasons": [], "finding_details": [],
        })
    aggregation_started = time.perf_counter()
    api_inventory = (
        aggregate_api_events(scan_api_events)
        if scan_api_events else aggregate_api_inventory(results)
    )
    for item in api_inventory:
        item["traffic_class"] = traffic_class(item.get("traffic_role"), in_portal_scope=url_in_scan_scope(
            f"https://{item.get('host') or ''}/", root_host, req.allow_subdomains, approved_portal_hosts,
        ) if item.get("host") else True)
    business_api_inventory = [
        item for item in api_inventory
        if item.get("traffic_role") == "APPLICATION_API"
    ]
    resource_inventory = (
        aggregate_resource_events(scan_resource_events)
        if scan_resource_events else aggregate_resource_inventory(results)
    )
    resource_details, resource_summary = build_resource_report(
        scan_resource_events + scan_api_events,
        large_resource_threshold_bytes=req.large_resource_threshold_bytes,
        large_image_threshold_bytes=req.large_image_threshold_bytes,
        large_js_threshold_bytes=req.large_js_threshold_bytes,
        large_css_font_threshold_bytes=req.large_css_font_threshold_bytes,
    )
    resource_summary["scope"] = "scan-wide unique resource calls"
    # Keep route snapshots and scan-wide aggregation explicit. A route can
    # observe the same resource more than once, while the inventory is unique
    # by method/host/path and also includes late observer events.
    resource_summary["route_resource_call_count"] = sum(
        len(result.get("resources", [])) for result in results
    )
    resource_summary["scan_wide_unique_resource_count"] = len(resource_inventory)
    resource_summary["scan_wide_resource_call_count"] = sum(
        int(item.get("calls", 0)) for item in resource_inventory
    )
    for event in scan_resource_events + scan_api_events:
        event.pop("_resource_timing_key", None)
    security_recommendations = aggregate_security_recommendations(results)
    summary["unique_apis"] = len(api_inventory)
    summary["business_apis"] = len(business_api_inventory)
    summary["api_calls"] = sum(item["calls"] for item in api_inventory)
    # The scan-wide stream also contains discovery and late requests that may
    # fall outside a route's snapshot. Never undercount their policy blocks.
    summary["read_only_blocks"] = sum(
        bool(event.get("blocked_by_validator"))
        and event.get("block_reason") == "READ_ONLY_MUTATION_BLOCKED"
        for event in scan_api_events
    )
    network_observation = {
        "final_drain": network_drain,
        "total_http_requests_observed": sum(scan_http_method_counts.values()),
        "http_methods_observed": dict(sorted(scan_http_method_counts.items())),
        "api_requests_observed": len(scan_api_events),
        # Backward-compatible API-only count, not a total HTTP traffic count.
        "observed_requests": len(scan_api_events),
        "observed_methods": sorted({event["method"] for event in scan_api_events}),
        "policy_evaluated": sum(bool(event.get("policy_evaluated")) for event in scan_api_events),
        "blocked_requests": sum(bool(event.get("blocked_by_validator")) for event in scan_api_events),
        "responses_seen": sum(bool(event.get("response_seen")) for event in scan_api_events),
        "responses_completed": sum(bool(event.get("response_completed")) for event in scan_api_events),
        "requests_failed": sum(
            bool(event.get("request_failed"))
            and not event.get("blocked_by_validator") and not event.get("request_canceled")
            for event in scan_api_events
        ),
        "browser_request_failed_events": sum(bool(event.get("request_failed")) for event in scan_api_events),
        "route_handler_seen": sum(bool(event.get("route_handler_seen")) for event in scan_api_events),
        "request_dispatched": sum(bool(event.get("request_dispatched")) for event in scan_api_events),
        "read_only_blocks": summary["read_only_blocks"],
        "aggregated_requests": sum(item["calls"] for item in api_inventory),
        "requests_canceled": sum(bool(event.get("request_canceled")) for event in scan_api_events),
        "requests_incomplete": sum(event.get("lifecycle_status") == "INCOMPLETE" for event in scan_api_events),
    }
    if network_observation["observed_requests"] != network_observation["aggregated_requests"]:
        raise RuntimeError("Observed API request count does not reconcile with report inventory")
    summary["post_diagnostics"] = summarize_post_diagnostics(
        scan_api_events,
        total_http_requests=network_observation["total_http_requests_observed"],
    )
    if summary["post_diagnostics"]["post_requests_observed"] != sum(
        item["calls"] for item in api_inventory if item["method"] == "POST"
    ):
        raise RuntimeError("Observed POST request count does not reconcile with report inventory")
    for event in scan_api_events:
        event["serialized_to_report"] = True
    log_event(logging.INFO, "NETWORK_OBSERVATION_COMPLETED", scan_id=scan_id, **network_observation)
    summary["api_failures"] = sum(
        item["target_failure_count"]
        for item in api_inventory
    )
    summary["unique_resources"] = len(resource_inventory)
    summary["resource_calls"] = sum(item["calls"] for item in resource_inventory)
    summary["resource_failures"] = sum(item["failures"] for item in resource_inventory)
    summary["security_recommendations"] = len(security_recommendations)
    route_durations = sorted(
        int(result.get("validation_ms") or 0) for result in results
    )
    summary["authentication_duration_ms"] = authentication_duration_ms
    summary["discovery_duration_ms"] = discovery_duration_ms
    summary["validation_duration_ms"] = validation_duration_ms
    summary["average_route_duration_ms"] = (
        round(sum(route_durations) / len(route_durations)) if route_durations else 0
    )
    summary["p50_route_duration_ms"] = (
        route_durations[(len(route_durations) - 1) // 2] if route_durations else 0
    )
    summary["p95_route_duration_ms"] = (
        route_durations[max(0, (95 * len(route_durations) + 99) // 100 - 1)]
        if route_durations else 0
    )
    summary["finalization_duration_ms"] = round(
        (time.perf_counter() - finalization_started) * 1000
    )
    summary["total_scan_duration_ms"] = round(
        (time.perf_counter() - scan_started) * 1000
    )
    aggregation_duration_ms = round((time.perf_counter() - aggregation_started) * 1000)
    report_generation_started = time.perf_counter()
    scan_timing = {
        "preflight_ms": preflight_duration_ms,
        "browser_startup_ms": browser_startup_duration_ms,
        "navigation_ms": navigation_duration_ms,
        "readiness_ms": readiness_duration_ms,
        "aggregation_ms": aggregation_duration_ms,
        "network_observation_ms": network_observation_duration_ms,
        "authentication_ms": authentication_duration_ms,
        "initial_bootstrap_ms": int(results[0].get("total_validation_ms") or 0) if results else 0,
        "discovery_ms": discovery_duration_ms,
        "route_validation_ms": validation_duration_ms,
        "finalization_ms": summary["finalization_duration_ms"],
        "total_scan_ms": summary["total_scan_duration_ms"],
        "application_settle_ms": sum(int(item.get("application_settle_ms") or 0) for item in results),
        "validator_overhead_ms": sum(int(item.get("validator_overhead_ms") or 0) for item in results),
        "browser_contexts": browser_context_count,
        "pages": browser_page_count,
        "full_navigations": sum(not item["same_document_transition"] for item in results),
        "spa_transitions": sum(item["same_document_transition"] for item in results),
        "timing_basis": "Measured overlapping phase windows; not additive. Network observation spans the browser listener lifetime. Report generation excludes HTTP serialization.",
    }
    # Explicit whitelist: never serialize authentication secrets, profile state,
    # credential headers, cookie values, or free-form approval descriptions.
    scan_configuration = req.model_dump(include={
        "max_pages", "max_depth", "max_redirects", "timeout_ms", "per_route_timeout_ms", "total_timeout_ms",
        "navigation_timeout_ms", "authentication_timeout_ms", "readiness_timeout_ms", "api_timeout_ms",
        "concurrency_limit",
        "slow_page_threshold_ms", "render_settle_ms", "min_observation_ms", "network_quiet_ms",
        "large_resource_threshold_bytes", "large_image_threshold_bytes",
        "large_js_threshold_bytes", "large_css_font_threshold_bytes",
        "check_links", "check_console", "check_resources", "check_performance", "check_security_headers",
        "allow_subdomains", "allow_private_networks", "max_navigation_actions", "max_discovery_scrolls",
        "discovery_timeout_ms", "network_settle_cap_ms", "shell_marker_grace_ms", "menu_settle_ms", "reexplore_navigation_each_route",
        "session_refresh_interval_ms", "session_recovery_attempts",
    })
    scan_configuration["authentication_mode"] = req.authentication.mode
    scan_configuration["readiness_selector_configured"] = bool(req.readiness_selector)
    scan_configuration["readiness_event_configured"] = bool(req.readiness_event)
    scan_configuration["authentication_host_count"] = len(req.authentication_hosts)
    scan_configuration.update(authentication_approval_counts)
    scan_configuration["route_concurrency"] = 1
    scan_configuration["maximum_concurrent_scans"] = MAX_CONCURRENT_SCANS
    scan_configuration["approved_read_post_operations"] = [
        {"method": rule.method, "host": rule.host,
         "path_pattern" if rule.path_pattern else "path": safe_api_identity("https://" + rule.host + rule.path)[2]}
        for rule in read_only_policy.safe_application_requests
    ]
    trust_status: TrustStatus = getattr(app.state, "trust_status", TrustStatus(enabled=False))
    log_event(
        logging.INFO,
        (
            "SCAN_CANCELLED" if termination_reason == "USER_CANCELLED" else
            "SCAN_TIMEOUT" if termination_reason == "SCAN_TIMEOUT" else
            "SCAN_COMPLETED"
        ),
        scan_id=scan_id,
        pages=len(results),
        loaded=summary["loaded"],
        failed_to_load=summary["failed_to_load"],
        passed=summary["passed_pages"],
        findings=summary["total_findings"],
        classification=summary["classifications"],
        scan_completeness=summary["scan_completeness"],
        termination_reason=termination_reason,
    )
    route_by_activation = {item.get("route_activation_id"): item for item in results}
    report = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "validator_version": VALIDATOR_VERSION,
        "build_identity": build_diagnostics(),
        "scan_id": scan_id,
        "run_id": scan_id,
        "target": sanitized_url(req.target),
        "pages": len(results),
        "summary": summary,
        "results": results,
        "route_inventory": route_inventory,
        "navigation_coverage": navigation_coverage(results, summary, route_inventory),
        "coverage_dimensions": build_coverage_dimensions(results, summary),
        "api_inventory": api_inventory,
        "authentication_diagnostics": authentication_diagnostics,
        "authentication_diagnostic_groups": group_authentication_diagnostics(
            _safe_authentication_diagnostics(authentication_diagnostics), route_name_by_id,
        ),
        "suggested_authentication_hosts": suggested_authentication_hosts(
            _safe_authentication_diagnostics(authentication_diagnostics),
        ),
        "api_request_occurrences": [
            {
                **event,
                "route_name": route_name_by_id.get(str(event.get("initiating_route") or "")),
                "parent_navigation_item": route_by_activation.get(
                    event.get("route_activation_id"), {},
                ).get("parent_route_name"),
            }
            for event in scan_api_events
        ],
        "business_api_inventory": business_api_inventory,
        "network_observation": network_observation,
        "scan_configuration": scan_configuration,
        "scan_timing": scan_timing,
        "timings": scan_timing,
        "resource_inventory": resource_inventory,
        "resource_details": resource_details,
        "resource_summary": resource_summary,
        "security_recommendations": security_recommendations,
        "coverage": {
            "discovery_status": summary["discovery_status"],
            "validation_status": summary["validation_status"],
            "scan_completeness": summary["scan_completeness"],
            "execution_status": summary.get("execution_status"),
            "coverage_status": summary.get("coverage_status"),
            "coverage_grade": summary.get("coverage_grade", "UNKNOWN"),
            "coverage_scope": summary.get("coverage_scope", "OBSERVED_REACHABLE_SCOPE"),
            "total_application_coverage": summary.get("total_application_coverage", "UNKNOWN"),
            "coverage_reasons": summary.get("coverage_reasons", []),
            "termination_reason": termination_reason,
            "routes_discovered": summary["routes_discovered"],
            "routes_eligible": summary["routes_eligible"],
            "routes_queued": summary["routes_queued"],
            "routes_validated": summary["routes_validated"],
            "routes_skipped": summary["routes_skipped"],
            "routes_remaining": summary["routes_remaining"],
            "routes_not_tested": summary["routes_not_tested"],
            "navigation_controls_discovered": summary["navigation_controls_discovered"],
            "navigation_controls_activated": summary["navigation_controls_activated"],
            "navigation_controls_unresolved": summary["navigation_controls_unresolved"],
            "navigation_control_count_scope": "Menu-expander observations across routes plus unique discovered UI views",
            "business_apis": summary["business_apis"],
            "api_requests_observed": summary.get("api_requests_observed", 0),
            "api_responses_completed": summary.get("api_responses_completed", 0),
            "api_requests_blocked": summary.get("api_requests_blocked", 0),
            "api_requests_failed": summary.get("api_requests_failed", 0),
            "api_requests_incomplete": summary.get("api_requests_incomplete", 0),
            "api_requests_canceled": summary.get("api_requests_canceled", 0),
            "api_requests_not_actively_tested": summary.get("api_requests_not_actively_tested", 0),
            "not_tested_reason_counts": summary["not_tested_reason_counts"],
        },
        "not_tested_routes": [
            {
                "route": route if route.startswith("UI_VIEW_") else sanitized_url(route),
                **({"url": sanitized_url(route_locations[route])} if route.startswith("UI_VIEW_") else {}),
                "reason": (
                    "NOT_TESTED_MAX_ROUTES" if termination_reason == "MAX_ROUTES_REACHED" else
                    "NOT_TESTED_TIMEOUT" if termination_reason == "SCAN_TIMEOUT" else
                    "NOT_TESTED_CANCELLED" if termination_reason == "USER_CANCELLED" else
                    "NOT_TESTED_SESSION_EXPIRED" if termination_reason == "SESSION_EXPIRED" else
                    "NOT_TESTED"
                ),
            }
            for route in sorted(remaining_routes)
        ],
        "skipped_routes": [
            {"route": route if route.startswith("UI_VIEW_") else sanitized_url(route),
             **({"url": sanitized_url(route_locations[route])} if route.startswith("UI_VIEW_") else {}),
             "reason": "SKIPPED_MAX_DEPTH" if route in depth_limited_routes else "SKIPPED_MAX_NAVIGATION_ACTIONS"}
            for route in sorted(depth_limited_routes | action_limited_routes)
        ],
        "session": session_refresh,
        "session_interruption": session_interruption,
        "mid_scan_authentication_blocks": _safe_authentication_diagnostics([
            item for item in authentication_diagnostics
            if item.get("affects_authentication") and application_gate_confirmed
            and item.get("route_activation_id") != bootstrap_activation_id
        ]),
        "safety": {
            "crawl_scope": root_host,
            "navigation_redirects": "cross-origin-with-network-policy",
            "subdomains_enabled": req.allow_subdomains,
            "private_network_enabled": req.allow_private_networks,
            "read_only_enforced": True,
            "mutations_enabled": False,
            "service_worker_policy": "BLOCKED_TO_PRESERVE_NETWORK_MUTATION_GUARD",
            "network_observation_limitations": [
                "Service workers are blocked so requests cannot bypass read-only interception. "
                "Worker-only application behavior is not exercised; calls never initiated by "
                "the browser cannot be discovered or declared healthy."
            ],
            "approved_portal_hosts": sorted(approved_portal_hosts),
            "query_parameter_policy": req.query_parameter_policy,
            "max_discovery_scrolls": req.max_discovery_scrolls,
            "authentication_mode": req.authentication.mode,
            "credential_scope_host_count": authentication_manager.credential_host_count,
            "corporate_ca_trust": trust_status.enabled,
        },
    }
    scan_timing["report_generation_ms"] = round((time.perf_counter() - report_generation_started) * 1000)
    summary["finalization_duration_ms"] = round((time.perf_counter() - finalization_started) * 1000)
    summary["total_scan_duration_ms"] = round((time.perf_counter() - scan_started) * 1000)
    scan_timing["finalization_ms"] = summary["finalization_duration_ms"]
    scan_timing["total_scan_ms"] = summary["total_scan_duration_ms"]
    report["scan_status"] = (
        "CANCELLED" if cancellation_requested else
        "PARTIAL" if summary.get("execution_status") not in {None, "COMPLETE", "COMPLETED"}
        or summary.get("termination_reason") == "SESSION_EXPIRED" else "COMPLETED"
    )
    report["outcome"] = report["scan_status"]
    report["authentication_status"] = (
        "NOT_STARTED" if not application_gate_confirmed else
        "NOT_REQUIRED" if req.authentication.mode == "none" else "AUTHENTICATED"
    )
    summary["routes_tested"] = sum(item.get("page_load_status") != "NOT_TESTED" for item in results)
    report["coverage"]["routes_tested"] = summary["routes_tested"]
    await publish_progress(str(report["scan_status"]))
    report["scan_lifecycle"] = scan_lifecycle
    return report


async def _run_scan_job(job: ScanJob, req: ScanRequest) -> None:
    async def update_job(state: str, **values) -> None:
        # Publish terminal state only after attaching the final report below.
        # Otherwise a concurrent status poll can see FAILED/report_ready=false
        # and discard the actionable authentication failure report.
        if state not in TERMINAL_STATES:
            job.update(state, **values)

    try:
        report = await execute_scan(
            req,
            scan_id=job.scan_id,
            progress_callback=update_job,
            cancel_event=job.cancel_event,
        )
        job.report = report
        summary = report.get("summary", {})
        termination_reason = summary.get("termination_reason")
        terminal_state = (
            "FAILED" if report.get("scan_status") == "FAILED" else
            "CANCELLED" if termination_reason == "USER_CANCELLED" else
            "COMPLETED" if summary.get("scan_completeness") == "COMPLETE" else
            "PARTIAL"
        )
        job.update(
            terminal_state,
            discovered=int(summary.get("routes_discovered", 0)),
            queued=0,
            validated=int(summary.get("routes_validated", 0)),
            healthy=int(summary.get("healthy_routes", 0)),
            failed=int(summary.get("failed_pages", 0)),
            warnings=int(summary.get("routes_with_warnings", 0)),
            current_route=None,
            remaining_budget_ms=0,
        )
    except asyncio.CancelledError:
        job.error = "Scan was cancelled during application shutdown"
        job.update("CANCELLED", current_route=None, remaining_budget_ms=0)
        raise
    except HTTPException as exc:
        job.error = sanitize_text(str(exc.detail), limit=1000)
        job.update("FAILED", current_route=None, remaining_budget_ms=0)
        log_event(
            logging.ERROR,
            "SCAN_FAILED",
            scan_id=job.scan_id,
            error=job.error,
        )
    except Exception as exc:
        job.error = sanitized_diagnostic(str(exc))
        job.update("FAILED", current_route=None, remaining_budget_ms=0)
        log_event(
            logging.ERROR,
            "SCAN_FAILED",
            scan_id=job.scan_id,
            error=job.error,
        )


def _scan_job_or_404(scan_id: str) -> ScanJob:
    job = SCAN_REGISTRY.get(scan_id)
    if job is None:
        raise HTTPException(404, "Scan was not found or is no longer retained")
    return job


@app.post("/api/scans", status_code=202)
async def create_scan(req: ScanRequest):
    if req.allow_mutations:
        raise HTTPException(400, "Portal health validation is read-only; mutations cannot be enabled")
    try:
        root_host, _ = validate_http_url(req.target.strip())
    except DestinationError as exc:
        raise HTTPException(400, exc.public_message) from exc
    configuration_error = None
    # Retain an actionable failed job for unusable credentials/profiles without
    # queueing browser work, using the same scan-ID/report contract as runtime failures.
    # A profile never implicitly approves any identity-provider destination.
    try:
        authentication_approvals_for_scan(req, root_host)
        auth_headers(req.authentication)
        if req.authentication.mode == "storage_state":
            storage_state_path(req.authentication.storage_profile)
    except (HTTPException, AuthenticationConfigurationError, OSError, ValueError):
        configuration_error = create_authentication_error(
            "AUTHENTICATION_CONFIGURATION_ERROR", stage="INITIALIZING", duration_ms=0,
        )
    scan_id = str(uuid.uuid4())
    try:
        job = SCAN_REGISTRY.create(scan_id)
    except ScanCapacityError as exc:
        raise HTTPException(503, "Scan capacity is currently exhausted; retry later") from exc
    if configuration_error is not None:
        job.report = apply_global_authentication_failure({
            "report_schema_version": REPORT_SCHEMA_VERSION, "validator_version": VALIDATOR_VERSION,
            "build_identity": build_diagnostics(), "scan_id": scan_id, "run_id": scan_id,
            "target": sanitized_url(req.target),
            "scan_lifecycle": {"state": "FAILED", "events": [
                {"state": "INITIALIZING", "elapsed_ms": 0}, {"state": "FAILED", "elapsed_ms": 0},
            ]},
        }, configuration_error)
        job.update("FAILED")
        log_event(logging.WARNING, "SCAN_AUTHENTICATION_FAILED", scan_id=scan_id,
                  classification="AUTHENTICATION_CONFIGURATION_ERROR", stage="INITIALIZING")
        return {
            "scan_id": scan_id, "state": "FAILED", "status_url": f"/api/scans/{scan_id}",
            "report_url": f"/api/scans/{scan_id}/report", "cancel_url": f"/api/scans/{scan_id}/cancel",
        }
    job.task = asyncio.create_task(_run_scan_job(job, req.model_copy(deep=True)), name=f"portal-scan-{scan_id}")
    log_event(logging.INFO, "SCAN_CREATED", scan_id=scan_id)
    return {
        "scan_id": scan_id,
        "state": "QUEUED",
        "status_url": f"/api/scans/{scan_id}",
        "report_url": f"/api/scans/{scan_id}/report",
        "cancel_url": f"/api/scans/{scan_id}/cancel",
    }


@app.get("/api/scans/{scan_id}")
async def scan_status(scan_id: str):
    return _scan_job_or_404(scan_id).snapshot()


@app.get("/api/scans/{scan_id}/report")
async def scan_report(scan_id: str):
    job = _scan_job_or_404(scan_id)
    if job.report is not None:
        return job.report
    if job.state == "FAILED":
        raise HTTPException(409, job.error or "Scan failed before a report was produced")
    raise HTTPException(409, f"Scan report is not ready; current state is {job.state}")


@app.post("/api/scans/{scan_id}/cancel", status_code=202)
async def cancel_scan(scan_id: str):
    job = SCAN_REGISTRY.request_cancel(scan_id)
    if job is None:
        raise HTTPException(404, "Scan was not found or is no longer retained")
    if job.state not in TERMINAL_STATES:
        log_event(logging.INFO, "SCAN_CANCELLATION_REQUESTED", scan_id=scan_id)
    return job.snapshot()


@app.post("/api/scan", deprecated=True)
async def scan(req: ScanRequest):
    """Backward-compatible synchronous endpoint; the UI uses /api/scans."""
    return await execute_scan(req)
