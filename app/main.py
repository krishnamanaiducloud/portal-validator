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
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Awaitable, Callable, Literal
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from playwright.async_api import BrowserContext, Route, async_playwright

from app.authentication import (
    AuthenticationConfigurationError,
    build_authentication_manager,
)
from app.logging_config import LOGGER, log_event
from app.discovery import (
    DOCUMENT_NAVIGATION,
    DOWNLOAD_OBSERVED,
    POPUP_NAVIGATION,
    ROUTE_OBSERVER_SCRIPT,
    SAME_DOCUMENT_NAVIGATIONS,
    DiscoveredRoute,
    collect_route_name_evidence,
    discover_page_routes,
    expand_safe_navigation,
    finalize_duplicate_route_names,
    normalize_route_url,
    perform_route_navigation,
    resolve_route_name,
    route_identity_fields,
)
from app.health import (
    api_health_findings,
    assess_page_health,
    realtime_health_findings,
    route_performance_timing,
    wait_for_render_settle,
)
from app.navigation import (
    AuthenticationNavigationPolicy,
    NavigationTracker,
    classify_authentication,
    classify_navigation_error,
    origin_for_url,
)
from app.network import (
    SAFE_HTTP_METHODS,
    PassiveNetworkObserver,
    ReadOnlyPolicy,
    RouteNetworkActivity,
    load_read_only_policy,
    request_identity,
    safe_api_identity,
    summarize_route_api_coverage,
)
from app.reporting import (
    aggregate_api_events,
    aggregate_api_inventory,
    aggregate_report,
    aggregate_resource_events,
    aggregate_resource_inventory,
    aggregate_security_recommendations,
    classify_page_result,
    finding,
    refresh_route_api_health,
)
from app.session import RuntimeSessionStore, load_refresh_config, refresh_browser_session
from app.resources import build_resource_report, enrich_resource_timings, large_resource_findings, resource_timing_key, safe_content_type
from app.scans import ScanCapacityError, ScanJob, ScanRegistry, TERMINAL_STATES
from app.security import (
    DestinationError,
    normalized_host,
    resolve_and_validate,
    sanitize_text,
    sanitize_url,
    validate_http_url,
)
from app.trust import TrustStatus, inspect_trust_status


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
AUTH_STATE_DIR = Path(os.getenv("SESSION_STATE_DIR", "/auth"))
MAX_CONCURRENT_SCANS = max(1, int(os.getenv("MAX_CONCURRENT_SCANS", "2")))
SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
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
VALIDATOR_VERSION = "1.9.0"
REPORT_SCHEMA_VERSION = "2.3"


@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.trust_status = inspect_trust_status()
    application.state.read_only_policy = load_read_only_policy()
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

    @model_validator(mode="after")
    def validate_explicit_operation(self):
        # Use the same strict policy parser for UI and deployment rules.
        rule = load_read_only_policy(raw=json.dumps({
            "safe_application_requests": [self.model_dump(exclude_none=True)],
        })).safe_application_requests[0]
        self.host = rule.host
        return self


class ScanRequest(BaseModel):
    model_config = {"frozen": True}
    target: str = Field(min_length=1, max_length=4096)
    max_pages: int = Field(50, ge=1, le=250)
    max_depth: int = Field(3, ge=0, le=10)
    max_redirects: int = Field(10, ge=0, le=30)
    timeout_ms: int = Field(15000, ge=1000, le=120000)
    total_timeout_ms: int = Field(300000, ge=1000, le=900000)
    check_links: bool = True
    check_console: bool = True
    check_resources: bool = True
    check_performance: bool = True
    check_security_headers: bool = True
    allow_subdomains: bool = False
    allow_private_networks: bool = False
    resource_hosts: list[str] = Field(default_factory=list, max_length=50)
    approved_read_post_operations: list[ApprovedReadPostOperation] = Field(
        default_factory=list, max_length=100,
    )
    portal_hosts: list[str] = Field(default_factory=list, max_length=25)
    credential_hosts: list[str] = Field(default_factory=list, max_length=25)
    query_parameter_policy: Literal["ignore", "allowlist", "preserve"] = "ignore"
    allowed_query_parameters: list[str] = Field(default_factory=list, max_length=25)
    slow_page_threshold_ms: int = Field(5000, ge=500, le=120000)
    large_resource_threshold_bytes: int = Field(1048576, ge=1024, le=104857600)
    large_image_threshold_bytes: int = Field(524288, ge=1024, le=104857600)
    large_js_threshold_bytes: int = Field(1048576, ge=1024, le=104857600)
    large_css_font_threshold_bytes: int = Field(524288, ge=1024, le=104857600)
    render_settle_ms: int = Field(750, ge=0, le=5000)
    min_observation_ms: int = Field(500, ge=0, le=10000)
    network_quiet_ms: int = Field(300, ge=0, le=5000)
    max_navigation_actions: int = Field(20, ge=0, le=50)
    max_discovery_scrolls: int = Field(3, ge=0, le=20)
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


def browser_context_options(state_path: Path | None) -> dict[str, object]:
    options: dict[str, object] = {
        "ignore_https_errors": False,
        "service_workers": "block",
    }
    if state_path is not None:
        options["storage_state"] = str(state_path)
    return options


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
    try:
        password_form = await page.locator("input[type=password]").count() > 0
        mfa_form = await page.locator(
            "input[autocomplete=one-time-code], input[inputmode=numeric][maxlength]"
        ).count() > 0
        return password_form, mfa_form
    except Exception:
        return False, False


async def acknowledge_configured_access_gate(
    page,
    policy: ReadOnlyPolicy,
    current_url: str,
    acknowledged: set[tuple[str, str]],
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
    await control.click(timeout=5000)
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
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok", "version": app.version}


@app.get("/api/auth-profiles")
async def auth_profiles():
    profiles = discover_storage_profiles()
    return {
        "profiles": profiles,
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


async def execute_scan(
    req: ScanRequest,
    *,
    scan_id: str | None = None,
    progress_callback: ProgressCallback | None = None,
    cancel_event: asyncio.Event | None = None,
):
    scan_id = scan_id or str(uuid.uuid4())
    scan_started = time.perf_counter()
    deadline = scan_started + req.total_timeout_ms / 1000
    preflight_timeout_reached = False

    async def publish_progress(state: str, **values) -> None:
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

    await publish_progress("STARTING")
    requested_target = req.target.strip()
    log_event(logging.INFO, "SCAN_STARTED", scan_id=scan_id, requested_url=requested_target)
    try:
        root_host, _port = validate_http_url(requested_target)
    except DestinationError as exc:
        log_event(logging.ERROR, "SCAN_FAILED", scan_id=scan_id, classification=exc.classification, error=exc.public_message)
        raise HTTPException(400, exc.public_message) from exc
    log_event(logging.INFO, "URL_VALIDATED", scan_id=scan_id, requested_url=requested_target, hostname=root_host)
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
    except AuthenticationConfigurationError as exc:
        raise HTTPException(400, str(exc)) from exc
    if req.authentication.mode == "bearer":
        log_event(
            logging.INFO,
            "BEARER_AUTH_CONFIGURED",
            scan_id=scan_id,
            credential_scope_host_count=authentication_manager.credential_host_count,
        )
    mounted_state_path = (
        storage_state_path(req.authentication.storage_profile)
        if req.authentication.mode == "storage_state"
        else None
    )
    runtime_session_store = RuntimeSessionStore()
    state_path = (
        runtime_session_store.seed(req.authentication.storage_profile, mounted_state_path)
        if mounted_state_path is not None and req.authentication.storage_profile
        else None
    )
    state_generation = state_path.stat().st_mtime_ns if state_path is not None else None
    try:
        refresh_config = (
            load_refresh_config(req.authentication.storage_profile, AUTH_STATE_DIR)
            if req.authentication.mode == "storage_state" and req.authentication.storage_profile
            else None
        )
    except (OSError, ValueError, json.JSONDecodeError, DestinationError) as exc:
        raise HTTPException(400, "Session refresh configuration is invalid") from exc
    authentication_duration_ms = round((time.perf_counter() - scan_started) * 1000)
    discovery_duration_ms = 0
    validation_duration_ms = 0
    results: list[dict] = []
    requested_route = normalize_route_url(
        requested_target,
        query_policy=req.query_parameter_policy,
        allowed_query_parameters=set(req.allowed_query_parameters),
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
    )])
    seen: set[str] = set()
    discovered_routes: set[str] = {requested_route}
    queued_routes: set[str] = {requested_route}
    depth_limited_routes: set[str] = set()
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
    ) -> None:
        entry = route_provenance.setdefault(identity, {"observations": 0, "sources": []})
        entry["observations"] = int(entry["observations"]) + 1
        source = {
            "source": route.source,
            "discovery_type": route.discovery_type,
            "label": sanitize_text(route.label, limit=160) if route.label else None,
            "label_source": route.label_source,
            "discovered_from": sanitized_url(discovered_from) if discovered_from else None,
        }
        sources = entry["sources"]
        if source not in sources:
            sources.append(source)
    total_timeout_reached = False
    cancellation_requested = False
    document_evidence: dict[tuple[str, str, int | None], dict[str, object]] = {}
    scan_api_events: list[dict] = []
    scan_resource_events: list[dict] = []
    session_expired = False
    active_route_identity: str | None = None
    network_observer: PassiveNetworkObserver | None = None
    popup_tasks: set[asyncio.Task] = set()
    browser_context_count = 0
    browser_page_count = 0
    session_refresh: dict[str, object] = {"attempted": False}

    await publish_progress(
        "DISCOVERING",
        discovered=len(discovered_routes),
        queued=len(queue),
    )
    @asynccontextmanager
    async def scan_deadline_scope():
        nonlocal total_timeout_reached
        budget = asyncio.timeout_at(deadline)
        try:
            async with budget:
                yield
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


    async with scan_deadline_scope(), SCAN_SEMAPHORE:
        if time.perf_counter() >= deadline:
            raise TimeoutError("Total scan budget expired before browser startup")
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage"],
            )
            log_event(logging.INFO, "BROWSER_LAUNCHED", scan_id=scan_id)
            try:
                context = await browser.new_context(**browser_context_options(state_path))
                browser_context_count += 1
                await context.add_init_script(script=ROUTE_OBSERVER_SCRIPT)
                await configure_cookies(context, req, root_host, approved_portal_hosts)
                page = None
                console_errors: list[str] = []
                page_errors: list[str] = []
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
                request_routes = weakref.WeakKeyDictionary()
                request_observation = weakref.WeakKeyDictionary()
                request_owners = weakref.WeakKeyDictionary()
                active_route_id: str | None = None
                active_route_activation_id: str | None = None
                current_tracker: NavigationTracker | None = None
                navigation_policy_error: DestinationError | None = None
                navigation_hosts: set[str] = set()
                authentication_navigation = AuthenticationNavigationPolicy()
                validator_blocks: dict[tuple[str, str, str, bool], deque[str]] = defaultdict(deque)
                acknowledged_access_gates: set[tuple[str, str]] = set()
                observation_phase = "AUTHENTICATION"
                popup_origins = weakref.WeakKeyDictionary()

                def record_console_error(message):
                    if message.type in {"error", "warning"}:
                        console_errors.append(sanitized_diagnostic(message.text))

                def record_page_error(error):
                    page_errors.append(sanitized_diagnostic(str(error)))

                def is_api_observation(request) -> bool:
                    return (
                        request.resource_type in {"xhr", "fetch"}
                        or request.method.upper() not in SAFE_READ_ONLY_METHODS
                    )

                def request_origin(request):
                    try:
                        owner = popup_origins.get(request_identity(request.frame.page))
                    except Exception:
                        owner = None
                    return owner or (active_route_id, active_route_activation_id, observation_phase)

                def api_importance(request) -> str:
                    phase = request_origin(request)[2]
                    if phase == "AUTHENTICATION" or (
                        request.method.upper() not in SAFE_READ_ONLY_METHODS
                        and is_main_navigation(request)
                        and authentication_navigation.active
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

                def request_event_key(request) -> tuple[str, str, str, bool]:
                    return (
                        sanitized_url(request.url),
                        request.method.upper(),
                        request.resource_type,
                        is_main_navigation(request),
                    )

                def ensure_api_observed(request) -> dict | None:
                    if not is_api_observation(request):
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
                    return event

                def record_request(request):
                    key = request_identity(request)
                    if key in request_started:
                        ensure_api_observed(request)
                        return
                    request_started[key] = time.perf_counter()
                    request_routes[key] = request_origin(request)[0]
                    request_owners[key] = request_origin(request)[:2]
                    route_network_activity.request_started(
                        request, request_origin(request)[0],
                        relevant=api_importance(request) == "REQUIRED" and request.resource_type not in {"websocket", "eventsource"},
                    )
                    request_observation[key] = (
                        request_phase(request),
                        api_importance(request),
                    )
                    api_event = ensure_api_observed(request)
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

                def record_failed_request(request):
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
                    failed_resources.append({
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
                        resource_events.append({
                            "url": sanitized_url(request.url),
                            "_resource_timing_key": resource_timing_key(request.url),
                            "resource_type": request.resource_type,
                            "status": None,
                            "error": sanitized_diagnostic(request.failure or "Request failed"),
                            "blocked_by_validator": block_reason is not None,
                            "block_reason": block_reason,
                            "phase": phase,
                            "duration_ms": duration_ms,
                            "initiating_route": initiating_route,
                        })
                    if request.resource_type == "eventsource":
                        event_streams.append({
                            "url": sanitized_url(request.url),
                            "status": None,
                            "error": sanitized_diagnostic(request.failure or "Request failed"),
                        })

                def record_request_finished(request):
                    route_network_activity.request_finished(request)
                    network_observer.record_finished(request)
                    request_owners.pop(request_identity(request), None)

                def record_response(response):
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
                        resource_events.append({
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
                        })
                        if response.status >= 400:
                            failed_resources.append({
                                "url": sanitized_url(response.url),
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
                        frame_events.append({
                            "url": sanitized_url(frame.url),
                            "main_frame": bool(page is not None and frame == page.main_frame),
                        })

                async def record_popup(popup):
                    try:
                        await popup.wait_for_load_state("domcontentloaded", timeout=max(1, min(req.timeout_ms, round((deadline - time.perf_counter()) * 1000))))
                        if popup.url.startswith(("http://", "https://")):
                            popup_routes.append(DiscoveredRoute(
                                url=popup.url,
                                label=sanitize_text(await popup.title(), limit=160) or "New window",
                                source="popup",
                                navigation_mode=POPUP_NAVIGATION,
                            ))
                    except Exception as exc:
                        log_event(
                            logging.INFO,
                            "POPUP_OBSERVATION_FAILED",
                            scan_id=scan_id,
                            error=sanitized_diagnostic(str(exc)),
                        )
                    # Keep the naturally opened page alive until context cleanup:
                    # closing on DOMContentLoaded cancels lazy APIs and auth work.

                async def route_guard(route: Route):
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
                    if main_navigation:
                        try:
                            validated_host, _ = validate_http_url(request.url)
                            await _resolve_with_logging(validated_host, req, scan_id)
                            if is_primary_navigation(request) and current_tracker is None:
                                raise DestinationError("NAVIGATION_ERROR", "Navigation tracker is unavailable")
                            authentication_navigation.observe(request.url)
                            if is_primary_navigation(request) and current_tracker is not None:
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
                        auth_navigation_allowed = False
                        if main_navigation:
                            try:
                                post_data = request.post_data
                            except Exception:
                                post_data = None
                            auth_navigation_allowed = authentication_navigation.allows_main_frame_method(
                                request.method,
                                request.url,
                                post_data,
                            )
                        approved_rule = (
                            None if auth_navigation_allowed else
                            approved_operation
                        )
                        if not auth_navigation_allowed and approved_rule is None:
                            await abort_by_validator(route, "read_only_mutation_policy")
                            return
                        if auth_navigation_allowed:
                            request_observation[request_identity(request)] = (
                                "AUTHENTICATION",
                                "AUTHENTICATION",
                            )
                            network_observer.mark_allowed(
                                request,
                                "AUTH_FLOW",
                                phase="AUTHENTICATION",
                                importance="AUTHENTICATION",
                            )
                            log_event(
                                logging.INFO,
                                "AUTH_FLOW_POST_ALLOWED",
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
                    elif api_event is not None:
                        network_observer.mark_allowed(request, "SAFE_METHOD")

                    headers = authentication_manager.headers_for_request(
                        request.headers,
                        host,
                    )
                    await route.continue_(headers=headers)
                    network_observer.mark_dispatched(request)

                context.on("request", record_request)
                context.on("requestfailed", record_failed_request)
                context.on("requestfinished", record_request_finished)
                context.on("response", record_response)
                await context.route("**/*", route_guard)
                page = await context.new_page()
                browser_page_count += 1
                page.on("console", record_console_error)
                page.on("pageerror", record_page_error)
                page.on("websocket", record_websocket)
                page.on("download", record_download)
                page.on("framenavigated", record_frame_navigation)
                def schedule_popup(popup, owner=None):
                    nonlocal browser_page_count
                    browser_page_count += 1
                    owner = owner or (active_route_id, active_route_activation_id, observation_phase)
                    popup_origins[request_identity(popup)] = owner
                    popup.on("popup", lambda child: schedule_popup(child, owner))
                    task = asyncio.create_task(record_popup(popup))
                    popup_tasks.add(task)
                    task.add_done_callback(popup_tasks.discard)
                page.on("popup", schedule_popup)
                if refresh_config is not None:
                    current_tracker = NavigationTracker(req.max_redirects)
                    navigation_policy_error = None
                    navigation_hosts.clear()
                    authentication_navigation = AuthenticationNavigationPolicy()
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
                authentication_duration_ms = round((time.perf_counter() - scan_started) * 1000)
                while queue and len(results) < req.max_pages:
                    if cancel_event is not None and cancel_event.is_set():
                        cancellation_requested = True
                        break
                    if time.perf_counter() >= deadline:
                        total_timeout_reached = True
                        break
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
                    ) = queue.popleft()
                    route_identity = normalize_route_url(
                        url,
                        query_policy=req.query_parameter_policy,
                        allowed_query_parameters=set(req.allowed_query_parameters),
                    ) or url
                    if route_identity in seen or depth > req.max_depth:
                        continue
                    seen.add(route_identity)
                    active_route_identity = route_identity
                    active_route_id = sanitized_url(route_identity)
                    active_route_activation_id = f"activation-{len(results) + 1}"
                    await publish_progress(
                        "VALIDATING",
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
                    authentication_navigation = AuthenticationNavigationPolicy()
                    observation_phase = (
                        "APPLICATION_BOOTSTRAP"
                        if not results and depth == 0
                        else "ROUTE_VALIDATION"
                    )
                    requested_url = sanitized_url(url)
                    requested_host = normalized_host(urlparse(url).hostname or "")
                    final_url: str | None = None
                    final_raw_url = url
                    console_start = len(console_errors)
                    page_error_start = len(page_errors)
                    resource_start = len(resource_events)
                    websocket_start = len(websocket_events)
                    event_stream_start = len(event_streams)
                    download_start = len(download_events)
                    frame_event_start = len(frame_events)
                    popup_start = len(popup_routes)
                    started = time.perf_counter()
                    route_deadline = min(deadline, started + req.timeout_ms / 1000)
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
                    name_evidence = {"primary_heading": "", "breadcrumb": ""}
                    navigation_actions = {"activated": 0, "skipped": 0}
                    route_discovery_ms = 0
                    navigation_ms = 0
                    render_start_ms = None
                    frame_observations: list[dict[str, object]] = []
                    final_in_scope = False
                    remaining_ms = max(0, round((deadline - time.perf_counter()) * 1000))
                    if remaining_ms == 0:
                        error = "Total scan timeout exceeded"
                        error_classification = "TIMEOUT"
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
                            async with asyncio.timeout_at(route_deadline):
                                response, route_transition_succeeded, activation_method = await perform_route_navigation(
                                    page,
                                    url,
                                    navigation_mode,
                                    min(req.timeout_ms, remaining_ms),
                                    label=route_label,
                                    source=route_source,
                                )
                                navigation_ms = round((time.perf_counter() - started) * 1000)
                                log_event(
                                    logging.INFO,
                                    "ROUTE_ACTIVATION_COMPLETED",
                                    scan_id=scan_id,
                                    current_route=active_route_id,
                                    activation_method=activation_method,
                                )
                                final_raw_url = page.url
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
                                title = sanitize_text(await page.title(), limit=512)
                                name_evidence = await collect_route_name_evidence(page)
                                final_in_scope = url_in_scan_scope(
                                    final_raw_url,
                                    root_host,
                                    req.allow_subdomains,
                                    approved_portal_hosts,
                                )
                                password_form, mfa_form = await detect_auth_signals(page)
                                authentication_classification = classify_authentication(
                                    authentication_mode=req.authentication.mode,
                                    status=status,
                                    final_url=final_raw_url,
                                    target_in_scope=final_in_scope,
                                    error_classification=None,
                                    password_form=password_form,
                                    mfa_form=mfa_form,
                                )
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
                                render_start_ms = round((time.perf_counter() - started) * 1000)
                                render_health = await wait_for_render_settle(
                                    page,
                                    settle_ms=req.render_settle_ms,
                                    maximum_ms=max(0, round((route_deadline - time.perf_counter()) * 1000)),
                                    network_activity=lambda: route_network_activity.snapshot(
                                        active_route_id
                                    ),
                                    minimum_observation_ms=req.min_observation_ms,
                                    network_quiet_ms=req.network_quiet_ms,
                                )
                                log_event(
                                    logging.INFO,
                                    "ROUTE_SETTLE_COMPLETED",
                                    scan_id=scan_id,
                                    current_route=active_route_id,
                                    settle_reason=render_health.get("settle_reason"),
                                    settle_elapsed_ms=render_health.get("settle_elapsed_ms"),
                                    network_pending=render_health.get("network_pending"),
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
                                ):
                                    observation_phase = "DISCOVERY"
                                    discovery_started = time.perf_counter()
                                    await publish_progress(
                                        "DISCOVERING",
                                        discovered=len(discovered_routes),
                                        queued=len(queue),
                                        validated=len(results),
                                        current_route=active_route_id,
                                    )
                                    if req.max_navigation_actions:
                                        navigation_actions = await expand_safe_navigation(
                                            page,
                                            req.max_navigation_actions,
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
                                    else:
                                        safe_routes = []
                                    discovered = safe_routes + await discover_page_routes(
                                        page,
                                        req.max_discovery_scrolls,
                                    )
                                    discovered.extend(popup_routes[popup_start:])
                                    unique_discovered: dict[str, DiscoveredRoute] = {}
                                    for route in discovered:
                                        identity = normalize_route_url(
                                            route.url,
                                            query_policy=req.query_parameter_policy,
                                            allowed_query_parameters=set(req.allowed_query_parameters),
                                        )
                                        if identity is not None:
                                            remember_route_discovery(identity, route, final_raw_url)
                                            existing = unique_discovered.get(identity)
                                            if existing is None or (not existing.label and route.label):
                                                unique_discovered[identity] = route
                                    discovered = list(unique_discovered.values())
                                    download_routes = [
                                        route for route in discovered
                                        if route.navigation_mode == DOWNLOAD_OBSERVED
                                    ]
                                    navigation_actions["downloads_observed"] = len(download_routes)
                                    links = [
                                        route.url for route in discovered
                                        if route.navigation_mode != DOWNLOAD_OBSERVED
                                    ]
                                    crawl_links, external_links = partition_links(
                                        links,
                                        root_host,
                                        req.allow_subdomains,
                                        approved_portal_hosts,
                                        req.query_parameter_policy,
                                        set(req.allowed_query_parameters),
                                    )
                                    if external_links:
                                        log_event(
                                            logging.INFO,
                                            "EXTERNAL_LINK_SKIPPED",
                                            scan_id=scan_id,
                                            count=len(external_links),
                                        )
                                    if final_in_scope:
                                        metadata: dict[str, DiscoveredRoute] = {}
                                        for route in discovered:
                                            identity = normalize_route_url(
                                                route.url,
                                                query_policy=req.query_parameter_policy,
                                                allowed_query_parameters=set(req.allowed_query_parameters),
                                            )
                                            if identity is not None:
                                                metadata.setdefault(identity, route)
                                        for link in crawl_links:
                                            path = urlparse(link).path.lower()
                                            if (
                                                not any(word in path for word in DANGEROUS_PATH_WORDS)
                                                and link not in discovered_routes
                                            ):
                                                discovered_route = metadata.get(link) or DiscoveredRoute(
                                                    url=link,
                                                    label="Discovered route",
                                                    source="semantic",
                                                    navigation_mode=DOCUMENT_NAVIGATION,
                                                )
                                                label = (
                                                    sanitize_text(discovered_route.label, limit=160)
                                                    if discovered_route.label else "Discovered route"
                                                )
                                                source = discovered_route.source
                                                mode = discovered_route.navigation_mode
                                                discovered_routes.add(link)
                                                if depth >= req.max_depth:
                                                    depth_limited_routes.add(link)
                                                    log_event(
                                                        logging.INFO,
                                                        "ROUTE_SKIPPED",
                                                        scan_id=scan_id,
                                                        current_url=link,
                                                        reason="MAX_DEPTH_REACHED",
                                                    )
                                                    continue
                                                route_item = (
                                                    link,
                                                    depth + 1,
                                                    label,
                                                    source,
                                                    mode,
                                                    final_raw_url,
                                                    discovered_route.discovery_type,
                                                    discovered_route.label_source,
                                                    (
                                                        sanitize_text(discovered_route.accessible_name, limit=160)
                                                        if discovered_route.accessible_name else None
                                                    ),
                                                )
                                                if mode in SAME_DOCUMENT_NAVIGATIONS:
                                                    # Queue all branches breadth-first so one menu does not
                                                    # consume the validation budget before its peers.
                                                    queue.append(route_item)
                                                else:
                                                    queue.append(route_item)
                                                queued_routes.add(link)
                                                log_event(
                                                    logging.DEBUG,
                                                    "LINK_DISCOVERED",
                                                    scan_id=scan_id,
                                                    current_url=link,
                                                    crawl_depth=depth + 1,
                                                    navigation_type=mode,
                                                )
                                    route_discovery_ms = round(
                                        (time.perf_counter() - discovery_started) * 1000
                                    )
                                    discovery_duration_ms += route_discovery_ms
                                    observation_phase = "ROUTE_VALIDATION"
                        except Exception as exc:
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
                            log_event(
                                logging.ERROR,
                                error_classification,
                                scan_id=scan_id,
                                requested_url=url,
                                final_url=final_raw_url,
                                error=error,
                            )

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

                    health_validation_started = time.perf_counter()
                    elapsed = round((time.perf_counter() - started) * 1000)
                    route_validation_ms = max(0, elapsed - route_discovery_ms)
                    performance_timing = route_performance_timing(
                        navigation_ms=navigation_ms,
                        render_health=render_health,
                        total_validation_ms=route_validation_ms,
                        render_start_ms=render_start_ms,
                    )
                    page_console = list(dict.fromkeys(
                        console_errors[console_start:]
                    )) if req.check_console else []
                    page_script_errors = list(dict.fromkeys(
                        page_errors[page_error_start:]
                    )) if req.check_console else []
                    page_failures = [
                        failure for failure in failed_resources
                        if failure.get("route_activation_id") == active_route_activation_id
                    ] if req.check_resources else []
                    page_api_events = [
                        event for event in api_events
                        if event.get("route_activation_id") == active_route_activation_id
                    ]
                    page_resource_events = resource_events[resource_start:] if req.check_resources else []
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
                    page_frame_events = frame_events[frame_event_start:]
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
                        query_policy=req.query_parameter_policy,
                        allowed_query_parameters=set(req.allowed_query_parameters),
                    ) or route_identity
                    identity = route_identity_fields(
                        final_identity,
                        query_policy=req.query_parameter_policy,
                        allowed_query_parameters=set(req.allowed_query_parameters),
                    )
                    requested_identity = route_identity_fields(
                        route_identity,
                        query_policy=req.query_parameter_policy,
                        allowed_query_parameters=set(req.allowed_query_parameters),
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
                    provenance = route_provenance.get(route_identity, {"observations": 1, "sources": []})
                    health_validation_ms = round((time.perf_counter() - health_validation_started) * 1000)
                    route_validation_ms = max(0, round((time.perf_counter() - started) * 1000) - route_discovery_ms)
                    performance_timing = route_performance_timing(
                        navigation_ms=navigation_ms,
                        render_health=render_health,
                        total_validation_ms=route_validation_ms,
                        render_start_ms=render_start_ms,
                    )
                    performance_timing["route_transition_ms"] = navigation_ms if navigation_mode in SAME_DOCUMENT_NAVIGATIONS else 0
                    performance_timing["health_validation_ms"] = health_validation_ms
                    performance_timing["discovery_ms"] = route_discovery_ms
                    validation_duration_ms += route_validation_ms
                    result = {
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
                        "expected_origin": sanitized_url(url, include_path=False),
                        "normalized_route_identity": sanitized_url(route_identity),
                        "navigation_type": navigation_mode,
                        "status": status,
                        "http_status_display": "N/A (SPA)" if route_transition_succeeded else status,
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
                        "slow": req.check_performance and int(performance_timing["application_load_ms"]) > req.slow_page_threshold_ms,
                        "discovery_ms": route_discovery_ms,
                        "validation_ms": route_validation_ms,
                        "navigation_actions": navigation_actions,
                        "unsafe_actions_skipped": navigation_actions["skipped"],
                        "discovery_limitations": int(navigation_actions.get("skipped", 0)),
                        "read_only_blocks": read_only_blocks,
                        "security_headers": header_report,
                        "missing_security_headers": missing_headers,
                        **classification,
                    }
                    results.append(result)
                    active_route_identity = None
                    await publish_progress(
                        "VALIDATING",
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
                    if session_expired:
                        break
                    if time.perf_counter() >= deadline:
                        total_timeout_reached = bool(queue)
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
                    )
                    session_refresh["runtime_state_updated"] = updated_state is not None
                    session_refresh["concurrent_update_preserved"] = updated_state is None
                await context.close()
                network_observer.finalize_pending()
            finally:
                await browser.close()

    await publish_progress(
        "FINALIZING",
        discovered=len(discovered_routes),
        queued=len(queue),
        validated=len(results),
        current_route=None,
    )
    finalization_started = time.perf_counter()
    for result in results:
        # Continuous observation can complete a request after its initiating
        # route snapshot. Reconcile that route, never the currently active one.
        route_events = [event for event in scan_api_events
                        if event.get("route_activation_id") == result.get("route_activation_id")]
        result.update(refresh_route_api_health(result, route_events))
        canonical = str(result.get("canonical_route") or "")
        provenance = route_provenance.get(canonical)
        if provenance:
            result["discovery_sources"] = provenance.get("sources", [])
            result["duplicate_discovery_count"] = max(
                0, int(provenance.get("observations", 1)) - 1
            )
    finalize_duplicate_route_names(results)
    remaining_routes = (discovered_routes - seen) - depth_limited_routes
    if cancellation_requested:
        termination_reason = "USER_CANCELLED"
    elif session_expired:
        termination_reason = "SESSION_EXPIRED"
    elif total_timeout_reached:
        termination_reason = "SCAN_TIMEOUT"
    elif remaining_routes and len(results) >= req.max_pages:
        termination_reason = "MAX_ROUTES_REACHED"
    elif depth_limited_routes:
        termination_reason = "MAX_DEPTH_REACHED"
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
        routes_skipped=len(depth_limited_routes),
        termination_reason=termination_reason,
    )
    api_inventory = (
        aggregate_api_events(scan_api_events)
        if scan_api_events else aggregate_api_inventory(results)
    )
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
    for event in scan_resource_events + scan_api_events:
        event.pop("_resource_timing_key", None)
    security_recommendations = aggregate_security_recommendations(results)
    summary["unique_apis"] = len(api_inventory)
    summary["api_calls"] = sum(item["calls"] for item in api_inventory)
    # The scan-wide stream also contains discovery and late requests that may
    # fall outside a route's snapshot. Never undercount their policy blocks.
    summary["read_only_blocks"] = sum(
        bool(event.get("blocked_by_validator"))
        and event.get("block_reason") == "READ_ONLY_MUTATION_BLOCKED"
        for event in scan_api_events
    )
    network_observation = {
        "observed_requests": len(scan_api_events),
        "observed_methods": sorted({event["method"] for event in scan_api_events}),
        "policy_evaluated": sum(bool(event.get("policy_evaluated")) for event in scan_api_events),
        "blocked_requests": sum(bool(event.get("blocked_by_validator")) for event in scan_api_events),
        "responses_seen": sum(bool(event.get("response_seen")) for event in scan_api_events),
        "responses_completed": sum(bool(event.get("response_completed")) for event in scan_api_events),
        "requests_failed": sum(bool(event.get("request_failed")) for event in scan_api_events),
        "route_handler_seen": sum(bool(event.get("route_handler_seen")) for event in scan_api_events),
        "request_dispatched": sum(bool(event.get("request_dispatched")) for event in scan_api_events),
        "read_only_blocks": summary["read_only_blocks"],
        "aggregated_requests": sum(item["calls"] for item in api_inventory),
    }
    if network_observation["observed_requests"] != network_observation["aggregated_requests"]:
        raise RuntimeError("Observed API request count does not reconcile with report inventory")
    for event in scan_api_events:
        event["serialized_to_report"] = True
    log_event(logging.INFO, "NETWORK_OBSERVATION_COMPLETED", scan_id=scan_id, **network_observation)
    summary["api_failures"] = sum(
        item["status_4xx"] + item["status_5xx"] + item["network_failures"]
        + item["response_body_failures"]
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
    scan_timing = {
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
        "full_navigations": sum(item["navigation_type"] not in SAME_DOCUMENT_NAVIGATIONS for item in results),
        "spa_transitions": sum(item["navigation_type"] in SAME_DOCUMENT_NAVIGATIONS for item in results),
    }
    # Explicit whitelist: never serialize authentication secrets, profile state,
    # credential headers, cookie values, or free-form approval descriptions.
    scan_configuration = req.model_dump(include={
        "max_pages", "max_depth", "max_redirects", "timeout_ms", "total_timeout_ms",
        "slow_page_threshold_ms", "render_settle_ms", "min_observation_ms", "network_quiet_ms",
        "large_resource_threshold_bytes", "large_image_threshold_bytes",
        "large_js_threshold_bytes", "large_css_font_threshold_bytes",
        "check_links", "check_console", "check_resources", "check_performance", "check_security_headers",
        "allow_subdomains", "allow_private_networks", "max_navigation_actions", "max_discovery_scrolls",
    })
    scan_configuration["authentication_mode"] = req.authentication.mode
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
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "validator_version": VALIDATOR_VERSION,
        "scan_id": scan_id,
        "run_id": scan_id,
        "target": sanitized_url(req.target),
        "pages": len(results),
        "summary": summary,
        "results": results,
        "api_inventory": api_inventory,
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
            "termination_reason": termination_reason,
            "routes_discovered": summary["routes_discovered"],
            "routes_eligible": summary["routes_eligible"],
            "routes_queued": summary["routes_queued"],
            "routes_validated": summary["routes_validated"],
            "routes_skipped": summary["routes_skipped"],
            "routes_remaining": summary["routes_remaining"],
            "routes_not_tested": summary["routes_not_tested"],
            "not_tested_reason_counts": summary["not_tested_reason_counts"],
        },
        "not_tested_routes": [
            {
                "route": sanitized_url(route),
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
            {"route": sanitized_url(route), "reason": "SKIPPED_MAX_DEPTH"}
            for route in sorted(depth_limited_routes)
        ],
        "session": session_refresh,
        "safety": {
            "crawl_scope": root_host,
            "navigation_redirects": "cross-origin-with-network-policy",
            "subdomains_enabled": req.allow_subdomains,
            "private_network_enabled": req.allow_private_networks,
            "read_only_enforced": True,
            "mutations_enabled": False,
            "service_worker_policy": "BLOCKED_TO_PRESERVE_NETWORK_MUTATION_GUARD",
            "approved_portal_hosts": sorted(approved_portal_hosts),
            "query_parameter_policy": req.query_parameter_policy,
            "max_discovery_scrolls": req.max_discovery_scrolls,
            "authentication_mode": req.authentication.mode,
            "credential_scope_host_count": authentication_manager.credential_host_count,
            "corporate_ca_trust": trust_status.enabled,
        },
    }


async def _run_scan_job(job: ScanJob, req: ScanRequest) -> None:
    async def update_job(state: str, **values) -> None:
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
        validate_http_url(req.target.strip())
    except DestinationError as exc:
        raise HTTPException(400, exc.public_message) from exc
    scan_id = str(uuid.uuid4())
    try:
        job = SCAN_REGISTRY.create(scan_id)
    except ScanCapacityError as exc:
        raise HTTPException(503, "Scan capacity is currently exhausted; retry later") from exc
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
