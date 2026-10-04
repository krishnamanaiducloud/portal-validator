from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urldefrag, urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr, field_validator
from playwright.async_api import BrowserContext, Route, async_playwright

from app.logging_config import LOGGER, log_event
from app.discovery import (
    ROUTE_OBSERVER_SCRIPT,
    DiscoveredRoute,
    discover_page_routes,
    expand_safe_navigation,
    normalize_route_url,
)
from app.health import api_health_findings, assess_page_health, capture_render_health
from app.navigation import (
    AuthenticationNavigationPolicy,
    NavigationTracker,
    classify_authentication,
    classify_navigation_error,
)
from app.reporting import aggregate_report, classify_page_result
from app.session import RuntimeSessionStore, load_refresh_config, refresh_browser_session
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

SAFE_READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
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


@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.trust_status = inspect_trust_status()
    yield


app = FastAPI(
    title="Portal Validator",
    version="1.3.0",
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


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4096)
    max_pages: int = Field(25, ge=1, le=250)
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
    portal_hosts: list[str] = Field(default_factory=list, max_length=25)
    credential_hosts: list[str] = Field(default_factory=list, max_length=25)
    query_parameter_policy: Literal["ignore", "allowlist", "preserve"] = "ignore"
    allowed_query_parameters: list[str] = Field(default_factory=list, max_length=25)
    slow_page_threshold_ms: int = Field(5000, ge=500, le=120000)
    render_settle_ms: int = Field(750, ge=0, le=5000)
    max_navigation_actions: int = Field(20, ge=0, le=50)
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
    if authentication.mode == "basic":
        if authentication.username is None or authentication.password is None:
            raise HTTPException(400, "Basic authentication requires username and password")
        raw = f"{authentication.username}:{authentication.password.get_secret_value()}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
    if authentication.mode == "bearer":
        if authentication.token is None:
            raise HTTPException(400, "Bearer authentication requires a token")
        return {"Authorization": "Bearer " + authentication.token.get_secret_value()}
    if authentication.mode == "headers":
        if not authentication.headers:
            raise HTTPException(400, "Custom-header authentication requires at least one header")
        return {name: value.get_secret_value() for name, value in authentication.headers.items()}
    return {}


def headers_for_destination(
    request_headers: dict[str, str],
    sensitive_headers: dict[str, str],
    destination_host: str,
    credential_hosts: set[str],
) -> dict[str, str]:
    """Attach scan credentials only to explicitly approved destination hosts."""
    headers = request_headers.copy()
    sensitive_names = {name.lower() for name in sensitive_headers}
    for header_name in list(headers):
        if header_name.lower() in sensitive_names:
            headers.pop(header_name, None)
    if normalized_host(destination_host) in credential_hosts:
        headers.update(sensitive_headers)
    return headers


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


@app.post("/api/scan")
async def scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())
    requested_target = urldefrag(req.target.strip()).url
    log_event(logging.INFO, "SCAN_STARTED", scan_id=scan_id, requested_url=requested_target)
    try:
        root_host, _port = validate_http_url(requested_target)
    except DestinationError as exc:
        log_event(logging.ERROR, "SCAN_FAILED", scan_id=scan_id, classification=exc.classification, error=exc.public_message)
        raise HTTPException(400, exc.public_message) from exc
    log_event(logging.INFO, "URL_VALIDATED", scan_id=scan_id, requested_url=requested_target, hostname=root_host)
    try:
        await _resolve_with_logging(root_host, req, scan_id)
    except DestinationError as exc:
        log_event(logging.ERROR, exc.classification, scan_id=scan_id, hostname=root_host, error=exc.public_message)
        raise HTTPException(400, exc.public_message) from exc

    if req.allow_mutations:
        raise HTTPException(400, "Portal health validation is read-only; mutations cannot be enabled")

    approved_resource_hosts = {normalized_host(host) for host in req.resource_hosts}
    for host in approved_resource_hosts:
        try:
            await _resolve_with_logging(host, req, scan_id)
        except DestinationError as exc:
            raise HTTPException(400, exc.public_message) from exc

    approved_portal_hosts = {normalized_host(host) for host in req.portal_hosts}
    for host in approved_portal_hosts:
        try:
            await _resolve_with_logging(host, req, scan_id)
        except DestinationError as exc:
            raise HTTPException(400, exc.public_message) from exc

    boundary = portal_boundary_host(root_host)
    credential_hosts = {boundary, f"www.{boundary}"}
    for host in req.credential_hosts:
        if not host_in_scan_scope(
            host,
            root_host,
            req.allow_subdomains,
            approved_portal_hosts,
        ):
            raise HTTPException(400, "Credential host must remain inside the configured crawl scope")
        try:
            await _resolve_with_logging(host, req, scan_id)
        except DestinationError as exc:
            raise HTTPException(400, exc.public_message) from exc
        credential_hosts.add(host)

    sensitive_headers = auth_headers(req.authentication)
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
    results: list[dict] = []
    requested_route = normalize_route_url(
        requested_target,
        query_policy=req.query_parameter_policy,
        allowed_query_parameters=set(req.allowed_query_parameters),
    ) or requested_target
    queue = deque([(requested_target, 0, "Requested route", "target")])
    seen: set[str] = set()
    discovered_routes: set[str] = {requested_route}
    deadline = time.perf_counter() + (req.total_timeout_ms / 1000)

    async with SCAN_SEMAPHORE:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage"],
            )
            log_event(logging.INFO, "BROWSER_LAUNCHED", scan_id=scan_id)
            try:
                context = await browser.new_context(**browser_context_options(state_path))
                await context.add_init_script(script=ROUTE_OBSERVER_SCRIPT)
                await configure_cookies(context, req, root_host, approved_portal_hosts)
                page = await context.new_page()
                console_errors: list[str] = []
                failed_resources: list[dict] = []
                api_events: list[dict] = []
                popup_routes: list[DiscoveredRoute] = []
                current_tracker: NavigationTracker | None = None
                navigation_policy_error: DestinationError | None = None
                navigation_hosts: set[str] = set()
                authentication_navigation = AuthenticationNavigationPolicy()
                validator_blocks: dict[tuple[str, str, str, bool], deque[str]] = defaultdict(deque)

                def record_console_error(message):
                    if message.type == "error":
                        console_errors.append(sanitized_diagnostic(message.text))

                def is_main_navigation(request) -> bool:
                    try:
                        return bool(request.is_navigation_request() and request.frame.parent_frame is None)
                    except Exception:
                        return False

                def is_primary_navigation(request) -> bool:
                    try:
                        return bool(is_main_navigation(request) and request.frame == page.main_frame)
                    except Exception:
                        return False

                def request_event_key(request) -> tuple[str, str, str, bool]:
                    return (
                        sanitized_url(request.url),
                        request.method.upper(),
                        request.resource_type,
                        is_main_navigation(request),
                    )

                async def abort_by_validator(route: Route, reason: str) -> None:
                    request = route.request
                    validator_blocks[request_event_key(request)].append(reason)
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
                    })
                    if request.resource_type in {"xhr", "fetch"}:
                        api_events.append({
                            "url": sanitized_url(request.url),
                            "method": request.method.upper(),
                            "status": None,
                            "error": sanitized_diagnostic(request.failure or "Request failed"),
                            "blocked_by_validator": block_reason is not None,
                        })

                def record_response(response):
                    if response.request.resource_type in {"xhr", "fetch"}:
                        api_events.append({
                            "url": sanitized_url(response.url),
                            "method": response.request.method.upper(),
                            "status": response.status,
                            "error": None,
                            "blocked_by_validator": False,
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

                page.on("console", record_console_error)
                page.on("requestfailed", record_failed_request)
                page.on("response", record_response)

                async def record_popup(popup):
                    try:
                        await popup.wait_for_load_state("domcontentloaded", timeout=min(req.timeout_ms, 10000))
                        if popup.url.startswith(("http://", "https://")):
                            popup_routes.append(DiscoveredRoute(
                                url=popup.url,
                                label=sanitize_text(await popup.title(), limit=160) or "New window",
                                source="popup",
                            ))
                    except Exception as exc:
                        log_event(
                            logging.INFO,
                            "POPUP_OBSERVATION_FAILED",
                            scan_id=scan_id,
                            error=sanitized_diagnostic(str(exc)),
                        )
                    finally:
                        if not popup.is_closed():
                            await popup.close()

                page.on("popup", record_popup)

                async def route_guard(route: Route):
                    nonlocal navigation_policy_error
                    request = route.request
                    request_url = urlparse(request.url)
                    host = normalized_host(request_url.hostname or "")
                    portal_scoped = bool(host and host_in_scan_scope(
                        host,
                        root_host,
                        req.allow_subdomains,
                        approved_portal_hosts,
                    ))
                    resource_scoped = host in approved_resource_hosts
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
                        portal_scoped or resource_scoped or host in navigation_hosts
                    ):
                        await abort_by_validator(route, "third_party_resource_policy")
                        return

                    if request.method.upper() not in SAFE_READ_ONLY_METHODS:
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
                        if not auth_navigation_allowed:
                            await abort_by_validator(route, "read_only_mutation_policy")
                            return
                        if auth_navigation_allowed:
                            log_event(
                                logging.INFO,
                                "AUTHENTICATION_NAVIGATION_ALLOWED",
                                scan_id=scan_id,
                                hostname=host,
                                method=request.method.upper(),
                            )

                    headers = headers_for_destination(
                        request.headers,
                        sensitive_headers,
                        host,
                        credential_hosts,
                    )
                    await route.continue_(headers=headers)

                await context.route("**/*", route_guard)
                session_refresh: dict[str, object] = {"attempted": False}
                if refresh_config is not None:
                    current_tracker = NavigationTracker(req.max_redirects)
                    navigation_policy_error = None
                    navigation_hosts.clear()
                    authentication_navigation = AuthenticationNavigationPolicy()
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
                while queue and len(seen) < req.max_pages:
                    url, depth, route_label, route_source = queue.popleft()
                    route_identity = normalize_route_url(
                        url,
                        query_policy=req.query_parameter_policy,
                        allowed_query_parameters=set(req.allowed_query_parameters),
                    ) or url
                    if route_identity in seen or depth > req.max_depth:
                        continue
                    seen.add(route_identity)
                    current_tracker = NavigationTracker(req.max_redirects)
                    navigation_policy_error = None
                    navigation_hosts.clear()
                    authentication_navigation = AuthenticationNavigationPolicy()
                    requested_url = sanitized_url(url)
                    requested_host = normalized_host(urlparse(url).hostname or "")
                    final_url: str | None = None
                    final_raw_url = url
                    console_start = len(console_errors)
                    failed_start = len(failed_resources)
                    api_start = len(api_events)
                    popup_start = len(popup_routes)
                    started = time.perf_counter()
                    status: int | None = None
                    title: str | None = None
                    error: str | None = None
                    error_classification: str | None = None
                    authentication_classification: str | None = None
                    response_headers: dict[str, str] = {}
                    links: list[str] = []
                    discovered: list[DiscoveredRoute] = []
                    external_links: list[str] = []
                    redirects: list[dict] = []
                    render_health: dict[str, object] | None = None
                    navigation_actions = {"activated": 0, "skipped": 0}
                    frame_observations: list[dict[str, object]] = []
                    final_in_scope = False
                    remaining_ms = max(0, round((deadline - time.perf_counter()) * 1000))
                    if remaining_ms == 0:
                        error = "Total scan timeout exceeded"
                        error_classification = "TIMEOUT"
                    else:
                        log_event(
                            logging.INFO,
                            "NAVIGATION_STARTED",
                            scan_id=scan_id,
                            requested_url=url,
                            hostname=requested_host,
                            page_number=len(results) + 1,
                            crawl_depth=depth,
                        )
                        try:
                            response = await page.goto(
                                url,
                                wait_until="domcontentloaded",
                                timeout=min(req.timeout_ms, remaining_ms),
                            )
                            if response is None:
                                raise RuntimeError("Navigation completed without an HTTP response")
                            final_raw_url = page.url
                            final_url = sanitized_url(final_raw_url)
                            await reconcile_http_redirect_chain(response, current_tracker)
                            redirects = current_tracker.redirects()
                            for redirect in redirects:
                                log_event(logging.INFO, "REDIRECT_DETECTED", scan_id=scan_id, **redirect)
                                if not redirect["same_origin"]:
                                    log_event(logging.INFO, "CROSS_ORIGIN_REDIRECT", scan_id=scan_id, **redirect)
                            status = response.status
                            response_headers = {
                                name.lower(): value for name, value in (await response.all_headers()).items()
                            }
                            title = sanitize_text(await page.title(), limit=512)
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
                                "PAGE_LOADED",
                                scan_id=scan_id,
                                final_url=final_raw_url,
                                hostname=normalized_host(urlparse(final_raw_url).hostname or ""),
                                http_status=status,
                                redirect_count=len(redirects),
                                classification=authentication_classification,
                            )
                            if authentication_classification != "PASS":
                                log_event(
                                    logging.WARNING,
                                    authentication_classification,
                                    scan_id=scan_id,
                                    final_url=final_raw_url,
                                )
                            log_event(logging.INFO, "PAGE_VALIDATION_STARTED", scan_id=scan_id, final_url=final_raw_url)
                            if req.render_settle_ms:
                                await page.wait_for_timeout(req.render_settle_ms)
                            render_health = await capture_render_health(page)
                            frame_observations = [
                                {
                                    "url": sanitized_url(frame.url),
                                    "main_frame": frame == page.main_frame,
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
                                if req.max_navigation_actions:
                                    navigation_actions = await expand_safe_navigation(
                                        page,
                                        req.max_navigation_actions,
                                    )
                                    if navigation_actions["activated"]:
                                        await page.wait_for_timeout(min(500, req.render_settle_ms or 250))
                                discovered = await discover_page_routes(page)
                                discovered.extend(popup_routes[popup_start:])
                                links = [route.url for route in discovered]
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
                                if final_in_scope and depth < req.max_depth:
                                    metadata = {
                                        normalize_route_url(
                                            route.url,
                                            query_policy=req.query_parameter_policy,
                                            allowed_query_parameters=set(req.allowed_query_parameters),
                                        ): (route.label or "Discovered route", route.source)
                                        for route in discovered
                                    }
                                    for link in crawl_links:
                                        path = urlparse(link).path.lower()
                                        if not any(word in path for word in DANGEROUS_PATH_WORDS) and link not in discovered_routes:
                                            label, source = metadata.get(link, ("Discovered route", "semantic"))
                                            discovered_routes.add(link)
                                            queue.append((link, depth + 1, label, source))
                                            log_event(
                                                logging.DEBUG,
                                                "LINK_DISCOVERED",
                                                scan_id=scan_id,
                                                current_url=link,
                                                crawl_depth=depth + 1,
                                            )
                        except Exception as exc:
                            if navigation_policy_error is not None:
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

                    elapsed = round((time.perf_counter() - started) * 1000)
                    page_console = console_errors[console_start:] if req.check_console else []
                    page_failures = failed_resources[failed_start:] if req.check_resources else []
                    page_api_events = api_events[api_start:] if req.check_resources else []
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
                    header_report = {
                        name: response_headers.get(name) for name in header_names
                    } if req.check_security_headers else {}
                    missing_headers = [name for name, value in header_report.items() if not value]
                    render_classification: str | None = None
                    health_findings: list[dict] = []
                    if render_health is not None:
                        render_classification, health_findings = assess_page_health(
                            render_health,
                            load_ms=elapsed,
                            slow_page_threshold_ms=req.slow_page_threshold_ms,
                        )
                    health_findings.extend(api_health_findings([
                        event for event in page_api_events
                        if not event.get("blocked_by_validator")
                    ]))
                    classification = classify_page_result(
                        url=final_url or requested_url,
                        status=status,
                        error=error,
                        missing_security_headers=missing_headers,
                        console_errors=page_console,
                        failed_resources=page_failures,
                        security_headers_tested=req.check_security_headers,
                        authentication_classification=authentication_classification or error_classification,
                        render_classification=render_classification,
                        additional_findings=health_findings,
                    )
                    api_failure_count = sum(
                        bool(event.get("error"))
                        or (isinstance(event.get("status"), int) and event["status"] >= 400)
                        for event in page_api_events
                        if not event.get("blocked_by_validator")
                    )
                    read_only_blocks = sum(
                        failure.get("block_reason") == "read_only_mutation_policy"
                        for failure in page_failures
                    )
                    result = {
                        "url": final_url or requested_url,
                        "requested_url": requested_url,
                        "final_url": final_url,
                        "depth": depth,
                        "route_label": route_label,
                        "route_source": route_source,
                        "status": status,
                        "title": title,
                        "load_ms": elapsed if req.check_performance else None,
                        "error": error,
                        "redirect_count": len(redirects),
                        "redirects": redirects,
                        "links_found": len(links),
                        "routes_discovered": len(discovered),
                        "external_links_found": len(external_links),
                        "external_links": external_links[:100],
                        "console_errors": page_console,
                        "failed_resources": page_failures,
                        "resource_failure_count": unexpected_subresource_failures,
                        "api_requests": page_api_events,
                        "api_failures": api_failure_count,
                        "frames": frame_observations,
                        "render_health": render_health,
                        "slow": elapsed > req.slow_page_threshold_ms,
                        "navigation_actions": navigation_actions,
                        "unsafe_actions_skipped": navigation_actions["skipped"],
                        "read_only_blocks": read_only_blocks,
                        "security_headers": header_report,
                        "missing_security_headers": missing_headers,
                        **classification,
                    }
                    results.append(result)
                    log_event(
                        logging.INFO,
                        "PAGE_VALIDATION_COMPLETED",
                        scan_id=scan_id,
                        final_url=final_raw_url,
                        classification=result["classification"],
                        elapsed_ms=elapsed,
                    )
                    if time.perf_counter() >= deadline:
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
            finally:
                await browser.close()

    summary = aggregate_report(results, routes_discovered=len(discovered_routes))
    trust_status: TrustStatus = getattr(app.state, "trust_status", TrustStatus(enabled=False))
    log_event(
        logging.INFO,
        "SCAN_COMPLETED",
        scan_id=scan_id,
        pages=len(results),
        loaded=summary["loaded"],
        failed_to_load=summary["failed_to_load"],
        passed=summary["passed_pages"],
        findings=summary["total_findings"],
        classification=summary["classifications"],
    )
    return {
        "scan_id": scan_id,
        "run_id": scan_id,
        "target": sanitized_url(req.target),
        "pages": len(results),
        "summary": summary,
        "results": results,
        "session": session_refresh,
        "safety": {
            "crawl_scope": root_host,
            "navigation_redirects": "cross-origin-with-network-policy",
            "subdomains_enabled": req.allow_subdomains,
            "private_network_enabled": req.allow_private_networks,
            "read_only_enforced": True,
            "mutations_enabled": False,
            "approved_portal_hosts": sorted(approved_portal_hosts),
            "query_parameter_policy": req.query_parameter_policy,
            "authentication_mode": req.authentication.mode,
            "corporate_ca_trust": trust_status.enabled,
        },
    }
