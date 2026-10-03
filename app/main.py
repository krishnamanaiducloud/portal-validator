from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import os
import re
import socket
import time
import uuid
from collections import Counter, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urldefrag, urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr, field_validator
from playwright.async_api import BrowserContext, Route, async_playwright

from app.trust import TrustStatus, configure_ca_trust

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
AUTH_STATE_DIR = Path(os.getenv("SESSION_STATE_DIR", "/auth"))
MAX_CONCURRENT_SCANS = max(1, int(os.getenv("MAX_CONCURRENT_SCANS", "2")))
SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
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
TLS_ERROR_RE = re.compile(r"net::ERR_CERT_[A-Z0-9_]+")
URL_IN_MESSAGE_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
COMMON_COUNTRY_CODE_SECOND_LEVEL_LABELS = frozenset({
    "ac", "co", "com", "edu", "gov", "net", "org",
})
LOGGER = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.trust_status = configure_ca_trust()
    yield


app = FastAPI(
    title="Portal Validator",
    version="1.1.2",
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
    target: str = Field(min_length=8, max_length=4096)
    max_pages: int = Field(25, ge=1, le=250)
    max_depth: int = Field(3, ge=0, le=10)
    timeout_ms: int = Field(15000, ge=1000, le=120000)
    check_links: bool = True
    check_console: bool = True
    check_resources: bool = True
    check_performance: bool = True
    check_security_headers: bool = True
    allow_subdomains: bool = False
    allow_private_networks: bool = False
    resource_hosts: list[str] = Field(default_factory=list, max_length=50)
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

    @field_validator("resource_hosts")
    @classmethod
    def validate_resource_hosts(cls, hosts: list[str]):
        cleaned = []
        for host in hosts:
            value = host.strip().lower().rstrip(".")
            if not value or "/" in value or "://" in value:
                raise ValueError(f"Resource host must be a hostname: {host}")
            cleaned.append(value)
        return list(dict.fromkeys(cleaned))


def normalized_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


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
    return bool(parsed.scheme in {"http", "https"} and parsed.hostname and host_in_scope(parsed.hostname, root_host, allow_subdomains))


def evaluate_navigation_scope(
    requested_url: str,
    final_url: str,
    root_host: str,
    allow_subdomains: bool,
) -> tuple[str, str, bool]:
    requested = urlparse(requested_url)
    final = urlparse(final_url)
    requested_host = normalized_host(requested.hostname or "")
    final_host = normalized_host(final.hostname or "")
    accepted = bool(
        final.scheme in {"http", "https"}
        and final_host
        and host_in_scope(final_host, root_host, allow_subdomains)
    )
    return requested_host, final_host, accepted


def sanitized_url(value: str, *, include_path: bool = True) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return "[redacted-url]"
    host = normalized_host(parsed.hostname)
    display_host = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{display_host}:{port}" if port is not None else display_host
    path = parsed.path if include_path else ""
    return f"{parsed.scheme}://{netloc}{path or ''}"


def sanitized_diagnostic(value: str) -> str:
    first_line = value.splitlines()[0] if value else "Unknown navigation error"
    return URL_IN_MESSAGE_RE.sub(
        lambda match: sanitized_url(match.group(0), include_path=False),
        first_line,
    )[:1000]


async def validate_destination(host: str, allow_private: bool) -> None:
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(400, f"Cannot resolve target host: {exc}") from exc
    for raw_ip in {info[4][0] for info in infos}:
        ip = ipaddress.ip_address(raw_ip.split("%", 1)[0])
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise HTTPException(400, f"Blocked destination address: {ip}")
        if ip.is_private and not allow_private:
            raise HTTPException(400, "Private-network target requires explicit approval")


def storage_state_path(profile: str | None) -> Path:
    if not profile or not PROFILE_RE.fullmatch(profile):
        raise HTTPException(400, "Storage-state profile name is invalid")
    path = (AUTH_STATE_DIR / f"{profile}.json").resolve()
    root = AUTH_STATE_DIR.resolve()
    if root not in path.parents or not path.is_file():
        raise HTTPException(400, "Storage-state profile was not found")
    return path


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


def classify_page_result(
    *,
    url: str,
    status: int | None,
    error: str | None,
    missing_security_headers: list[str],
    console_errors: list[str],
    failed_resources: list[dict],
    security_headers_tested: bool,
) -> dict[str, str | int | bool | None]:
    loaded = error is None and status is not None
    page_load_status = "LOADED" if loaded else "FAILED_TO_LOAD"

    if error and TLS_ERROR_RE.search(error):
        category = "TLS_CERTIFICATE_ERROR"
    elif error and "outside the approved portal scope" in error:
        category = "SCOPE_VIOLATION"
    elif error and "Timeout" in error:
        category = "TIMEOUT"
    elif error:
        category = "PAGE_LOAD_ERROR"
    elif status is not None and status >= 400:
        category = "HTTP_ERROR"
    else:
        category = None

    if category == "TLS_CERTIFICATE_ERROR":
        tls_status = "UNTRUSTED"
        tls_basis = "BROWSER_CERTIFICATE_VALIDATION"
        tls_detail = "Chromium rejected the HTTPS certificate chain."
    elif loaded and urlparse(url).scheme == "https":
        tls_status = "TRUSTED"
        tls_basis = "BROWSER_CERTIFICATE_VALIDATION"
        tls_detail = "Chromium established HTTPS with certificate verification enabled; the origin certificate was not independently inspected."
    elif loaded:
        tls_status = "NOT_APPLICABLE"
        tls_basis = "NOT_APPLICABLE"
        tls_detail = "The final page used HTTP rather than HTTPS."
    else:
        tls_status = "NOT_TESTED"
        tls_basis = "NOT_TESTED"
        tls_detail = "Browser TLS trust could not be evaluated because main-document navigation did not complete."

    if not loaded or not security_headers_tested:
        security_headers_status = "NOT_TESTED"
    elif missing_security_headers:
        security_headers_status = "WARNING"
    else:
        security_headers_status = "PASS"

    findings = (
        len(missing_security_headers)
        + len(console_errors)
        + len(failed_resources)
        + int(bool(status is not None and status >= 400))
    )
    if not loaded:
        validation_status = "NOT_TESTED"
    elif status is not None and status >= 400:
        validation_status = "FAIL"
    elif findings:
        validation_status = "WARNING"
        category = category or "VALIDATION_FINDINGS"
    else:
        validation_status = "PASS"

    return {
        "page_load_status": page_load_status,
        "validation_status": validation_status,
        "category": category,
        "tls_status": tls_status,
        "tls_basis": tls_basis,
        "tls_detail": tls_detail,
        "security_headers_status": security_headers_status,
        "findings": findings,
        "passed": loaded and validation_status != "FAIL",
    }


async def configure_cookies(context: BrowserContext, req: ScanRequest, root_host: str) -> None:
    if req.authentication.mode != "cookies":
        return
    if not req.authentication.cookies:
        raise HTTPException(400, "Cookie authentication requires at least one cookie")
    cookies = []
    for cookie in req.authentication.cookies:
        domain = normalized_host(cookie.domain or root_host)
        if not host_in_scope(domain.lstrip("."), root_host, req.allow_subdomains):
            raise HTTPException(400, f"Cookie domain is outside the approved portal scope: {domain}")
        cookies.append({"name": cookie.name, "value": cookie.value.get_secret_value(), "domain": domain, "path": cookie.path, "secure": cookie.secure, "httpOnly": cookie.http_only, "sameSite": cookie.same_site})
    await context.add_cookies(cookies)


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok", "version": app.version}


@app.get("/api/auth-profiles")
async def auth_profiles():
    if not AUTH_STATE_DIR.is_dir():
        return {"profiles": []}
    return {"profiles": sorted(path.stem for path in AUTH_STATE_DIR.glob("*.json") if PROFILE_RE.fullmatch(path.stem))}


@app.post("/api/scan")
async def scan(req: ScanRequest):
    parsed = urlparse(req.target.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Target must be an http(s) URL without embedded credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(400, "Target contains an invalid port") from exc
    if port not in {None, 80, 443, 8080, 8443}:
        raise HTTPException(400, "Target port is not allowed")
    root_host = normalized_host(parsed.hostname)
    await validate_destination(root_host, req.allow_private_networks)
    if req.allow_mutations and not req.mutation_acknowledged:
        raise HTTPException(400, "Mutation testing requires explicit acknowledgement")
    if req.allow_mutations and not req.mutation_endpoint_allowlist:
        raise HTTPException(400, "Mutation testing requires an endpoint allowlist")
    for prefix in req.mutation_endpoint_allowlist:
        if not prefix.startswith("/") or ".." in prefix:
            raise HTTPException(400, "Mutation allowlist entries must be safe absolute paths")

    approved_resource_hosts = {normalized_host(host) for host in req.resource_hosts}
    for host in approved_resource_hosts:
        await validate_destination(host, req.allow_private_networks)
    sensitive_headers = auth_headers(req.authentication)
    state_path = storage_state_path(req.authentication.storage_profile) if req.authentication.mode == "storage_state" else None
    run_id = str(uuid.uuid4())
    results: list[dict] = []
    queue = deque([(urldefrag(req.target.strip()).url, 0)])
    seen: set[str] = set()
    LOGGER.info(
        "Portal scan started run_id=%s requested_host=%s allow_subdomains=%s",
        run_id,
        root_host,
        req.allow_subdomains,
    )

    async with SCAN_SEMAPHORE:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage"],
            )
            try:
                context_args = {"ignore_https_errors": False, "service_workers": "block"}
                if state_path:
                    context_args["storage_state"] = str(state_path)
                context = await browser.new_context(**context_args)
                await configure_cookies(context, req, root_host)
                page = await context.new_page()
                console_errors: list[str] = []
                failed_resources: list[dict] = []
                blocked_main_navigation_host: str | None = None
                blocked_main_navigation_url: str | None = None

                def record_console_error(message):
                    if message.type == "error":
                        console_errors.append(sanitized_diagnostic(message.text))

                def record_failed_request(request):
                    try:
                        is_main_document = bool(
                            request.is_navigation_request()
                            and request.frame == page.main_frame
                        )
                    except Exception:
                        is_main_document = False
                    failed_resources.append({
                        "url": sanitized_url(request.url),
                        "error": sanitized_diagnostic(request.failure or "Request failed"),
                        "resource_type": request.resource_type,
                        "main_document": is_main_document,
                    })

                page.on("console", record_console_error)
                page.on("requestfailed", record_failed_request)

                async def route_guard(route: Route):
                    nonlocal blocked_main_navigation_host, blocked_main_navigation_url
                    request = route.request
                    request_url = urlparse(request.url)
                    host = normalized_host(request_url.hostname or "")
                    portal_scoped = bool(host and host_in_scope(host, root_host, req.allow_subdomains))
                    resource_scoped = host in approved_resource_hosts
                    try:
                        is_main_navigation = bool(
                            request.is_navigation_request()
                            and request.frame == page.main_frame
                        )
                    except Exception:
                        is_main_navigation = False
                    if request.is_navigation_request() and not portal_scoped:
                        if is_main_navigation:
                            blocked_main_navigation_host = host
                            blocked_main_navigation_url = sanitized_url(request.url)
                            LOGGER.warning(
                                "Rejected out-of-scope redirect run_id=%s final_host=%s",
                                run_id,
                                host or "unknown",
                            )
                        await route.abort("blockedbyclient")
                        return
                    if request_url.scheme not in {"http", "https"} or not (portal_scoped or resource_scoped):
                        await route.abort("blockedbyclient")
                        return
                    if request.method.upper() in MUTATING_METHODS:
                        allowed = req.allow_mutations and portal_scoped and any(request_url.path.startswith(prefix) for prefix in req.mutation_endpoint_allowlist)
                        if not allowed:
                            await route.abort("blockedbyclient")
                            return
                    headers = request.headers.copy()
                    if portal_scoped:
                        headers.update(sensitive_headers)
                    await route.continue_(headers=headers)

                await context.route("**/*", route_guard)
                while queue and len(seen) < req.max_pages:
                    url, depth = queue.popleft()
                    if url in seen or depth > req.max_depth:
                        continue
                    seen.add(url)
                    requested_url = sanitized_url(url)
                    requested_host = normalized_host(urlparse(url).hostname or "")
                    final_url: str | None = None
                    final_host = ""
                    blocked_main_navigation_host = None
                    blocked_main_navigation_url = None
                    console_start, failed_start = len(console_errors), len(failed_resources)
                    started = time.perf_counter()
                    status = title = error = None
                    headers: dict[str, str] = {}
                    links: list[str] = []
                    LOGGER.info(
                        "Portal navigation started run_id=%s requested_host=%s depth=%d",
                        run_id,
                        requested_host,
                        depth,
                    )
                    try:
                        response = await page.goto(url, wait_until="domcontentloaded", timeout=req.timeout_ms)
                        if response is None:
                            raise RuntimeError("Navigation completed without an HTTP response")
                        final_url = sanitized_url(page.url)
                        requested_host, final_host, navigation_accepted = evaluate_navigation_scope(
                            url,
                            page.url,
                            root_host,
                            req.allow_subdomains,
                        )
                        LOGGER.info(
                            "Portal navigation completed run_id=%s requested_host=%s final_host=%s",
                            run_id,
                            requested_host,
                            final_host,
                        )
                        if not navigation_accepted:
                            LOGGER.warning(
                                "Rejected out-of-scope redirect run_id=%s requested_host=%s final_host=%s",
                                run_id,
                                requested_host,
                                final_host or "unknown",
                            )
                            raise RuntimeError(
                                "Navigation redirected outside the approved portal scope: "
                                f"requested_host={requested_host} final_host={final_host or 'unknown'}"
                            )
                        if requested_host != final_host:
                            LOGGER.info(
                                "Accepted in-scope redirect run_id=%s requested_host=%s final_host=%s",
                                run_id,
                                requested_host,
                                final_host,
                            )
                        status = response.status if response else None
                        headers = await response.all_headers() if response else {}
                        title = await page.title()
                        if req.check_links:
                            links = await page.locator("a[href]").evaluate_all("elements => elements.map(element => element.href)")
                            if depth < req.max_depth:
                                for link in links:
                                    clean = urldefrag(link).url
                                    path = urlparse(clean).path.lower()
                                    if clean and url_in_scope(clean, root_host, req.allow_subdomains) and not any(word in path for word in DANGEROUS_PATH_WORDS) and clean not in seen:
                                        queue.append((clean, depth + 1))
                    except Exception as exc:
                        if blocked_main_navigation_host:
                            final_host = blocked_main_navigation_host
                            final_url = blocked_main_navigation_url
                            error = (
                                "Navigation redirected outside the approved portal scope: "
                                f"requested_host={requested_host} final_host={final_host}"
                            )
                        else:
                            error = sanitized_diagnostic(str(exc))
                        LOGGER.warning(
                            "Main navigation failed run_id=%s requested_host=%s final_host=%s error=%s",
                            run_id,
                            requested_host,
                            final_host or "unknown",
                            error,
                        )
                    elapsed = round((time.perf_counter() - started) * 1000)
                    header_report = {name: headers.get(name) for name in SECURITY_HEADERS} if req.check_security_headers else {}
                    page_console = console_errors[console_start:] if req.check_console else []
                    page_failures = failed_resources[failed_start:] if req.check_resources else []
                    subresource_failures = sum(
                        not failure["main_document"] for failure in page_failures
                    )
                    if subresource_failures:
                        LOGGER.warning(
                            "Subresource failures recorded run_id=%s requested_host=%s count=%d",
                            run_id,
                            requested_host,
                            subresource_failures,
                        )
                    missing_headers = [name for name, value in header_report.items() if not value]
                    classification = classify_page_result(
                        url=final_url or requested_url,
                        status=status,
                        error=error,
                        missing_security_headers=missing_headers,
                        console_errors=page_console,
                        failed_resources=page_failures,
                        security_headers_tested=req.check_security_headers,
                    )
                    results.append({
                        "url": final_url or requested_url,
                        "requested_url": requested_url,
                        "final_url": final_url,
                        "depth": depth, "status": status, "title": title,
                        "load_ms": elapsed if req.check_performance else None, "error": error,
                        "links_found": len(links), "console_errors": page_console,
                        "failed_resources": page_failures, "security_headers": header_report,
                        "missing_security_headers": missing_headers,
                        **classification,
                    })
                await context.close()
            finally:
                await browser.close()

    load_counts = Counter(result["page_load_status"] for result in results)
    validation_counts = Counter(result["validation_status"] for result in results)
    trust_status: TrustStatus = getattr(app.state, "trust_status", TrustStatus(enabled=False))
    LOGGER.info(
        "Portal scan completed run_id=%s pages=%d loaded=%d failed_to_load=%d findings=%d",
        run_id,
        len(results),
        load_counts["LOADED"],
        load_counts["FAILED_TO_LOAD"],
        sum(result["findings"] for result in results),
    )
    return {
        "run_id": run_id, "target": sanitized_url(req.target), "pages": len(results),
        "summary": {
            "loaded": load_counts["LOADED"],
            "failed_to_load": load_counts["FAILED_TO_LOAD"],
            "pass": validation_counts["PASS"],
            "warning": validation_counts["WARNING"],
            "fail": validation_counts["FAIL"],
            "not_tested": validation_counts["NOT_TESTED"],
            # Retain the original aggregate fields for existing API consumers.
            # A loaded page with warnings remains successful for this legacy view.
            "passed": validation_counts["PASS"] + validation_counts["WARNING"],
            "failed": validation_counts["FAIL"] + load_counts["FAILED_TO_LOAD"],
            "findings": sum(result["findings"] for result in results),
            "duration_ms": sum(result["load_ms"] or 0 for result in results),
        },
        "results": results,
        "safety": {"navigation_scope": root_host, "subdomains_enabled": req.allow_subdomains, "private_network_enabled": req.allow_private_networks, "mutations_enabled": req.allow_mutations, "authentication_mode": req.authentication.mode, "corporate_ca_trust": trust_status.enabled},
    }
