from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
SENSITIVE_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
})
SENSITIVE_KEYS = frozenset({
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "code",
    "authorization_code",
    "client_secret",
    "api_key",
    "apikey",
    "key",
    "password",
    "passwd",
    "secret",
    "assertion",
    "samlresponse",
    "samlrequest",
    "session",
    "session_id",
    "code_verifier",
    "code_challenge",
    "state",
    "storage_state",
    "localstorage",
    "sessionstorage",
})
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{4,})?\b")
AUTH_VALUE_RE = re.compile(r"(?i)\b(Basic|Bearer)\s+[A-Za-z0-9._~+/=-]+")
HEADER_LINE_RE = re.compile(
    r"(?i)\b(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-API-Key|"
    r"X-Auth-Token|X-CSRF-Token|X-XSRF-Token)\s*[:=]\s*[^\r\n]+"
)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(token|access_token|refresh_token|id_token|code|authorization_code|"
    r"client_secret|api_key|apikey|password|passwd|secret|assertion|SAMLResponse|"
    r"SAMLRequest|session|session_id|code_verifier|code_challenge|state)"
    r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^,;\s&}\]]+)"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)
METADATA_ADDRESSES = frozenset({
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
})


@dataclass(frozen=True)
class DestinationError(ValueError):
    classification: str
    public_message: str

    def __str__(self) -> str:
        return self.public_message


def normalized_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in SENSITIVE_KEYS or normalized in {
        header.replace("-", "_") for header in SENSITIVE_HEADERS
    }


def sanitize_url(value: str, *, include_path: bool = True) -> str:
    try:
        parsed = urlparse(value)
    except (TypeError, ValueError):
        return "[REDACTED_URL]"
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return "[REDACTED_URL]"
    host = normalized_host(parsed.hostname)
    display_host = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError:
        return "[REDACTED_URL]"
    netloc = f"{display_host}:{port}" if port is not None else display_host
    query = urlencode([
        (key, "[REDACTED]" if is_sensitive_key(key) else item_value)
        for key, item_value in parse_qsl(parsed.query, keep_blank_values=True)
    ], doseq=True)
    return urlunparse((
        parsed.scheme.lower(),
        netloc,
        parsed.path if include_path else "",
        "",
        query,
        "",
    ))


def sanitize_text(value: object, *, limit: int = 4000) -> str:
    text = str(value)
    text = PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    text = URL_RE.sub(lambda match: sanitize_url(match.group(0)), text)
    text = HEADER_LINE_RE.sub(lambda match: f"{match.group(1)}: [REDACTED]", text)
    text = AUTH_VALUE_RE.sub(lambda match: f"{match.group(1)} [REDACTED]", text)
    text = JWT_RE.sub("[REDACTED_JWT]", text)
    text = SENSITIVE_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        text,
    )
    return text[:limit]


def sanitize_data(value: Any, *, key: object | None = None) -> Any:
    if key is not None and is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): sanitize_data(item_value, key=item_key) for item_key, item_value in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [sanitize_data(item) for item in value]
    if isinstance(value, bytes):
        return "[REDACTED_BYTES]"
    if isinstance(value, str):
        return sanitize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_text(value)


def sanitized_exception(exc: BaseException) -> str:
    first_line = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
    return sanitize_text(first_line, limit=1000)


def validate_http_url(value: str) -> tuple[str, int | None]:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise DestinationError("NAVIGATION_ERROR", "URL contains an invalid port") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise DestinationError("NAVIGATION_ERROR", "Destination must be an HTTP or HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise DestinationError("NAVIGATION_ERROR", "Destination URLs must not contain embedded credentials")
    if port is not None and port not in ALLOWED_PORTS:
        raise DestinationError("NAVIGATION_ERROR", "Destination port is not allowed")
    return normalized_host(parsed.hostname), port


def validate_resolved_addresses(addresses: set[str], allow_private: bool) -> list[str]:
    validated: list[str] = []
    for raw_ip in sorted(addresses):
        ip = ipaddress.ip_address(raw_ip.split("%", 1)[0])
        if ip in METADATA_ADDRESSES:
            raise DestinationError("NETWORK_ERROR", "Cloud metadata destinations are blocked")
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise DestinationError("NETWORK_ERROR", "Destination address is blocked by network policy")
        if not ip.is_global and not allow_private:
            raise DestinationError("NETWORK_ERROR", "Private-network destination requires explicit approval")
        validated.append(str(ip))
    if not validated:
        raise DestinationError("DNS_ERROR", "Destination host resolved to no addresses")
    return validated


async def resolve_and_validate(host: str, allow_private: bool) -> list[str]:
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo,
            host,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise DestinationError("DNS_ERROR", "Destination hostname could not be resolved") from exc
    return validate_resolved_addresses({info[4][0] for info in infos}, allow_private)
