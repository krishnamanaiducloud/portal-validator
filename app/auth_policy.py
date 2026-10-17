"""Operator-approved authentication destinations, independent of browser state."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from app.network import policy_hostname


AUTH_POLICIES_FILE_ENV = "PORTAL_VALIDATOR_AUTH_POLICIES_FILE"
MAX_POLICY_FILE_BYTES = 1024 * 1024
MAX_POLICIES = 100
MAX_HOSTS_PER_POLICY = 25
MAX_ENDPOINTS_PER_POLICY = 50
POLICY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
CONFIGURATION_ERROR = "Authentication policy configuration is invalid or unavailable."


class AuthenticationPolicyConfigurationError(ValueError):
    """A configured operator policy cannot be used safely."""


@dataclass(frozen=True)
class AuthenticationPolicy:
    id: str
    portal_hosts: frozenset[str]
    authentication_hosts: frozenset[str]
    authentication_endpoints: frozenset[str] = frozenset()


def canonical_authentication_endpoint(value: str) -> str:
    """Canonicalize one exact authentication POST endpoint, never authorize it.

    Endpoint configuration has no query, fragment, userinfo or wildcard
    semantics. Ambiguous path encodings fail closed. DNS, network and TLS
    validation remain the browser guard's responsibility.
    """
    try:
        if (not isinstance(value, str) or not value or len(value) > 4096
                or any(character.isspace() or ord(character) <= 32 or ord(character) == 127 for character in value)
                or any(character in value for character in ("?", "#", "\\"))):
            raise ValueError("Invalid endpoint URL")
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if (scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or "%" in parsed.netloc or parsed.netloc.endswith(":")):
            raise ValueError("Invalid endpoint origin")
        host = policy_hostname(parsed.hostname)
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid endpoint port")
        path = parsed.path or "/"
        if (len(path) > 2048 or "//" in path
                or re.search(r"%(?![A-Fa-f0-9]{2})", path)
                or re.search(r"%(?:2f|5c|25)", path, re.IGNORECASE)):
            raise ValueError("Invalid endpoint path")
        decoded_path = unquote(path, errors="strict")
        if (any(segment in {".", ".."} for segment in decoded_path.split("/"))
                or any(character in decoded_path for character in "\\*{}[]?#")
                or any(character.isspace() or ord(character) <= 32 or ord(character) == 127 for character in decoded_path)):
            raise ValueError("Invalid endpoint path")
        # Decode only RFC-unreserved characters. Reserved escaped characters
        # retain their meaning, while escape casing and literal Unicode become
        # deterministic across configuration and actual request matching.
        path = quote(path, safe="/%:@!$&'()+,;=-._~")
        path = re.sub(r"%([A-Fa-f0-9]{2})", lambda match: (
            chr(int(match[1], 16)) if re.fullmatch(r"[A-Za-z0-9._~-]", chr(int(match[1], 16)))
            else "%" + match[1].upper()
        ), path)
        netloc = f"[{host}]" if ":" in host else host
        if port is not None and port != {"http": 80, "https": 443}[scheme]:
            netloc += f":{port}"
        return urlunsplit((scheme, netloc, path, "", ""))
    except (ValueError, TypeError, UnicodeError):
        raise AuthenticationPolicyConfigurationError(CONFIGURATION_ERROR) from None


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _policy_hosts(value: object) -> frozenset[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_HOSTS_PER_POLICY:
        raise ValueError("Invalid policy host list")
    if not all(isinstance(host, str) for host in value):
        raise ValueError("Invalid policy hostname")
    return frozenset(policy_hostname(host) for host in value)


def load_authentication_policies(
    path: str | Path | None = None,
) -> tuple[AuthenticationPolicy, ...]:
    """Read an optional strict operator policy without consulting session state.

    An unset environment variable leaves existing explicit scan approvals
    unchanged. A configured but unusable file raises a generic error rather
    than silently removing the operator policy. Kubernetes ConfigMap file
    symlinks may resolve to backing files within their mounted directory.
    """
    configured = path if path is not None else os.getenv(AUTH_POLICIES_FILE_ENV)
    if configured is None:
        return ()
    try:
        if not isinstance(configured, (str, Path)) or not str(configured).strip():
            raise ValueError("Invalid policy file")
        requested = Path(configured)
        mount_root = requested.parent.resolve(strict=True)
        resolved = requested.resolve(strict=True)
        if mount_root not in resolved.parents or not resolved.is_file():
            raise ValueError("Invalid policy file")
        with resolved.open("rb") as handle:
            payload = handle.read(MAX_POLICY_FILE_BYTES + 1)
        if not payload or len(payload) > MAX_POLICY_FILE_BYTES:
            raise ValueError("Invalid policy file size")
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_json_object)
        if not isinstance(document, dict) or set(document) != {"version", "policies"}:
            raise ValueError("Invalid policy document")
        if type(document["version"]) is not int or document["version"] != 1:
            raise ValueError("Unsupported policy version")
        entries = document["policies"]
        if not isinstance(entries, list) or len(entries) > MAX_POLICIES:
            raise ValueError("Invalid policy list")
        policies: list[AuthenticationPolicy] = []
        identifiers: set[str] = set()
        for entry in entries:
            required_fields = {"id", "portal_hosts", "authentication_hosts"}
            if (not isinstance(entry, dict) or not required_fields <= set(entry)
                    or set(entry) - required_fields - {"authentication_endpoints"}):
                raise ValueError("Invalid policy entry")
            identifier = entry["id"]
            if (not isinstance(identifier, str) or not POLICY_ID_RE.fullmatch(identifier)
                    or identifier in identifiers):
                raise ValueError("Invalid policy identifier")
            identifiers.add(identifier)
            portal_hosts = _policy_hosts(entry["portal_hosts"])
            authentication_hosts = _policy_hosts(entry["authentication_hosts"])
            endpoint_values = entry.get("authentication_endpoints", [])
            if not isinstance(endpoint_values, list) or len(endpoint_values) > MAX_ENDPOINTS_PER_POLICY:
                raise ValueError("Invalid endpoint list")
            endpoints = frozenset(canonical_authentication_endpoint(endpoint) for endpoint in endpoint_values)
            if any(policy_hostname(urlsplit(endpoint).hostname) not in portal_hosts | authentication_hosts
                   for endpoint in endpoints):
                raise ValueError("Endpoint host is outside approved policy scope")
            policies.append(AuthenticationPolicy(
                id=identifier,
                portal_hosts=portal_hosts,
                authentication_hosts=authentication_hosts,
                authentication_endpoints=endpoints,
            ))
        return tuple(policies)
    except (OSError, ValueError, TypeError, RecursionError):
        raise AuthenticationPolicyConfigurationError(CONFIGURATION_ERROR) from None


def approved_authentication_hosts_for_target(
    host: str, policies: Iterable[AuthenticationPolicy],
) -> tuple[frozenset[str], tuple[str, ...]]:
    """Return explicit approvals only for an exact configured portal hostname."""
    try:
        if not isinstance(host, str):
            raise ValueError("Invalid target hostname")
        target = policy_hostname(host)
    except ValueError:
        raise AuthenticationPolicyConfigurationError("Authentication policy target host is invalid.") from None
    approved: set[str] = set()
    matched_ids: set[str] = set()
    for policy in policies:
        if target in policy.portal_hosts:
            approved.update(policy.authentication_hosts)
            matched_ids.add(policy.id)
    return frozenset(approved), tuple(sorted(matched_ids))


def approved_authentication_endpoints_for_target(
    host: str, policies: Iterable[AuthenticationPolicy],
) -> frozenset[str]:
    """Return exact configured POST endpoints within an exact portal policy."""
    try:
        if not isinstance(host, str):
            raise ValueError("Invalid target hostname")
        target = policy_hostname(host)
    except ValueError:
        raise AuthenticationPolicyConfigurationError("Authentication policy target host is invalid.") from None
    return frozenset(
        endpoint for policy in policies if target in policy.portal_hosts
        for endpoint in policy.authentication_endpoints
    )
