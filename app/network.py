from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from app.security import JWT_RE, SENSITIVE_KEYS, normalized_host, sanitize_text, sanitize_url


SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
VALID_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9-]{0,31}$")
UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
HEX_IDENTIFIER_RE = re.compile(r"^[0-9a-f]{24,64}$", re.IGNORECASE)
INTEGER_IDENTIFIER_RE = re.compile(r"^[0-9]{2,}$")
OPAQUE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_-]{32,}$")
SENSITIVE_PATH_LABELS = frozenset(
    key.replace("-", "_").lower() for key in SENSITIVE_KEYS
)
POLICY_CLASSIFICATIONS = frozenset({
    "APPROVED_READ_POST",
    "APPROVED_READ_REQUEST",
    "SESSION_REFRESH",
    "ACCESS_GATE",
})


def normalize_api_endpoint(path: str) -> str:
    """Return a query-free, conservatively normalized and redacted API path."""
    if not path:
        return "/"
    parsed_path = urlparse(path).path if "://" in path else path.split("?", 1)[0].split("#", 1)[0]
    segments = parsed_path.split("/")
    output: list[str] = []
    previous = ""
    for raw_segment in segments:
        if not raw_segment:
            continue
        decoded = unquote(raw_segment)
        normalized_label = decoded.strip().lower().replace("-", "_")
        if previous in SENSITIVE_PATH_LABELS:
            output.append("{redacted}")
        elif JWT_RE.search(decoded):
            output.append("{redacted}")
        elif (
            UUID_SEGMENT_RE.fullmatch(decoded)
            or HEX_IDENTIFIER_RE.fullmatch(decoded)
            or INTEGER_IDENTIFIER_RE.fullmatch(decoded)
            or OPAQUE_IDENTIFIER_RE.fullmatch(decoded)
        ):
            output.append("{id}")
        else:
            output.append(raw_segment[:256])
        previous = normalized_label
    normalized = "/" + "/".join(output)
    return normalized[:2048] or "/"


def safe_api_identity(url: str) -> tuple[str, str, str]:
    parsed = urlparse(url)
    host = normalized_host(parsed.hostname or "")
    endpoint = normalize_api_endpoint(parsed.path or "/")
    origin = sanitize_url(url, include_path=False).split("?", 1)[0]
    safe_url = f"{origin}{endpoint}" if origin != "[REDACTED_URL]" else origin
    return safe_url, host, endpoint


@dataclass(frozen=True)
class ApprovedRequestRule:
    method: str
    host: str
    path: str
    classification: str

    def matches(self, method: str, url: str) -> bool:
        parsed = urlparse(url)
        return (
            method.upper() == self.method
            and normalized_host(parsed.hostname or "") == self.host
            # The execution policy is exact. Inventory normalization must never
            # broaden an administrator-approved path into a wildcard.
            and (parsed.path or "/") == self.path
        )


@dataclass(frozen=True)
class AccessGateRule:
    host: str
    selector: str


@dataclass(frozen=True)
class ReadOnlyPolicy:
    safe_application_requests: tuple[ApprovedRequestRule, ...] = ()
    access_gates: tuple[AccessGateRule, ...] = ()

    def match(self, method: str, url: str) -> ApprovedRequestRule | None:
        return next(
            (rule for rule in self.safe_application_requests if rule.matches(method, url)),
            None,
        )

    def access_gate_for(self, url: str) -> AccessGateRule | None:
        host = normalized_host(urlparse(url).hostname or "")
        return next((rule for rule in self.access_gates if rule.host == host), None)


def load_read_only_policy(
    *,
    raw: str | None = None,
    path: str | Path | None = None,
) -> ReadOnlyPolicy:
    """Load administrator-owned read-only exceptions from JSON, never scan input."""
    configured_raw = raw if raw is not None else os.getenv("PORTAL_VALIDATOR_READ_ONLY_POLICY")
    configured_path = path if path is not None else os.getenv("PORTAL_VALIDATOR_READ_ONLY_POLICY_FILE")
    if configured_raw and configured_path:
        raise ValueError("Configure one read-only policy source, not both")
    if configured_path:
        policy_path = Path(configured_path)
        if not policy_path.is_file() or policy_path.stat().st_size > 64 * 1024:
            raise ValueError("Read-only policy file is missing or too large")
        configured_raw = policy_path.read_text(encoding="utf-8")
    if not configured_raw:
        return ReadOnlyPolicy()
    try:
        data = json.loads(configured_raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Read-only policy is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("Read-only policy must be a JSON object")
    request_items = data.get("safe_application_requests", [])
    gate_items = data.get("access_gates", [])
    if not isinstance(request_items, list) or len(request_items) > 100:
        raise ValueError("safe_application_requests must contain at most 100 rules")
    if not isinstance(gate_items, list) or len(gate_items) > 25:
        raise ValueError("access_gates must contain at most 25 rules")

    rules: list[ApprovedRequestRule] = []
    for item in request_items:
        if not isinstance(item, dict):
            raise ValueError("Each safe application request rule must be an object")
        method = str(item.get("method") or "").strip().upper()
        host = normalized_host(str(item.get("host") or ""))
        raw_path = str(item.get("path") or "").strip()
        classification = str(
            item.get("classification")
            or ("APPROVED_READ_POST" if method == "POST" else "APPROVED_READ_REQUEST")
        ).strip().upper()
        if not VALID_METHOD_RE.fullmatch(method) or method in SAFE_HTTP_METHODS:
            raise ValueError("Policy methods must be explicit mutation-capable HTTP methods")
        if not host or "/" in host or "://" in host:
            raise ValueError("Policy rule host must be an exact hostname")
        if not raw_path.startswith("/") or "?" in raw_path or "#" in raw_path:
            raise ValueError("Policy rule path must be an exact query-free absolute path")
        if classification not in POLICY_CLASSIFICATIONS:
            raise ValueError("Policy rule classification is not supported")
        rules.append(ApprovedRequestRule(
            method=method,
            host=host,
            path=raw_path,
            classification=classification,
        ))

    gates: list[AccessGateRule] = []
    for item in gate_items:
        if not isinstance(item, dict):
            raise ValueError("Each access gate rule must be an object")
        host = normalized_host(str(item.get("host") or ""))
        selector = str(item.get("selector") or "").strip()
        if not host or "/" in host or "://" in host:
            raise ValueError("Access gate host must be an exact hostname")
        if not selector or len(selector) > 512:
            raise ValueError("Access gate selector is missing or too long")
        gates.append(AccessGateRule(host=host, selector=selector))
    return ReadOnlyPolicy(tuple(rules), tuple(gates))


class PassiveNetworkObserver:
    """Correlate request lifecycles while retaining metadata-only attempt records."""

    def __init__(self, events: list[dict[str, Any]]):
        self.events = events
        self._events_by_request: dict[int, dict[str, Any]] = {}

    def observe_request(
        self,
        request: Any,
        *,
        phase: str,
        importance: str,
        initiating_route: str | None,
        main_document: bool,
    ) -> dict[str, Any]:
        key = id(request)
        existing = self._events_by_request.get(key)
        if existing is not None:
            return existing
        method = str(request.method).upper()
        safe_url, host, endpoint = safe_api_identity(str(request.url))
        event: dict[str, Any] = {
            "url": safe_url,
            "host": host,
            "endpoint": endpoint,
            "method": method,
            "status": None,
            "error": None,
            "blocked_by_validator": False,
            "block_reason": None,
            "protocol": "GRAPHQL" if endpoint.lower().endswith("/graphql") else "REST",
            "resource_type": str(request.resource_type),
            "phase": phase,
            "importance": importance,
            "observed_at": _observed_at(),
            "duration_ms": None,
            "initiating_route": initiating_route,
            "main_document": main_document,
            "request_classification": "SAFE_METHOD" if method in SAFE_HTTP_METHODS else "UNKNOWN",
            "allowed_by_policy": method in SAFE_HTTP_METHODS,
            "target_reached": None,
            "lifecycle": "REQUESTED",
            "_started_at": time.perf_counter(),
        }
        self._events_by_request[key] = event
        self.events.append(event)
        return event

    def mark_allowed(
        self,
        request: Any,
        classification: str,
        *,
        phase: str | None = None,
        importance: str | None = None,
    ) -> dict[str, Any] | None:
        event = self._events_by_request.get(id(request))
        if event is None:
            return None
        event["request_classification"] = classification
        event["allowed_by_policy"] = True
        event["lifecycle"] = "ALLOWED"
        if phase is not None:
            event["phase"] = phase
        if importance is not None:
            event["importance"] = importance
        return event

    def mark_blocked(
        self,
        request: Any,
        reason: str,
        *,
        classification: str = "BLOCKED_MUTATION",
    ) -> dict[str, Any] | None:
        event = self._events_by_request.get(id(request))
        if event is None:
            return None
        event.update({
            "blocked_by_validator": True,
            "block_reason": reason,
            "request_classification": classification,
            "allowed_by_policy": False,
            "target_reached": False,
            "lifecycle": "BLOCKED",
            "duration_ms": self._duration(event),
        })
        return event

    def record_response(self, request: Any, status: int) -> dict[str, Any] | None:
        event = self._events_by_request.get(id(request))
        if event is None or event.get("lifecycle") == "BLOCKED":
            return event
        if event.get("lifecycle") == "RESPONSE":
            return event
        if event.get("request_classification") == "UNKNOWN":
            event["request_classification"] = "APPLICATION_REQUEST"
        event.update({
            "status": int(status),
            "target_reached": True,
            "lifecycle": "RESPONSE",
            "duration_ms": self._duration(event),
        })
        return event

    def record_failure(self, request: Any, error: str) -> dict[str, Any] | None:
        event = self._events_by_request.get(id(request))
        if event is None or event.get("lifecycle") in {"BLOCKED", "RESPONSE", "FAILED"}:
            return event
        if event.get("request_classification") == "UNKNOWN":
            event["request_classification"] = "APPLICATION_REQUEST"
        event.update({
            "error": sanitize_text(str(error).splitlines()[0], limit=1000),
            "target_reached": True,
            "lifecycle": "FAILED",
            "duration_ms": self._duration(event),
        })
        return event

    def finalize_pending(self) -> None:
        for event in self.events:
            if event.get("lifecycle") in {"REQUESTED", "ALLOWED"}:
                if event.get("request_classification") == "UNKNOWN":
                    event["request_classification"] = "APPLICATION_REQUEST"
                event["lifecycle"] = "PENDING_AT_SCAN_END"
                event["duration_ms"] = self._duration(event)
            event.pop("_started_at", None)

    @staticmethod
    def _duration(event: dict[str, Any]) -> int | None:
        started = event.get("_started_at")
        return round((time.perf_counter() - started) * 1000) if isinstance(started, float) else None


def _observed_at() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
