from __future__ import annotations

import asyncio
import json
import ipaddress
import os
import re
import time
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from graphql import GraphQLError, OperationType, get_operation_ast, parse
from graphql.language.ast import OperationDefinitionNode

from app.security import JWT_RE, SENSITIVE_KEYS, normalized_host, sanitize_text, sanitize_url


SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
PUBLIC_POLICY_NAMES = {
    "APPROVED_READ_POST": "APPROVED_READ_ONLY",
    "APPROVED_READ_REQUEST": "APPROVED_READ_ONLY",
    "BLOCKED_MUTATION": "READ_ONLY_BLOCKED",
    "READ_ONLY_BLOCK": "READ_ONLY_BLOCKED",
}
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


def api_timeout_init_script(timeout_ms: int) -> str:
    """Apply an explicitly requested browser API deadline without replaying calls.

    Preserve the caller's payload, credentials and existing cancellation signal.
    This is opt-in; the default scan does not wrap fetch/XHR. Synchronous XHR
    does not support timeouts and remains bounded by the outer scan deadline.
    """
    if not 1000 <= timeout_ms <= 120000:
        raise ValueError("API timeout is outside the supported range")
    return """(() => {
      const timeout = TIMEOUT_MS;
      const originalFetch = window.fetch;
      window.fetch = function(input, init) {
        const existing = init && init.signal !== undefined ? init.signal :
          (input instanceof Request ? input.signal : undefined);
        const deadline = AbortSignal.timeout(timeout);
        const signal = existing ? AbortSignal.any([existing, deadline]) : deadline;
        return originalFetch.call(this, input, {...init, signal});
      };
      const originalOpen = XMLHttpRequest.prototype.open;
      const originalSend = XMLHttpRequest.prototype.send;
      const asynchronous = new WeakMap();
      XMLHttpRequest.prototype.open = function(method, url, async = true, ...rest) {
        asynchronous.set(this, async !== false);
        return originalOpen.call(this, method, url, async, ...rest);
      };
      XMLHttpRequest.prototype.send = function(body) {
        if (asynchronous.get(this) !== false) {
          this.timeout = this.timeout > 0 ? Math.min(this.timeout, timeout) : timeout;
        }
        return originalSend.call(this, body);
      };
    })();""".replace("TIMEOUT_MS", str(timeout_ms))


def policy_hostname(value: Any) -> str:
    host = normalized_host(str(value or ""))
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Policy rule host must be an exact hostname") from exc
    if len(host) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in host.split(".")
    ):
        raise ValueError("Policy rule host must be an exact hostname without URL, credentials, port or wildcards")
    return host


def classify_traffic(
    *,
    method: str,
    endpoint: str,
    resource_type: str,
    phase: str,
    blocked_by_validator: bool = False,
    classification: str = "",
) -> str:
    """Classify safe network metadata without inspecting headers or bodies."""
    if blocked_by_validator:
        return "VALIDATOR_BLOCKED"
    normalized_type = resource_type.lower()
    normalized_path = endpoint.lower()
    normalized_phase = phase.upper()
    # Traffic purpose and execution policy are independent. A challenge POST
    # must not become a successful business API just because it returned 200.
    if classification == "ACCESS_GATE" or any(marker in normalized_path for marker in (
        "/cdn-cgi/challenge-platform/", "/challenge/", "/captcha/", "/turnstile/",
    )):
        return "CHALLENGE_API"
    if normalized_path.endswith("/config.json") or normalized_path == "/config.json":
        return "MICROFRONTEND_CONFIG"
    if classification == "SESSION_REFRESH" or normalized_phase == "SESSION_REFRESH":
        return "SESSION_REFRESH"
    auth_tokens = set(re.split(r"[^a-z0-9]+", normalized_path))
    if classification == "AUTH_FLOW" or auth_tokens & {
        "oauth", "oauth2", "oidc", "saml", "saml2", "authorize", "authorization", "login", "signin",
    }:
        return "AUTH_API"
    if normalized_type == "document":
        return "DOCUMENT"
    if normalized_type not in {"xhr", "fetch"}:
        return "STATIC_RESOURCE"
    if any(marker in normalized_path for marker in (
        "/analytics", "/beacon", "/collect", "/metrics", "/telemetry",
    )):
        return "TELEMETRY"
    if classification in {"APPROVED_READ_POST", "APPROVED_READ_REQUEST"} or normalized_path.startswith("/api/") or normalized_path.endswith("/graphql"):
        return "APPLICATION_API"
    return "UNCLASSIFIED_API"


def request_identity(request: Any) -> Any:
    """Stable weak-referenceable identity across Playwright API wrappers.

    This identity is used only as a weak mapping key, never serialized or logged.
    Keeping the underlying implementation weak avoids retaining its raw headers
    or body after Playwright finishes/disposes the request.
    """
    return getattr(request, "_impl_obj", request)


def public_policy_classification(classification: str) -> str:
    """Stable display vocabulary, retaining legacy execution classifications."""
    return PUBLIC_POLICY_NAMES.get(classification, classification)


class RouteNetworkActivity:
    """Track bounded route activity without retaining request secrets."""

    def __init__(self) -> None:
        self._pending: weakref.WeakKeyDictionary[Any, str | None] = weakref.WeakKeyDictionary()
        self._last_activity: dict[str | None, float] = {}
        self._generation: dict[str | None, int] = {}

    def request_started(self, request: Any, route_id: str | None, *, relevant: bool = True) -> None:
        if not relevant or str(request.resource_type).lower() in {"websocket", "eventsource"}:
            return
        key = request_identity(request)
        if key in self._pending:
            return
        self._pending[key] = route_id
        self._touch(route_id)

    def request_finished(self, request: Any) -> None:
        key = request_identity(request)
        if key not in self._pending:
            return
        route_id = self._pending.pop(key)
        self._touch(route_id)

    def snapshot(self, route_id: str | None) -> dict[str, int | float]:
        return {
            "generation": self._generation.get(route_id, 0),
            "pending": sum(value == route_id for value in self._pending.values()),
            "last_activity": self._last_activity.get(route_id, 0.0),
        }

    def _touch(self, route_id: str | None) -> None:
        self._last_activity[route_id] = time.perf_counter()
        self._generation[route_id] = self._generation.get(route_id, 0) + 1


def summarize_route_api_coverage(events: list[dict[str, Any]]) -> dict[str, int | str]:
    """Report business-API coverage separately from config and authentication."""
    application_events = [
        event for event in events
        if (
            event.get("traffic_role", event.get("traffic_category")) == "APPLICATION_API"
            or (
                "traffic_role" not in event
                and
                event.get("traffic_category") == "VALIDATOR_BLOCKED"
                and event.get("resource_type") in {"xhr", "fetch"}
                and not str(event.get("endpoint") or "").lower().endswith("/config.json")
                and event.get("phase") not in {"AUTHENTICATION", "SESSION_REFRESH"}
            )
        )
    ]
    blocked = sum(bool(event.get("blocked_by_validator")) for event in application_events)
    executed = sum(
        not event.get("blocked_by_validator")
        and bool(event.get("request_dispatched") or event.get("response_seen")
                 or ("request_dispatched" not in event and isinstance(event.get("status"), int)))
        for event in application_events
    )
    return {
        "api_coverage": (
            "APPLICATION_API_OBSERVED" if executed else
            "APPLICATION_API_BLOCKED" if blocked else
            "NO_APPLICATION_API_OBSERVED"
        ),
        "apis_observed": len(events),
        "application_apis_observed": len(application_events),
        "application_apis_executed": executed,
        "blocked_api_attempts": blocked,
    }


def summarize_post_observation(events: list[dict[str, Any]]) -> dict[str, int]:
    """Count observed POST calls without inventing approval or replay evidence.

    Authentication, challenge and unapproved POST attempts are observations,
    not explicitly approved read-only operations. A response proves dispatch,
    including native redirect requests that bypass Playwright's route handler;
    it does not itself establish read-only execution approval.
    """
    summary = {
        "observed_calls": 0,
        "approved_read_only_calls": 0,
        "executed_approved_calls": 0,
    }
    for event in events:
        if str(event.get("method") or "GET").upper() != "POST":
            continue
        summary["observed_calls"] += 1
        classification = str(
            event.get("policy_classification") or event.get("request_classification") or ""
        )
        approved = (
            classification in {"APPROVED_READ_POST", "APPROVED_READ_REQUEST", "APPROVED_READ_ONLY"}
            and not event.get("blocked_by_validator")
            and event.get("policy_decision") not in {"BLOCK", "PENDING"}
        )
        summary["approved_read_only_calls"] += approved
        summary["executed_approved_calls"] += approved and bool(
            event.get("request_dispatched") or event.get("response_seen")
            or ("response_seen" not in event and isinstance(event.get("status"), int))
        )
    return summary


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
    path_pattern: bool = False
    graphql_queries_only: bool = False

    def matches(self, method: str, url: str) -> bool:
        parsed = urlparse(url)
        if (
            method.upper() != self.method
            or normalized_host(parsed.hostname or "") != self.host
        ):
            return False
        candidate = parsed.path or "/"
        if not self.path_pattern:
            # Inventory normalization must never broaden an administrator-approved
            # execution path into a wildcard.
            return candidate == self.path
        if "//" in candidate:
            return False
        expected_segments = self.path.strip("/").split("/")
        candidate_segments = candidate.strip("/").split("/")
        # A raw encoded slash can look like one segment here but become a
        # different operation after a proxy/router decodes it. Likewise reject
        # another escape layer rather than guessing how many times an upstream
        # component decodes paths. Ordinary bounded IDs remain supported.
        for segment in candidate_segments:
            try:
                decoded = unquote(segment, errors="strict")
            except UnicodeDecodeError:
                return False
            if (
                decoded in {".", ".."}
                or any(marker in decoded for marker in ("/", "\\", "%", "?", "#"))
                or any(ord(character) <= 32 or ord(character) == 127 for character in decoded)
            ):
                return False
        return len(expected_segments) == len(candidate_segments) and all(
            expected == "{segment}" or expected == actual
            for expected, actual in zip(expected_segments, candidate_segments)
        )


def is_read_only_graphql_body(body: str | None) -> bool:
    """Validate configured GraphQL queries in memory; never retain/log payloads.

    Endpoint approval is still mandatory. Persisted operations without a query
    cannot be proven read-only here and therefore fail closed. No execution or
    replay is performed by this parser.
    """
    if not isinstance(body, str) or not body:
        return False

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                # Different JSON decoders may select different duplicate values.
                # Never approve an ambiguous operation or variable payload.
                raise ValueError("Duplicate JSON object key")
            result[key] = value
        return result

    try:
        if len(body.encode("utf-8")) > 65536:
            return False
        payload = json.loads(body, object_pairs_hook=unique_object)
        operations = payload if isinstance(payload, list) else [payload]
        if not operations or len(operations) > 20:
            return False
        for operation in operations:
            if not isinstance(operation, dict) or not isinstance(operation.get("query"), str):
                return False
            name = operation.get("operationName")
            if name is not None and not isinstance(name, str):
                return False
            document = parse(operation["query"], no_location=True, max_tokens=10000)
            definitions = [item for item in document.definitions if isinstance(item, OperationDefinitionNode)]
            if not definitions or any(item.operation != OperationType.QUERY for item in definitions):
                return False
            if get_operation_ast(document, name) is None:
                return False
        return True
    except (ValueError, TypeError, GraphQLError, RecursionError):
        # Parser exception messages may include source payloads: never expose them.
        return False


@dataclass(frozen=True)
class AccessGateRule:
    host: str
    selector: str


@dataclass(frozen=True)
class ReadOnlyPolicy:
    safe_application_requests: tuple[ApprovedRequestRule, ...] = ()
    access_gates: tuple[AccessGateRule, ...] = ()

    def match(self, method: str, url: str) -> ApprovedRequestRule | None:
        matches = [rule for rule in self.safe_application_requests if rule.matches(method, url)]
        # An overlapping legacy endpoint exception must not bypass an explicit
        # query-only restriction on that same operation.
        return next((rule for rule in matches if rule.graphql_queries_only), matches[0] if matches else None)

    def access_gate_for(self, url: str) -> AccessGateRule | None:
        host = normalized_host(urlparse(url).hostname or "")
        return next((rule for rule in self.access_gates if rule.host == host), None)


def load_read_only_policy(
    *,
    raw: str | None = None,
    path: str | Path | None = None,
) -> ReadOnlyPolicy:
    """Load explicit read-only POST exceptions from administrator configuration."""
    explicit_source = raw is not None or path is not None
    configured_raw = raw if explicit_source else os.getenv("PORTAL_VALIDATOR_READ_ONLY_POLICY")
    configured_path = path if explicit_source else os.getenv("PORTAL_VALIDATOR_READ_ONLY_POLICY_FILE")
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
        host = policy_hostname(item.get("host"))
        has_exact_path = "path" in item
        has_path_pattern = "path_pattern" in item
        if has_exact_path == has_path_pattern:
            raise ValueError("Policy rule must configure exactly one path or path_pattern")
        raw_path = str(
            item.get("path") if has_exact_path else item.get("path_pattern")
        ).strip()
        classification = str(
            item.get("classification")
            or ("APPROVED_READ_POST" if method == "POST" else "APPROVED_READ_REQUEST")
        ).strip().upper()
        if method != "POST":
            raise ValueError("Read-only policy exceptions must use POST; other mutation methods remain blocked")
        if not host or "/" in host or "://" in host:
            raise ValueError("Policy rule host must be an exact hostname")
        if not raw_path.startswith("/") or "?" in raw_path or "#" in raw_path:
            raise ValueError("Policy rule path must be a query-free absolute path")
        if (
            len(raw_path) > 2048 or raw_path.startswith("//")
            or "\\" in raw_path or any(ord(character) <= 32 for character in raw_path)
            or any(segment in {".", ".."} for segment in unquote(raw_path).split("/"))
            or re.search(r"%(?:2f|5c|00)", raw_path, re.IGNORECASE)
        ):
            raise ValueError("Policy rule path must be normalized and must not contain ambiguous separators")
        if has_exact_path and any(marker in raw_path for marker in ("*", "{", "}")):
            raise ValueError("Exact policy paths cannot contain wildcard syntax")
        if has_path_pattern:
            segments = [segment for segment in raw_path.split("/") if segment]
            literals = [segment for segment in segments if segment != "{segment}"]
            if (
                len(segments) < 3
                or len(literals) < 2
                or segments[0] == "{segment}"
                or any(
                    segment != "{segment}" and not re.fullmatch(r"[A-Za-z0-9._~-]+", segment)
                    for segment in segments
                )
            ):
                raise ValueError(
                    "Policy path_pattern must be segment-bounded with at least two literal segments"
                )
        if classification not in POLICY_CLASSIFICATIONS:
            raise ValueError("Policy rule classification is not supported")
        graphql_queries_only = item.get("graphql_queries_only", False)
        if not isinstance(graphql_queries_only, bool):
            raise ValueError("graphql_queries_only must be a boolean")
        if graphql_queries_only and classification not in {"APPROVED_READ_POST", "APPROVED_READ_REQUEST"}:
            raise ValueError("GraphQL query restrictions require a read-only application rule")
        rules.append(ApprovedRequestRule(
            method=method,
            host=host,
            path=raw_path,
            classification=classification,
            path_pattern=has_path_pattern,
            graphql_queries_only=graphql_queries_only,
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
        # CPython object ids can be reused after Playwright disposes a completed
        # request. Retaining id(request) forever aliases later POSTs to old GETs.
        # Weak object keys preserve identity without keeping raw Request objects
        # (which contain headers/bodies) alive for the duration of a scan.
        self._events_by_request: weakref.WeakKeyDictionary[Any, dict[str, Any]] = weakref.WeakKeyDictionary()
        self._sequence = 0
        self._finalized = False

    @property
    def finalized(self) -> bool:
        return self._finalized

    def observe_request(
        self,
        request: Any,
        *,
        phase: str,
        importance: str,
        initiating_route: str | None,
        main_document: bool,
        route_activation_id: str | None = None,
    ) -> dict[str, Any]:
        key = self._request_key(request)
        existing = self._events_by_request.get(key)
        if existing is not None:
            return existing
        if self._finalized:
            raise RuntimeError("Network observation has been finalized")
        method = str(request.method).upper()
        self._sequence += 1
        safe_url, host, endpoint = safe_api_identity(str(request.url))
        try:
            frame_identity = (
                "MAIN_FRAME" if request.frame.parent_frame is None else "CHILD_FRAME"
            )
        except Exception:
            frame_identity = "UNKNOWN_FRAME"
        event: dict[str, Any] = {
            "request_id": f"request-{self._sequence}",
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
            "route_activation_id": route_activation_id,
            "observer_seen": True,
            "policy_evaluated": False,
            "policy_decision": "PENDING",
            "policy_reason": None,
            "route_handler_seen": False,
            "request_reached_network": None,
            "request_dispatched": False,
            "response_seen": False,
            "response_status": None,
            "response_completed": False,
            "request_failed": False,
            "failure_category": None,
            "aggregation_seen": False,
            "serialized_to_report": False,
            "main_document": main_document,
            "frame_identity": frame_identity,
            "request_classification": "SAFE_METHOD" if method in SAFE_HTTP_METHODS else "UNKNOWN",
            "policy_classification": "SAFE_METHOD" if method in SAFE_HTTP_METHODS else "UNKNOWN",
            "allowed_by_policy": method in SAFE_HTTP_METHODS,
            "target_reached": None,
            "lifecycle": "REQUESTED",
            "lifecycle_status": "OBSERVED",
            "traffic_category": classify_traffic(
                method=method,
                endpoint=endpoint,
                resource_type=str(request.resource_type),
                phase=phase,
            ),
            "_started_at": time.perf_counter(),
        }
        event["traffic_role"] = event["traffic_category"]
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
        if self._finalized:
            return None
        event = self._events_by_request.get(self._request_key(request))
        if event is None:
            return None
        event["request_classification"] = classification
        event["policy_classification"] = public_policy_classification(classification)
        event["allowed_by_policy"] = True
        event["lifecycle"] = "ALLOWED"
        event["lifecycle_status"] = "ALLOWED"
        event.update(policy_evaluated=True, policy_decision="ALLOW", policy_reason=classification)
        if phase is not None:
            event["phase"] = phase
        if importance is not None:
            event["importance"] = importance
        event["traffic_category"] = classify_traffic(
            method=str(event.get("method") or "GET"),
            endpoint=str(event.get("endpoint") or "/"),
            resource_type=str(event.get("resource_type") or "other"),
            phase=str(event.get("phase") or "VALIDATION"),
            classification=classification,
        )
        event["traffic_role"] = event["traffic_category"]
        return event

    def mark_blocked(
        self,
        request: Any,
        reason: str,
        *,
        classification: str = "BLOCKED_MUTATION",
    ) -> dict[str, Any] | None:
        if self._finalized:
            return None
        event = self._events_by_request.get(self._request_key(request))
        if event is None:
            return None
        event.update({
            "blocked_by_validator": True,
            "block_reason": reason,
            "request_classification": classification,
            "policy_classification": public_policy_classification(classification),
            "allowed_by_policy": False,
            "target_reached": False,
            "lifecycle": "BLOCKED",
            "lifecycle_status": "BLOCKED",
            "duration_ms": self._duration(event),
            "policy_evaluated": True,
            "policy_decision": "BLOCK",
            "policy_reason": reason,
            "request_reached_network": False,
            "failure_category": reason,
        })
        event["traffic_category"] = "VALIDATOR_BLOCKED"
        return event

    def record_response(self, request: Any, status: int) -> dict[str, Any] | None:
        if self._finalized:
            return None
        event = self._events_by_request.get(self._request_key(request))
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
            "lifecycle_status": "RESPONDED",
            "duration_ms": self._duration(event),
            "request_reached_network": True,
            # Native redirect hops bypass context.route(). Their response is
            # positive dispatch evidence, not a route-handler/policy approval.
            "request_dispatched": True,
            "response_seen": True,
            "response_status": int(status),
        })
        return event

    def record_failure(self, request: Any, error: str) -> dict[str, Any] | None:
        if self._finalized:
            return None
        event = self._events_by_request.get(self._request_key(request))
        if event is not None and event.get("lifecycle") == "BLOCKED":
            event["request_failed"] = True
            return event
        if event is None or event.get("lifecycle") == "FAILED":
            return event
        if event.get("request_classification") == "UNKNOWN":
            event["request_classification"] = "APPLICATION_REQUEST"
        canceled = any(marker in str(error).upper() for marker in (
            "ERR_ABORTED", "ABORTERROR", "NS_BINDING_ABORTED", "CANCELLED", "CANCELED",
        ))
        event.update({
            "error": sanitize_text(str(error).splitlines()[0], limit=1000),
            "target_reached": True if event.get("response_seen") else None,
            "lifecycle": "FAILED",
            "lifecycle_status": "CANCELED" if canceled else "FAILED",
            "request_canceled": canceled,
            "duration_ms": self._duration(event),
            "request_reached_network": True if event.get("response_seen") else None,
            "request_failed": True,
            "failure_category": (
                "REQUEST_CANCELED" if canceled else
                "RESPONSE_BODY_FAILURE" if event.get("response_seen") else "NETWORK_FAILURE"
            ),
            "response_completed": False,
        })
        return event

    def mark_route_handler(self, request: Any) -> None:
        if self._finalized:
            return
        event = self._events_by_request.get(self._request_key(request))
        if event is not None:
            event["route_handler_seen"] = True

    def mark_dispatched(self, request: Any) -> None:
        if self._finalized:
            return
        event = self._events_by_request.get(self._request_key(request))
        if event is not None:
            event["request_dispatched"] = True
            # The response event can race route.continue_(). Never regress it.
            if event.get("lifecycle_status") == "ALLOWED":
                event["lifecycle_status"] = "SENT"

    def record_finished(self, request: Any) -> None:
        if self._finalized:
            return
        event = self._events_by_request.get(self._request_key(request))
        if event is None or not event.get("response_seen") or event.get("blocked_by_validator") or event.get("request_failed"):
            return
        try:
            response_end = request.timing.get("responseEnd")
        except Exception:
            response_end = None
        event["duration_ms"] = (
            round(response_end) if isinstance(response_end, (int, float)) and response_end >= 0
            else self._duration(event)
        )
        event["response_completed"] = True
        event["lifecycle_status"] = "COMPLETED"

    def finalize_pending(self) -> None:
        # Freeze evidence at the explicit observation cutoff. Closing a context
        # generates cancellation/failure events that are validator cleanup, not
        # natural target outcomes, and must not overwrite unfinished evidence.
        if self._finalized:
            return
        self._finalized = True
        for event in self.events:
            if event.get("lifecycle") in {"REQUESTED", "ALLOWED"}:
                if event.get("request_classification") == "UNKNOWN":
                    event["request_classification"] = "APPLICATION_REQUEST"
                event["lifecycle"] = "PENDING_AT_SCAN_END"
                event["duration_ms"] = self._duration(event)
            if not event.get("blocked_by_validator") and not event.get("request_failed") and not event.get("response_completed"):
                event["lifecycle_status"] = "INCOMPLETE"
                event["incomplete_reason"] = (
                    "RESPONSE_BODY_NOT_COMPLETED" if event.get("response_seen") else
                    "NO_RESPONSE_BEFORE_SCAN_END" if event.get("request_dispatched") else
                    "NOT_DISPATCHED_BEFORE_SCAN_END"
                )
            event.pop("_started_at", None)

    @staticmethod
    def _request_key(request: Any) -> Any:
        # Async API wrappers can themselves be recreated for one underlying
        # request. The implementation's identity is stable throughout its
        # lifecycle; the weak key does not retain its sensitive raw contents.
        return request_identity(request)

    @staticmethod
    def _duration(event: dict[str, Any]) -> int | None:
        started = event.get("_started_at")
        return round((time.perf_counter() - started) * 1000) if isinstance(started, float) else None


async def drain_pending_api_observations(
    observer: PassiveNetworkObserver,
    *,
    maximum_ms: int,
    quiet_ms: int,
    cancel_event: asyncio.Event | None = None,
) -> dict[str, Any]:
    """Allow naturally observed requests to finish within a bounded final window.

    Includes optional, discovery and popup traffic, not just required APIs on
    the last route. New attempts and lifecycle changes reset the quiet window.
    The caller owns the total scan deadline and freezes observation afterward.
    No requests are issued, retried or replayed by this function.
    """
    maximum_ms = max(0, int(maximum_ms))
    quiet_ms = max(0, int(quiet_ms))
    started = time.perf_counter()
    deadline = started + maximum_ms / 1000
    last_change = started
    previous: tuple[tuple[object, ...], ...] | None = None

    def snapshot() -> tuple[tuple[tuple[object, ...], ...], int]:
        signature = tuple(
            (
                event.get("request_id"), event.get("lifecycle_status"),
                bool(event.get("response_seen")), bool(event.get("response_completed")),
                bool(event.get("request_failed")), bool(event.get("blocked_by_validator")),
            )
            for event in observer.events
        )
        pending = sum(
            not event.get("blocked_by_validator")
            and not event.get("request_failed")
            and not event.get("response_completed")
            for event in observer.events
        )
        return signature, pending

    while True:
        now = time.perf_counter()
        signature, pending = snapshot()
        if signature != previous:
            previous = signature
            last_change = now
        cancelled = bool(cancel_event is not None and cancel_event.is_set())
        ready = pending == 0 and (now - last_change) * 1000 >= quiet_ms
        timed_out = not ready and now >= deadline
        if observer.finalized or cancelled or ready or timed_out:
            return {
                "pending": pending,
                "observed_requests": len(observer.events),
                "elapsed_ms": max(0, round((now - started) * 1000)),
                "timed_out": timed_out,
                "cancelled": cancelled,
                "reason": (
                    "OBSERVATION_ALREADY_FINALIZED" if observer.finalized else
                    "CANCELLED" if cancelled else
                    "API_QUIET" if ready else "FINALIZATION_TIMEOUT"
                ),
            }
        pause = min(0.05, max(0.0, deadline - now))
        if cancel_event is None:
            await asyncio.sleep(pause)
        else:
            try:
                await asyncio.wait_for(cancel_event.wait(), timeout=pause)
            except TimeoutError:
                pass


def _observed_at() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
