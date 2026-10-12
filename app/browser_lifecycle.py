"""Explicit, metadata-only browser stages for one independently validated view."""
from __future__ import annotations

import time


TRANSITIONS = {
    "BROWSER_CREATED": {"INITIAL_NAVIGATION"},
    "INITIAL_NAVIGATION": {"AUTHENTICATING"},
    "AUTHENTICATING": {"SESSION_ESTABLISHED"},
    "SESSION_ESTABLISHED": {"APPLICATION_BOOTSTRAP"},
    "APPLICATION_BOOTSTRAP": {"APPLICATION_READY"},
    "APPLICATION_READY": {"ROUTE_DISCOVERY", "ROUTE_VALIDATION"},
    "ROUTE_DISCOVERY": {"ROUTE_VALIDATION"},
    "ROUTE_VALIDATION": {"REPORT"},
    "REPORT": set(),
}


class BrowserLifecycle:
    """Reject impossible healthy progress; retain the first failed stage.

    No URLs, cookie values, DOM contents or authentication payloads belong in
    this structure. Callers supply only enumerated classification reasons.
    """

    def __init__(self):
        self.started = time.perf_counter()
        self.state = "BROWSER_CREATED"
        self.failed_stage: str | None = None
        self.failure_reason: str | None = None
        self.events = [{"state": self.state, "elapsed_ms": 0}]

    def advance(self, state: str) -> None:
        if state == self.state:
            return
        if self.failed_stage is not None and state != "REPORT":
            return
        if state not in TRANSITIONS.get(self.state, set()) and not (
            state == "REPORT" and self.failed_stage is not None
        ):
            raise ValueError(f"Invalid browser lifecycle transition: {self.state} -> {state}")
        self.state = state
        self.events.append({
            "state": state, "elapsed_ms": max(0, round((time.perf_counter() - self.started) * 1000)),
        })

    def fail(self, reason: str, *, stage: str | None = None) -> None:
        if stage is not None and stage not in TRANSITIONS:
            raise ValueError("Unknown failed browser lifecycle stage")
        if not reason or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for character in reason):
            raise ValueError("Browser lifecycle reason must be a safe classification code")
        if self.failed_stage is None:
            self.failed_stage = stage or self.state
            self.failure_reason = reason

    def snapshot(self) -> dict[str, object]:
        return {
            "state": self.state, "failed_stage": self.failed_stage,
            "failure_reason": self.failure_reason,
            "events": [dict(event) for event in self.events],
        }
