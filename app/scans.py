from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


TERMINAL_STATES = frozenset({"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"})
SCAN_STATES = frozenset({
    "QUEUED",
    "STARTING",
    "AUTHENTICATING",
    "DISCOVERING",
    "VALIDATING",
    "FINALIZING",
    *TERMINAL_STATES,
})


class ScanCapacityError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanJob:
    scan_id: str
    state: str = "QUEUED"
    created_at: str = field(default_factory=_utc_now)
    started_at: str | None = None
    completed_at: str | None = None
    discovered: int = 0
    queued: int = 0
    validated: int = 0
    healthy: int = 0
    failed: int = 0
    warnings: int = 0
    current_route: str | None = None
    remaining_budget_ms: int | None = None
    report: dict[str, Any] | None = None
    error: str | None = None
    cancel_requested: bool = False
    task: asyncio.Task[None] | None = field(default=None, repr=False)
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _started_monotonic: float | None = field(default=None, repr=False)

    def update(self, state: str | None = None, **values: Any) -> None:
        if state is not None:
            if state not in SCAN_STATES:
                raise ValueError(f"Unsupported scan state: {state}")
            self.state = state
            if state != "QUEUED" and self.started_at is None:
                self.started_at = _utc_now()
                self._started_monotonic = time.monotonic()
            if state in TERMINAL_STATES and self.completed_at is None:
                self.completed_at = _utc_now()
        for name in (
            "discovered", "queued", "validated", "healthy", "failed",
            "warnings", "current_route", "remaining_budget_ms",
        ):
            if name in values:
                setattr(self, name, values[name])

    @property
    def elapsed_ms(self) -> int:
        if self._started_monotonic is None:
            return 0
        return max(0, round((time.monotonic() - self._started_monotonic) * 1000))

    def snapshot(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "state": self.state,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "discovered": self.discovered,
            "queued": self.queued,
            "validated": self.validated,
            "healthy": self.healthy,
            "failed": self.failed,
            "warnings": self.warnings,
            "current_route": self.current_route,
            "elapsed_ms": self.elapsed_ms,
            "remaining_budget_ms": self.remaining_budget_ms,
            "cancel_requested": self.cancel_requested,
            "report_ready": self.report is not None,
            "error": self.error,
        }


class ScanRegistry:
    """Bounded in-process scan state for the single-replica OpenShift deployment."""

    def __init__(self, maximum_jobs: int = 100) -> None:
        self.maximum_jobs = max(10, maximum_jobs)
        self._jobs: OrderedDict[str, ScanJob] = OrderedDict()

    def create(self, scan_id: str) -> ScanJob:
        self.prune()
        if len(self._jobs) >= self.maximum_jobs:
            raise ScanCapacityError("The scan queue is at capacity")
        job = ScanJob(scan_id=scan_id)
        self._jobs[scan_id] = job
        return job

    def get(self, scan_id: str) -> ScanJob | None:
        return self._jobs.get(scan_id)

    def prune(self) -> None:
        while len(self._jobs) >= self.maximum_jobs:
            removable = next(
                (key for key, job in self._jobs.items() if job.state in TERMINAL_STATES),
                None,
            )
            if removable is None:
                break
            self._jobs.pop(removable, None)

    def request_cancel(self, scan_id: str) -> ScanJob | None:
        job = self.get(scan_id)
        if job is None:
            return None
        if job.state not in TERMINAL_STATES:
            job.cancel_requested = True
            job.cancel_event.set()
        return job

    async def shutdown(self) -> None:
        tasks = [
            job.task for job in self._jobs.values()
            if job.task is not None and not job.task.done()
        ]
        for job in self._jobs.values():
            if job.task in tasks:
                job.cancel_requested = True
                job.cancel_event.set()
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=10)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
