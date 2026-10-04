from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from app.security import DestinationError, sanitize_url, validate_http_url


@dataclass(frozen=True)
class SessionRefreshConfig:
    refresh_url: str
    timeout_ms: int = 60000
    settle_ms: int = 1500


class RuntimeSessionStore:
    """Maintain a private, pod-local refreshed copy of a mounted storage state."""

    def __init__(self, root: Path | None = None):
        default = Path(os.getenv("HOME", "/tmp/portal-validator-home")) / ".portal-validator/sessions"
        self.root = root or default

    def path_for(self, profile: str) -> Path:
        return self.root / f"{profile}.json"

    def seed(self, profile: str, mounted_path: Path) -> Path:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = self.path_for(profile)
        if not target.is_file() or target.stat().st_mtime < mounted_path.stat().st_mtime:
            self._atomic_write(target, mounted_path.read_bytes())
        return target

    async def persist(
        self,
        profile: str,
        context,
        *,
        expected_mtime_ns: int | None = None,
    ) -> Path | None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = self.path_for(profile)
        if (
            expected_mtime_ns is not None
            and target.is_file()
            and target.stat().st_mtime_ns != expected_mtime_ns
        ):
            return None
        state = await context.storage_state()
        payload = json.dumps(state, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if (
            expected_mtime_ns is not None
            and target.is_file()
            and target.stat().st_mtime_ns != expected_mtime_ns
        ):
            return None
        self._atomic_write(target, payload)
        return target

    def _atomic_write(self, target: Path, payload: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=self.root)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            target.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)


def load_refresh_config(profile: str, auth_state_dir: Path) -> SessionRefreshConfig | None:
    path = (auth_state_dir / f"{profile}.refresh.json").resolve()
    root = auth_state_dir.resolve()
    if root not in path.parents or not path.is_file():
        return None
    if path.stat().st_size <= 0 or path.stat().st_size > 64 * 1024:
        raise ValueError("Session refresh configuration size is invalid")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("refresh_url"), str):
        raise ValueError("Session refresh configuration requires refresh_url")
    refresh_url = data["refresh_url"].strip()
    validate_http_url(refresh_url)
    timeout_ms = int(data.get("timeout_ms", 60000))
    if timeout_ms < 1000 or timeout_ms > 120000:
        raise ValueError("Session refresh timeout must be between 1000 and 120000 ms")
    settle_ms = int(data.get("settle_ms", 1500))
    if settle_ms < 0 or settle_ms > 10000:
        raise ValueError("Session refresh settle time must be between 0 and 10000 ms")
    return SessionRefreshConfig(
        refresh_url=refresh_url,
        timeout_ms=timeout_ms,
        settle_ms=settle_ms,
    )


async def refresh_browser_session(page, config: SessionRefreshConfig) -> dict[str, str | int | bool]:
    """Allow the browser/IdP to perform its normal silent refresh; never handle credentials."""
    try:
        response = await page.goto(
            config.refresh_url,
            wait_until="domcontentloaded",
            timeout=config.timeout_ms,
        )
        if config.settle_ms:
            await page.wait_for_timeout(config.settle_ms)
        final_url = page.url
        return {
            "attempted": True,
            "status": response.status if response else 0,
            "requested_origin": _safe_origin(config.refresh_url),
            "final_origin": _safe_origin(final_url),
        }
    except Exception as exc:
        if isinstance(exc, DestinationError):
            message = exc.public_message
        else:
            message = "Session refresh navigation did not complete"
        return {
            "attempted": True,
            "status": 0,
            "requested_origin": _safe_origin(config.refresh_url),
            "final_origin": _safe_origin(page.url) if page.url else "",
            "error": message,
        }


def _safe_origin(value: str) -> str:
    safe = sanitize_url(value, include_path=False)
    parsed = urlparse(safe)
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
