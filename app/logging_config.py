from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

from app.security import sanitize_data, sanitize_text


LOGGER_NAME = "portal_validator"


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            payload = json.loads(record.getMessage())
        except (json.JSONDecodeError, RecursionError):
            record.msg = sanitize_text(record.msg)
            if isinstance(record.args, dict):
                record.args = sanitize_data(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_data(item) for item in record.args)
        else:
            # Redact values, not serialized JSON syntax. Regex redaction of an
            # OAuth URL could consume a closing quote; whole-message truncation
            # could also invalidate JSON. Logger and handler filters may both run.
            record.msg = json.dumps(sanitize_data(payload), sort_keys=True, separators=(",", ":"))
            record.args = ()
        if record.exc_info:
            record.exc_text = "[REDACTED_EXCEPTION]"
        return True


class MaximumLevelFilter(logging.Filter):
    def __init__(self, maximum: int):
        super().__init__()
        self.maximum = maximum

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= self.maximum


def configure_logging() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    configured_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, configured_level, logging.INFO))
    logger.propagate = False
    if not getattr(logger, "_portal_validator_configured", False):
        formatter = logging.Formatter("%(message)s")
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setLevel(logging.DEBUG)
        stdout_handler.addFilter(MaximumLevelFilter(logging.WARNING))
        stdout_handler.addFilter(RedactingFilter())
        stdout_handler.setFormatter(formatter)
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.ERROR)
        stderr_handler.addFilter(RedactingFilter())
        stderr_handler.setFormatter(formatter)
        logger.addHandler(stdout_handler)
        logger.addHandler(stderr_handler)
        logger.addFilter(RedactingFilter())
        logger._portal_validator_configured = True  # type: ignore[attr-defined]
    return logger


LOGGER = configure_logging()


def configure_uvicorn_logging() -> None:
    """Apply the same redaction boundary to server and access-log records."""
    for logger_name in ("uvicorn.access", "uvicorn.error"):
        logger = logging.getLogger(logger_name)
        if not getattr(logger, "_portal_validator_redaction_configured", False):
            logger.addFilter(RedactingFilter())
            logger._portal_validator_redaction_configured = True  # type: ignore[attr-defined]


configure_uvicorn_logging()


def log_event(level: int, event: str, *, scan_id: str | None = None, **fields: Any) -> None:
    payload: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
    }
    if scan_id:
        payload["scan_id"] = scan_id
    payload.update(fields)
    LOGGER.log(level, json.dumps(sanitize_data(payload), sort_keys=True, separators=(",", ":")))
