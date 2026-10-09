"""Central redaction must preserve structured JSON and raw access-log formats."""

import io
import json
import logging

import pytest

from app import logging_config
from app.logging_config import RedactingFilter


@pytest.mark.parametrize("query", (
    "code=fixture-private-code&state=fixture-private-state",
    "state=fixture-private-state",
    "SAMLRequest=fixture-private-saml&RelayState=public-route",
))
def test_structured_authentication_logs_remain_json_after_repeated_redaction(query):
    record = logging.LogRecord(
        "portal_validator", logging.INFO, __file__, 1,
        json.dumps({
            "event": "AUTH_NAVIGATION",
            "url": f"https://identity.example/authorize?{query}",
            "nested": {
                "Authorization": "Bearer fixture-private-bearer",
                "Cookie": "session=fixture-private-cookie",
                "storage_state": {"cookies": [{"value": "fixture-private-storage"}]},
            },
        }), (), None,
    )
    redaction = RedactingFilter()
    for _ in range(3):
        assert redaction.filter(record)
    rendered = logging.Formatter("%(message)s").format(record)
    # Check the actual record.message produced by the logging formatter, not only
    # the original payload before logger/handler filters have run.
    payload = json.loads(record.message)
    assert payload["event"] == "AUTH_NAVIGATION"
    assert payload["nested"] == {
        "Authorization": "[REDACTED]",
        "Cookie": "[REDACTED]",
        "storage_state": "[REDACTED]",
    }
    assert "fixture-private-" not in rendered
    assert "[REDACTED]" in payload["url"]


def test_log_event_survives_both_logger_and_handler_redaction(monkeypatch):
    stream = io.StringIO()
    logger = logging.Logger("isolated-redaction-test", level=logging.DEBUG)
    logger.addFilter(RedactingFilter())
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    monkeypatch.setattr(logging_config, "LOGGER", logger)

    logging_config.log_event(
        logging.INFO, "AUTH_CALLBACK", scan_id="generic-scan",
        url="https://portal.example/callback?code=fixture-private-code&state=fixture-private-state",
        authorization="Bearer fixture-private-bearer", token="fixture-private-token",
    )

    rendered = stream.getvalue()
    payload = json.loads(rendered)
    assert payload["event"] == "AUTH_CALLBACK"
    assert payload["scan_id"] == "generic-scan"
    assert payload["authorization"] == payload["token"] == "[REDACTED]"
    assert "fixture-private-" not in rendered


def test_formatted_structured_record_is_redacted_after_interpolation():
    record = logging.LogRecord(
        "portal_validator", logging.INFO, __file__, 1,
        '{"event":"AUTH_CALLBACK","url":"%s","authorization":"%s"}',
        ("https://portal.example/callback?state=fixture-private-state", "Bearer fixture-private-bearer"),
        None,
    )
    assert RedactingFilter().filter(record)
    rendered = logging.Formatter("%(message)s").format(record)
    assert json.loads(record.message)["authorization"] == "[REDACTED]"
    assert "fixture-private-" not in rendered


def test_raw_access_log_format_and_sensitive_arguments_remain_redacted():
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1234", "GET", "/callback?code=fixture-private-code&state=fixture-private-state", "1.1", 200),
        None,
    )
    assert RedactingFilter().filter(record)
    rendered = logging.Formatter("%(message)s").format(record)
    assert rendered.startswith('127.0.0.1:1234 - "GET /callback?')
    assert rendered.endswith('HTTP/1.1" 200')
    assert "fixture-private-" not in rendered


def test_long_structured_record_retains_valid_json():
    record = logging.LogRecord(
        "portal_validator", logging.INFO, __file__, 1,
        json.dumps({"event": "LONG_EVENT", "detail": "x" * 5000, "token": "fixture-private-token"}),
        (), None,
    )
    assert RedactingFilter().filter(record)
    logging.Formatter("%(message)s").format(record)
    payload = json.loads(record.message)
    assert payload["event"] == "LONG_EVENT"
    assert payload["token"] == "[REDACTED]"
    assert len(payload["detail"]) <= 4000


@pytest.mark.parametrize("parameter", (
    "__cf_chl_rt_tk", "__cf_chl_tk", "challenge_token", "captcha_token",
))
def test_access_challenge_tokens_are_redacted_without_hiding_diagnostic_codes(parameter):
    from app.discovery import normalize_route_url
    from app.security import sanitize_url

    url = f"https://portal.example/?{parameter}=fixture-private-challenge&view=public"
    assert "fixture-private-challenge" not in sanitize_url(url)
    assert "view=public" in sanitize_url(url)
    assert normalize_route_url(url, query_policy="preserve") == "https://portal.example/?view=public"
    for message, arguments in (
        (json.dumps({"event": "ACCESS_RESTRICTED", "url": url}), ()),
        ('GET /?%s=fixture-private-challenge HTTP/1.1', (parameter,)),
    ):
        record = logging.LogRecord("portal_validator", logging.INFO, __file__, 1,
                                   message, arguments, None)
        assert RedactingFilter().filter(record)
        rendered = logging.Formatter("%(message)s").format(record)
        assert "fixture-private-challenge" not in rendered
        if message.startswith("{"):
            assert json.loads(rendered)["event"] == "ACCESS_RESTRICTED"
    record = logging.LogRecord(
        "portal_validator", logging.INFO, __file__, 1, "Request metadata: %s",
        ({"nested": {"password": "fixture-private-password", parameter: "fixture-private-challenge"}},), None,
    )
    assert RedactingFilter().filter(record)
    assert "fixture-private-" not in logging.Formatter("%(message)s").format(record)
