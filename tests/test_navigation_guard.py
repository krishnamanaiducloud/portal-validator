import asyncio

import pytest

from app.navigation_guard import RedirectResponseGuard
from app.security import DestinationError


class Page:
    closed = False

    def is_closed(self):
        return self.closed

    async def close(self):
        self.closed = True


class Session:
    def __init__(self):
        self.commands = []
        self.listeners = {}

    def on(self, event, callback):
        self.listeners[event] = callback

    def remove_listener(self, event, callback):
        self.listeners.pop(event, None)

    async def send(self, method, params):
        self.commands.append((method, params))

    async def detach(self):
        self.commands.append(("detach", {}))


def redirect(*, location="/next", status=302):
    return {
        "requestId": "request-1", "request": {"url": "https://portal.example/start"},
        "responseStatusCode": status,
        "responseHeaders": [{"name": "Location", "value": location}],
    }


def guard_with(validator):
    page, session, errors = Page(), Session(), []
    return RedirectResponseGuard(
        page, session, validate_destination=validator,
        on_policy_error=lambda error, metadata: errors.append(error), validation_timeout_ms=20,
    ), errors


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_each_redirect_is_validated_before_release_and_retains_source(status):
    observed = []

    async def validate(destination, source, metadata):
        assert not guard.session.commands
        observed.append((destination, source))

    guard, errors = guard_with(validate)
    await guard._handle(redirect(status=status))
    assert observed == [("https://portal.example/next", "https://portal.example/start")]
    assert guard.session.commands == [("Fetch.continueRequest", {"requestId": "request-1"})]
    assert not errors


@pytest.mark.asyncio
async def test_policy_rejection_fails_request_without_releasing_redirect():
    async def validate(destination, source, metadata):
        raise DestinationError("NETWORK_ERROR", "Destination blocked by policy")

    guard, errors = guard_with(validate)
    await guard._handle(redirect(location="http://169.254.169.254/"))
    assert len(errors) == 1 and errors[0].classification == "NETWORK_ERROR"
    assert guard.session.commands == [(
        "Fetch.failRequest", {"requestId": "request-1", "errorReason": "BlockedByClient"},
    )]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["exception", "timeout"])
async def test_unexpected_validation_failure_is_fail_closed_and_non_sensitive(failure):
    async def validate(destination, source, metadata):
        if failure == "timeout":
            await asyncio.sleep(1)
        raise RuntimeError("private-token-must-not-be-reported")

    guard, errors = guard_with(validate)
    await guard._handle(redirect())
    assert guard.session.commands[0][0] == "Fetch.failRequest"
    assert "private-token" not in str(errors)
    assert errors[0].classification == "NETWORK_ERROR"


@pytest.mark.asyncio
async def test_duplicate_location_headers_are_rejected():
    async def validate(destination, source, metadata):
        pytest.fail("Ambiguous headers must not reach validation")

    guard, errors = guard_with(validate)
    event = redirect()
    event["responseHeaders"].append({"name": "location", "value": "https://other.example/"})
    await guard._handle(event)
    assert guard.session.commands[0][0] == "Fetch.failRequest"
    assert errors[0].classification == "NAVIGATION_ERROR"


@pytest.mark.asyncio
async def test_ordinary_responses_continue_without_body_access_or_extra_validation():
    async def validate(destination, source, metadata):
        pytest.fail("Non-redirects must not create artificial destination requests")

    guard, errors = guard_with(validate)
    await guard._handle(redirect(status=200))
    assert guard.session.commands[0][0] == "Fetch.continueRequest" and not errors


@pytest.mark.asyncio
async def test_guard_cannot_detach_and_release_paused_requests_while_page_is_open():
    async def validate(destination, source, metadata):
        return None

    guard, _ = guard_with(validate)
    with pytest.raises(RuntimeError, match="Close the guarded page"):
        await guard.close()
    assert not guard.session.commands
    await guard.page.close()
    await guard.close()
    assert guard.closed and guard.session.commands == [("detach", {})]
