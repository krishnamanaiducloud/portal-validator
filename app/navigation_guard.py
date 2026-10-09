"""Validate native HTTP redirect destinations before Chromium follows them.

Playwright routes intentionally omit intermediate native redirect requests.
Response-stage CDP interception observes those hops without fetching/replaying
traffic or changing TLS verification, response bodies, methods, or cookies.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin

from playwright.async_api import Error as PlaywrightError

from app.security import DestinationError


def _interception_is_gone(error: Exception, command: str) -> bool:
    """Recognize only Chromium's exact already-disposed Fetch job response.

    Chromium returns this protocol error when its interception job no longer
    exists, for example after navigation canceled a paused response. Match at
    the corresponding send call only: validator errors must never be ignored.
    """
    return (
        isinstance(error, PlaywrightError)
        and command in {"Fetch.continueRequest", "Fetch.failRequest"}
        and str(error) == f"CDPSession.send: Protocol error ({command}): Invalid InterceptionId."
    )


class _BrowserTarget:
    def __init__(self, browser: Any) -> None:
        self.browser = browser

    def is_closed(self) -> bool:
        return not self.browser.is_connected()

    async def close(self) -> None:
        await self.browser.close()


class RedirectResponseGuard:
    def __init__(
        self, page: Any, session: Any, *,
        validate_destination: Callable[[str, str, dict[str, Any]], Awaitable[None]],
        on_policy_error: Callable[[DestinationError, dict[str, Any]], None],
        validation_timeout_ms: int,
        main_frame_id: str | None = None,
        primary_document_scope: bool = True,
    ) -> None:
        self.page = page
        self.session = session
        self.validate_destination = validate_destination
        self.on_policy_error = on_policy_error
        self.validation_timeout_ms = validation_timeout_ms
        self.main_frame_id = main_frame_id
        self.primary_document_scope = primary_document_scope
        self.tasks: set[asyncio.Task] = set()
        self.errors: list[DestinationError] = []
        self.closed = False

    @classmethod
    async def install(
        cls, context: Any, page: Any, *,
        validate_destination: Callable[[str, str, dict[str, Any]], Awaitable[None]],
        on_policy_error: Callable[[DestinationError, dict[str, Any]], None],
        validation_timeout_ms: int = 5000,
        target: Any | None = None,
        primary_document_scope: bool = True,
    ) -> RedirectResponseGuard:
        if validation_timeout_ms <= 0:
            raise ValueError("Redirect validation timeout must be positive")
        session = await context.new_cdp_session(target if target is not None else page)
        frame_tree = await session.send("Page.getFrameTree", {})
        guard = cls(
            page, session, validate_destination=validate_destination,
            on_policy_error=on_policy_error, validation_timeout_ms=validation_timeout_ms,
            main_frame_id=frame_tree["frameTree"]["frame"]["id"],
            primary_document_scope=primary_document_scope,
        )
        session.on("Fetch.requestPaused", guard._paused)
        await session.send("Fetch.enable", {
            "patterns": [{"urlPattern": "*", "requestStage": "Response"}],
        })
        return guard

    @classmethod
    async def install_browser(
        cls, browser: Any, *,
        validate_destination: Callable[[str, str, dict[str, Any]], Awaitable[None]],
        on_policy_error: Callable[[DestinationError, dict[str, Any]], None],
        validation_timeout_ms: int = 5000,
    ) -> RedirectResponseGuard:
        """Guard a dedicated scan browser before its first HTTP navigation.

        Browser-level Fetch covers popup first responses and out-of-process
        frames, which a parent Page session does not. No target auto-attach,
        renderer pause, request replay, or private Playwright APIs are used.
        Prefer installation before context creation; an unused about:blank
        context/page is also safe as long as no network navigation has started.
        """
        if validation_timeout_ms <= 0:
            raise ValueError("Redirect validation timeout must be positive")
        session = await browser.new_browser_cdp_session()
        guard = cls(
            _BrowserTarget(browser), session, validate_destination=validate_destination,
            on_policy_error=on_policy_error, validation_timeout_ms=validation_timeout_ms,
        )
        session.on("Fetch.requestPaused", guard._paused)
        await session.send("Fetch.enable", {
            "patterns": [{"urlPattern": "*", "requestStage": "Response"}],
        })
        return guard

    async def bind_primary_page(self, context: Any, page: Any) -> None:
        """Bind metadata before navigating; interception is already browser-wide."""
        session = await context.new_cdp_session(page)
        try:
            frame_tree = await session.send("Page.getFrameTree", {})
            self.main_frame_id = frame_tree["frameTree"]["frame"]["id"]
        finally:
            await session.detach()

    def _paused(self, event: dict[str, Any]) -> None:
        if self.closed:
            return
        task = asyncio.create_task(self._handle(event))
        self.tasks.add(task)
        task.add_done_callback(self._finished)

    def _finished(self, task: asyncio.Task) -> None:
        self.tasks.discard(task)
        if not task.cancelled():
            # Retrieve the exception: failures are already reported safely below.
            task.exception()

    def _metadata(self, event: dict[str, Any]) -> dict[str, Any]:
        request = event.get("request", {})
        return {
            "url": request.get("url", ""),
            "method": str(request.get("method", "GET")).upper(),
            "resource_type": str(event.get("resourceType", "other")).lower(),
            "response_status": event.get("responseStatusCode"),
            "document_navigation": event.get("resourceType") == "Document",
            "primary_page": self.main_frame_id is not None and event.get("frameId") == self.main_frame_id,
            "main_document": (
                self.primary_document_scope and self.main_frame_id is not None
                and event.get("resourceType") == "Document"
                and event.get("frameId") == self.main_frame_id
            ),
        }

    def _report(self, error: DestinationError, event: dict[str, Any]) -> None:
        self.errors.append(error)
        self.on_policy_error(error, self._metadata(event))

    async def _handle(self, event: dict[str, Any]) -> None:
        request_id = event["requestId"]
        try:
            if event.get("responseStatusCode") in {301, 302, 303, 307, 308}:
                locations = [
                    item["value"] for item in event.get("responseHeaders", [])
                    if item.get("name", "").lower() == "location"
                ]
                if len(locations) > 1:
                    raise DestinationError("NAVIGATION_ERROR", "Redirect has ambiguous Location headers")
                if locations:
                    destination = urljoin(event["request"]["url"], locations[0])
                    async with asyncio.timeout(self.validation_timeout_ms / 1000):
                        await self.validate_destination(
                            destination, event["request"]["url"], self._metadata(event),
                        )
            try:
                await self.session.send("Fetch.continueRequest", {"requestId": request_id})
            except PlaywrightError as exc:
                if _interception_is_gone(exc, "Fetch.continueRequest"):
                    # Validation has already succeeded. Chromium disposed the
                    # pause, so there is no unchecked request left to release.
                    return
                raise
        except asyncio.CancelledError:
            # Closing the page aborts paused requests; never release one unchecked.
            raise
        except Exception as exc:
            error = exc if isinstance(exc, DestinationError) else DestinationError(
                "NETWORK_ERROR", "Redirect security validation could not be completed",
            )
            try:
                self._report(error, event)
            finally:
                try:
                    await self.session.send("Fetch.failRequest", {
                        "requestId": request_id, "errorReason": "BlockedByClient",
                    })
                except PlaywrightError as exc:
                    if not _interception_is_gone(exc, "Fetch.failRequest") and not self.page.is_closed():
                        # An open page with a failed security command cannot continue.
                        # An already-disposed job needs no abort; its policy
                        # denial above remains reported without closing siblings.
                        await self.page.close()

    async def close(self) -> None:
        """Close after the page/context: detaching earlier could release a pause."""
        if self.closed:
            return
        if not self.page.is_closed():
            raise RuntimeError("Close the guarded page before detaching its redirect guard")
        self.closed = True
        self.session.remove_listener("Fetch.requestPaused", self._paused)
        for task in tuple(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
        try:
            await self.session.detach()
        except PlaywrightError:
            # Target closure already detached the security session.
            if not self.page.is_closed():
                raise
