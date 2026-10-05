import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from playwright.async_api import async_playwright

from app.health import assess_page_health, route_performance_timing, wait_for_render_settle
from app.resources import (
    RESOURCE_TIMING_SCRIPT,
    build_resource_report,
    enrich_resource_timings,
    large_resource_findings,
    resource_timing_key,
)


class TimingFrame:
    def __init__(self, entries):
        self.entries = entries
        self.evaluations = []

    async def evaluate(self, script):
        self.evaluations.append(script)
        return self.entries


class TimingPage:
    def __init__(self, entries):
        self.frames = [TimingFrame(entries)]


def resource_timing(url, *, transfer=1800, encoded=1500, decoded=3000, same_origin=True, start=10):
    return {
        "name": url,
        "initiator_type": "img",
        "start_time": start,
        "duration_ms": 125.25,
        "transfer_size_bytes": transfer,
        "encoded_body_size_bytes": encoded,
        "decoded_body_size_bytes": decoded,
        "response_end": start + 125.25,
        "same_origin": same_origin,
    }


@pytest.mark.asyncio
async def test_passive_natural_resource_sizes_never_fetch_or_replay():
    page = TimingPage([resource_timing("https://portal.example.net/image.jpg?token=hidden")])
    event = {
        "url": "https://portal.example.net/image.jpg?token=hidden",
        "resource_type": "image", "status": 200,
        "initiating_route": "https://portal.example.net/#/home?session=hidden",
    }
    assert await enrich_resource_timings(page, [event]) == 1
    details, summary = build_resource_report([event], large_image_threshold_bytes=1024)
    item = details[0]
    assert item["transfer_size_bytes"] == 1800
    assert item["encoded_body_size_bytes"] == 1500
    assert item["decoded_body_size_bytes"] == 3000
    assert item["duration_ms"] == 125.25
    assert item["size_categories"] == ["LARGE_IMAGE"]
    assert item["route"] == "https://portal.example.net/#/home"
    assert summary["total_transfer_size_bytes"] == 1800
    assert summary["large_images"] == 1
    assert "hidden" not in json.dumps(details)
    assert page.frames[0].evaluations == [RESOURCE_TIMING_SCRIPT]
    assert "fetch(" not in RESOURCE_TIMING_SCRIPT
    assert "XMLHttpRequest" not in RESOURCE_TIMING_SCRIPT
    warnings = large_resource_findings(details)
    assert warnings[0]["type"] == "LARGE_IMAGE"
    assert warnings[0]["severity"] == "WARNING"
    assert warnings[0]["blocking"] is False


@pytest.mark.asyncio
async def test_cross_origin_opaque_sizes_are_unavailable_not_zero_transfer():
    page = TimingPage([resource_timing("https://cdn.example.net/app.js", transfer=0, encoded=0, decoded=0, same_origin=False)])
    event = {"url": "https://cdn.example.net/app.js", "resource_type": "script", "status": 200}
    await enrich_resource_timings(page, [event])
    details, summary = build_resource_report([event])
    assert details[0]["transfer_size_bytes"] is None
    assert details[0]["encoded_body_size_bytes"] is None
    assert details[0]["size_source"] == "UNAVAILABLE"
    assert summary["total_transfer_size_bytes"] is None
    assert summary["resources_with_transfer_size"] == 0


@pytest.mark.asyncio
async def test_cached_large_javascript_labels_encoded_size_without_faking_network_bytes():
    page = TimingPage([resource_timing("https://cdn.example.net/app.js", transfer=0, encoded=2000000, decoded=6000000, same_origin=False)])
    event = {"url": "https://cdn.example.net/app.js", "resource_type": "script", "status": 200}
    await enrich_resource_timings(page, [event])
    details, summary = build_resource_report([event])
    assert details[0]["transfer_size_bytes"] == 0
    assert details[0]["size_categories"] == ["LARGE_JS_BUNDLE"]
    assert details[0]["warning_size_basis"] == "ENCODED_BODY_SIZE"
    assert summary["total_transfer_size_bytes"] == 0


@pytest.mark.asyncio
async def test_current_route_resource_timing_does_not_recount_previous_spa_entry():
    page = TimingPage([
        resource_timing("https://portal.example.net/api/items", transfer=200, start=100),
        resource_timing("https://portal.example.net/api/items", transfer=500, start=900),
    ])
    event = {"url": "https://portal.example.net/api/items", "resource_type": "fetch", "status": 201}
    await enrich_resource_timings(page, [event])
    assert event["transfer_size_bytes"] == 500


@pytest.mark.asyncio
async def test_opaque_timing_key_separates_query_variants_without_retaining_secrets():
    first_url = "https://portal.example.net/api/items?token=first-secret"
    second_url = "https://portal.example.net/api/items?token=second-secret"
    page = TimingPage([
        resource_timing(first_url, transfer=200, start=100),
        resource_timing(second_url, transfer=500, start=900),
    ])
    event = {
        "url": "https://portal.example.net/api/items", "resource_type": "fetch", "status": 200,
        "_resource_timing_key": resource_timing_key(first_url),
    }
    await enrich_resource_timings(page, [event])
    assert event["transfer_size_bytes"] == 200
    details, _ = build_resource_report([event])
    assert "secret" not in json.dumps(event)
    assert "_resource_timing_key" not in json.dumps(details)


@pytest.mark.asyncio
async def test_failed_or_blocked_resources_cannot_inherit_old_transfer_size():
    page = TimingPage([resource_timing("https://portal.example.net/api/query")])
    events = [
        {"url": "https://portal.example.net/api/query", "resource_type": "fetch", "status": None, "blocked_by_validator": True},
        {"url": "https://portal.example.net/api/query", "resource_type": "fetch", "status": None, "error": "Network failure"},
        {"url": "https://portal.example.net/api/query", "resource_type": "fetch", "status": 200, "response_completed": False},
    ]
    assert await enrich_resource_timings(page, events) == 0
    details, summary = build_resource_report(events)
    assert all(item["transfer_size_bytes"] is None for item in details)
    assert summary["resource_failures"] == 1
    assert summary["resources_observed"] == 3
    assert page.frames[0].evaluations == []


def test_resource_report_has_only_safe_metadata_and_allows_multiple_types():
    event = {
        "url": "https://user:password@portal.example.net/assets/token/secret/image.png?cookie=hidden",
        "resource_type": "image", "status": 200,
        "headers": {"Authorization": "secret"}, "body": "private",
        "transfer_size_bytes": 2000000,
    }
    details, summary = build_resource_report([event, event])
    assert summary["resources_observed"] == 1
    assert details[0]["size_categories"] == ["LARGE_IMAGE", "LARGE_RESOURCE"]
    encoded = json.dumps(details)
    for unsafe in ("password", "secret", "hidden", "Authorization", "private"):
        assert unsafe not in encoded
    assert details[0]["path"].startswith("/assets/token/{redacted}")


def test_observation_delay_does_not_create_slow_page_finding():
    timing = route_performance_timing(
        navigation_ms=150,
        render_start_ms=180,
        render_health={
            "settle_render_ready_ms": 0,
            "settle_application_ms": 300,
            "settle_validator_observation_ms": 6000,
        },
        total_validation_ms=7500,
    )
    assert timing["application_load_ms"] == 480
    assert timing["validator_observation_ms"] == 6000
    assert timing["total_validation_ms"] == 7500
    snapshot = {"text_length": 100, "visible_elements": 10, "busy_indicators": 0}
    _, findings = assess_page_health(snapshot, load_ms=timing["application_load_ms"], slow_page_threshold_ms=5000)
    assert "SLOW_PAGE" not in {item["type"] for item in findings}


def test_genuine_application_delay_remains_slow():
    timing = route_performance_timing(
        navigation_ms=6000,
        render_health={"settle_application_ms": 500, "settle_validator_observation_ms": 1000},
        total_validation_ms=7600,
    )
    assert timing["application_load_ms"] == 6500
    _, findings = assess_page_health(
        {"text_length": 100, "visible_elements": 10, "busy_indicators": 0},
        load_ms=timing["application_load_ms"], slow_page_threshold_ms=5000,
    )
    assert {item["type"] for item in findings} == {"SLOW_PAGE"}


def test_disabled_performance_check_does_not_emit_slow_warning():
    _, findings = assess_page_health(
        {"text_length": 100, "visible_elements": 10, "busy_indicators": 0},
        load_ms=9000, slow_page_threshold_ms=5000, performance_enabled=False,
    )
    assert not findings


@pytest.mark.asyncio
async def test_settle_tracks_ready_time_separately_from_stability_confirmation(monkeypatch):
    import app.health as health
    clock = [0.0]

    async def sleep(seconds):
        clock[0] += seconds

    async def capture(_):
        return {
            "ready_state": "complete", "title": "Generic portal", "text_length": 100,
            "visible_elements": 10, "busy_indicators": 0, "challenge_indicators": 0,
        }

    monkeypatch.setattr(health.time, "perf_counter", lambda: clock[0])
    monkeypatch.setattr(health.asyncio, "sleep", sleep)
    monkeypatch.setattr(health, "capture_render_health", capture)
    snapshot = await wait_for_render_settle(
        object(), settle_ms=100, maximum_ms=3000,
        minimum_observation_ms=2000, network_quiet_ms=500,
    )
    assert snapshot["settle_elapsed_ms"] >= 2000
    assert snapshot["settle_application_ms"] == 0
    assert snapshot["settle_validator_observation_ms"] >= 2000
    assert snapshot["settle_render_ready_ms"] == 0


@pytest.mark.asyncio
async def test_real_chromium_reports_natural_image_bytes_without_extra_http_requests():
    requests = Counter()
    image = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
        '<!--' + 'fixture-size-padding' * 150 + '--><rect width="10" height="10"/></svg>'
    ).encode()

    class ResourceHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests[self.path] += 1
            if self.path == "/":
                body = b'<html><body><h1>Generic resource fixture</h1><img src="/image.svg"></body></html>'
                content_type = "text/html"
            elif self.path == "/image.svg":
                body = image
                content_type = "image/svg+xml"
            else:
                body = b""
                content_type = "text/plain"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), ResourceHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).is_file():
                pytest.skip("matching Playwright Chromium is not installed on this host")
            browser = await playwright.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                page = await context.new_page()
                events = []

                def response_seen(response):
                    if response.request.resource_type == "image":
                        events.append({
                            "url": response.url, "resource_type": "image",
                            "status": response.status,
                            "initiating_route": f"http://127.0.0.1:{server.server_port}/",
                        })

                context.on("response", response_seen)
                await page.goto(f"http://127.0.0.1:{server.server_port}/", wait_until="load")
                before = requests.copy()
                assert before["/image.svg"] == 1
                assert await enrich_resource_timings(page, events) == 1
                details, summary = build_resource_report(events, large_image_threshold_bytes=1024)
                assert requests == before
                assert details[0]["encoded_body_size_bytes"] == len(image)
                assert details[0]["transfer_size_bytes"] >= len(image)
                assert details[0]["type"] == "IMAGE"
                assert details[0]["size_categories"] == ["LARGE_IMAGE"]
                assert summary["large_images"] == 1
            finally:
                await browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
