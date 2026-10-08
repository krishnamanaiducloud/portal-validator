import html
import json
from pathlib import Path

import pytest
from playwright.async_api import async_playwright

from app.main import ScanRequest, execute_scan
from app.network import is_read_only_graphql_body, load_read_only_policy
from test_scan_post_lifecycle import production_spa


@pytest.mark.parametrize("query", [
    "{ health }", "query Health { health }",
    'query { search(text: "mutation is just a string") }',
    "# mutation is a comment\nquery { health }",
    "query { ...Fields } fragment Fields on Query { health }",
])
def test_explicit_graphql_query_contract_accepts_parsed_queries(query):
    assert is_read_only_graphql_body(json.dumps({"query": query}))


@pytest.mark.parametrize("payload", [
    {"query": "mutation { deleteAccount }"},
    {"query": "subscription { changes }"},
    {"query": "query Read { health } mutation Write { deleteAccount }", "operationName": "Read"},
    {"query": "query A { health } query B { health }"},
    {"query": "query A { health }", "operationName": "Missing"},
    {"query": "fragment Fields on Query { health }"},
    {"query": "query { fixture-private-invalid-body"},
    {"extensions": {"persistedQuery": {"sha256Hash": "unverified"}}},
    [], [{"query": "{ health }"}, {"query": "mutation { change }"}],
    {"query": "{ health }", "operationName": 123},
])
def test_graphql_unknown_mutation_or_malformed_body_fails_closed(payload, caplog):
    assert not is_read_only_graphql_body(json.dumps(payload))
    assert "fixture-private" not in caplog.text


def test_query_only_policy_takes_precedence_over_overlapping_legacy_rule():
    rule = {"method": "POST", "host": "api.example.net", "path": "/operations"}
    policy = load_read_only_policy(raw=json.dumps({
        "safe_application_requests": [rule, {**rule, "graphql_queries_only": True}],
    }))
    assert policy.match("POST", "https://api.example.net/operations").graphql_queries_only
    assert not is_read_only_graphql_body("x" * 65537)
    assert not is_read_only_graphql_body(None)
    assert not is_read_only_graphql_body("not JSON")
    assert is_read_only_graphql_body(json.dumps([{"query": "{ health }"}, {"query": "{ health }"}]))


@pytest.mark.parametrize("body", [
    '{"query":"mutation { deleteAccount }","query":"{ health }"}',
    '{"query":"{ health }","query":"mutation { deleteAccount }"}',
    '{"query":"query A { health }","operationName":"Write","operationName":"A"}',
    '{"query":"{ health }","variables":{"id":"one","id":"two"}}',
    chr(0xD800),
])
def test_ambiguous_or_invalid_unicode_graphql_body_fails_closed(body, caplog):
    assert not is_read_only_graphql_body(body)
    assert "deleteAccount" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("query,allowed", [("query { health }", True), ("mutation { deleteAccount }", False)])
async def test_production_scan_observes_graphql_without_replaying_or_allowing_mutation(production_spa, query, allowed):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    origin, handler = production_spa
    handler.graphql_operation = query
    report = await execute_scan(ScanRequest(
        target=origin, max_pages=2, timeout_ms=10000, total_timeout_ms=60000,
        render_settle_ms=200, min_observation_ms=500, network_quiet_ms=200,
        max_navigation_actions=0, check_security_headers=False,
        approved_read_post_operations=[{
            "method": "POST", "host": "127.0.0.1", "path": "/api/query",
            "graphql_queries_only": True,
        }],
    ))
    post = next(item for item in report["api_inventory"] if item["method"] == "POST")
    assert post["calls"] == 7
    assert post["blocked_count"] == (0 if allowed else 7)
    assert post["status_2xx"] == (7 if allowed else 0)
    assert len(handler.post_paths) == (7 if allowed else 0)
    assert handler.mutation_calls == 0
    assert "fixture-private" not in json.dumps(report)


@pytest.mark.asyncio
@pytest.mark.parametrize("query,allowed", [("query { health }", True), ("mutation { deleteAccount }", False)])
async def test_main_frame_auth_signal_cannot_bypass_query_only_rule(production_spa, monkeypatch, query, allowed):
    async with async_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("matching Playwright Chromium is not installed on this host")
    origin, handler = production_spa
    original_get = handler.do_GET

    def main_frame_post(self):
        if self.path != "/":
            return original_get(self)
        # text/plain forms serialize name=value. Keep that separator inside a
        # padding string so the real browser submits a valid JSON main document.
        name = html.escape('{"query":' + json.dumps(query) + ',"padding":"', quote=True)
        body = (
            '<!doctype html><html><body><form id="operation" method="POST" '
            'enctype="text/plain" action="/api/query?client_id=fixture">'
            f'<input name="{name}" value="&quot;}}"></form>'
            '<script>document.querySelector("#operation").submit()</script></body></html>'
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    monkeypatch.setattr(handler, "do_GET", main_frame_post)
    report = await execute_scan(ScanRequest(
        target=origin, max_pages=1, timeout_ms=10000, total_timeout_ms=60000,
        render_settle_ms=200, min_observation_ms=500, network_quiet_ms=200,
        max_navigation_actions=0, check_security_headers=False,
        approved_read_post_operations=[{
            "method": "POST", "host": "127.0.0.1", "path": "/api/query",
            "graphql_queries_only": True,
        }],
    ))
    assert len(handler.post_paths) == (1 if allowed else 0)
    assert handler.mutation_calls == 0
    assert "fixture-private" not in json.dumps(report)
