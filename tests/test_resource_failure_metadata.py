"""Failure diagnostics retain actual resource method/time without fake evidence."""
from app.reporting import aggregate_resource_events


def test_failed_resource_metadata_retains_observation_times_and_method():
    inventory = aggregate_resource_events([
        {"url": "https://assets.example/app.js", "method": "GET", "resource_type": "script",
         "observed_at": "2026-01-01T00:00:00.000+00:00", "status": 502,
         "lifecycle_status": "INCOMPLETE", "initiating_route": "route-a"},
        {"url": "https://assets.example/app.js", "method": "GET", "resource_type": "script",
         "observed_at": "2026-01-01T00:00:01.000+00:00", "status": 200,
         "lifecycle_status": "COMPLETED", "initiating_route": "route-b"},
    ])
    assert len(inventory) == 1
    item = inventory[0]
    assert item["method"] == "GET"
    assert item["method_counts"] == {"GET": 2}
    assert item["first_seen"] == "2026-01-01T00:00:00.000+00:00"
    assert item["last_seen"] == "2026-01-01T00:00:01.000+00:00"
    assert item["failures"] == 1
    assert item["response_status_counts"] == {"502": 1, "200": 1}
    assert item["routes_using_resource"] == ["route-a", "route-b"]


def test_policy_block_does_not_become_a_resource_failure():
    item = aggregate_resource_events([{
        "url": "https://assets.example/widget.js", "method": "GET", "resource_type": "script",
        "blocked_by_validator": True, "error": "net::ERR_BLOCKED_BY_CLIENT", "lifecycle_status": "BLOCKED",
    }])[0]
    assert item["validator_blocks"] == 1
    assert item["failures"] == 0
    assert item["first_seen"] is None and item["last_seen"] is None


def test_legacy_resource_metadata_does_not_invent_request_method_or_times():
    item = aggregate_resource_events([{
        "url": "https://assets.example/widget.js", "resource_type": "script", "status": 503,
    }])[0]
    assert item["method"] is None
    assert item["method_counts"] == {}
    assert item["first_seen"] is None and item["last_seen"] is None
