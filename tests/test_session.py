import json
from pathlib import Path

import pytest

from app.session import RuntimeSessionStore, load_refresh_config, refresh_browser_session


class FakeContext:
    async def storage_state(self):
        return {"cookies": [{"name": "session", "value": "new-secret"}], "origins": []}


class FakeResponse:
    status = 204


class FakePage:
    url = "https://portal.example.com/ready"

    async def goto(self, url, *, wait_until, timeout):
        assert wait_until == "domcontentloaded"
        assert timeout == 45000
        self.url = "https://portal.example.com/ready"
        return FakeResponse()

    async def wait_for_timeout(self, timeout):
        assert timeout == 250


@pytest.mark.asyncio
async def test_runtime_session_is_seeded_and_refreshed_atomically(tmp_path):
    mounted = tmp_path / "mounted.json"
    mounted.write_text(json.dumps({"cookies": [], "origins": []}), encoding="utf-8")
    store = RuntimeSessionStore(tmp_path / "runtime")
    runtime = store.seed("approved", mounted)
    assert runtime.stat().st_mode & 0o777 == 0o600
    updated = await store.persist(
        "approved",
        FakeContext(),
        expected_mtime_ns=runtime.stat().st_mtime_ns,
    )
    assert updated == runtime
    data = json.loads(runtime.read_text(encoding="utf-8"))
    assert data["cookies"][0]["value"] == "new-secret"


@pytest.mark.asyncio
async def test_concurrent_session_refresh_does_not_overwrite_newer_state(tmp_path):
    mounted = tmp_path / "mounted.json"
    mounted.write_text(json.dumps({"cookies": [], "origins": []}), encoding="utf-8")
    store = RuntimeSessionStore(tmp_path / "runtime")
    runtime = store.seed("approved", mounted)
    stale_generation = runtime.stat().st_mtime_ns
    await store.persist("approved", FakeContext(), expected_mtime_ns=stale_generation)
    skipped = await store.persist("approved", FakeContext(), expected_mtime_ns=stale_generation)
    assert skipped is None


def test_refresh_configuration_is_generic_and_validated(tmp_path):
    (tmp_path / "approved.refresh.json").write_text(json.dumps({
        "refresh_url": "https://identity.example.net/session/refresh",
        "timeout_ms": 45000,
        "settle_ms": 250,
    }), encoding="utf-8")
    config = load_refresh_config("approved", tmp_path)
    assert config.refresh_url == "https://identity.example.net/session/refresh"
    assert config.timeout_ms == 45000
    assert config.settle_ms == 250
    assert load_refresh_config("missing", tmp_path) is None


@pytest.mark.asyncio
async def test_silent_refresh_returns_only_safe_metadata(tmp_path):
    config_path = tmp_path / "approved.refresh.json"
    config_path.write_text(json.dumps({
        "refresh_url": "https://identity.example.net/refresh?token=secret",
        "timeout_ms": 45000,
        "settle_ms": 250,
    }), encoding="utf-8")
    result = await refresh_browser_session(FakePage(), load_refresh_config("approved", tmp_path))
    assert result == {
        "attempted": True,
        "status": 204,
        "requested_origin": "https://identity.example.net",
        "final_origin": "https://portal.example.com",
    }
    assert "secret" not in str(result)
