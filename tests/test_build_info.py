import base64
import hashlib
import json
import re

import pytest
from fastapi.testclient import TestClient

from app import build_info
from app.main import app
from app.version import VALIDATOR_VERSION


@pytest.fixture
def source(tmp_path):
    (tmp_path / "app/static").mkdir(parents=True)
    (tmp_path / "app/static/app.js").write_text("console.log('generic fixture');", encoding="utf-8")
    (tmp_path / "app/main.py").write_text("# generic fixture\n", encoding="utf-8")
    (tmp_path / "container-entrypoint.sh").write_text('#!/bin/sh\nexec "$@"\n', encoding="utf-8")
    return tmp_path


def record_manifest(root, commit="a" * 40):
    manifest = build_info.create_build_manifest(root, commit, "2026-10-11T10:00:00-05:00")
    (root / build_info.MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def test_local_source_is_explicitly_unverified(source):
    identity = build_info.build_diagnostics(source)
    assert identity["source_integrity"]["status"] == "UNVERIFIED"
    assert identity["version"] == VALIDATOR_VERSION
    assert identity["git_commit"] is None
    assert identity["image_digest"] is None


def test_final_image_manifest_matches_actual_files(source):
    record_manifest(source)
    identity = build_info.build_diagnostics(source)
    assert identity["source_integrity"]["status"] == "VERIFIED"
    assert identity["git_commit"] == "a" * 40
    assert identity["build_timestamp"] == "2026-10-11T15:00:00Z"


@pytest.mark.parametrize("change", ["backend", "frontend", "entrypoint", "added", "deleted", "version"])
def test_source_or_asset_mount_drift_is_a_mismatch(source, change):
    manifest = record_manifest(source)
    if change == "backend":
        (source / "app/main.py").write_text("# changed backend", encoding="utf-8")
    elif change == "frontend":
        (source / "app/static/app.js").write_text("// changed frontend", encoding="utf-8")
    elif change == "entrypoint":
        (source / "container-entrypoint.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    elif change == "added":
        (source / "app/unexpected.py").write_text("# unexpected mount", encoding="utf-8")
    elif change == "deleted":
        (source / "app/main.py").unlink()
    else:
        manifest["version"] = "0.0.0"
        (source / build_info.MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    assert build_info.build_diagnostics(source)["source_integrity"]["status"] == "MISMATCH"


def test_bytecode_does_not_cause_false_source_drift(source):
    record_manifest(source)
    (source / "app/__pycache__").mkdir()
    (source / "app/__pycache__/main.cpython-314.pyc").write_bytes(b"generated")
    assert build_info.build_diagnostics(source)["source_integrity"]["status"] == "VERIFIED"


@pytest.mark.parametrize("with_manifest", [True, False])
def test_missing_frontend_is_reported_as_mismatch_not_diagnostic_server_error(source, with_manifest):
    if with_manifest:
        record_manifest(source)
    (source / "app/static/app.js").unlink()
    identity = build_info.build_diagnostics(source)
    assert identity["source_integrity"]["status"] == "MISMATCH"
    assert identity["frontend_sha256"] is None


def test_unreadable_frontend_is_safe_mismatch(source, monkeypatch):
    record_manifest(source)
    def unreadable(_root):
        raise PermissionError("fixture-secret-path")
    monkeypatch.setattr(build_info, "frontend_identity", unreadable)
    identity = build_info.build_diagnostics(source)
    assert identity["source_integrity"]["status"] == "MISMATCH"
    assert "fixture-secret-path" not in json.dumps(identity)


def test_missing_revision_never_claims_verified_source(source):
    record_manifest(source, None)
    identity = build_info.build_diagnostics(source)
    assert identity["source_integrity"]["status"] == "UNVERIFIED"
    assert "did not record a Git revision" in identity["source_integrity"]["reason"]


@pytest.mark.parametrize("payload", ["not json", "[]", "{}", '{"schema_version": 1}', '"secret"'])
def test_invalid_manifest_fails_closed_without_printing_contents(source, payload):
    (source / build_info.MANIFEST_NAME).write_text(payload, encoding="utf-8")
    identity = build_info.build_diagnostics(source)
    assert identity["source_integrity"]["status"] == "MISMATCH"
    assert "secret" not in json.dumps(identity)


@pytest.mark.parametrize("commit", ["main", "latest", "abc", "a" * 41, "token=do-not-expose"])
def test_build_rejects_invalid_git_revision(source, commit):
    with pytest.raises(ValueError, match="exact 40-character"):
        build_info.create_build_manifest(source, commit)


@pytest.mark.parametrize("timestamp", ["yesterday", "2026-10-11T15:00:00", "token=do-not-expose"])
def test_build_rejects_invalid_timestamp(source, timestamp):
    with pytest.raises(ValueError):
        build_info.create_build_manifest(source, "a" * 40, timestamp)


def test_digest_is_only_reported_when_explicitly_supplied_and_valid(source, monkeypatch):
    monkeypatch.setenv("AUTHORIZATION", "Bearer fixture-secret")
    monkeypatch.setenv("PORTAL_VALIDATOR_IMAGE_DIGEST", "sha256:" + "b" * 64)
    identity = build_info.build_diagnostics(source)
    assert identity["image_digest"] == "sha256:" + "b" * 64
    assert identity["image_digest_source"] == "workload_configuration"
    assert "fixture-secret" not in json.dumps(identity)
    monkeypatch.setenv("PORTAL_VALIDATOR_IMAGE_DIGEST", "not-a-digest-secret")
    identity = build_info.build_diagnostics(source)
    assert identity["image_digest"] is None
    assert "not-a-digest-secret" not in json.dumps(identity)


def test_home_serves_content_addressed_script_with_real_subresource_integrity():
    with TestClient(app) as client:
        home = client.get("/")
        match = re.search(r'<script src="(/static/app.js\?v=([a-f0-9]{64}))" integrity="([^"]+)"', home.text)
        assert match
        script_url, expected_sha, integrity = match.groups()
        script = client.get(script_url)
        digest = hashlib.sha256(script.content).digest()
        assert expected_sha == digest.hex()
        assert integrity == "sha256-" + base64.b64encode(digest).decode("ascii")
        assert f'data-frontend-sha256="{expected_sha}"' in home.text
        identity = client.get("/api/diagnostics/build")
        assert identity.status_code == 200
        assert identity.json()["frontend_sha256"] == expected_sha
        assert identity.headers["cache-control"] == "no-store"
        assert home.headers["cache-control"] == "no-store"
        assert "'unsafe-inline'" not in home.headers["content-security-policy"]
