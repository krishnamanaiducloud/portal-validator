"""Non-sensitive build identity and detection of source/asset mount drift.

The manifest is generated inside the final image, not copied from the worktree.
It compares runtime files with that image's source snapshot; it is not a signed
image attestation. A registry digest must be supplied separately by the workload
or verified against the registry/deployment by an operator.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from app.version import VALIDATOR_VERSION

SOURCE_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_NAME = "build-info.json"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def source_hashes(root: Path) -> dict[str, str]:
    """Hash application assets/code, excluding generated Python bytecode."""
    app_dir = root / "app"
    if not app_dir.is_dir():
        raise ValueError("Application source directory is missing")
    files = [
        path for path in app_dir.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    ]
    entrypoint = root / "container-entrypoint.sh"
    if entrypoint.is_file():
        files.append(entrypoint)
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(files)
    }


def _timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Build timestamp must contain a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def create_build_manifest(root: Path, git_commit: str | None = None,
                          timestamp: str | None = None) -> dict:
    git_commit = git_commit or None
    if git_commit is not None and not _COMMIT.fullmatch(git_commit):
        raise ValueError("Build revision must be an exact 40-character Git commit")
    return {
        "schema_version": 1,
        "version": VALIDATOR_VERSION,
        "git_commit": git_commit,
        "build_timestamp": _timestamp(timestamp),
        "source_sha256": source_hashes(root),
    }


def frontend_identity(root: Path = SOURCE_ROOT) -> tuple[str, str]:
    digest = hashlib.sha256((root / "app/static/app.js").read_bytes()).digest()
    return digest.hex(), "sha256-" + base64.b64encode(digest).decode("ascii")


def build_diagnostics(root: Path = SOURCE_ROOT) -> dict:
    """Never return environment contents, certificate data or source contents."""
    manifest_path = root / MANIFEST_NAME
    try:
        frontend_sha256, _ = frontend_identity(root)
    except OSError:
        frontend_sha256 = None
    supplied_digest = os.getenv("PORTAL_VALIDATOR_IMAGE_DIGEST", "")
    image_digest = supplied_digest if _DIGEST.fullmatch(supplied_digest) else None
    result = {
        "version": VALIDATOR_VERSION,
        "git_commit": None,
        "build_timestamp": None,
        "image_digest": image_digest,
        "image_digest_source": "workload_configuration" if image_digest else "not_supplied",
        "frontend_sha256": frontend_sha256,
        "source_integrity": {
            "status": "UNVERIFIED",
            "reason": "No container build manifest is available (local development or older image).",
        },
    }
    if frontend_sha256 is None:
        result["source_integrity"] = {
            "status": "MISMATCH",
            "reason": "The runtime dashboard script is missing or unreadable.",
        }
    if not manifest_path.is_file():
        return result
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("Invalid build manifest")
        hashes = manifest["source_sha256"]
        if manifest.get("schema_version") != 1 or not isinstance(hashes, dict) or not hashes:
            raise ValueError("Invalid build manifest")
        if any(not isinstance(name, str) or not isinstance(digest, str)
               or not _SHA256.fullmatch(digest) for name, digest in hashes.items()):
            raise ValueError("Invalid build hashes")
        commit = manifest.get("git_commit")
        if commit is not None and (not isinstance(commit, str) or not _COMMIT.fullmatch(commit)):
            raise ValueError("Invalid build revision")
        timestamp = manifest["build_timestamp"]
        if not isinstance(timestamp, str) or not timestamp:
            raise ValueError("Invalid build timestamp")
        timestamp = _timestamp(timestamp)
        result.update(git_commit=commit, build_timestamp=timestamp)
        if (frontend_sha256 is None or manifest.get("version") != VALIDATOR_VERSION
                or hashes != source_hashes(root)):
            result["source_integrity"] = {
                "status": "MISMATCH",
                "reason": "Runtime application files differ from the final image's build manifest.",
            }
        elif commit is None:
            result["source_integrity"]["reason"] = (
                "Runtime files match the build manifest, but the build did not record a Git revision."
            )
        else:
            result["source_integrity"] = {
                "status": "VERIFIED",
                "reason": "Runtime application files match the final image's recorded source snapshot.",
            }
    except (OSError, ValueError, TypeError, KeyError):
        result["source_integrity"] = {
            "status": "MISMATCH",
            "reason": "The container build manifest or runtime source snapshot is unreadable or invalid.",
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Record final-image source identity")
    parser.add_argument("--git-commit", default="")
    parser.add_argument("--timestamp", default="")
    args = parser.parse_args()
    manifest = create_build_manifest(SOURCE_ROOT, args.git_commit, args.timestamp)
    target = SOURCE_ROOT / MANIFEST_NAME
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    target.chmod(0o444)
    print("Final image application build manifest created")


if __name__ == "__main__":
    main()
