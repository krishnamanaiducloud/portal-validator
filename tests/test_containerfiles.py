"""Structural guards against retaining build tools or duplicated browser layers."""

from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def test_runtime_copies_matching_venv_and_browser_without_copy_up():
    dockerfile = (REPO / "Dockerfile").read_text()
    runtime = dockerfile.split("FROM runtime-base\n", 1)[1]
    assert "COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv" in runtime
    assert "COPY --from=builder --chown=0:0 /ms-playwright /ms-playwright" in runtime
    assert "chmod -R" not in runtime
    assert "chgrp -R" not in runtime
    assert "Final runtime Chromium launch verified" in runtime
    assert "command -v certutil" in runtime
    assert "USER 10001:10001" in runtime
    assert 'ENTRYPOINT ["/app/container-entrypoint.sh"]' in runtime


def test_runtime_uses_signed_exact_apk_transaction_and_debug_adds_only_delta():
    dockerfile = (REPO / "Dockerfile").read_text()
    debugfile = (REPO / "Dockerfile-debug").read_text()
    assert "@sha256:" in dockerfile
    assert "--no-network --no-progress add --no-cache" in dockerfile
    assert "--allow-untrusted" not in dockerfile
    assert "--no-check-certificate" not in dockerfile
    assert "apk upgrade" not in dockerfile
    assert "FROM ${PRODUCTION_IMAGE}" in debugfile
    assert "COPY --from" not in debugfile
    assert "python -m pip uninstall -y pip setuptools" in debugfile
    assert "USER 10001:10001" in debugfile
