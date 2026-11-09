FROM cgr.dev/chainguard/wolfi-base:latest@sha256:24f549a7fcace88e69b9557941168c74645688ecc4acf7fb6d734a6b74e9019d AS runtime-base

# The venv is copied into a runtime that installs python-3.15, so the builder
# must stay on a Python 3.15 digest; the assertion below catches minor drift.
FROM cgr.dev/chainguard/python:latest-dev@sha256:6b7c43c25f9446e8b1cf850797826a3d40b7cccdc6370c6e1b31cb28adae0a18 AS builder

ARG BROWSER_PLAYWRIGHT_VERSION=1.65.0
ARG BROWSER_REVISION=1254
ARG PYTHON_DRIVER_REVISION=1248
ARG TARGETARCH

ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    npm_config_fetch_timeout=30000 npm_config_fetch_retries=5 \
    npm_config_fetch_retry_mintimeout=1000 npm_config_fetch_retry_maxtimeout=10000

USER 0
WORKDIR /app
COPY requirements.txt .
RUN --mount=type=cache,id=portal-validator-builder-apks-${TARGETARCH},target=/var/cache/apk,sharing=locked \
    set -eu; \
    python -c "import sys; assert sys.version_info[:2] == (3, 15), sys.version"; \
    installed=0; \
    for attempt in 1 2 3 4 5; do \
      if timeout 120 apk --cache-dir /var/cache/apk --cache-max-age 0 \
        --timeout 60 --no-progress add nodejs-24 npm; then \
        installed=1; break; \
      fi; \
      echo "Builder package installation failed; retry $attempt" >&2; \
      sleep "$attempt"; \
    done; \
    test "$installed" = 1; \
    python -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir --no-compile -r requirements.txt \
    && npx --yes "playwright@${BROWSER_PLAYWRIGHT_VERSION}" install chromium \
    && test -d "/ms-playwright/chromium-${BROWSER_REVISION}" \
    && test -d "/ms-playwright/chromium_headless_shell-${BROWSER_REVISION}" \
    && ln -s "chromium-${BROWSER_REVISION}" "/ms-playwright/chromium-${PYTHON_DRIVER_REVISION}" \
    && ln -s "chromium_headless_shell-${BROWSER_REVISION}" "/ms-playwright/chromium_headless_shell-${PYTHON_DRIVER_REVISION}" \
    && chgrp -R 0 /ms-playwright \
    && chmod -R a+rX,go-w /ms-playwright \
    && /app/.venv/bin/python -c "from pathlib import Path; from playwright.sync_api import sync_playwright; manager = sync_playwright().start(); browser_path = Path(manager.chromium.executable_path); print(f'Playwright expected Chromium: {browser_path}'); assert browser_path.is_file(), f'Playwright Chromium missing: {browser_path}'; assert str(browser_path).startswith('/ms-playwright/'), f'Unexpected Chromium location: {browser_path}'; manager.stop(); print('Playwright Chromium installation verified')" \
    && /app/.venv/bin/pip uninstall -y pip setuptools

# Install only signed runtime packages; Node, npm and browser download tooling
# remain confined to the separate builder stage above.
FROM runtime-base AS runtime-packages
ARG APK_REPOSITORY=https://apk.cgr.dev/chainguard
ARG TARGETARCH
USER 0
# The current Python builder carries the newest Wolfi trust store. Copy it
# before apk resolves runtime packages so newly rotated repository chains are
# verified without disabling TLS or signature checks.
COPY --from=builder --chown=0:0 --chmod=0644 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN --mount=type=cache,id=portal-validator-runtime-apks-${TARGETARCH},target=/var/cache/apk,sharing=locked \
    set -eu; \
    printf '%s\n' "$APK_REPOSITORY" > /tmp/runtime-repositories; \
    installed=0; \
    for attempt in 1 2 3 4 5; do \
      if timeout 120 apk --repositories-file /tmp/runtime-repositories \
        --cache-dir /var/cache/apk --cache-max-age 0 --timeout 60 --no-progress add \
        'glibc>=2.44-r8' python-3.15 libnss-tools openssl font-opensans libatk-bridge-2.0 \
        cups-libs libxcomposite libxdamage libxfixes libxrandr libxkbcommon \
        mesa-gbm alsa-lib pango libx11 libxcb libxext libstdc++ libexpat1 dbus-libs libudev; then \
        installed=1; break; \
      fi; \
      echo "Runtime package installation failed; retry $attempt" >&2; \
      sleep "$attempt"; \
    done; \
    test "$installed" = 1; \
    rm -f /tmp/runtime-repositories

FROM runtime-packages

ARG APK_REPOSITORY=https://apk.cgr.dev/chainguard

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    MAX_CONCURRENT_SCANS=2 SESSION_STATE_DIR=/auth PATH=/app/.venv/bin:$PATH

USER 0
WORKDIR /app
RUN set -eux; \
    glibc_version="$(awk '/^P:/ { package=substr($0,3) } /^V:/ && package ~ /^glibc(-[0-9.]+)?$/ { print substr($0,3); exit }' /usr/lib/apk/db/installed)"; \
    test -n "$glibc_version"; \
    test "$(apk version -t "$glibc_version" 2.44-r8)" != '<'; \
    printf '%s\n' "$APK_REPOSITORY" > /etc/apk/repositories; \
    addgroup -g 10001 validator; \
    adduser -D -H -u 10001 -G validator -s /sbin/nologin validator; \
    mkdir -p /auth /app; \
    chown -R 10001:10001 /auth /app

ENV HOME=/tmp/portal-validator-home \
    PORTAL_VALIDATOR_MANAGED_CA_BUNDLE=/etc/portal-validator/certs/ca-bundle.crt \
    CHROMIUM_NSS_DB=/tmp/portal-validator-home/.local/share/pki/nssdb \
    RUNTIME_CA_BUNDLE=/tmp/portal-validator-home/.portal-validator/ca-bundle.crt \
    SSL_CERT_FILE=/tmp/portal-validator-home/.portal-validator/ca-bundle.crt \
    REQUESTS_CA_BUNDLE=/tmp/portal-validator-home/.portal-validator/ca-bundle.crt \
    CURL_CA_BUNDLE=/tmp/portal-validator-home/.portal-validator/ca-bundle.crt

COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv
COPY --from=builder --chown=0:0 /ms-playwright /ms-playwright
COPY --chown=10001:10001 --chmod=0555 container-entrypoint.sh /app/container-entrypoint.sh
COPY --chown=10001:10001 app ./app

# Source identity must not invalidate unchanged OS/venv/browser layers.
ARG VCS_REF=""
ARG BUILD_TIMESTAMP=""
LABEL org.opencontainers.image.version="1.13.12" \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.created=$BUILD_TIMESTAMP

RUN python -m app.build_info --git-commit "$VCS_REF" --timestamp "$BUILD_TIMESTAMP" \
    && python -c "from app.build_info import build_diagnostics; identity = build_diagnostics(); assert identity['source_integrity']['status'] != 'MISMATCH', identity; print('Final runtime build identity verified')" \
    && python -c "from pathlib import Path; from playwright.sync_api import sync_playwright; manager = sync_playwright().start(); browser_path = Path(manager.chromium.executable_path); print(f'Playwright expected Chromium: {browser_path}'); assert browser_path.is_file(), f'Playwright Chromium missing: {browser_path}'; manager.stop(); print('Final runtime Playwright Chromium verified')" \
    && command -v certutil >/dev/null \
    && HOME=/tmp/portal-validator-build-home python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(headless=True); print(f'Final runtime Chromium version: {b.version}'); assert b.version.startswith('158.0.8127.18'), b.version; b.close(); b = p.chromium.launch(headless=True, channel='chromium'); assert b.version.startswith('158.0.8127.18'), b.version; b.close(); p.stop(); print('Final runtime Chromium launch verified')" \
    && rm -rf /tmp/portal-validator-build-home

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
ENTRYPOINT ["/app/container-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips=*"]
