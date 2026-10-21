FROM cgr.dev/chainguard/wolfi-base:latest@sha256:c2a4815b6ca49b9bbafd451b4bde690d567a86b2b6b54877faac8082a7bc4296 AS runtime-base

# The venv is copied into a runtime that installs python-3.15, so the builder
# must stay on a Python 3.15 digest; the assertion below catches minor drift.
FROM cgr.dev/chainguard/python:latest-dev@sha256:905b31747ebcae4242e0b71fcd2640c712b79a96f929811d3202b9716b66592a AS builder

ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

USER 0
WORKDIR /app
COPY requirements.txt .
RUN python -c "import sys; assert sys.version_info[:2] == (3, 15), sys.version" \
    && python -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir --no-compile -r requirements.txt \
    && /app/.venv/bin/python -m playwright install chromium \
    && chgrp -R 0 /ms-playwright \
    && chmod -R a+rX,go-w /ms-playwright \
    && /app/.venv/bin/python -c "from pathlib import Path; from playwright.sync_api import sync_playwright; manager = sync_playwright().start(); browser_path = Path(manager.chromium.executable_path); print(f'Playwright expected Chromium: {browser_path}'); assert browser_path.is_file(), f'Playwright Chromium missing: {browser_path}'; assert str(browser_path).startswith('/ms-playwright/'), f'Unexpected Chromium location: {browser_path}'; manager.stop(); print('Playwright Chromium installation verified')" \
    && /app/.venv/bin/pip uninstall -y pip setuptools

# Download an exact, signed APK transaction without shipping download/build tools.
FROM cgr.dev/chainguard/python:latest-dev@sha256:905b31747ebcae4242e0b71fcd2640c712b79a96f929811d3202b9716b66592a AS runtime-packages
ARG APK_REPOSITORY=https://apk.cgr.dev/chainguard
USER 0
COPY --from=runtime-base / /tmp/apk-root/
RUN --mount=type=cache,id=portal-validator-apks,target=/tmp/apks set -eu; \
    mkdir -p /runtime-repository/x86_64 /tmp/apk-root; \
    wget --https-only --prefer-family=IPv4 --timeout=30 --tries=5 \
      --retry-connrefused --retry-on-host-error \
      --retry-on-http-error=429,500,502,503,504 --quiet \
      "$APK_REPOSITORY/x86_64/APKINDEX.tar.gz" \
      -O /runtime-repository/x86_64/APKINDEX.tar.gz; \
    printf '%s\n' /runtime-repository > /etc/apk/repositories; \
    transaction="$(apk --root /tmp/apk-root --initdb --keys-dir /etc/apk/keys \
      --repositories-file /etc/apk/repositories --no-network --simulate --no-progress \
      add 'glibc>=2.44-r8' python-3.15 libnss-tools openssl font-opensans libatk-bridge-2.0 \
      cups-libs libxcomposite libxdamage libxfixes libxrandr libxkbcommon \
      mesa-gbm alsa-lib pango libx11 libxcb libxext libstdc++ libexpat1 dbus-libs libudev 2>&1)" \
      || { printf '%s\n' "$transaction" >&2; exit 1; }; \
    printf '%s\n' "$transaction"; \
    printf '%s\n' "$transaction" \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (\([^)]*\)).*/\1=\2/p' \
      > /runtime-repository/constraints; \
    test -s /runtime-repository/constraints; \
    package_files="$(printf '%s\n' "$transaction" \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (\([^)]*\)).*/\1-\2.apk/p')"; \
    for package_file in $package_files; do \
      if [ ! -s "/tmp/apks/$package_file" ]; then \
        downloaded=0; \
        for attempt in 1 2 3 4 5; do \
          if wget --https-only --prefer-family=IPv4 --timeout=30 --tries=3 \
            --retry-connrefused --retry-on-host-error \
            --retry-on-http-error=429,500,502,503,504 --quiet \
            "$APK_REPOSITORY/x86_64/$package_file" -O "/tmp/apks/$package_file.partial"; then \
            downloaded=1; break; \
          fi; \
          echo "Package download failed; retry $attempt: $package_file" >&2; \
          sleep "$attempt"; \
        done; \
        test "$downloaded" = 1; \
        mv "/tmp/apks/$package_file.partial" "/tmp/apks/$package_file"; \
      fi; \
      cp "/tmp/apks/$package_file" /runtime-repository/x86_64/; \
    done

FROM runtime-base

ARG APK_REPOSITORY=https://apk.cgr.dev/chainguard

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    MAX_CONCURRENT_SCANS=2 SESSION_STATE_DIR=/auth PATH=/app/.venv/bin:$PATH

USER 0
WORKDIR /app
RUN --mount=type=bind,from=runtime-packages,source=/runtime-repository,target=/runtime-repository \
    set -eux; \
    printf '%s\n' /runtime-repository > /etc/apk/repositories; \
    apk --no-network --no-progress add --no-cache $(cat /runtime-repository/constraints); \
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
LABEL org.opencontainers.image.version="1.13.9" \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.created=$BUILD_TIMESTAMP

RUN python -m app.build_info --git-commit "$VCS_REF" --timestamp "$BUILD_TIMESTAMP" \
    && python -c "from app.build_info import build_diagnostics; identity = build_diagnostics(); assert identity['source_integrity']['status'] != 'MISMATCH', identity; print('Final runtime build identity verified')" \
    && python -c "from pathlib import Path; from playwright.sync_api import sync_playwright; manager = sync_playwright().start(); browser_path = Path(manager.chromium.executable_path); print(f'Playwright expected Chromium: {browser_path}'); assert browser_path.is_file(), f'Playwright Chromium missing: {browser_path}'; manager.stop(); print('Final runtime Playwright Chromium verified')" \
    && command -v certutil >/dev/null \
    && HOME=/tmp/portal-validator-build-home python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(headless=True); b.close(); b = p.chromium.launch(headless=True, channel='chromium'); b.close(); p.stop(); print('Final runtime Chromium launch verified')" \
    && rm -rf /tmp/portal-validator-build-home

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
ENTRYPOINT ["/app/container-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips=*"]
