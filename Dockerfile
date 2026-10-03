FROM cgr.dev/chainguard/python:latest-dev@sha256:1c830d26eef0eb4231d8c119e037bee325329aa0ac67c527a86d6e62c05d23d1

ARG APK_REPOSITORY=https://apk.cgr.dev/chainguard

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    MAX_CONCURRENT_SCANS=2 SESSION_STATE_DIR=/auth PATH=/app/.venv/bin:$PATH

USER 0
WORKDIR /app
RUN --mount=type=cache,id=portal-validator-apks,target=/tmp/apks set -eux; \
    mkdir -p /tmp/repository/x86_64; \
    wget --https-only --prefer-family=IPv4 --timeout=30 --tries=5 \
      --retry-connrefused --retry-on-host-error \
      --retry-on-http-error=429,500,502,503,504 --quiet \
      "$APK_REPOSITORY/x86_64/APKINDEX.tar.gz" \
      -O /tmp/repository/x86_64/APKINDEX.tar.gz; \
    printf '%s\n' /tmp/repository > /etc/apk/repositories; \
    apk --no-network --no-progress update; \
    chromium_deps="$(apk --no-network --no-cache --simulate --no-progress add chromium 2>&1 \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (.*/\1/p' \
      | grep -v '^chromium$')"; \
    transaction="$(apk --no-network --no-cache --simulate --no-progress \
      add libnss-tools openssl $chromium_deps 2>&1)"; \
    runtime_constraints="$(printf '%s\n' "$transaction" \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (\([^)]*\)).*/\1=\2/p')"; \
    runtime_package_files="$(printf '%s\n' "$transaction" \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (\([^)]*\)).*/\1-\2.apk/p' \
      | grep -v '^chromium-')"; \
    for package_file in $runtime_package_files; do \
          if [ ! -s "/tmp/apks/$package_file" ]; then \
            wget --https-only --prefer-family=IPv4 --timeout=30 --tries=5 \
              --retry-connrefused --retry-on-host-error \
              --retry-on-http-error=429,500,502,503,504 \
              --quiet "$APK_REPOSITORY/x86_64/$package_file" \
              -O "/tmp/apks/$package_file.partial"; \
            mv "/tmp/apks/$package_file.partial" "/tmp/apks/$package_file"; \
          fi; \
    done; \
    ln -s /tmp/apks/*.apk /tmp/repository/x86_64/; \
    apk --no-network --no-progress add --no-cache $runtime_constraints; \
    rm -rf /tmp/repository /var/cache/apk/*; \
    printf '%s\n' 'https://apk.cgr.dev/chainguard' > /etc/apk/repositories; \
    addgroup -g 10001 validator \
    && adduser -D -H -u 10001 -G validator -s /sbin/nologin validator \
    && mkdir -p /auth /app \
    && chown -R 10001:10001 /auth /app

ENV HOME=/tmp/portal-validator-home \
    PORTAL_VALIDATOR_MANAGED_CA_BUNDLE=/etc/portal-validator/certs/ca-bundle.crt \
    CHROMIUM_NSS_DB=/tmp/portal-validator-home/.local/share/pki/nssdb \
    RUNTIME_CA_BUNDLE=/tmp/portal-validator-home/.portal-validator/ca-bundle.crt

COPY requirements.txt .
RUN python -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir --no-compile -r requirements.txt \
    && /app/.venv/bin/python -m playwright install chromium \
    && chgrp -R 0 /ms-playwright \
    && chmod -R a+rX,go-w /ms-playwright \
    && /app/.venv/bin/python -c "from pathlib import Path; from playwright.sync_api import sync_playwright; manager = sync_playwright().start(); browser_path = Path(manager.chromium.executable_path); print(f'Playwright expected Chromium: {browser_path}'); assert browser_path.is_file(), f'Playwright Chromium missing: {browser_path}'; assert str(browser_path).startswith('/ms-playwright/'), f'Unexpected Chromium location: {browser_path}'; manager.stop(); print('Playwright Chromium installation verified')" \
    && /app/.venv/bin/pip uninstall -y pip setuptools \
    && apk --no-network del \
      bash \
      binutils \
      build-base \
      gcc \
      git \
      glibc-2.44-dev \
      libstdc++-dev \
      libxcrypt-dev \
      linux-headers \
      make \
      openssf-compiler-options \
      pkgconf \
      posix-cc-wrappers \
      py3.14-pip \
      py3.14-pip-base \
      py3.14-setuptools \
      python-3.14-base-dev \
      python-3.14-dev \
      uv \
      wget

ENV SSL_CERT_FILE=/tmp/portal-validator-home/.portal-validator/ca-bundle.crt \
    REQUESTS_CA_BUNDLE=/tmp/portal-validator-home/.portal-validator/ca-bundle.crt \
    CURL_CA_BUNDLE=/tmp/portal-validator-home/.portal-validator/ca-bundle.crt
COPY --chown=10001:10001 --chmod=0555 container-entrypoint.sh /app/container-entrypoint.sh
COPY --chown=10001:10001 app ./app

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
ENTRYPOINT ["/app/container-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips=*"]
