FROM cgr.dev/chainguard/python:latest-dev@sha256:1c830d26eef0eb4231d8c119e037bee325329aa0ac67c527a86d6e62c05d23d1

ARG APK_REPOSITORY=https://apk.cgr.dev/chainguard

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    MAX_CONCURRENT_SCANS=2 SESSION_STATE_DIR=/auth PATH=/app/.venv/bin:$PATH

USER 0
WORKDIR /app
RUN --mount=type=cache,id=portal-validator-apks,target=/tmp/apks set -eux; \
    mkdir -p /tmp/repository/x86_64; \
    wget --https-only --timeout=30 --tries=5 --retry-connrefused \
      --retry-on-http-error=429,500,502,503,504 --quiet \
      "$APK_REPOSITORY/x86_64/APKINDEX.tar.gz" \
      -O /tmp/repository/x86_64/APKINDEX.tar.gz; \
    printf '%s\n' /tmp/repository > /etc/apk/repositories; \
    apk --no-network --no-progress update; \
    chromium_deps="$(apk --no-network --simulate --no-progress add chromium 2>&1 \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (.*/\1/p' \
      | grep -v '^chromium$')"; \
    transaction="$(apk --no-network --simulate --no-progress \
      add libnss-tools $chromium_deps 2>&1)"; \
    runtime_constraints="$(printf '%s\n' "$transaction" \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (\([^)]*\)).*/\1=\2/p')"; \
    runtime_package_files="$(printf '%s\n' "$transaction" \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (\([^)]*\)).*/\1-\2.apk/p' \
      | grep -v '^chromium-')"; \
    for package_file in $runtime_package_files; do \
          if [ ! -s "/tmp/apks/$package_file" ]; then \
            wget --https-only --timeout=30 --tries=5 --retry-connrefused \
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
    CHROMIUM_NSS_DB=/tmp/portal-validator-home/.local/share/pki/nssdb \
    RUNTIME_CA_BUNDLE=/tmp/portal-validator-ca-bundle.pem
ARG CHROMIUM_VERSION=154.0.8037.92
ENV CHROMIUM_EXECUTABLE_PATH=/opt/chrome-headless-shell/chrome-headless-shell

COPY requirements.txt .
RUN python -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir --no-compile -r requirements.txt \
    && curl -fsSL --connect-timeout 15 --max-time 300 --retry 5 --retry-all-errors \
      "https://storage.googleapis.com/chrome-for-testing-public/${CHROMIUM_VERSION}/linux64/chrome-headless-shell-linux64.zip" \
      -o /tmp/chromium.zip \
    && unzip -q /tmp/chromium.zip -d /opt \
    && mv /opt/chrome-headless-shell-linux64 /opt/chrome-headless-shell \
    && rm /tmp/chromium.zip \
    && chmod -R a+rX /opt/chrome-headless-shell \
    && /opt/chrome-headless-shell/chrome-headless-shell --version \
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
COPY --chown=10001:10001 app ./app

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
ENTRYPOINT []
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips=*"]
