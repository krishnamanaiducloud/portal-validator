FROM cgr.dev/chainguard/python:latest-dev@sha256:1c830d26eef0eb4231d8c119e037bee325329aa0ac67c527a86d6e62c05d23d1

ARG APK_REPOSITORY=https://apk.cgr.dev/chainguard

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    MAX_CONCURRENT_SCANS=2 SESSION_STATE_DIR=/auth PATH=/app/.venv/bin:$PATH

USER 0
WORKDIR /app
RUN set -eux; \
    printf '%s\n' "$APK_REPOSITORY" > /etc/apk/repositories; \
    for attempt in 1 2 3 4 5; do \
      apk --timeout 30 --no-progress update && break; \
      [ "$attempt" -eq 5 ] && exit 1; \
    done; \
    chromium_deps="$(apk --simulate --no-progress add chromium 2>&1 \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (.*/\1/p' \
      | grep -v '^chromium$')"; \
    apk --timeout 30 --no-progress add --no-cache $chromium_deps; \
    rm -rf /var/cache/apk/*; \
    printf '%s\n' 'https://apk.cgr.dev/chainguard' > /etc/apk/repositories; \
    addgroup -g 10001 validator \
    && adduser -D -H -u 10001 -G validator -s /sbin/nologin validator \
    && mkdir -p /auth /app \
    && chown -R 10001:10001 /auth /app

ENV HOME=/tmp
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
