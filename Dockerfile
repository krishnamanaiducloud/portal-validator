FROM cgr.dev/chainguard/python:latest-dev@sha256:87729167739190d9309588120a8ac0ffbf2eb95dd895abb9bada6bb9ecbf5a04

ARG APK_REPOSITORY=https://apk.cgr.dev/chainguard

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    MAX_CONCURRENT_SCANS=2 SESSION_STATE_DIR=/auth PATH=/app/.venv/bin:$PATH

USER 0
WORKDIR /app
RUN set -eux; \
    printf '%s\n' "$APK_REPOSITORY" > /etc/apk/repositories; \
    for attempt in 1 2 3 4 5; do \
      apk --timeout 30 --no-progress add --no-cache chromium && break; \
      [ "$attempt" -eq 5 ] && exit 1; \
    done; \
    chromium_deps="$(apk info --depends chromium | sed '1d')"; \
    apk --timeout 30 --no-progress add --no-cache $chromium_deps; \
    apk --no-network del chromium; \
    printf '%s\n' 'https://apk.cgr.dev/chainguard' > /etc/apk/repositories; \
    addgroup -g 10001 validator \
    && adduser -D -H -u 10001 -G validator -s /sbin/nologin validator \
    && mkdir -p /auth /app \
    && chown -R 10001:10001 /auth /app

ENV HOME=/tmp
ARG CHROMIUM_VERSION=154.0.8037.57
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
    && apk --no-network del python-3.14-dev python-3.14-base-dev py3.14-pip py3.14-pip-base py3.14-setuptools \
    && rm -f /usr/share/python-wheels/pip-*.whl /var/lib/db/sbom/py3-pip-wheel-*.spdx.json
COPY --chown=10001:10001 app ./app

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
ENTRYPOINT []
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips=*"]
