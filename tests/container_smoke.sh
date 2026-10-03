#!/bin/sh
set -eu

id
python -m app.trust status
certutil -L -d "sql:$CHROMIUM_NSS_DB"

python - <<'PY'
from pathlib import Path
import os

from playwright.sync_api import sync_playwright

with sync_playwright() as playwright:
    path = Path(playwright.chromium.executable_path)
    print("BROWSER_PATH=", path, sep="")
    print("BROWSER_EXISTS=", path.is_file(), sep="")
    browser = playwright.chromium.launch(headless=True)
    print("BROWSER_LAUNCHED=true")
    if os.getenv("SMOKE_NAVIGATE", "true").lower() == "true":
        page = browser.new_page()
        response = page.goto(
            os.getenv("SMOKE_URL", "https://google.com"),
            wait_until="domcontentloaded",
            timeout=60000,
        )
        print("HTTPS_STATUS=", response.status if response else None, sep="")
        print("HTTPS_TITLE=", page.title(), sep="")
    browser.close()
PY
