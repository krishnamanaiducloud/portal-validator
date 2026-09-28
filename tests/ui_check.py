import asyncio
import os

from playwright.async_api import async_playwright


async def main():
    base_url = os.getenv("PORTAL_VALIDATOR_URL", "http://host.docker.internal:18080")
    screenshot = os.getenv("UI_SCREENSHOT", "/reports/portal-validator.png")
    executable_path = os.getenv("CHROMIUM_EXECUTABLE_PATH")
    console_errors = []
    async with async_playwright() as playwright:
        launch_options = {"headless": True, "args": ["--disable-dev-shm-usage"]}
        if executable_path:
            launch_options["executable_path"] = executable_path
        browser = await playwright.chromium.launch(**launch_options)
        page = await browser.new_page(viewport={"width": 1440, "height": 1100}, device_scale_factor=1)
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
        await page.goto(base_url, wait_until="networkidle")
        assert await page.title() == "Portal Validator"
        assert await page.get_by_role("heading", name="Know your portal before users do.").is_visible()
        assert await page.get_by_role("button", name="Run validation →").is_enabled()
        assert await page.locator("#auth-mode option").count() == 6
        await page.locator("#auth-mode").select_option("storage_state")
        assert await page.get_by_text("Mounted SSO profile", exact=True).is_visible()
        await page.screenshot(path=screenshot, full_page=True)
        actionable_errors = [error for error in console_errors if "Cross-Origin-Opener-Policy header has been ignored" not in error]
        assert not actionable_errors, actionable_errors
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
