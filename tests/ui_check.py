import asyncio
import os

from playwright.async_api import async_playwright


async def main():
    base_url = os.getenv("PORTAL_VALIDATOR_URL", "http://host.docker.internal:18080")
    screenshot = os.getenv("UI_SCREENSHOT", "/reports/portal-validator.png")
    console_errors = []
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=["--disable-dev-shm-usage"],
        )
        page = await browser.new_page(
            viewport={"width": 1440, "height": 1100},
            device_scale_factor=1,
        )
        page.on(
            "console",
            lambda message: console_errors.append(message.text)
            if message.type == "error" else None,
        )
        await page.goto(base_url, wait_until="networkidle")
        assert await page.title() == "Portal Validator"
        assert await page.get_by_role(
            "heading", name="Know your portal. Route by route.",
        ).is_visible()
        assert await page.get_by_role("button", name="Run validation →").is_enabled()
        assert await page.locator("#auth-mode option").count() == 6
        assert await page.locator("#redirects").input_value() == "10"
        await page.locator("#auth-mode").select_option("storage_state")
        assert await page.get_by_text("Mounted SSO profile", exact=True).is_visible()
        await page.evaluate("""
          renderReport({
            target:'https://portal.example.com', pages:1, run_id:'ui-check',
            summary:{routes_discovered:3,routes_validated:1,healthy_routes:1,routes_with_warnings:0,
              failed_pages:0,auth_issues:0,api_failures:0,resource_failures:0,slow_pages:0,
              read_only_blocks:0,duration_ms:125},
            results:[{url:'https://portal.example.com/health',requested_url:'https://portal.example.com/health',
              final_url:'https://portal.example.com/health',route_label:'Health',route_source:'navigation',
              classification:'PASS',page_load_status:'LOADED',validation_status:'PASS',tls_status:'TRUSTED',
              security_headers_status:'PASS',status:200,load_ms:125,depth:1,slow:false,api_failures:0,
              resource_failure_count:0,read_only_blocks:0,console_errors:[],finding_details:[],redirects:[],
              render_health:{text_length:120},api_requests:[],failed_resources:[],frames:[],security_headers:{},
              external_links:[]}]
          })
        """)
        assert await page.locator(".route-table tbody tr").count() == 1
        assert not await page.locator(".raw-report").get_attribute("open")
        main_width = await page.locator("main").evaluate("element => element.getBoundingClientRect().width")
        assert main_width > 1300
        await page.screenshot(path=screenshot, full_page=True)
        actionable_errors = [
            error for error in console_errors
            if "Cross-Origin-Opener-Policy header has been ignored" not in error
        ]
        assert not actionable_errors, actionable_errors
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
