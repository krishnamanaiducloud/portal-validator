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
        assert await page.locator("#pages").input_value() == "50"
        await page.locator("#auth-mode").select_option("storage_state")
        assert await page.get_by_text("Mounted SSO profile", exact=True).is_visible()
        await page.evaluate("""
          renderReport({
            target:'https://portal.example.com', pages:1, run_id:'ui-check',
            summary:{routes_discovered:3,routes_validated:1,healthy_routes:1,routes_with_warnings:0,
              failed_pages:0,auth_issues:0,api_failures:0,resource_failures:0,slow_pages:0,
              read_only_blocks:0,duration_ms:125,routes_not_tested:2,console_failures:0,
              unique_apis:2,security_recommendations:1},
            coverage:{scan_completeness:'PARTIAL',termination_reason:'MAX_ROUTES_REACHED',routes_discovered:3,routes_validated:1,routes_not_tested:2,routes_remaining:2},
            api_inventory:[{method:'GET',host:'api.example.net',endpoint:'/health',calls:1,status_2xx:1,
              status_3xx:0,status_4xx:0,status_5xx:0,network_failures:0,route_count:1,
              average_duration_ms:12,worst_duration_ms:12,health:'HEALTHY',routes_using_endpoint:['/health']},
              {method:'POST',host:'api.example.net',endpoint:'/query',calls:10,status_2xx:8,
              status_3xx:0,status_4xx:2,status_5xx:0,network_failures:0,route_count:1,
              average_duration_ms:25,worst_duration_ms:40,health:'DEGRADED',routes_using_endpoint:['/health']}],
            security_recommendations:[{type:'MISSING_SECURITY_HEADER',header:'content-security-policy',
              severity:'RECOMMENDATION',impact:'NON_BLOCKING',affected_document_count:1,
              affected_documents:['https://portal.example.com/health']}],
            results:[{url:'https://portal.example.com/health',requested_url:'https://portal.example.com/health',
              final_url:'https://portal.example.com/health',route_label:'Health',route_source:'navigation',
              classification:'PASS',page_load_status:'LOADED',validation_status:'PASS',tls_status:'TRUSTED',
              security_headers_status:'PASS',navigation_status:'SUCCESS',render_status:'PASS',api_status:'PASS',
              resource_status:'PASS',console_status:'PASS',authentication_status:'PASS',read_only_status:'ENFORCED',
              navigation_type:'DOCUMENT_NAVIGATION',warning_findings:0,status:200,load_ms:125,depth:1,slow:false,api_failures:0,
              resource_failure_count:0,read_only_blocks:0,console_errors:[],finding_details:[],redirects:[],
              render_health:{text_length:120},api_requests:[],failed_resources:[],frames:[],security_headers:{},
              external_links:[]}]
          })
        """)
        assert await page.locator("#result-list tr").count() == 1
        assert await page.locator(".metric").count() >= 10
        assert await page.locator("#api-list tr").count() == 2
        assert await page.locator("#security-list .recommendation").count() == 1
        calls_sort = page.get_by_role("button", name="Calls", exact=True)
        assert await calls_sort.count() == 1
        await calls_sort.click()
        assert await page.locator('[data-api-sort="calls"]').evaluate(
            "element => element.closest('th').getAttribute('aria-sort')"
        ) == "ascending"
        await calls_sort.click()
        assert await page.locator('[data-api-sort="calls"]').evaluate(
            "element => element.closest('th').getAttribute('aria-sort')"
        ) == "descending"
        assert await page.locator("#api-list tr td:nth-child(4)").first.text_content() == "10"
        route_scroller = page.locator('[data-scroll-for="route-table-wrap"]')
        assert await route_scroller.is_visible()
        await route_scroller.evaluate("element => { element.scrollLeft = 120; element.dispatchEvent(new Event('scroll')); }")
        assert await page.locator("#route-table-wrap").evaluate("element => element.scrollLeft") == 120
        await page.get_by_role("button", name="Show Discovered evidence").click()
        assert await page.locator("#evidence-panel").is_visible()
        assert not await page.locator(".raw-report").get_attribute("open")
        main_width = await page.locator("main").evaluate("element => element.getBoundingClientRect().width")
        assert main_width > 1300
        gateway_message = await page.evaluate("""
          async () => {
            const original = window.fetch;
            window.fetch = async () => new Response('<html><body>Gateway Timeout</body></html>', {
              status: 504, statusText: 'Gateway Timeout', headers: {'content-type':'text/html'}
            });
            try { await requestJson('/test', {}, 'Scan request'); }
            catch (error) { return error.message; }
            finally { window.fetch = original; }
          }
        """)
        assert "HTTP 504" in gateway_message
        assert "Unexpected token" not in gateway_message
        await page.screenshot(path=screenshot, full_page=True)
        large_inventory = await page.evaluate("""
          () => {
            lastReport.api_inventory = Array.from({length:1000}, (_, index) => ({
              method:index % 2 ? 'GET' : 'POST', host:'api.example.net', endpoint:`/items/${index}`,
              calls:index + 1, status_2xx:index + 1, status_3xx:0, status_4xx:0, status_5xx:0,
              network_failures:0, route_count:1, average_duration_ms:index % 37,
              worst_duration_ms:index % 53, health:'HEALTHY', routes_using_endpoint:['/health']
            }));
            updateApiRouteFilter(lastReport.api_inventory);
            const started = performance.now();
            renderApiInventory();
            return {milliseconds:performance.now() - started, rows:document.querySelectorAll('#api-list tr').length};
          }
        """)
        assert large_inventory["rows"] == 1000
        assert large_inventory["milliseconds"] < 3000
        await page.set_viewport_size({"width": 390, "height": 844})
        assert await page.get_by_role("button", name="Run validation →").is_visible()
        page_overflow = await page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
        assert page_overflow <= 1
        actionable_errors = [
            error for error in console_errors
            if "Cross-Origin-Opener-Policy header has been ignored" not in error
        ]
        assert not actionable_errors, actionable_errors
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
