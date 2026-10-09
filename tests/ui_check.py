import asyncio
import json
import os
from pathlib import Path

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
        assert "Maximum time / route" in await page.locator("#timeout").evaluate("element => element.closest('label').textContent")
        assert await page.locator("#min-observation").input_value() == "500"
        assert await page.locator("#network-quiet").input_value() == "300"
        assert await page.locator("#slow-threshold").input_value() == "5000"
        assert await page.locator("#timeout").get_attribute("max") == "120000"
        assert await page.locator("#total-timeout").get_attribute("max") == "900000"
        assert await page.evaluate("phaseConfiguration()") == {}
        await page.locator("#scan-timing-settings > summary").click()
        concurrency = page.locator("#concurrency-limit")
        concurrency_cap = int(await concurrency.get_attribute("max"))
        assert concurrency_cap >= 1
        assert await concurrency.input_value() == ""
        await concurrency.fill("1")
        assert await page.evaluate("phaseConfiguration()") == {"concurrency_limit": 1}
        await concurrency.fill(str(concurrency_cap + 1))
        assert f"integer between 1 and {concurrency_cap}" in await page.evaluate("""() => {
          try { phaseConfiguration(); return ''; } catch (error) { return error.message; }
        }""")
        await concurrency.fill("")
        assert "concurrency_limit" not in await page.evaluate("phaseConfiguration()")
        for control in ("navigation-timeout", "authentication-timeout", "api-timeout", "readiness-timeout"):
            await page.locator(f"#{control}").fill("12345")
        await page.locator("#readiness-selector").fill("[data-app-ready]")
        await page.locator("#authentication-hosts").fill("login.example.net, identity.example.org")
        assert await page.evaluate("phaseConfiguration()") == {
            "navigation_timeout_ms": 12345, "authentication_timeout_ms": 12345,
            "api_timeout_ms": 12345, "readiness_timeout_ms": 12345,
            "readiness_selector": "[data-app-ready]",
            "authentication_hosts": ["login.example.net", "identity.example.org"],
        }
        await page.locator("#api-timeout").fill("1")
        assert "integer between" in await page.evaluate("""() => {
          try { phaseConfiguration(); return ''; } catch (error) { return error.message; }
        }""")
        for control in ("navigation-timeout", "authentication-timeout", "api-timeout", "readiness-timeout", "readiness-selector", "authentication-hosts"):
            await page.locator(f"#{control}").fill("")
        await page.locator("#scan-timing-settings > summary").click()
        await page.locator("#auth-mode").select_option("storage_state")
        assert await page.get_by_text("Mounted SSO profile", exact=True).is_visible()
        await page.locator("#read-post-settings > summary").click()
        await page.locator("#add-read-post").click()
        await page.locator("#add-read-post").click()
        operations = page.locator(".read-post-operation")
        assert await operations.count() == 2
        await operations.nth(0).locator(".operation-host").fill("api.example.net")
        await operations.nth(0).locator(".operation-path").fill("/v1/query")
        await operations.nth(1).locator(".operation-host").fill("API.EXAMPLE.NET.")
        await operations.nth(1).locator(".operation-path-type").select_option("path_pattern")
        await operations.nth(1).locator(".operation-path").fill("/v1/items/{segment}/query")
        assert await page.evaluate("approvedReadPostOperations()") == [
            {"method": "POST", "host": "api.example.net", "path": "/v1/query"},
            {"method": "POST", "host": "api.example.net", "path_pattern": "/v1/items/{segment}/query"},
        ]
        await operations.nth(0).locator(".operation-graphql").check()
        assert (await page.evaluate("approvedReadPostOperations()"))[0]["graphql_queries_only"] is True
        await operations.nth(0).locator(".operation-graphql").uncheck()
        await operations.nth(1).locator(".operation-path").fill("/**")
        rejection = await page.evaluate("""() => {
            try { approvedReadPostOperations(); return null; }
            catch (error) { return error.message; }
        }""")
        assert "wildcards" in rejection
        await operations.nth(1).locator(".remove-operation").click()
        await operations.nth(0).locator(".remove-operation").click()
        await page.locator("#read-post-settings > summary").click()
        await page.evaluate("""
          renderReport({
            target:'https://portal.example.com', pages:1, run_id:'ui-check',
            summary:{routes_discovered:3,routes_validated:1,healthy_routes:1,routes_with_warnings:1,
              failed_pages:0,auth_issues:0,api_failures:0,resource_failures:0,slow_pages:0,
              read_only_blocks:5,duration_ms:125,total_scan_duration_ms:8500,routes_not_tested:2,console_failures:0,
              post_summary:{observed_calls:11,approved_read_only_calls:9,executed_approved_calls:8},
              post_diagnostics:{total_http_requests_observed:24,post_requests_observed:11,post_requests_allowed:9,
                post_requests_blocked:2,approved_read_only_post_endpoints:1,unverified_post_endpoints:2,
                post_requests_without_completed_responses:3,unique_post_endpoints_reported:2},
              unique_apis:6,security_recommendations:1},
            coverage:{scan_completeness:'PARTIAL',termination_reason:'MAX_ROUTES_REACHED',routes_discovered:3,routes_validated:1,routes_not_tested:2,routes_remaining:2},
            api_inventory:[{method:'GET',host:'api.example.net',endpoint:'/health',calls:1,status_2xx:1,
              status_3xx:0,status_4xx:0,status_5xx:0,network_failures:0,route_count:1,
              allowed_calls:1,blocked_count:0,application_bootstrap_phase_count:1,authentication_phase_count:0,route_validation_phase_count:0,session_refresh_phase_count:0,
              average_duration_ms:12,worst_duration_ms:12,health:'HEALTHY',observation_outcome:'HEALTHY',routes_using_endpoint:['/health']},
              {method:'POST',host:'api.example.net',endpoint:'/query',calls:10,status_2xx:8,
              status_3xx:0,status_4xx:1,status_5xx:0,network_failures:0,route_count:1,
              allowed_calls:9,blocked_count:1,application_bootstrap_phase_count:2,authentication_phase_count:0,route_validation_phase_count:8,session_refresh_phase_count:0,
              average_duration_ms:25,worst_duration_ms:40,health:'DEGRADED',observation_outcome:'WARNING',policies:['APPROVED_READ_POST'],policy_classifications:['APPROVED_READ_ONLY'],classification_counts:{APPROVED_READ_POST:9,BLOCKED_MUTATION:1},routes_using_endpoint:['/health'],
              response_status_counts:{200:8,401:1},failure_count:1,authentication_classifications:['NOT_AUTHENTICATION'],
              post_classifications:['POST_OBSERVED','POST_READ_ONLY_APPROVED','POST_READ_ONLY_UNVERIFIED','POST_BLOCKED_BY_POLICY','POST_MUTATION_RESTRICTED']},
              ...['POST','PUT','PATCH','DELETE'].map((method, index) => ({method,host:'api.example.net',endpoint:`/blocked/${index}`,calls:1,status_2xx:0,
              status_3xx:0,status_4xx:0,status_5xx:0,network_failures:0,route_count:1,allowed_calls:0,
              blocked_count:1,application_bootstrap_phase_count:0,authentication_phase_count:0,route_validation_phase_count:1,session_refresh_phase_count:0,
              average_duration_ms:null,worst_duration_ms:null,health:'NOT_EXECUTED',observation_outcome:'BLOCKED_BY_VALIDATOR',observation_status:'BLOCKED_BY_POLICY',policies:['READ_ONLY_BLOCK'],routes_using_endpoint:['/health'],
              response_status_counts:{},failure_count:0,authentication_classifications:['NOT_AUTHENTICATION'],
              post_classifications:method === 'POST' ? ['POST_OBSERVED','POST_READ_ONLY_UNVERIFIED','POST_BLOCKED_BY_POLICY','POST_MUTATION_RESTRICTED'] : []}))],
            resource_details:[
              {type:'IMAGE',host:'cdn.example.net',path:'/hero.png',route:'/health',status:200,duration_ms:34,transfer_size_bytes:700000,encoded_body_size_bytes:699000,decoded_body_size_bytes:699000,size_categories:['LARGE_IMAGE'],failed:false},
              {type:'IMAGE',host:'cdn.example.net',path:'/opaque.png',route:'/health',status:200,duration_ms:14,transfer_size_bytes:null,encoded_body_size_bytes:null,decoded_body_size_bytes:null,size_categories:[],failed:false},
              {type:'SCRIPT',host:'cdn.example.net',path:'/app.js',route:'/health',status:503,duration_ms:8,transfer_size_bytes:300,encoded_body_size_bytes:200,decoded_body_size_bytes:200,size_categories:[],failed:true}],
            resource_summary:{resources_observed:3,total_transfer_size_bytes:700300,resources_with_transfer_size:2,large_resources:1,large_images:1,resource_failures:1},
            security_recommendations:[{type:'MISSING_SECURITY_HEADER',header:'content-security-policy',
              severity:'RECOMMENDATION',impact:'NON_BLOCKING',affected_document_count:1,
              affected_documents:['https://portal.example.com/health']}],
            scan_configuration:{timeout_ms:15000,slow_page_threshold_ms:5000,min_observation_ms:500,network_quiet_ms:300},
            scan_timing:{authentication_ms:20,discovery_ms:30,route_validation_ms:125,total_scan_ms:175},
            results:[{url:'https://portal.example.com/health',requested_url:'https://portal.example.com/health',
              discovered_url:'https://portal.example.com/health',final_url:'https://portal.example.com/health',
              route_label:'Health',navigation_label:'Health',route_name:'Health',route_name_source:'NAVIGATION_LABEL',
              route_name_confidence:'HIGH',route_source:'navigation',display_path:'/health',host:'portal.example.com',
              canonical_route:'https://portal.example.com/health',discovery_sources:[],duplicate_discovery_count:0,
              classification:'PASS_WITH_WARNINGS',page_load_status:'LOADED',validation_status:'WARNING',tls_status:'TRUSTED',
              security_headers_status:'PASS',navigation_status:'SUCCESS',render_status:'PASS',api_status:'PASS',
              resource_status:'PASS',console_status:'PASS',authentication_status:'PASS',read_only_status:'ENFORCED',
              navigation_type:'DOCUMENT_NAVIGATION',warning_findings:1,status:200,load_ms:125,navigation_ms:20,render_ready_ms:105,application_settle_ms:105,validator_observation_ms:6000,total_validation_ms:6125,application_load_ms:125,depth:1,slow:false,api_failures:0,
              resource_failure_count:0,read_only_blocks:0,console_errors:[],finding_details:[{type:'CONSOLE_WARNING',severity:'WARNING',message:'Optional component emitted a warning.'}],redirects:[],
              warning_reasons:[{code:'CONSOLE_WARNING',description:'Optional component emitted a warning.',severity:'WARNING',affected_component:'CONSOLE',evidence:{count:1},threshold:null}],
              render_health:{text_length:120},api_requests:[],failed_resources:[],frames:[],security_headers:{},
              external_links:[]}]
          })
        """)
        assert await page.locator("#result-list tr").count() == 1
        assert await page.locator("#result-list .route-name-cell strong").text_content() == "Health"
        assert await page.locator("#result-list .route-cell code").text_content() == "/health"
        assert await page.get_by_role("button", name="Show Scan duration evidence").locator("strong").inner_text() == "8.5s"
        assert await page.locator("#post-summary-observed_calls").inner_text() == "11"
        assert await page.locator("#post-summary-approved_read_only_calls").inner_text() == "9"
        assert await page.locator("#post-summary-executed_approved_calls").inner_text() == "8"
        await page.evaluate("delete lastReport.summary.total_scan_duration_ms; renderReport(lastReport)")
        assert await page.get_by_role("button", name="Show Scan duration evidence").locator("strong").inner_text() == "175ms"
        await page.evaluate("lastReport.summary.total_scan_duration_ms = 8500; renderReport(lastReport)")
        await page.evaluate("""() => {
          window.accessOriginalReport = lastReport;
          const baseline = lastReport.results[0];
          renderReport({...lastReport, summary:{...lastReport.summary, access_issues:2, auth_issues:1},
            results:[baseline, ...['ACCESS_RESTRICTED','CHALLENGE_REQUIRED','AUTH_REQUIRED'].map((classification,index) =>
              ({...baseline, route_id:`access-fixture-${index}`, route_name:classification,
                classification, passed:false, validation_status:'NOT_TESTED',
                authentication_status:index===2?'AUTH_REQUIRED':'NOT_TESTED',
                coverage_detail:'Application coverage is limited; authentication was not established.'}))]});
        }""")
        assert await page.get_by_role("button", name="Show Auth issues evidence").locator("strong").inner_text() == "1"
        assert await page.get_by_role("button", name="Show Access / challenges evidence").locator("strong").inner_text() == "2"
        await page.get_by_role("button", name="Show Access / challenges evidence").click()
        assert await page.locator("#result-list .route-row").count() == 2
        assert await page.locator("#result-list .coverage-limitation").count() == 2
        await page.get_by_role("button", name="Show Failed evidence").click()
        assert await page.locator("#result-list .route-row").count() == 0
        await page.get_by_role("button", name="Show Auth issues evidence").click()
        assert await page.locator("#result-list .route-name-cell strong").all_text_contents() == ["AUTH_REQUIRED"]
        await page.evaluate("renderReport(window.accessOriginalReport); delete window.accessOriginalReport")
        await page.evaluate("""() => {
          window.uiViewOriginalReport = lastReport;
          const baseline = lastReport.results[0];
          renderReport({...lastReport, results:[baseline, ...['Service reports','Recent activity'].map((name,index) =>
            ({...baseline, route_id:`UI_VIEW_fixture_${index}`, view_type:'UI_TAB',
              route_name:name,navigation_type:'UI_VIEW_ACTIVATION'}))]});
        }""")
        assert await page.locator("#result-list .route-row").count() == 3
        await page.locator("#navigation-filter").select_option("UI_VIEW_ACTIVATION")
        assert await page.locator("#result-list .route-name-cell strong").all_text_contents() == ["Recent activity", "Service reports"]
        await page.locator("#result-list .route-inspect").first.click()
        await page.locator("#route-inspector .inspect-raw > summary").click()
        assert "UI_VIEW_fixture_1" in await page.locator("#route-inspector").inner_text()
        await page.evaluate("renderReport(window.uiViewOriginalReport); delete window.uiViewOriginalReport")
        route_panel = page.locator("#route-results-panel")
        route_handle = page.locator("#route-results-resize")
        # Restoring the report starts its intentional smooth document scroll.
        # Stop that animation before measuring screen coordinates for a drag;
        # otherwise the handle can move between bounding_box and pointerdown.
        await page.evaluate("window.scrollTo({top: window.scrollY, behavior: 'instant'})")
        await route_handle.evaluate(
            "element => element.scrollIntoView({behavior:'instant', block:'center'})"
        )
        initial_route_height = await route_panel.evaluate("element => element.getBoundingClientRect().height")
        handle_box = await route_handle.bounding_box()
        await page.mouse.move(handle_box["x"] + handle_box["width"] / 2, handle_box["y"] + handle_box["height"] / 2)
        await page.mouse.down()
        await page.mouse.move(handle_box["x"] + handle_box["width"] / 2, handle_box["y"] + handle_box["height"] / 2 - 100, steps=5)
        await page.mouse.up()
        resized_route_height = await route_panel.evaluate("element => element.getBoundingClientRect().height")
        assert abs(resized_route_height - (initial_route_height - 100)) <= 2, (
            initial_route_height, resized_route_height, handle_box
        )
        await route_handle.press("ArrowDown")
        route_panel_height = await route_panel.evaluate("element => element.getBoundingClientRect().height")
        assert abs(route_panel_height - (resized_route_height + 25)) <= 2
        assert int(await route_handle.get_attribute("aria-valuenow")) == round(route_panel_height)
        await page.locator("#route-results-expand").click()
        assert await page.locator("#route-results-expand").inner_text() == "Collapse"
        assert await route_panel.evaluate("element => element.getBoundingClientRect().height") > route_panel_height
        await page.locator("#route-results-expand").click()
        assert abs(await route_panel.evaluate("element => element.getBoundingClientRect().height") - route_panel_height) <= 2
        await page.locator("#route-results-fullscreen").click()
        assert await page.locator("#route-results-dialog").evaluate("element => element.open && element.matches(':modal')")
        assert await route_panel.evaluate("element => element.clientHeight >= window.innerHeight - 2")
        await page.locator("#route-results-close").click()
        assert abs(await route_panel.evaluate("element => element.getBoundingClientRect().height") - route_panel_height) <= 2
        await page.locator("#route-results-fullscreen").click()
        await page.keyboard.press("Escape")
        assert not await page.locator("#route-results-dialog").evaluate("element => element.open")
        assert await page.locator("#route-results-fullscreen").evaluate("element => document.activeElement === element")
        assert "Coverage: PARTIAL" in await page.locator("#coverage").text_content()
        assert "Execution: FINISHED" in await page.locator("#coverage").text_content()
        await page.get_by_role("button", name="Show Healthy evidence", exact=True).click()
        assert await page.locator("#result-list .route-row").count() == 1
        await page.evaluate("activeDrilldown = 'all'; renderRows()")
        assert await page.locator(".metric").count() >= 10
        assert await page.locator("#api-list tr").count() == 6
        assert await page.locator("#api-method-filter option").all_text_contents() == [
            "All methods", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT",
        ]
        diagnostic_values = {
            "total_http_requests_observed": "24", "post_requests_observed": "11",
            "post_requests_allowed": "9", "post_requests_blocked": "2",
            "approved_read_only_post_endpoints": "1", "unverified_post_endpoints": "2",
            "post_requests_without_completed_responses": "3", "unique_post_endpoints_reported": "2",
        }
        for name, expected in diagnostic_values.items():
            assert await page.locator(f"#post-diagnostic-{name}").text_content() == expected
        await page.evaluate("window.savedPostDiagnostics = lastReport.summary.post_diagnostics; delete lastReport.summary.post_diagnostics; renderApiInventory()")
        assert await page.locator("#post-diagnostic-total_http_requests_observed").text_content() == "Not recorded"
        await page.evaluate("lastReport.summary.post_diagnostics = window.savedPostDiagnostics; delete window.savedPostDiagnostics; renderApiInventory()")
        await page.locator("#api-method-filter").select_option("OPTIONS")
        assert await page.locator("#api-list .empty-table").text_content() == "No API requests match these filters."
        await page.locator("#api-method-filter").select_option("POST")
        assert await page.locator("#api-list tr").count() == 2
        assert await page.locator("#api-list tr td:first-child").all_text_contents() == ["POST", "POST"]
        query_row = page.locator("#api-list tr").filter(has=page.locator("button.api-endpoint", has_text="/query"))
        assert await query_row.locator(".api-response-status-cell").text_content() == "200 (8), 401 (1)"
        assert await query_row.locator(".api-failure-count-cell").text_content() == "1"
        assert await query_row.locator(".api-associated-routes-cell").text_content() == "/health"
        assert await query_row.locator(".api-auth-class-cell").text_content() == "NOT_AUTHENTICATION"
        assert "POST_READ_ONLY_APPROVED" in await query_row.locator(".api-post-class-cell").text_content()
        blocked_post_row = page.locator("#api-list tr").filter(has=page.locator("button.api-endpoint", has_text="/blocked/0"))
        assert await blocked_post_row.locator(".dimension-state").text_content() == "BLOCKED_BY_POLICY"
        assert "POST_BLOCKED_BY_POLICY" in await blocked_post_row.locator(".api-post-class-cell").text_content()
        await page.locator("#api-method-filter").select_option("all")
        await page.evaluate("""() => {
          const challenge = lastReport.api_inventory.find(item => item.endpoint === '/blocked/0');
          Object.assign(challenge, {traffic_role:'CHALLENGE',traffic_roles:{CHALLENGE:1},observed_calls:1,
            allowed_calls:0,blocked_calls:1,sent_calls:0,responded_calls:0,completed_calls:0,
            failed_calls:0,canceled_calls:0,incomplete_calls:0});
          lastReport.api_inventory.find(item => item.endpoint === '/query').traffic_role = 'BUSINESS';
          renderApiInventory();
        }""")
        await page.locator("#api-role-filter").select_option("CHALLENGE")
        assert await page.locator("#api-list tr").count() == 1
        assert await page.locator("#api-list .api-role-cell").text_content() == "CHALLENGE"
        assert "BLOCKED_BY_POLICY" in await page.locator("#api-list").text_content()
        await page.locator("#api-list .api-endpoint").click()
        lifecycle = await page.locator("#evidence-content .inspect-section dl").evaluate("""element =>
          Object.fromEntries([...element.children].map(row => [row.querySelector('dt').textContent, row.querySelector('dd').textContent]))
        """)
        assert lifecycle["observed"] == "1"
        assert lifecycle["blocked"] == "1"
        assert lifecycle["sent"] == "0"
        assert lifecycle["completed"] == "0"
        assert lifecycle["incomplete"] == "0"
        await page.locator("#evidence-close").click()
        await page.locator("#api-role-filter").select_option("all")
        await page.locator("#api-policy-filter").select_option("blocked")
        assert await page.locator("#api-list tr").count() == 5
        await page.locator("#api-policy-filter").select_option("all")
        await page.locator("#api-policy-filter").select_option("approved-post")
        assert await page.locator("#api-list tr").count() == 1
        assert "APPROVED_READ_ONLY" in await page.locator("#api-list").text_content()
        assert "APPROVED_READ_POST" not in await page.locator("#api-list .api-policy-cell").text_content()
        assert await page.evaluate("apiDisplayPolicies({policies:['APPROVED_READ_POST','READ_ONLY_BLOCK'],policy_classifications:['APPROVED_READ_ONLY','READ_ONLY_BLOCKED'],classification_counts:{BLOCKED_MUTATION:1}})") == ["APPROVED_READ_ONLY", "READ_ONLY_BLOCKED"]
        # Saved older reports have only internal policy names, not the new
        # canonical policy_classifications field. They must filter identically.
        await page.evaluate("""() => {
          const post = lastReport.api_inventory.find(item => item.endpoint === '/query');
          delete post.policy_classifications; delete post.classification_counts;
          renderApiInventory();
        }""")
        assert await page.locator("#api-list tr").count() == 1
        assert "/query" in await page.locator("#api-list").text_content()
        assert await page.locator("#api-list .api-policy-cell").text_content() == "APPROVED_READ_ONLY"
        await page.evaluate("""() => {
          const post = lastReport.api_inventory.find(item => item.endpoint === '/query');
          delete post.policies; post.classification_counts = {APPROVED_READ_POST:9};
          renderApiInventory();
        }""")
        assert await page.locator("#api-list tr").count() == 1
        assert await page.locator("#api-list .api-policy-cell").text_content() == "APPROVED_READ_ONLY"
        await page.evaluate("""() => {
          const post = lastReport.api_inventory.find(item => item.endpoint === '/query');
          post.policies = ['APPROVED_READ_POST']; post.policy_classifications = ['APPROVED_READ_ONLY'];
          post.classification_counts = {APPROVED_READ_POST:9,BLOCKED_MUTATION:1};
          renderApiInventory();
        }""")
        await page.locator("#api-policy-filter").select_option("target-failures")
        assert await page.locator("#api-list tr").count() == 1
        assert "/query" in await page.locator("#api-list").text_content()
        await page.locator("#api-policy-filter").select_option("all")
        await page.evaluate("window.savedInventory = lastReport.api_inventory; lastReport.api_inventory = lastReport.api_inventory.filter(item => item.method !== 'POST'); updateApiMethodFilter(lastReport.api_inventory)")
        await page.locator("#api-method-filter").select_option("POST")
        assert await page.locator("#api-list .empty-table").text_content() == "No POST requests were observed for this scan."
        await page.evaluate("lastReport.api_inventory = window.savedInventory; delete window.savedInventory; updateApiMethodFilter(lastReport.api_inventory)")
        await page.locator("#api-method-filter").select_option("all")
        assert await page.locator("#api-list .blocked-by-validator").count() == 4
        await page.evaluate("window.lifecycleInventory = lastReport.api_inventory")
        for outcome in ("INCOMPLETE", "CANCELED"):
            await page.evaluate("""outcome => {
              lastReport.api_inventory = [{...window.lifecycleInventory[0],
                health:'NOT_EXECUTED',observation_outcome:outcome,
                sent_calls:1,responded_calls:0,completed_calls:0,failed_calls:0,
                incomplete_calls:outcome === 'INCOMPLETE' ? 1 : 0,
                canceled_calls:outcome === 'CANCELED' ? 1 : 0}];
              renderApiInventory();
            }""", outcome)
            assert await page.locator("#api-list .dimension-state").text_content() == outcome
            assert "NOT_EXECUTED" not in await page.locator("#api-list").text_content()
            await page.locator("#api-list .api-endpoint").click()
            lifecycle = await page.locator("#evidence-content .inspect-section dl").evaluate("""element =>
              Object.fromEntries([...element.children].map(row => [row.querySelector('dt').textContent, row.querySelector('dd').textContent]))
            """)
            assert lifecycle["sent"] == "1" and lifecycle["completed"] == "0"
            assert lifecycle["incomplete" if outcome == "INCOMPLETE" else "canceled"] == "1"
            await page.locator("#evidence-close").click()
        await page.evaluate("lastReport.api_inventory = window.lifecycleInventory; delete window.lifecycleInventory; renderApiInventory()")
        assert await page.locator("#api-table-wrap table").get_attribute("data-density") == "compact"
        await page.locator("#api-density").select_option("comfortable")
        assert await page.locator("#api-table-wrap table").get_attribute("data-density") == "comfortable"
        await page.locator("#api-density").select_option("compact")
        assert "excludes blocked" in await page.locator('[data-api-sort="average_duration_ms"]').evaluate("element => element.closest('th').title")
        assert await page.locator('[data-api-sort="application_bootstrap_phase_count"]').text_content() == "Bootstrap Calls"
        assert await page.locator('[data-api-sort="average_duration_ms"]').text_content() == "Average Time (ms)"
        assert await page.locator('[data-api-sort="worst_duration_ms"]').text_content() == "Worst Time (ms)"
        await page.locator("#api-columns > summary").click()
        assert await page.locator("#api-columns input[type=checkbox]").count() == 26
        screenshot_base, screenshot_extension = os.path.splitext(screenshot)
        await page.screenshot(path=f"{screenshot_base}-columns{screenshot_extension or '.png'}")
        await page.locator('[data-column-kind="api"][data-column-key="host"]').uncheck()
        assert not await page.locator('[data-api-sort="host"]').is_visible()
        assert await page.locator('[data-sort="route_name"]').is_visible()
        await page.locator('#api-columns [data-column-action="clear"]').click()
        assert await page.locator('[data-api-sort="method"]').is_visible()
        assert await page.locator('[data-api-sort="endpoint"]').is_visible()
        assert not await page.locator('[data-api-sort="calls"]').is_visible()
        await page.locator('#api-columns [data-column-action="all"]').click()
        assert await page.locator('[data-api-sort="calls"]').is_visible()
        await page.locator('[data-column-kind="api"][data-column-key="host"]').uncheck()
        await page.locator("#api-columns > summary").click()
        await page.locator("#route-columns > summary").click()
        await page.locator('[data-column-kind="route"][data-column-key="authentication_status"]').uncheck()
        assert not await page.locator('[data-sort="authentication_status"]').is_visible()
        assert await page.locator('[data-api-sort="authentication_phase_count"]').is_visible()
        await page.locator("#route-columns > summary").click()
        saved_report = await page.evaluate("lastReport")
        # Simulate an older release preference set. New POST-evidence columns
        # must remain visible unless explicitly disabled.
        await page.evaluate("localStorage.setItem('portal-validator.api-columns', JSON.stringify({host:false}))")
        await page.reload(wait_until="networkidle")
        await page.evaluate("report => renderReport(report)", saved_report)
        assert abs(await route_panel.evaluate("element => element.getBoundingClientRect().height") - route_panel_height) <= 2
        assert not await page.locator('[data-api-sort="host"]').is_visible()
        assert not await page.locator('[data-sort="authentication_status"]').is_visible()
        assert await page.locator("#api-table-wrap th").last.text_content() == "POST classification"
        assert await page.locator("#api-table-wrap th").last.is_visible()
        for kind in ("api", "route"):
            await page.locator(f"#{kind}-columns > summary").click()
            await page.locator(f'#{kind}-columns [data-column-action="reset"]').click()
            await page.locator(f"#{kind}-columns > summary").click()
        assert await page.locator('[data-api-sort="host"]').is_visible()
        assert await page.locator('[data-sort="authentication_status"]').is_visible()
        # Inspect is outside the table's clipping/scroll context, and presents
        # selected server-sanitized evidence instead of credential form values.
        await page.evaluate("""() => {
          const route = lastReport.results[0];
          route.storage_state = {cookies:[{value:'do-not-export-cookie'}]};
          route.authorization = 'do-not-export-authorization';
          route.page_errors = ['Long diagnostic: ' + 'detail '.repeat(500) + 'END_OF_DIAGNOSTIC'];
          route.requested_url = 'https://portal.example.com/health?code=%5BREDACTED%5D';
          Object.defineProperty(navigator, 'clipboard', {configurable:true,
            value:{writeText:async value => {window.copiedRouteDiagnostics = value;}}});
          renderRows();
        }""")
        inspect = page.locator("#result-list .route-inspect").first
        await inspect.click()
        assert await inspect.get_attribute("aria-expanded") == "true"
        assert await page.locator("#route-inspector").is_visible()
        assert "END_OF_DIAGNOSTIC" in await page.locator("#route-inspector-content").inner_text()
        assert await page.locator("#route-inspector-content pre").first.evaluate("element => getComputedStyle(element).whiteSpace") == "pre-wrap"
        assert await page.locator("#route-inspector-content h4").all_text_contents() == [
            "1. Overview", "2. Page load", "3. Navigation", "4. Authentication",
            "5. APIs", "6. Resources", "7. Console", "8. TLS", "9. Security headers",
            "Performance",
        ]
        assert await page.locator("#route-inspector").evaluate(
            "element => element.getBoundingClientRect().width > document.querySelector('#results').clientWidth - 60"
        )
        initial_height = await page.locator("#route-inspector").evaluate("element => element.clientHeight")
        await page.locator("#route-inspector-resize").press("ArrowDown")
        resized_inspect_height = await page.locator("#route-inspector").evaluate("element => element.clientHeight")
        assert resized_inspect_height > initial_height
        await page.locator("#route-inspector-expand").click()
        assert await page.locator("#route-inspector-expand").text_content() == "Collapse"
        assert await page.locator("#route-inspector").evaluate("element => element.clientHeight") > initial_height
        assert await page.locator("#route-inspector").evaluate("element => getComputedStyle(element).resize") == "vertical"
        # Opening Inspect intentionally smooth-scrolls the outer document. Stop
        # that still-running animation before testing inner-scroll isolation;
        # separate CDP round trips must not mistake animation progress for an
        # outer scroll caused by the inspector's own scrollTop assignment.
        await page.evaluate("window.scrollTo({top: window.scrollY, behavior: 'instant'})")
        initial_scroll = await page.evaluate("window.scrollY")
        assert await page.locator("#route-inspector-content").evaluate("""element => {
          element.scrollTop = 300;
          return element.scrollTop > 0 && element.scrollHeight > element.clientHeight;
        }""")
        assert await page.evaluate("window.scrollY") == initial_scroll
        await page.locator("#route-inspector-copy").click()
        copied = await page.evaluate("window.copiedRouteDiagnostics")
        assert "[REDACTED]" in copied or "%5BREDACTED%5D" in copied
        assert "do-not-export" not in copied
        assert "storage_state" not in copied
        assert "authorization" not in copied
        async with page.expect_download() as route_download:
            await page.locator("#route-inspector-download").click()
        downloaded = await route_download.value
        assert downloaded.suggested_filename == "portal-route-diagnostics.json"
        assert json.loads(Path(await downloaded.path()).read_text(encoding="utf-8")) == json.loads(copied)
        await page.locator("#route-inspector-fullscreen").click()
        assert await page.locator("#route-inspector-dialog").evaluate("element => element.open && element.matches(':modal')")
        assert await page.locator("#route-inspector").evaluate("element => element.clientHeight >= window.innerHeight - 2")
        # Native dialog keeps keyboard focus inside diagnostics.
        await page.locator("#route-inspector-content").focus()
        await page.keyboard.press("Tab")
        assert await page.locator("#route-inspector-dialog").evaluate("element => element.contains(document.activeElement)")
        await page.keyboard.press("Escape")
        assert not await page.locator("#route-inspector").is_visible()
        assert not await page.locator("#route-inspector-dialog").evaluate("element => element.open")
        assert await inspect.evaluate("element => document.activeElement === element")
        assert await inspect.get_attribute("aria-expanded") == "false"
        await inspect.press("Enter")
        # Closing a route or modal must not discard the user's panel size.
        assert await page.locator("#route-inspector-expand").text_content() == "Collapse"
        await page.locator("#route-inspector-expand").click()
        assert await page.locator("#route-inspector-expand").text_content() == "Expand"
        assert await page.locator("#route-inspector").evaluate("element => element.clientHeight") == resized_inspect_height
        await page.locator("#route-inspector-close").click()
        assert await inspect.evaluate("element => document.activeElement === element")
        await page.evaluate("delete lastReport.results[0].storage_state; delete lastReport.results[0].authorization")
        await page.locator(".warning-count").click()
        assert "CONSOLE_WARNING" in await page.locator("#evidence-content").text_content()
        assert "Optional component emitted a warning" in await page.locator("#evidence-content").text_content()
        assert await page.locator("#evidence-content > pre").count() == 0
        assert "route remains healthy" in await page.locator("#evidence-content").text_content()
        assert "console warning" in await page.locator(".warning-summary").text_content()
        assert await page.locator("#result-list .outcome-badge").text_content() == "PASS WITH WARNINGS (1)"
        await page.locator("#evidence-close").click()
        await page.evaluate("""() => {
          lastReport.results[0].load_ms = 5820;
          lastReport.results[0].warning_reasons = [{code:'SLOW_ROUTE',description:'Slow route: 5.82s > configured 5.0s threshold',severity:'WARNING',affected_component:'ROUTE_PERFORMANCE',threshold:{value:5000,unit:'ms'},evidence:{application_load_ms:5820,validator_overhead_ms:6000}}];
          renderRows();
        }""")
        assert "5.82s > configured 5.0s threshold" in await page.locator(".warning-count").get_attribute("title")
        await page.locator(".warning-count").click()
        assert "Slow route: 5.82s > configured 5.0s threshold" in await page.locator("#evidence-content").text_content()
        assert "Configured threshold" in await page.locator("#evidence-content").text_content()
        await page.locator("#evidence-panel").screenshot(path=f"{screenshot_base}-warnings{screenshot_extension or '.png'}")
        await page.locator("#evidence-close").click()
        await page.evaluate("lastReport.results[0].load_ms = 125; lastReport.results[0].warning_reasons = [{code:'CONSOLE_WARNING',description:'Optional component emitted a warning.',severity:'WARNING',affected_component:'CONSOLE'}]; renderRows()")
        await page.locator("#scan-diagnostics > summary").click()
        assert "5000" in await page.locator("#scan-diagnostics-content").text_content()
        assert "authentication_ms" in await page.locator("#scan-diagnostics-content").text_content()
        await page.locator("#scan-diagnostics > summary").click()
        assert not await page.locator("#resource-details").get_attribute("open")
        assert await page.locator("#resource-summary .resource-card").count() == 7
        assert await page.evaluate("""() => {
          lastReport.resource_details.push({type:'FONT',host:'cdn.example.net',path:'/small.woff',size_categories:[]});
          renderResourceSummary();
          const count = document.querySelectorAll('#resource-summary .resource-card strong')[5].textContent;
          lastReport.resource_details.pop(); renderResourceSummary();
          return count;
        }""") == "0"
        await page.locator("#resource-details > summary").click()
        assert await page.locator("#resource-list tr").count() == 3
        await page.locator("#resource-type-filter").select_option("image")
        assert await page.locator("#resource-list tr").count() == 2
        assert "N/A" in await page.locator("#resource-list").text_content()
        await page.locator("#resource-large-only").check()
        assert await page.locator("#resource-list tr").count() == 1
        await page.locator("#resource-large-only").uncheck()
        await page.locator("#resource-type-filter").select_option("failed")
        assert await page.locator("#resource-list tr").count() == 1
        assert "503" in await page.locator("#resource-list").text_content()
        await page.locator("#resource-type-filter").select_option("all")
        await page.locator("#resource-search").fill("hero")
        assert await page.locator("#resource-list tr").count() == 1
        await page.locator("#resource-search").fill("")
        await page.locator("#resource-route-filter").select_option("/health")
        assert await page.locator("#resource-list tr").count() == 3
        await page.locator("#resource-status-filter").select_option("5")
        assert await page.locator("#resource-list tr").count() == 1
        assert "503" in await page.locator("#resource-list").text_content()
        await page.locator("#resource-status-filter").select_option("all")
        await page.locator("#resource-failed-only").check()
        assert await page.locator("#resource-list tr").count() == 1
        await page.locator("#resource-failed-only").uncheck()
        await page.locator('[data-resource-sort="duration_ms"]').click()
        assert "/app.js" in await page.locator("#resource-list tr").first.text_content()
        await page.locator("#resource-columns > summary").click()
        assert await page.locator("#resource-columns input[type=checkbox]").count() == 11
        await page.locator('[data-column-kind="resource"][data-column-key="host"]').uncheck()
        assert not await page.locator('[data-resource-sort="host"]').is_visible()
        await page.locator('#resource-columns [data-column-action="reset"]').click()
        assert await page.locator('[data-resource-sort="host"]').is_visible()
        await page.locator("#resource-columns > summary").click()
        await page.locator("#resource-details > summary").click()
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
        blocked_sort = page.get_by_role("button", name="Blocked", exact=True)
        assert await blocked_sort.count() == 1
        await blocked_sort.click()
        assert await page.locator('[data-api-sort="blocked_count"]').evaluate(
            "element => element.closest('th').getAttribute('aria-sort')"
        ) == "ascending"
        route_scroller = page.locator('[data-scroll-for="route-table-wrap"]')
        # Compact tables may fit a desktop viewport. Synchronized scrolling is
        # required only when selected columns genuinely overflow.
        await page.set_viewport_size({"width": 768, "height": 1024})
        await route_scroller.wait_for(state="visible")
        assert await route_scroller.is_visible()
        await route_scroller.evaluate("element => { element.scrollLeft = 120; element.dispatchEvent(new Event('scroll')); }")
        assert await page.locator("#route-table-wrap").evaluate("element => element.scrollLeft") == 120
        await route_scroller.evaluate("element => { element.scrollLeft = 0; element.dispatchEvent(new Event('scroll')); }")
        api_scroller = page.locator('[data-scroll-for="api-table-wrap"]')
        await api_scroller.wait_for(state="visible")
        await api_scroller.evaluate("element => { element.scrollLeft = 120; element.dispatchEvent(new Event('scroll')); }")
        assert await page.locator("#api-table-wrap").evaluate("element => element.scrollLeft") == 120
        await api_scroller.evaluate("element => { element.scrollLeft = 0; element.dispatchEvent(new Event('scroll')); }")
        await page.set_viewport_size({"width": 1440, "height": 1100})
        await page.get_by_role("button", name="Show Discovered routes evidence").click()
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
        # Exercise the actual form-to-API contract without contacting a target.
        # The fixture intercepts only this local validator's scan endpoints.
        submitted = []

        async def capture_scan(route):
            submitted.append(route.request.post_data_json)
            await route.fulfill(status=202, content_type="application/json", body=json.dumps({"scan_id": "ui-policy"}))

        async def completed_status(route):
            await route.fulfill(status=200, content_type="application/json", body=json.dumps({"state": "COMPLETED", "validated": 1, "discovered": 1, "healthy": 1, "failed": 0, "warnings": 1}))

        async def fixture_report(route):
            await route.fulfill(status=200, content_type="application/json", body=json.dumps(saved_report))

        await page.route("**/api/scans", capture_scan)
        await page.route("**/api/scans/ui-policy", completed_status)
        await page.route("**/api/scans/ui-policy/report", fixture_report)
        await page.locator("#auth-mode").select_option("none")
        await page.locator("#target").fill("portal.example.com")
        await page.locator("#read-post-settings > summary").click()
        await page.locator("#add-read-post").click()
        await page.locator(".operation-host").fill("api.example.net")
        await page.locator(".operation-path").fill("/v1/query")
        await page.locator("#min-observation").evaluate("element => { element.closest('details').open = true; }")
        await page.locator("#large-js-threshold").evaluate("element => { element.closest('details').open = true; }")
        await page.locator("#min-observation").fill("100")
        await page.locator("#network-quiet").fill("150")
        await page.locator("#large-js-threshold").fill("1536")
        await page.locator("#large-css-font-threshold").fill("768")
        await page.locator("#slow-threshold").fill("7250")
        await page.locator("#scan-timing-settings").evaluate("element => { element.open = true; }")
        await concurrency.fill("1")
        await page.locator("#run-button").click()
        await page.wait_for_function("() => !document.getElementById('run-button').disabled && document.getElementById('progress').hidden")
        assert len(submitted) == 1
        assert submitted[0]["approved_read_post_operations"] == [
            {"method": "POST", "host": "api.example.net", "path": "/v1/query"},
        ]
        assert submitted[0]["allow_mutations"] is False
        assert submitted[0]["large_resource_threshold_bytes"] == 1048576
        assert submitted[0]["large_image_threshold_bytes"] == 524288
        assert submitted[0]["large_js_threshold_bytes"] == 1572864
        assert submitted[0]["large_css_font_threshold_bytes"] == 786432
        assert submitted[0]["min_observation_ms"] == 100
        assert submitted[0]["network_quiet_ms"] == 150
        assert submitted[0]["slow_page_threshold_ms"] == 7250
        assert submitted[0]["concurrency_limit"] == 1
        await concurrency.fill("")
        await page.locator("#scan-timing-settings").evaluate("element => { element.open = false; }")
        await page.unroute("**/api/scans", capture_scan)
        await page.unroute("**/api/scans/ui-policy", completed_status)
        await page.unroute("**/api/scans/ui-policy/report", fixture_report)
        await page.locator(".remove-operation").click()
        await page.locator("#read-post-settings > summary").click()
        for inventory_size in (100, 500, 1000):
            large_inventory = await page.evaluate("""
          (inventorySize) => {
            lastReport.api_inventory = Array.from({length:inventorySize}, (_, index) => ({
              method:index % 2 ? 'GET' : 'POST', host:'api.example.net', endpoint:`/items/${index}`,
              calls:index + 1, status_2xx:index + 1, status_3xx:0, status_4xx:0, status_5xx:0,
              network_failures:0, route_count:1, allowed_calls:index + 1, blocked_count:0,
              average_duration_ms:index % 37, worst_duration_ms:index % 53, health:'HEALTHY',
              observation_outcome:'HEALTHY', routes_using_endpoint:['/health']
            }));
            updateApiMethodFilter(lastReport.api_inventory);
            updateApiRouteFilter(lastReport.api_inventory);
            const started = performance.now();
            renderApiInventory();
            return {milliseconds:performance.now() - started, rows:document.querySelectorAll('#api-list tr').length};
          }
        """, inventory_size)
            assert large_inventory["rows"] == 50
            assert large_inventory["milliseconds"] < 3000
            assert f"of {inventory_size}" in await page.locator("#api-page-status").inner_text()
            first_endpoint = await page.locator("#api-list .api-endpoint").first.inner_text()
            await page.locator("#api-page-next").click()
            assert "Page 2" in await page.locator("#api-page-status").inner_text()
            assert first_endpoint != await page.locator("#api-list .api-endpoint").first.inner_text()
            await page.locator("#api-page-prev").click()
            assert first_endpoint == await page.locator("#api-list .api-endpoint").first.inner_text()
            print(f"UI_TABLE_PERFORMANCE rows={inventory_size} render_ms={large_inventory['milliseconds']:.2f}")
        route_coverage = await page.evaluate("""() => {
          const first = lastReport.results[0];
          lastReport.results = Array.from({length:44}, (_, index) => ({...first,
            route_name:`Route ${index}`,display_path:`/route/${index}`,
            classification:index === 43 ? 'FAIL' : index < 33 ? 'PASS_WITH_WARNINGS' : 'PASS',
            warning_findings:index < 33 ? 1 : 0,
            warning_reasons:index < 33 ? first.warning_reasons : []
          }));
          renderRows();
          return {rows:document.querySelectorAll('#result-list .route-row').length,
            warnings:document.querySelectorAll('#result-list .warning-count').length};
        }""")
        assert route_coverage == {"rows": 44, "warnings": 33}
        assert await page.locator("#route-table-wrap").evaluate("""element => {
          element.scrollTop = 300;
          const header = element.querySelector('th').getBoundingClientRect();
          const frame = element.getBoundingClientRect();
          return element.scrollTop > 0 && Math.abs(header.top - frame.top) < 3;
        }""")
        await page.locator("#route-table-wrap").evaluate("element => { element.scrollTop = 0; }")
        await page.locator("#route-results-fullscreen").click()
        await page.locator("#result-list .route-inspect").first.click()
        assert await page.locator("#route-inspector-dialog").evaluate("element => element.open && element.matches(':modal')")
        await page.keyboard.press("Escape")
        assert await page.locator("#route-results-dialog").evaluate("element => element.open")
        await page.keyboard.press("Escape")
        assert not await page.locator("#route-results-dialog").evaluate("element => element.open")
        await page.evaluate("""() => {
          window.paginationRoutes = lastReport.results;
          const first = lastReport.results[0];
          lastReport.results = Array.from({length:52}, (_, index) => ({...first,
            route_name:`Pagination route ${index}`,display_path:`/pagination/${index}`,
            classification:'PASS',warning_findings:0,warning_reasons:[]}));
          renderRows();
        }""")
        first_route_page = await page.locator("#result-list .route-name-cell strong").all_text_contents()
        assert len(first_route_page) == 50
        assert "of 52" in await page.locator("#route-page-status").inner_text()
        await page.locator("#route-page-next").click()
        second_route_page = await page.locator("#result-list .route-name-cell strong").all_text_contents()
        assert len(second_route_page) == 2
        assert "Page 2" in await page.locator("#route-page-status").inner_text()
        assert not set(first_route_page) & set(second_route_page)
        assert len(set(first_route_page + second_route_page)) == 52
        await page.locator("#route-page-prev").click()
        assert await page.locator("#result-list .route-name-cell strong").all_text_contents() == first_route_page
        await page.evaluate("lastReport.results = window.paginationRoutes; delete window.paginationRoutes; renderRows()")
        assert await page.locator("#result-list .route-row").count() == 44
        await page.locator("#api-method-filter").select_option("GET")
        await page.locator("#api-status-filter").select_option("FAILED")
        await page.locator("#api-search").fill("previous-scan-filter")
        await page.locator("#result-search").fill("previous-route-filter")
        await page.locator("#resource-details").evaluate("element => { element.open = true; }")
        await page.locator("#resource-search").fill("previous-resource-filter")
        await page.locator("#resource-failed-only").check()
        await page.locator("#resource-large-only").check()
        await page.evaluate("renderReport(lastReport)")
        assert await page.locator("#api-method-filter").input_value() == "all"
        assert await page.locator("#api-status-filter").input_value() == "all"
        assert await page.locator("#api-search").input_value() == ""
        assert await page.locator("#result-search").input_value() == ""
        assert await page.locator("#resource-search").input_value() == ""
        assert not await page.locator("#resource-failed-only").is_checked()
        assert not await page.locator("#resource-large-only").is_checked()
        assert await page.locator("#api-list .api-endpoint").count() == 50
        await page.evaluate("""() => {
          window.originalResourceDetails = lastReport.resource_details;
          lastReport.resource_details = ['route-a','route-b'].flatMap(route =>
            Array.from({length:100}, (_, index) => ({route,url:`https://assets.example.net/${index}`,path:`/${index}`,type:'image',status:200})));
          renderResourceSummary();
        }""")
        await page.locator("#resource-route-filter").select_option("route-a")
        await page.locator("#resource-page-next").click()
        assert "Page 2" in await page.locator("#resource-page-status").inner_text()
        await page.locator("#resource-route-filter").select_option("route-b")
        assert "Page 1" in await page.locator("#resource-page-status").inner_text()
        await page.evaluate("lastReport.resource_details = window.originalResourceDetails; renderReport(lastReport)")
        for viewport in (
            {"width": 1920, "height": 1080},
            {"width": 1366, "height": 768},
            {"width": 768, "height": 1024},
            {"width": 390, "height": 844},
        ):
            await page.set_viewport_size(viewport)
            assert await page.get_by_role("button", name="Run validation →").is_visible()
            await page.locator("#route-results-fullscreen").click()
            assert await route_panel.evaluate("element => element.getBoundingClientRect().width <= window.innerWidth")
            assert await page.locator("#route-table-wrap").evaluate("element => element.clientHeight > 100")
            await page.keyboard.press("Escape")
            await page.locator("#result-list .route-inspect").first.click()
            assert await page.locator("#route-inspector").is_visible()
            await page.locator("#route-inspector-fullscreen").click()
            assert await page.locator("#route-inspector").evaluate(
                "element => element.getBoundingClientRect().width <= window.innerWidth"
            )
            await page.keyboard.press("Escape")
            assert not await page.locator("#route-inspector").is_visible()
            await page.locator("#resource-details").evaluate("element => { element.open = true; }")
            await page.locator("#read-post-settings > summary").click()
            await page.locator("#add-read-post").click()
            await page.locator(".operation-host").fill("api.example.net")
            await page.locator(".operation-path").fill("/v1/query")
            page_overflow = await page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            )
            overflow_elements = await page.locator("body *").evaluate_all(
                """elements => elements
                  .map(element => ({
                    tag: element.tagName,
                    id: element.id,
                    className: String(element.className || ''),
                    parentClassName: String(element.parentElement?.className || ''),
                    text: String(element.textContent || '').trim().slice(0, 80),
                    right: element.getBoundingClientRect().right,
                    width: element.getBoundingClientRect().width,
                  }))
                  .filter(item => item.right > document.documentElement.clientWidth + 1)
                  .slice(0, 10)"""
            )
            assert page_overflow <= 1, {
                "viewport": viewport,
                "page_overflow": page_overflow,
                "overflow_elements": overflow_elements,
            }
            await page.locator(".remove-operation").click()
            await page.locator("#read-post-settings > summary").click()
        actionable_errors = [
            error for error in console_errors
            if "Cross-Origin-Opener-Policy header has been ignored" not in error
        ]
        assert not actionable_errors, actionable_errors
        print("UI_SMOKE_PASSED: phase controls, traffic roles/lifecycle, POST form contract/counters, actual scan duration, blocked methods, columns/persistence, density, warnings, pointer/keyboard panel resizing and session persistence, expandable/fullscreen sanitized diagnostic copy/export, long diagnostics, independent scrolling/sticky headers/keyboard focus, resource filters, synchronized scrolling, 44 routes, 52 paginated routes, 1000 paginated API records, mobile layouts, strict CSP")
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
