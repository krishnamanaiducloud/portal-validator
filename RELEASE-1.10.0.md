# Portal Validator 1.10.0

## Diagnosis and changes

| Reported area | Evidence in the existing implementation | Focused correction |
| --- | --- | --- |
| Only the initial route found | Menu expansion sampled after 50 ms; asynchronous menu content could arrive after discovery finished | Apply the user-configured observation/quiet window after menu expansion, within the route deadline |
| Embedded portal navigation missed | Link discovery evaluated only the top-level page | Discover links/history in approved portal frames, keeping the existing crawl and network boundaries |
| Wrong query route activated | Semantic link matching compared origin/path/fragment but omitted query | Compare query parameters too; preserve distinct route identities under the configured query policy |
| Document mistaken for SPA transition | Observer's initial document baseline was reported as browser history | Exclude the baseline from history transitions |
| POSTs appear missing in a new scan | Method/status/search filters persisted from the preceding scan | Reset API filters when a new report arrives; keep column preferences separate |
| Large inventories expensive to render | Every row rendered simultaneously | Paginate route, API and resource tables; filtering, sorting and exports retain the complete inventory |
| Shared GraphQL endpoint could accept mutations | A host/path approval alone cannot distinguish GraphQL query vs mutation | Explicit query-only rules use a syntax parser; mutations, subscriptions and unverified operations fail closed |
| Vulnerable libc baseline | Previously pinned Chainguard digests preceded glibc 2.44-r8 | Refresh pinned bases and fail builds below the minimum installed glibc version |

Previous POST identity/lifecycle corrections remain intact. Context listeners are
registered before navigation; authorization never removes observations; blocked,
failed and incomplete calls remain visible. Approved POSTs execute naturally in
the original browser context, never through automatic replay.

Playwright remains 1.63.0 with matching Chromium revision 1243. Corporate trust,
SSO/session isolation, credential redaction, mutation blocking and SSRF code are
not relaxed. Production and debug images retain non-root execution and the
existing trust entrypoint. No certificate material or private portal identifiers
are included in this release.

## Controlled verification

- Same lazy-menu/frame fixture and settings, committed `ea9c11f` versus this
  correction: **1 → 4 validated routes**. This is a controlled regression result,
  not an estimate of any enterprise portal's total route coverage.
- A 52-route fixture completed with **357 approved POST calls**, one browser
  context, one page and 51 SPA transitions. No duplicate POST replay occurred.
  Recorded scan duration: 65,475 ms on the Windows test host; timing is dependent
  on host load and is not an OpenShift performance guarantee.
- GraphQL unit/production-path tests cover parsed queries, batched queries,
  mutations, subscriptions, ambiguous/malformed operations, unknown persisted
  queries, duplicate JSON keys, invalid Unicode, overlapping policy rules and
  visibility of blocked POST attempts. Main-frame requests with authentication
  query parameters cannot bypass an explicit GraphQL query-only restriction.
- Browser UI checks cover 44 routes, 1,000 paginated API observations, filters,
  warning explanations, columns, density, exports and responsive layouts.
  New scans clear old route/API/resource filters. Changing resource-route
  filters resets pagination even when both routes use identical resource URLs.
- Isolated Windows dependency environment: `python -m pip check` passed;
  `python -m pytest -q` completed with **253 passed, 1 skipped**. The skipped
  platform-specific trust test requires Linux tools and is checked separately
  in the runtime image. `tests/ui_check.py` passed with strict CSP and mobile
  layouts; rendering a 1,000-record inventory showed 50 paginated rows.

## Scope and remaining limitations

This is a focused production correction, not a claim that every item in the
broader platform roadmap is finished. Discovery remains bounded by configured
routes/depth/actions/scrolls and deadlines. Unknown controls are not clicked.
Service workers remain blocked to preserve interception-based mutation guards.
Query-only GraphQL requires explicit endpoint approval and a supplied query;
persisted-query hashes need a trusted contract and are not automatically allowed.

Navigation/readiness currently share the maximum-time-per-route budget. Separate
API timeout, authentication timeout and per-scan concurrency UI controls are not
introduced here; session-refresh timeouts and concurrent-scan limits remain
administrator controlled. Existing challenge/access-restriction classifications
are preserved rather than bypassed.

Private portal authentication and Chromium sandbox compatibility under the
actual OpenShift SCC still require deployment verification. No private cluster
or browser session was available to these controlled tests. No claim of complete
enterprise route coverage, zero vulnerabilities or successful private SSO is
made without corresponding runtime evidence.

## Post-deployment checks

Run in the deployment's existing OpenShift project after an authorized rollout:

```sh
oc rollout status deployment/portal-validator
oc logs deployment/portal-validator --tail=100
oc exec deployment/portal-validator -- sh -c 'id; echo "$HOME"; python -m app.trust status; certutil -L -d "sql:$CHROMIUM_NSS_DB"'
oc exec deployment/portal-validator -- sh -c 'tr "\000" "\n" < /proc/1/environ | grep -E "^(HOME|PLAYWRIGHT_BROWSERS_PATH|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|RUNTIME_CA_BUNDLE)="'
oc exec -i deployment/portal-validator -- python - <<'PY'
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    print("Chromium:", p.chromium.executable_path)
    browser = p.chromium.launch(headless=True)
    try:
        page = browser.new_page()
        response = page.goto("https://google.com", wait_until="domcontentloaded", timeout=30000)
        print("HTTP:", response.status if response else None)
        print("Title:", page.title())
    finally:
        browser.close()
PY
```

Use an authorized internal target locally for the equivalent private-portal test;
do not publish its URL, authentication material, reports or certificate files.
Confirm mounted profile validity, route coverage and POST policy against that
portal independently of these controlled fixtures.
