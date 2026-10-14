# Portal Validator 1.12.11 — known-good discovery regressions

## Historical comparison and corrections

Compared the discovery behavior at `9407720a7cf9490e35eed162f2fe14455490a464`
(1.3.1) with the current implementation. Classic anchors, navigation metadata
and safe collapsed menus still produced equivalent candidates. Three concrete
regressions were reproduced instead of reverting the application or relaxing
authentication, SSRF, TLS or read-only execution.

| Reproduced behavior before | Focused correction |
| --- | --- |
| Default query ignoring collapsed `#/workspace?view=home`, `view=reports` and `view=activity` into one route. | Preserve sanitized SPA fragment parameters as route identity; continue ignoring ordinary HTTP queries by default. Explicit allowlists and secret/tracking exclusions remain enforced. |
| Breadth-first traversal visited a sibling document before a queued hash/history route. Synthetic history then changed that sibling's URL without restoring the SPA, losing its content and API activity. | Retain the actual observed source document GET separately from its logical history URL. Restore a displaced source through guarded document navigation, retain its real response, then activate the SPA route. The document observer baseline identifies the actual source, ignoring an initial hash; shared history URLs cannot establish document ownership. |
| An authenticated rendered shell containing a completed ARIA progress bar failed readiness and stopped validation after one page. | A finite completed determinate bar is status, not an active loader. Explicit busy state, incomplete/indeterminate/invalid progress, configured readiness and challenge gates remain blocking. |

## Synthetic before/after evidence

- Fragment-query fixture: one discovered/validated landing route before;
  three distinct validated views afterward, for both hash and hashbang routing.
- Displaced-source fixture: queued Reports inspected the unrelated document and
  missed its API before; afterward both hash/history variants render Reports,
  retain the context cookie, and capture the real API GET 200 once with matching
  route and activation attribution. Sibling SPA transitions still use one document.
  History URLs without a server document fallback restore their actual shell
  GET instead. A displaced source without an observed GET fails explicitly;
  authentication/business POST documents are never replayed.
  A sibling application independently visiting the same history URL still
  restores the correct source document instead of inheriting the wrong DOM.
  A popup whose observer started at `about:blank` uses its actual Navigation
  Timing document identity instead; this preserves the original window,
  avoids duplicate tabs and does not accept unrelated history observations.
- Completed-progress authenticated fixture: one loaded page, two retained but
  untested routes and `APPLICATION_NOT_READY` before; three rendered, ready,
  passing routes afterward.

These controlled fixtures demonstrate specific fixes, not complete coverage of
an untested private application. A genuine failed authentication/readiness gate
still stops protected activation and retains passive route evidence with a
partial-coverage reason. Safe navigation limits, permissions and ambiguous
controls can still prevent exhaustive discovery.

## Files and security

Runtime changes are limited to `app/discovery.py`, `app/main.py` and
`app/health.py`. The existing query-policy UI/help now distinguishes document
queries from SPA fragment identity; the rest of the UI is unchanged.
Release identity, versioned image references, smoke expectations and README are
aligned to 1.12.11. Regression tests are in `tests/test_discovery.py`,
`tests/test_fragment_route_identity.py` and
`tests/test_readiness_discovery_regression.py`.

CA/NSS bootstrap, entrypoint, Playwright 1.63.0 and its Chromium revision 1243,
pinned base images, dependencies, arbitrary UID support, strict TLS, SSO
approvals, network guards and POST execution policies are unchanged. No POST
is synthesized or replayed. No organization-specific data or session material
is included. The deployment image reference changes; no cluster rollout is
performed by publishing these artifacts.

The fragment-query collapse was introduced in `c6c11534`; FIFO traversal was
introduced in `f5f0e929`. The first-unready activation stop appeared in
`07a5760`, with passive destination retention added in `5694dc3`. The readiness
and authentication gates themselves are preserved; the completed-loader false
positive is corrected rather than bypassing readiness.

## Verification and publication

Full-suite, UI, final-image and publication results are recorded after execution.
