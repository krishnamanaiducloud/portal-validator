# Portal Validator 1.13.2 — session recovery, sortable tables and session renewal

## Session expiry during a scan

With an SSO session profile, routes validated normally until the access token
expired, typically after a few minutes. Then the whole scan ended as
"Authentication failed" with zero routes. The authentication-first gate
treated any session rejection after the application was ready as a global
authentication failure, and discarded every route validated while the session
was still valid.

The scan now recovers:

1. When the session is rejected after the application was ready, the
   validator runs the profile's silent refresh, if one is configured.
2. It then reopens the portal through the same approved SSO flow as the
   initial bootstrap. An identity provider with a valid session silently
   re-issues the application session. Credentials are never entered or
   replayed.
3. If the application becomes ready again, the interrupted route is retried
   and the scan continues. Earlier 401 evidence is not re-applied to the
   recovered session.
4. *Session recovery attempts* (`session_recovery_attempts`, default 3)
   limits the retries. When they are exhausted, or the identity provider
   requires an interactive sign-in or MFA, the scan stops with
   `scan_status=PARTIAL` and `termination_reason=SESSION_EXPIRED`:
   - routes validated while the session was valid are kept;
   - the remaining routes are listed as `NOT_TESTED_SESSION_EXPIRED`;
   - the cause is reported in `session_interruption`.

Initial authentication failures still fail closed with zero routes. The
dashboard explains a stopped or recovered session.

## Sortable tables

The dashboard sorted only the route, API and resource tables. It could not sort:

- the failed endpoint table: Kind, Method, Sanitized endpoint, Associated
  routes/views, HTTP error, Failure classification, Affected calls, First
  observed and Last observed;
- the Blocked / Incomplete Requests table: Kind, Method, Sanitized endpoint,
  Issue, Calls and Associated routes/views;
- the resource table's Health column.

These columns now sort like the other tables. Clicking a column sorts it
ascending, and clicking again sorts it descending. `aria-sort` reflects the
order, numeric columns sort numerically, and text columns sort naturally.
Action columns (Details, Diagnostics) are not sortable.

## Session renewal

- **Renewed IndexedDB tokens are kept.** At the end of a scan the runtime
  session copy was saved without IndexedDB, so any token an authentication
  library kept there was lost and the next scan restored the stale session.
  The copy now includes IndexedDB. Cookies and localStorage were already
  saved.
- **Periodic silent refresh during long scans.** A profile with
  `<profile>.refresh.json` was refreshed only at scan start. Set
  *Session refresh interval* in the dashboard (`session_refresh_interval_ms`)
  or `interval_ms` in the refresh file to re-run the configured silent refresh
  during the scan. It runs on a separate validator-owned tab, which is never
  reported as an application route or popup.
- **Token renewal without an interactive sign-in.** An application's own
  refresh-token renewal no longer requires an observed sign-in flow. It is
  allowed only when all of the following hold:
  - the request is a `fetch`/XHR `POST` with `grant_type=refresh_token`
    (authorization-code and password grants are excluded);
  - it targets an explicitly approved authentication host and endpoint;
  - it comes from a portal document.

  Such a request is recorded as `SESSION_REFRESH`.
- **Refresh file limits.** `refresh.json` timeouts are no longer capped at
  120 s. Only the browser timer limit applies.

Renewal still requires the identity provider's host in *Authentication hosts*
or in the operator authentication policy. Renewal to an unapproved host remains
blocked. A static Bearer/API token entered in the dashboard cannot renew
itself; use an SSO session profile for applications with expiring tokens.

## Tests

- `tests/test_session_recovery.py` uses a portal whose session expires
  server-side mid-scan:
  - with a silently re-issuing identity provider, the session is recovered
    and every route is validated;
  - when sign-in is required, validated routes are kept and the rest are
    marked not tested;
  - zero recovery attempts never re-authenticates.
- `tests/test_authentication_first.py` now asserts that an unrecoverable
  expiry keeps the validated routes. It previously asserted that they were
  discarded.
- `tests/test_session_renewal.py`:
  - only refresh grants qualify;
  - restored-session renewal policy works without an interactive flow;
  - the application renews against an approved identity host;
  - renewal to an unapproved host stays blocked;
  - periodic refresh runs on an internal tab;
  - a renewed IndexedDB token is saved for the next scan.
- The IndexedDB and policy tests fail on 1.13.1 and pass on 1.13.2.
- `tests/ui_check.py` verifies sorting of the failure and request-issue tables
  in both directions, numeric ordering of affected calls, and the Health sort
  control.

## Published images

Built from commit `9a90436750ef13876da12122285c24fe9f4aab1e` for `linux/amd64`
on the same digest-pinned bases as 1.13.1. Later commits change documentation
and the Deployment reference only.

| Image | Digest | Compressed size |
|---|---|---|
| `docker.io/mohankrishna999/portal-validator:1.13.2` | `sha256:f6cd4c3017a49e763c669e83a6cbaaf399ba008a04fb0fc5af2049aa9f9209a9` | 503.6 MB |
| `docker.io/mohankrishna999/portal-validator:1.13.2-debug` | `sha256:e0c3d05544347fa28ef06eb766a94df56d8a3709a75f8b076e261daa6096882b` | 527.3 MB |

Both digests were confirmed from the registry. Each image was pulled by digest
and reported version 1.13.2, the commit above and `VERIFIED` source integrity.
`openshift/deployment.yaml` pins the production image by tag and digest. No
cluster rollout was performed.

## Verification

- Host suite (WSL2, Python 3.14): 1187 passed, 0 failed. Frontend
  `tests/ui_check.py` passed.
- Debug image (Python 3.15, arbitrary UID, read-only root, all capabilities
  dropped): 114 of 114 session recovery, session renewal,
  authentication-first, SSO, scan-speed, broad discovery and API tests passed.
- `tests/release_image_smoke.py` passed for both images: strict Python and
  Chromium TLS, `/healthz`, redacted access logs, graceful SIGTERM and an
  idempotent entrypoint.

## Security scan results

Trivy 0.72.0 (DB 2026-10-18 18:32 UTC) and Grype 0.104.0 (DB 2026-10-19 06:39
UTC) scanned both images on 2026-10-19:

| Check | `1.13.2` | `1.13.2-debug` |
|---|---|---|
| Trivy Critical/High/Medium/Low | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| Trivy secrets | 0 | 0 |
| Grype Critical/High/Medium/Low | 0 / 0 / 3 / 0 | 0 / 0 / 3 / 0 |
| SBOM packages (SPDX) | 121 | 172 |

The three Grype findings are the unchanged, still-unfixed `alsa-lib
1.2.16.1-r3` CVEs, carried forward under the exception documented in
`docs/RELEASE-1.13.0.md`.
