# Portal Validator 1.13.2 — sortable tables and session renewal

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
