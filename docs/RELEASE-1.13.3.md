# Portal Validator 1.13.3 — renewal blocks no longer fail scans

## Authentication failed after about five minutes

With an SSO session profile, scans still ended as "Authentication failed"
after about 318 seconds, with no routes reported. This lines up with a
5-minute access token: the application renews it in the background with a
refresh-token POST or a silent-renew iframe to its identity provider.

When the identity provider host was not approved, that renewal request was
blocked. 1.13.2 already recovered expired sessions, but it treated a
blocked renewal as `AUTHENTICATION_BLOCKED`, a policy failure that still
failed the whole scan. A legacy rule also stopped discovery after any route
with a blocked authentication request.

Now:

- An authentication request blocked after the application passed the
  authentication gate affects only its own route. That route is reported
  as `AUTHENTICATION_BLOCKED` and the scan continues.
- If the session later expires, mid-scan recovery (1.13.2) applies. When
  recovery is impossible, the scan stops as `PARTIAL` and keeps the routes
  already validated.
- The blocks are reported in `mid_scan_authentication_blocks`, including
  the identity host and endpoint. The dashboard names the host to add to
  *Authentication hosts* so the application can renew its session.
- Blocks that the application's own start-up depended on still fail the
  scan closed with zero routes. So do initial authentication failures.
- An unapproved identity host is still never contacted.

## Sortable route and API columns

The routes table's Navigation hierarchy and Discovery source columns, and
the API table's Traffic role, Policy and later columns, were added by
JavaScript without sort controls. All of them now sort on the values they
display. Details sorts by each route's total validation time, which is the
timing breakdown the inspector shows. `tests/ui_check.py` now fails if any
rendered data column in the routes, API, resource, failed-endpoint or
request-issue tables lacks a sort control. The only unsortable columns are
the failure tables' Diagnostics action buttons.

## Tests

- `tests/test_session_renewal.py`: a renewal blocked on a later route
  neither fails the scan nor stops discovery. The unapproved host is never
  contacted, and the block is reported with its host. This test fails on
  1.13.2.
- `tests/ui_check.py`: sortable-header audit across all five tables, and
  ascending/descending sorting of Navigation hierarchy, Discovery source and
  Details.
