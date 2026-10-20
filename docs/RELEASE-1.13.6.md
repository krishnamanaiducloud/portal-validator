# Portal Validator 1.13.6 — sub-tabs and read-only POST review

## Query-addressed sub-tabs are validated as separate views

Some applications address tabs and sub-tabs only through a query parameter,
for example `/reports?tab=daily` and `/reports?tab=monthly`. Under the
default `ignore` query parameter policy, these destinations normalized to the
same route. Only the first one was validated, and every other sub-tab was
dropped as a duplicate.

The scanner now learns which query parameters tell sibling tab, menu item or
option destinations apart. A parameter counts when it appears on two or more
siblings under the same path with different values. During that scan, those
parameters become part of route identity. Tracking and secret-bearing
parameters are still removed. Nothing is configured per site, so this works
the same way for any portal.

Nested `role="tab"` sub-tabs inside a tab panel were already discovered.
`tests/test_nested_subtabs.py` now covers both cases.

## Review panel for blocked read-only POST requests

POST requests are denied by default. A POST that was never approved as
read-only is blocked before it reaches the application. Its result therefore
cannot be validated, and the dashboard showed 0 approved read-only POST
endpoints.

When a scan observes POST endpoints that were blocked only because they were
unverified, the dashboard now lists them in a review panel:

- Nothing is pre-selected.
- Authentication traffic is never offered.
- **Approve selected as read-only** adds the selected endpoints under
  *Approved read-only API operations*. Inventory placeholders such as `{id}`
  become `{segment}` path patterns.
- **Approve and run again** also starts a new scan.

Approving an endpoint stays an explicit operator decision. Unapproved POSTs
remain blocked, and request bodies are never logged or replayed.

The previous 100-operation limit on approved read-only POST operations has
been removed from the UI.

## Notes for sign-in protected portals

Sub-tab discovery inside a route can only run once the route has rendered.
If routes report as sign-in blocked, approve the identity hosts suggested in
the authentication callout (added in 1.13.4) first. Their sub-tabs will be
discovered on the next run.
