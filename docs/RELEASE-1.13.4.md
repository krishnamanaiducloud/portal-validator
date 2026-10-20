# Portal Validator 1.13.4 — SSO route diagnosis, route states and dashboard

## Root-cause report

Evidence comes from a 1.13.3 scan of an authenticated microfrontend portal
(source verified) and from generic synthetic reproductions.

### Repeated `AUTHENTICATION_SOURCE_NOT_APPROVED`

- **Configuration.** No authentication hosts were approved: the report showed
  `0 approved authentication hosts`, with nothing submitted manually or by
  the operator. The *Authentication hosts* field contained only its example
  placeholder text.
- **What the portal does.** Each microfrontend route performs its own SAML
  round trip. The browser is sent to the identity host, that host's page
  auto-posts a `SAMLRequest` to itself, and the `SAMLResponse` is then posted
  back to the portal.
- **Why the request was blocked.** The identity host was not approved, so the
  first auto-post was correctly blocked, together with a separate OAuth token
  request.
- **The diagnostic was wrong.** Because the identity host's page posts to
  itself, the diagnostic reported *source not approved* and *protected
  coverage affected: not established*. It never named the host to approve,
  and the route was reported as a generic `NAVIGATION_ERROR` while the
  browser sat on the identity page.

`tests/test_route_sso_roundtrip.py` reproduces this pattern generically:

- With the identity host approved, every microfrontend route validates
  through its SAML round trip.
- Without approval, the old code produced exactly the observed diagnostics
  and `NAVIGATION_ERROR` routes.

The frontend, request model, host normalization and policy evaluation all
handled approved hosts correctly. The defects were in diagnosis and
reporting, not in host propagation.

### Duplicated menu routes and slow scans

Many menu entries are rendered both as links and as clickable menu items.
Each entry was queued twice: once as a link route, and once as a UI view
whose activation timed out at the per-route limit. About 41 such timeouts of
15 s each account for most of the observed 675 s scan.

### Misleading dashboard counts

`routes_validated` counted attempted routes. The dashboard showed 86
"validated" routes while only 4 were healthy and 81 never reached
application readiness.

## Changes

### Authentication diagnosis

When an identity provider's page posts its own sign-in form to itself in the
main frame:

- the request is reported as `AUTHENTICATION_HOSTS_REQUIRED` /
  `AUTHENTICATION_HOST_NOT_APPROVED`;
- `suggested_authentication_host` names the host;
- it is counted as affecting authentication.

The request itself stays blocked. A route whose sign-in step was blocked is
classified `AUTHENTICATION_BLOCKED` with a message naming the host, instead
of a navigation error.

### Grouped diagnostics

`authentication_diagnostic_groups` groups repeated policy observations by
reason, protocol, source and destination host, and policy decision, with
occurrence counts, affected routes and the suggested host.
`suggested_authentication_hosts` lists the identity hosts to approve. Every
individual record remains in the JSON report.

### Route states

Each visited route now has a `route_state`, derived only from browser
evidence:

- `VALIDATED`: the view loaded and application readiness was observed, so
  its health checks ran (they may still fail).
- `RENDERED`: the view loaded but never became ready.
- `NAVIGATION_ATTEMPTED`, `AUTHENTICATION_BLOCKED`, `AUTHORIZATION_DENIED`,
  `POLICY_BLOCKED`, `NAVIGATION_FAILED`, `TIMEOUT` and `INCOMPLETE`: the
  route stopped at that point.
- `DISCOVERED`: counted in the summary for routes that were never visited.

The summary adds `route_states`, `routes_visited`, `routes_rendered`,
`routes_application_validated`, `routes_blocked` and `routes_incomplete`.
Existing fields are unchanged for compatibility.

### Menu deduplication

A menu item with the same label and menu hierarchy as a discovered link is
validated once, through its link.

### Traffic class

Each API inventory entry has a `traffic_class`, derived from metadata only:

- `AUTHENTICATION`
- `BUSINESS_API`
- `CONFIGURATION_BOOTSTRAP`
- `STATIC_ASSET`
- `THIRD_PARTY_DEPENDENCY` (out-of-scope hosts, telemetry and challenges)
- `UNKNOWN`

### Security recommendations

Each recommendation now has:

- a title and a risk level;
- evidence and an explanation;
- remediation and the affected resources;
- confidence and the validation limitation.

All of them are labelled as hardening recommendations, not observed
vulnerabilities.

### Dashboard

- A route-coverage funnel (Discovered → Visited → Rendered → Validated →
  Healthy) with clickable state filters.
- An identity-host callout with *Add to Authentication hosts* and *Add and
  run again*.
- Grouped diagnostic cards.
- A Route state column and a Traffic class column.
- Richer security cards.
- A modern visual layer (`app/static/modern.css`): readable type, sticky
  table headers and identity columns, striped rows, status chips, and
  example placeholders that cannot be mistaken for configured values.

## Using it with an SSO portal

Add the identity provider hosts reported under *Sign-in blocked* to
*Authentication hosts*, or use *Add and run again*. In the scan that
prompted this release those were the SAML identity host and the OAuth token
host. Only approve hosts you trust as the portal's identity provider. Other
destinations and every non-authentication mutation remain blocked.

## Tests

- `tests/test_route_sso_roundtrip.py`. Two of these tests fail on 1.13.3.
  - **Approved identity host:** every microfrontend SAML round trip
    validates, with no suggested hosts.
  - **Unapproved identity host:** only the SSO routes are
    `AUTHENTICATION_BLOCKED`, with grouped diagnostics, the suggested host
    and route states.
  - **Duplicate menu entry:** an entry rendered as both a link and a menu
    item is validated once.
- `tests/ui_check.py` covers:
  - the route-state funnel;
  - the identity-host callout and one-click approval;
  - grouped diagnostics;
  - the new table columns.
