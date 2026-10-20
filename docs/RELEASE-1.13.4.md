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

## Generic validation of any website

The validator contains no organization-, portal-, identity-provider- or
cluster-specific values. Real public scans run with default settings and no
authentication:

| Site | Result |
|---|---|
| python.org | 15 routes visited, 13 validated and healthy. *Sign In* and *Sign Up* were reported as authentication-required routes and the scan continued. |
| developer.mozilla.org | 15 of 15 routes validated and healthy. |
| udemy.com | Its bot protection served a challenge (HTTP 403) to the automated browser. Reported as `CHALLENGE_REQUIRED`; nothing was bypassed. |

Fixes found by these scans:

- **Public scans and login-only pages.** On a public scan
  (`authentication.mode=none`), a login-required page or a 401 after the site
  is ready is a result for that route only. It no longer triggers session
  recovery, stops discovery, or ends the scan as `SESSION_EXPIRED`. Public
  scans report `authentication_status=NOT_REQUIRED` instead of
  `AUTHENTICATED`.
- **Bot-protection challenges.** A blocking status (403, 429 or 503) whose URL
  carries a generic challenge parameter (`__cf_chl_rt_tk`, `__cf_chl_tk`,
  `challenge_token`, `captcha_token`) is classified as `CHALLENGE_REQUIRED`.
  The remediation asks the site owner to allow the validator. The dashboard's
  failure heading now names the actual cause (challenge, access denied,
  unreachable site, TLS failure, application not ready), not always
  "Authentication failed".
- **Unclickable link controls.** A link control that never becomes clickable
  (covered, collapsed or off screen) no longer fails its route with a timeout.
  The click was never dispatched, so the guarded read-only fallbacks are used.
  The hard-coded 5-second click limits are replaced by limits derived from the
  configured timeouts.
- **Corporate CA directory.** The vendor-specific default directory name is
  replaced by a generic one; see the migration below.

## Migration: corporate CA directory

The default corporate CA directory is now `/etc/portal-validator/corporate-ca`.
The example OpenShift manifest mounts a ConfigMap named
`portal-validator-corporate-ca` there.

If you mount CA certificates at the previous default path without setting
`PORTAL_VALIDATOR_ADDITIONAL_CA_DIRS`, do one of the following:

- mount them at the new path; or
- set `PORTAL_VALIDATOR_ADDITIONAL_CA_DIRS` and
  `PORTAL_VALIDATOR_BROWSER_CA_DIRS` to your existing directory.

A configured directory that is missing still fails closed.

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

## Verification

- Host suite (WSL2, Python 3.14): 1197 passed. The one failing safety test
  (a dispatched click must never be retried) led to the trial-click design.
  It passes now, together with 79 navigation, discovery, challenge and SSO
  tests. Frontend `tests/ui_check.py` passed.
- Debug image (Python 3.15, arbitrary UID, read-only root, all capabilities
  dropped): 219 of 219 tests passed, covering SSO round trips, challenges,
  navigation safety, session recovery and renewal, authentication-first,
  public access, SSO, UI views, broad discovery, trust, health and the app.
- `tests/release_image_smoke.py` passed for both images.
- Real public scans with the final code are listed under *Generic validation
  of any website* above.

## Published images

Built from commit `7924f035f2a9b2852c355e763fae15cc3d9122e3` for
`linux/amd64`. Later commits change documentation and the Deployment
reference only.

| Image | Digest | Compressed size |
|---|---|---|
| `docker.io/mohankrishna999/portal-validator:1.13.4` | `sha256:e63a38154e24c49fecfde3e2632ac7c06389d3a672db20f89b99e728d2a624dd` | 503.7 MB |
| `docker.io/mohankrishna999/portal-validator:1.13.4-debug` | `sha256:e646fb5dec1d2c9420716a1b7ce4b517db36c5fbb505874deee2c832957840e1` | 527.3 MB |

Both digests were confirmed from the registry. Each image was pulled by digest
and reported version 1.13.4, the commit above and `VERIFIED` source integrity.
`openshift/deployment.yaml` pins the production image by tag and digest. No
cluster rollout was performed.

## Security scan results

Trivy 0.72.0 (DB 2026-10-19 19:08 UTC) and Grype 0.104.0 (DB 2026-10-19 06:39
UTC):

| Check | `1.13.4` | `1.13.4-debug` |
|---|---|---|
| Trivy Critical/High/Medium/Low | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| Trivy secrets | 0 | 0 |
| Grype Critical/High/Medium/Low | 0 / 0 / 3 / 0 | 0 / 0 / 3 / 0 |
| SBOM packages (SPDX) | 121 | 172 |

The three Grype findings are the unchanged, still-unfixed `alsa-lib
1.2.16.1-r3` CVEs, carried forward under the exception documented in
`docs/RELEASE-1.13.0.md`.
