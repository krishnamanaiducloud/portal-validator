# Portal Validator 1.14.0 — fast, fully configurable scanning

## Problems addressed

- Scans of large authenticated portals were slow.
- Some routes failed with "Configured maximum time per route exceeded".
- Not every route was discovered.
- Several scan limits were hard-capped in the API model, the discovery code and
  the dashboard markup.

## Root causes

- **Shared menus re-explored on every route.** Discovery reopened every header,
  navigation and sidebar menu on every validated route. After each click it
  waited a full route settle (minimum observation plus render stability
  window). A global navigation tree of 20 menus cost roughly 25 seconds per
  route.
- **Discovery used the route's validation budget.** Discovery ran inside the
  remaining time of the validated route, so large menu trees were cut short
  and their routes were never queued.
- **Polling applications never went network-quiet.** Render settling waited
  for zero pending requests. An application that polls continuously consumed
  its whole readiness budget, and the remaining checks then exceeded the route
  timeout.
- **Hard caps.**
  - API model: 1,500 routes, depth 10, 120 s per-phase timeouts, a 15 min
    total scan, 1,500 navigation actions, 20 scrolls, 5 s render settle, and
    25/50/100-item host and operation lists.
  - Discovery code: the same 1,500-action and 20-scroll caps again.
  - Real-control route activation searched only the first 500 links of a page.
  - Dashboard: matching `max` attributes, and the render-settle setting was a
    fixed list.

## Changes

- **Shared menus are explored once per scan.** Each navigation control in
  shared application chrome gets a signature: its menu ancestry and label,
  independent of the current URL. Shared chrome means a header, `nav`, `aside`,
  `role=navigation`/`banner`/`menubar`/`menu`, or a CDK or Bootstrap overlay.
  Once a control has been explored, later routes skip it. Its routes are
  already queued, together with the menu ancestry needed to reopen them.
  Page-local menus are still explored on every route. *Re-explore shared menus
  on every route* restores the previous behaviour for menus whose content
  differs per route.
- **Discovery has its own budget** (`discovery_timeout_ms`; it inherits the
  navigation or route timeout). It starts after the route has been validated,
  so discovery can no longer make a healthy route time out.
- **Network settle cap** (`network_settle_cap_ms`, default 2000). Once a view
  is rendered and its DOM is stable, settling stops waiting for network quiet
  after this long and records `DOM_STABLE_NETWORK_ACTIVE`. `0` keeps waiting
  for quiet until the readiness budget is used.
- **Menu settle** (`menu_settle_ms`, default 250) is the observation after
  each menu click during discovery. It replaces the full route settle.
- **No policy caps.** Counts have only a lower bound. Millisecond settings are
  bounded only by the browser timer limit (2,147,483,647 ms); larger
  `setTimeout` values overflow. Host and operation lists are unbounded.
  Concurrency remains bounded by the deployment's `MAX_CONCURRENT_SCANS`.
- **Every setting is configurable in the dashboard.** New inputs: discovery
  timeout, network settle cap, menu settle, the re-explore toggle and a numeric
  render-settle window. The dashboard reads defaults and bounds from the new
  `GET /api/scan-settings` endpoint instead of hard-coding them.

## Changed defaults

| Setting | 1.13.0 | 1.14.0 |
|---|---|---|
| Maximum routes (`max_pages`) | 50 | 500 |
| Maximum depth | 3 | 10 |
| Safe navigation actions | 20 | 200 |
| Total scan time | 300,000 ms | 1,800,000 ms |
| Render stability window | 750 ms | 400 ms |
| Minimum observation | 500 ms | 300 ms |
| Network settle cap | — | 2,000 ms |
| Menu settle | — | 250 ms |

All defaults remain overridable per scan. Safety controls are unchanged: read-only
request policy, SSRF/DNS checks, TLS verification, authentication host approval and
the authentication-first gate.

## Measured effect

On the synthetic authenticated 44-view portal (`tests/test_broad_authenticated_discovery.py`,
WSL2 host), with the same 44 views discovered and validated in every run:

| Configuration | Total scan | Discovery time |
|---|---|---|
| 1.13.0 defaults | 84 s | 31.7 s |
| 1.14.0 defaults, re-explore enabled | 66 s | 29.3 s |
| 1.14.0 defaults | 50 s | 11.1 s |

The fixture has only five shared menus. Portals with larger navigation trees, or
that poll continuously, gain proportionally more, because the per-route menu
re-expansion and the full-budget settle wait are removed. The full test suite ran
in 16.5 minutes instead of 38.

## Tests

- `tests/test_scan_speed.py` covers the following:
  - a polling view settles at the network cap instead of the route timeout;
  - a zero cap preserves the bounded wait;
  - each shared header menu is opened exactly once per scan, and on every
    route when re-exploration is enabled;
  - very large settings are accepted, values above the browser timer limit
    are rejected, and `/api/scan-settings` serves the bounds.
- Updated tests that pinned the old caps and defaults:
  - `test_authentication.py`
  - `test_browser_lifecycle.py`
  - `test_execution_evidence.py`
  - `test_authenticated_spa.py`
  - `ui_check.py`
