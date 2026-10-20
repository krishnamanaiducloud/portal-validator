# Portal Validator 1.13.7 — linked pages, notifications and profile views

## Linked pages no longer time out

When a readiness selector or event is configured, it describes the
application shell. A hyperlink to a separately loaded page outside that shell
never shows it. Examples are help, documentation, release notes, legal pages
or another in-scope site. Such routes used to wait for the selector until the
route's time budget ran out, and then failed with "Configured maximum time
per route exceeded".

A page now counts as a linked document when all of the following hold:

- it is a newly loaded document, after the application shell was proven;
- it rendered meaningful, stable content with no busy indicators;
- it never showed the configured condition for the **Linked page grace**
  period (default 2000 ms).

Such a page is validated as a linked document. Its settle reason is
`LINKED_DOCUMENT_RENDERED`, and the report records `application_readiness:
LINKED_DOCUMENT` so it stays distinguishable from pages that showed the shell
marker. Load time excludes the grace wait.

The grace period is configurable under *Route identity controls*. Setting it
to `0` restores strict behaviour, where every page must show the configured
condition. Same-document views of the application and the first
(authentication-gate) route always require the configured condition.

## Notification, profile and other header popovers are validated

Popup controls outside the primary navigation are now validated as views.
Examples are a notification bell, a profile or avatar menu showing the
signed-in user, and help or app-switcher buttons. Each must use
`aria-haspopup` or `aria-expanded` and control a panel through
`aria-controls` (or a `data-bs-target`/`data-target`/`#id` reference).

Validation opens the panel, waits for its own content to render, and
attributes the panel's API calls, such as notifications or user identity, to
that view. These controls appear with discovery source `ui-popover`.

- Header popovers are shared, so each is validated once per scan. Enable
  *Re-explore on every route* to validate them on every route.
- Links inside the panels (for example *My profile*) are still discovered
  and validated as their own routes.
- A popover already left open, for example by menu exploration, is toggled
  closed first so its load is observed. If it will not close, it is
  validated as it is, instead of waiting for the route timeout.
- Popovers opened by the validator are closed again before the next route,
  so an open overlay cannot cover the next control.
- Dropdowns inside the primary navigation (`nav`, `role="navigation"`,
  menubars, menus, trees, `aside`) are still explored for links only.
- Labels such as *Sign out*, *Delete* or *Submit* are never activated, and
  all requests remain under the read-only network policy.
