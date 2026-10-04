from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


DOCUMENT_NAVIGATION = "DOCUMENT_NAVIGATION"
SPA_ROUTE_TRANSITION = "SPA_ROUTE_TRANSITION"
HASH_ROUTE_TRANSITION = "HASH_ROUTE_TRANSITION"
SAFE_CLICK_NAVIGATION = "SAFE_CLICK_NAVIGATION"
SAME_DOCUMENT_NAVIGATIONS = frozenset({
    SPA_ROUTE_TRANSITION,
    HASH_ROUTE_TRANSITION,
    SAFE_CLICK_NAVIGATION,
})


TRACKING_QUERY_PREFIXES = ("utm_",)
TRACKING_QUERY_KEYS = frozenset({
    "dclid", "fbclid", "gclid", "mc_cid", "mc_eid", "msclkid", "ref", "source",
})
SENSITIVE_QUERY_KEYS = frozenset({
    "access_token", "authorization", "code", "id_token", "relaystate", "samlrequest",
    "samlresponse", "session", "state", "token",
})
DANGEROUS_CONTROL_WORDS = frozenset({
    "approve", "buy", "cancel", "checkout", "confirm", "create", "delete", "deploy",
    "destroy", "disable", "enable", "logout", "pay", "purchase", "reboot", "remove",
    "restart", "save", "sign out", "signout", "submit", "terminate", "update",
})


@dataclass(frozen=True)
class DiscoveredRoute:
    url: str
    label: str
    source: str
    navigation_mode: str = DOCUMENT_NAVIGATION


def navigation_mode_for_route(url: str, source: str, document_url: str) -> str:
    """Classify route execution without broadening the portal crawl boundary."""
    try:
        candidate = urlsplit(url)
        document = urlsplit(document_url)
    except ValueError:
        return DOCUMENT_NAVIGATION
    same_document = (
        candidate.scheme.lower(),
        (candidate.hostname or "").rstrip(".").lower(),
        candidate.port,
        candidate.path or "/",
        candidate.query,
    ) == (
        document.scheme.lower(),
        (document.hostname or "").rstrip(".").lower(),
        document.port,
        document.path or "/",
        document.query,
    )
    if same_document and candidate.fragment != document.fragment:
        return HASH_ROUTE_TRANSITION
    if source == "safe-click":
        return SAFE_CLICK_NAVIGATION
    if source == "browser-history":
        return SPA_ROUTE_TRANSITION
    return DOCUMENT_NAVIGATION


def normalize_route_url(
    value: str,
    *,
    base_url: str | None = None,
    query_policy: str = "ignore",
    allowed_query_parameters: set[str] | None = None,
) -> str | None:
    """Return a deterministic HTTP(S) route identity without auth/tracking secrets."""
    try:
        parsed = urlsplit(urljoin(base_url or value, value))
        hostname = (parsed.hostname or "").strip().rstrip(".").lower()
        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    host_netloc = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host_netloc
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{host_netloc}:{port}"

    allowed = {item.lower() for item in (allowed_query_parameters or set())}
    query_items: list[tuple[str, str]] = []
    if query_policy != "ignore":
        for key, item_value in parse_qsl(parsed.query, keep_blank_values=True):
            lowered = key.lower()
            if (
                lowered in SENSITIVE_QUERY_KEYS
                or lowered in TRACKING_QUERY_KEYS
                or lowered.startswith(TRACKING_QUERY_PREFIXES)
            ):
                continue
            if query_policy == "allowlist" and lowered not in allowed:
                continue
            query_items.append((key, item_value))
    query = urlencode(sorted(query_items), doseq=True)

    fragment = parsed.fragment
    if not (fragment.startswith("/") or fragment.startswith("!/")):
        fragment = ""
    elif any(f"{key}=" in fragment.lower() for key in SENSITIVE_QUERY_KEYS):
        fragment = ""
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, query, fragment))


def safe_navigation_control(attributes: dict[str, str | None]) -> bool:
    """Conservatively identify a non-form menu/tab expander safe to activate."""
    if attributes.get("inside_form") == "true" or attributes.get("disabled") == "true":
        return False
    if attributes.get("href"):
        return False
    label = " ".join(filter(None, (
        attributes.get("text"), attributes.get("aria_label"), attributes.get("title"),
    ))).strip().lower()
    if any(word in label for word in DANGEROUS_CONTROL_WORDS):
        return False
    role = (attributes.get("role") or "").lower()
    expanded = (attributes.get("aria_expanded") or "").lower()
    selected = (attributes.get("aria_selected") or "").lower()
    has_controls = bool(attributes.get("aria_controls"))
    return bool(
        (has_controls and expanded == "false")
        or (role == "tab" and has_controls and selected == "false")
        or (attributes.get("aria_haspopup") == "menu" and expanded == "false")
    )


ROUTE_OBSERVER_SCRIPT = r"""
(() => {
  if (window.__portalValidatorRouteObserverInstalled) return;
  window.__portalValidatorRouteObserverInstalled = true;
  window.__portalValidatorObservedRoutes = [{url: window.location.href, mode: 'document'}];
  const remember = (mode) => {
    const value = window.location.href;
    if (!window.__portalValidatorObservedRoutes.some(item => item.url === value)) {
      window.__portalValidatorObservedRoutes.push({url: value, mode});
    }
  };
  for (const method of ['pushState', 'replaceState']) {
    const original = history[method];
    history[method] = function(...args) {
      const result = original.apply(this, args);
      remember('history');
      return result;
    };
  }
  window.addEventListener('popstate', () => remember('history'));
  window.addEventListener('hashchange', () => remember('hash'));
})();
"""


DISCOVER_ROUTES_SCRIPT = r"""
() => {
  const values = [];
  const seen = new Set();
  const selectors = [
    'a[href]', 'area[href]', '[role="link"][href]', '[role="link"][data-href]',
    'nav [data-url]', '[role="navigation"] [data-url]', '[role="menuitem"][data-href]',
    '[role="tab"][data-href]'
  ];
  for (const element of document.querySelectorAll(selectors.join(','))) {
    const raw = element.getAttribute('href') || element.getAttribute('data-href') ||
      element.getAttribute('data-url');
    if (!raw) continue;
    let url;
    try { url = new URL(raw, document.baseURI).href; } catch (_) { continue; }
    if (seen.has(url)) continue;
    seen.add(url);
    const label = (element.getAttribute('aria-label') || element.textContent ||
      element.getAttribute('title') || '').replace(/\s+/g, ' ').trim().slice(0, 160);
    values.push({url, label, source: element.getAttribute('role') || element.tagName.toLowerCase()});
  }
  for (const observed of (window.__portalValidatorObservedRoutes || [])) {
    const url = typeof observed === 'string' ? observed : observed.url;
    if (!url) continue;
    if (!seen.has(url)) {
      seen.add(url);
      values.push({url, label: '', source: 'browser-history', observerMode: observed.mode || 'history'});
    }
  }
  return values;
}
"""


EXPAND_SAFE_NAVIGATION_SCRIPT = r"""
(maximum) => {
  const dangerous = new Set([
    'approve','buy','cancel','checkout','confirm','create','delete','deploy','destroy','disable',
    'enable','logout','pay','purchase','reboot','remove','restart','save','sign out','signout',
    'submit','terminate','update'
  ]);
  const controls = Array.from(document.querySelectorAll([
    'nav [aria-expanded="false"][aria-controls]',
    '[role="navigation"] [aria-expanded="false"][aria-controls]',
    '[role="menu"] [aria-expanded="false"][aria-controls]',
    'aside [aria-expanded="false"][aria-controls]',
    '[role="tab"][aria-selected="false"][aria-controls]',
    '[aria-haspopup="menu"][aria-expanded="false"]'
  ].join(',')));
  let activated = 0;
  let skipped = 0;
  const transitions = [];
  for (const element of controls) {
    if (activated >= maximum) break;
    const label = (element.getAttribute('aria-label') || element.textContent ||
      element.getAttribute('title') || '').replace(/\s+/g, ' ').trim().toLowerCase();
    const unsafe = element.closest('form') || element.hasAttribute('disabled') ||
      element.getAttribute('aria-disabled') === 'true' || element.hasAttribute('href') ||
      Array.from(dangerous).some(word => label.includes(word));
    if (unsafe) { skipped += 1; continue; }
    const before = window.location.href;
    element.click();
    const after = window.location.href;
    if (after !== before) {
      transitions.push({
        url: after,
        label: label.slice(0, 160),
        source: 'safe-click'
      });
    }
    activated += 1;
  }
  return {activated, skipped, transitions};
}
"""


SAME_DOCUMENT_TRANSITION_SCRIPT = r"""
({target, mode}) => {
  const destination = new URL(target, window.location.href);
  if (destination.origin !== window.location.origin) return false;
  if (mode === 'HASH_ROUTE_TRANSITION') {
    const previous = window.location.href;
    history.pushState(
      history.state,
      '',
      `${destination.pathname}${destination.search}${destination.hash}`
    );
    window.dispatchEvent(new HashChangeEvent('hashchange', {
      oldURL: previous,
      newURL: destination.href
    }));
    return true;
  }
  history.pushState(history.state, '', destination.href);
  window.dispatchEvent(new PopStateEvent('popstate', {state: history.state}));
  return true;
}
"""


async def expand_safe_navigation(page, maximum: int) -> dict[str, object]:
    result = await page.evaluate(EXPAND_SAFE_NAVIGATION_SCRIPT, maximum)
    return {
        "activated": int(result.get("activated", 0)),
        "skipped": int(result.get("skipped", 0)),
        "routes": [
            DiscoveredRoute(
                url=item["url"],
                label=str(item.get("label") or "")[:160],
                source="safe-click",
                navigation_mode=SAFE_CLICK_NAVIGATION,
            )
            for item in result.get("transitions", [])
            if isinstance(item, dict) and isinstance(item.get("url"), str)
        ],
    }


async def discover_page_routes(page) -> list[DiscoveredRoute]:
    raw = await page.evaluate(DISCOVER_ROUTES_SCRIPT)
    document_url = page.url
    routes: list[DiscoveredRoute] = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            continue
        routes.append(DiscoveredRoute(
            url=item["url"],
            label=str(item.get("label") or "")[:160],
            source=str(item.get("source") or "semantic")[:64],
            navigation_mode=(
                HASH_ROUTE_TRANSITION
                if item.get("observerMode") == "hash"
                else navigation_mode_for_route(
                    item["url"],
                    str(item.get("source") or "semantic"),
                    document_url,
                )
            ),
        ))
    return routes


async def perform_route_navigation(page, url: str, mode: str, timeout_ms: int):
    """Navigate a document or transition an existing SPA document.

    Playwright correctly returns no Response for same-document transitions; callers use
    the returned boolean as the navigation signal instead of fabricating an HTTP result.
    """
    if mode == DOCUMENT_NAVIGATION:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        if response is None:
            raise RuntimeError("Document navigation completed without an HTTP response")
        return response, False
    if mode not in SAME_DOCUMENT_NAVIGATIONS:
        raise RuntimeError("Unsupported navigation mode")
    transitioned = await page.evaluate(
        SAME_DOCUMENT_TRANSITION_SCRIPT,
        {"target": url, "mode": mode},
    )
    if not transitioned:
        raise RuntimeError("Same-document route transition crossed an origin boundary")
    try:
        await page.wait_for_function(
            "target => window.location.href === target",
            arg=url,
            timeout=timeout_ms,
        )
    except Exception as exc:
        raise RuntimeError("Same-document route transition did not reach the requested route") from exc
    if page.is_closed():
        raise RuntimeError("Browser page closed during same-document route transition")
    return None, True
