from __future__ import annotations

import asyncio
import re
import hashlib
import json
from collections.abc import Awaitable, Callable
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit


DOCUMENT_NAVIGATION = "DOCUMENT_NAVIGATION"
SEMANTIC_LINK_NAVIGATION = "SEMANTIC_LINK_NAVIGATION"
POPUP_NAVIGATION = "POPUP_NAVIGATION"
SPA_ROUTE_TRANSITION = "SPA_ROUTE_TRANSITION"
HASH_ROUTE_TRANSITION = "HASH_ROUTE_TRANSITION"
SAFE_CLICK_NAVIGATION = "SAFE_CLICK_NAVIGATION"
UI_VIEW_ACTIVATION = "UI_VIEW_ACTIVATION"
DOWNLOAD_OBSERVED = "DOWNLOAD_OBSERVED"
ANCHOR = "ANCHOR"
HISTORY_ROUTE_TRANSITION = "HISTORY_ROUTE_TRANSITION"
MENU_ITEM = "MENU_ITEM"
TAB = "TAB"
DOCUMENT_NAVIGATIONS = frozenset({
    DOCUMENT_NAVIGATION,
    SEMANTIC_LINK_NAVIGATION,
    POPUP_NAVIGATION,
})
SAME_DOCUMENT_NAVIGATIONS = frozenset({
    SPA_ROUTE_TRANSITION,
    HASH_ROUTE_TRANSITION,
    SAFE_CLICK_NAVIGATION,
    UI_VIEW_ACTIVATION,
})
NON_DOCUMENT_EXTENSIONS = frozenset({
    ".json", ".jsonl", ".map", ".js", ".mjs", ".cjs", ".css", ".xml",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".wasm", ".pdf",
    ".zip", ".gz", ".tar", ".mp3", ".mp4", ".webm", ".csv",
})


def context_replacement_error(error: Exception) -> bool:
    """Recognize transient document replacement, not arbitrary browser failures."""
    message = str(error).lower()
    return any(value in message for value in (
        "execution context was destroyed", "cannot find context with specified id",
        "cannot find execution context", "execution context is not available in detached frame",
    ))


async def retry_dom_operation(
    target,
    operation: Callable[[], Awaitable[Any]],
    *,
    timeout_ms: int = 5000,
    attempts: int = 3,
) -> Any:
    """Retry read-only DOM inspection across bounded document replacements.

    Never use this for a click, form submission, history mutation or request:
    an interrupted browser response does not prove an action was not dispatched.
    The caller's route/scan deadline remains authoritative.
    """
    async with asyncio.timeout(max(1, timeout_ms) / 1000):
        for attempt in range(max(1, min(attempts, 5))):
            try:
                return await operation()
            except Exception as error:
                if not context_replacement_error(error) or attempt + 1 >= max(1, min(attempts, 5)):
                    raise
                # DOMContentLoaded is intentionally used instead of networkidle:
                # authenticated SPAs may poll or hold long-lived connections.
                await target.wait_for_load_state("domcontentloaded", timeout=max(1, timeout_ms))
                await asyncio.sleep(0.05)


async def evaluate_dom(
    target, script: str, argument: Any = None, *, handle: bool = False,
    timeout_ms: int = 5000, attempts: int = 3,
) -> Any:
    method = target.evaluate_handle if handle else target.evaluate
    return await retry_dom_operation(
        target, lambda: method(script) if argument is None else method(script, argument),
        timeout_ms=timeout_ms, attempts=attempts,
    )


def is_document_route_candidate(url: str) -> bool:
    """Exclude explicit resource links, not speculative API/path-name matches."""
    path = unquote(urlsplit(url).path).rstrip("/").lower()
    return not any(path.endswith(extension) for extension in NON_DOCUMENT_EXTENSIONS)


TRACKING_QUERY_PREFIXES = ("utm_",)
TRACKING_QUERY_KEYS = frozenset({
    "dclid", "fbclid", "gclid", "mc_cid", "mc_eid", "msclkid", "ref", "source",
})
SENSITIVE_QUERY_KEYS = frozenset({
    "access_token", "api_key", "apikey", "assertion", "authorization",
    "authorization_code", "client_secret", "code", "code_challenge", "code_verifier",
    "id_token", "key", "password", "passwd", "refresh_token", "relaystate",
    "samlrequest", "samlresponse", "secret", "session", "session_id", "state", "token",
    "__cf_chl_rt_tk", "__cf_chl_tk", "challenge_token", "captcha_token",
})
DANGEROUS_CONTROL_WORDS = frozenset({
    "add", "approve", "begin", "buy", "cancel", "checkout", "confirm", "create", "delete",
    "deploy", "destroy", "disable", "edit", "enable", "execute", "export", "import",
    "logout", "pay", "purchase", "reboot", "reject", "remove", "restart", "save",
    "send", "sign out", "signout", "start", "stop", "submit", "terminate", "update",
    "upload",
})


@dataclass(frozen=True)
class DiscoveredRoute:
    url: str
    label: str
    source: str
    navigation_mode: str = DOCUMENT_NAVIGATION
    discovery_type: str = ANCHOR
    label_source: str | None = None
    accessible_name: str | None = None
    view_control: dict[str, str] | None = None
    navigation_hierarchy: tuple[str, ...] = ()
    # Scan-local lookup only: never serialize a browser handle or profile state.
    browser_page_key: str | None = None
    opener_route_id: str | None = None


def discovered_route_key(route: DiscoveredRoute, canonical_url: str) -> str:
    """Keep a real URL separate from a UI panel's non-URL coverage identity."""
    if route.view_control:
        panel = route.view_control.get("identity") or route.view_control["panel"]
        scope = route.view_control.get("scope", "")
        control_identity = f"{scope}\0{panel}" if scope else panel
        digest = hashlib.sha256(f"{canonical_url}\0{control_identity}".encode()).hexdigest()[:24]
        return f"UI_VIEW_{digest}"
    return canonical_url


def dangerous_control_label(label: str) -> bool:
    # Whole action words/phrases, not 'add' in Address or 'edit' in Credit.
    # Accessible names can be identifier-style (DeleteAccount/DELETEAccount).
    # Preserve their word boundaries before lowercasing for token matching.
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", label)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", separated)
    normalized = " " + " ".join(re.findall(r"[a-z0-9]+", separated.lower())) + " "
    return any(f" {word} " in normalized for word in DANGEROUS_CONTROL_WORDS)


GENERIC_ROUTE_LABELS = frozenset({
    "discovered route", "new window", "requested route", "route", "unnamed route",
})
GENERIC_DOCUMENT_TITLES = frozenset({
    "application", "dashboard", "home", "portal", "web application",
})


def route_identity_fields(
    value: str,
    *,
    query_policy: str = "ignore",
    allowed_query_parameters: set[str] | None = None,
) -> dict[str, str | None]:
    """Return safe, fragment-aware route identity fields for reports and UI."""
    canonical = normalize_route_url(
        value,
        query_policy=query_policy,
        allowed_query_parameters=allowed_query_parameters,
    ) or value
    parsed = urlsplit(canonical)
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    spa_route = fragment if parsed.fragment.startswith(("/", "!/")) else None
    query = f"?{parsed.query}" if parsed.query else ""
    path = parsed.path or "/"
    display_path = spa_route or f"{path}{query}"
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return {
        "origin": origin,
        "host": (parsed.hostname or "").rstrip(".").lower(),
        "pathname": path,
        "query_sanitized": query,
        "fragment": fragment,
        "spa_route": spa_route,
        "canonical_route": canonical,
        "display_path": display_path,
    }


def humanize_route_path(display_path: str | None) -> str | None:
    candidate = str(display_path or "").split("?", 1)[0].rstrip("/")
    candidate = candidate.removeprefix("#!").removeprefix("#")
    segment = unquote(candidate.rsplit("/", 1)[-1]).strip()
    if not segment:
        return None
    value = re.sub(r"[-_.]+", " ", segment)
    value = re.sub(r"\s+", " ", value).strip()
    return value.title()[:160] or None


def resolve_route_name(
    *,
    navigation_label: str | None,
    accessible_name: str | None,
    primary_heading: str | None,
    breadcrumb: str | None,
    metadata_name: str | None,
    document_title: str | None,
    display_path: str | None,
) -> tuple[str, str, str]:
    """Choose a deterministic name without letting generic titles erase route identity."""
    ranked = (
        (navigation_label, "NAVIGATION_LABEL", "HIGH"),
        (accessible_name, "ACCESSIBLE_NAME", "HIGH"),
        (primary_heading, "PRIMARY_HEADING", "HIGH"),
        (breadcrumb, "BREADCRUMB", "MEDIUM"),
        (metadata_name, "ROUTE_METADATA", "MEDIUM"),
    )
    for value, source, confidence in ranked:
        cleaned = str(value or "").strip()
        if cleaned and cleaned.casefold() not in GENERIC_ROUTE_LABELS:
            return cleaned[:160], source, confidence
    title = str(document_title or "").strip()
    if title and title.casefold() not in GENERIC_DOCUMENT_TITLES:
        return title[:160], "DOCUMENT_TITLE", "LOW"
    route_name = humanize_route_path(display_path)
    if route_name:
        return route_name, "ROUTE_SEGMENT", "MEDIUM"
    if title:
        return title[:160], "DOCUMENT_TITLE", "LOW"
    return "Unnamed route", "FALLBACK", "LOW"


def finalize_duplicate_route_names(results: list[dict[str, Any]]) -> None:
    """Replace repeated generic document-title names with meaningful route segments."""
    title_counts = Counter(
        str(item.get("document_title") or "").strip().casefold()
        for item in results
        if item.get("document_title")
    )
    for item in results:
        title_key = str(item.get("document_title") or "").strip().casefold()
        if item.get("route_name_source") != "DOCUMENT_TITLE" or title_counts[title_key] < 2:
            continue
        fallback = humanize_route_path(item.get("display_path"))
        if fallback:
            item.update(
                route_name=fallback,
                route_name_source="ROUTE_SEGMENT",
                route_name_confidence="MEDIUM",
            )


ROUTE_NAME_EVIDENCE_SCRIPT = r"""
() => {
  const visibleText = (selector) => {
    for (const element of document.querySelectorAll(selector)) {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      if (style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0) {
        const text = (element.textContent || '').replace(/\s+/g, ' ').trim();
        if (text) return text.slice(0, 160);
      }
    }
    return '';
  };
  return {
    primaryHeading: visibleText('main h1, [role="main"] h1, h1'),
    breadcrumb: visibleText('[aria-current="page"], nav[aria-label*="breadcrumb" i] li:last-child, [role="navigation"][aria-label*="breadcrumb" i] li:last-child'),
  };
}
"""


async def collect_route_name_evidence(page) -> dict[str, str]:
    result = await evaluate_dom(page, ROUTE_NAME_EVIDENCE_SCRIPT)
    return {
        "primary_heading": str(result.get("primaryHeading") or "")[:160],
        "breadcrumb": str(result.get("breadcrumb") or "")[:160],
    }


def discovery_type_for(source: str, navigation_mode: str) -> str:
    normalized = source.lower()
    if navigation_mode == HASH_ROUTE_TRANSITION:
        return HASH_ROUTE_TRANSITION
    if source == "browser-history":
        return HISTORY_ROUTE_TRANSITION
    if source == "safe-click":
        return "SAFE_CLICK"
    if normalized == "tab":
        return TAB
    if normalized == "menuitem":
        return MENU_ITEM
    if source == "popup":
        return POPUP_NAVIGATION
    return ANCHOR


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
    if source == "popup":
        return POPUP_NAVIGATION
    return SEMANTIC_LINK_NAVIGATION


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
    else:
        fragment_path, separator, fragment_query = fragment.partition("?")
        fragment_items: list[tuple[str, str]] = []
        if separator and query_policy != "ignore":
            for key, item_value in parse_qsl(fragment_query, keep_blank_values=True):
                lowered = key.lower()
                if (
                    lowered in SENSITIVE_QUERY_KEYS
                    or lowered in TRACKING_QUERY_KEYS
                    or lowered.startswith(TRACKING_QUERY_PREFIXES)
                ):
                    continue
                if query_policy == "allowlist" and lowered not in allowed:
                    continue
                fragment_items.append((key, item_value))
        fragment = fragment_path
        sanitized_fragment_query = urlencode(sorted(fragment_items), doseq=True)
        if sanitized_fragment_query:
            fragment = f"{fragment}?{sanitized_fragment_query}"
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
    ))).strip()
    if dangerous_control_label(label):
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


# Keep collection and activation on the same DOM contract. Returning an actual
# element handle avoids relying on CSS locator ordering across open shadow roots.
NAVIGATION_DOM_HELPERS = r"""
  const routeSelector = [
    'a[href]', 'area[href]', '[role="link"][href]', '[data-href]',
    '[data-url]', '[data-route]', '[routerlink]', '[ng-reflect-router-link]'
  ].join(',');
  const viewSelector = [
    '[role="tab"]', '[data-bs-toggle="tab"]', '[data-toggle="tab"]',
    '[data-tab-target]', '[data-bs-target]', '[data-target]',
    '[role="menuitem"]', '[role="link"]', 'button', '[role="button"]', 'nav button',
    '[role="navigation"] button', 'nav [aria-controls]',
    '[role="navigation"] [aria-controls]', '[role="navigation"] [role="button"]',
    'mat-nav-list mat-list-item', 'mat-nav-list [mat-list-item]'
  ].join(',');
  const navigationRoots = () => {
    const values = [document];
    for (let i = 0; i < values.length; i++) {
      for (const element of values[i].querySelectorAll('*')) {
        if (element.shadowRoot) values.push(element.shadowRoot);
      }
    }
    return values;
  };
  const rootScope = root => {
    const parts = [];
    while (root.host) {
      const host = root.host;
      const siblings = Array.from(host.parentNode?.children || []).filter(e => e.tagName === host.tagName);
      parts.unshift(host.tagName.toLowerCase() + ':' + siblings.indexOf(host) +
        (host.getAttribute('aria-label') ? '[' + host.getAttribute('aria-label') + ']' : ''));
      root = host.getRootNode();
    }
    return parts.join('/');
  };
  const controlLabel = element => (element.getAttribute('aria-label') ||
    element.textContent || element.getAttribute('title') || '').replace(/\s+/g, ' ').trim().slice(0,160);
  const composedClosest = (element, selector) => {
    for (let cursor = element; cursor; cursor = cursor.getRootNode().host) {
      const found = cursor.closest(selector);
      if (found) return found;
    }
    return null;
  };
  const isNavigationControl = element => element.matches(
    '[role="tab"],[role="menuitem"],[role="link"],[data-bs-toggle="tab"],[data-toggle="tab"],'+
    '[data-tab-target],[data-bs-target],[data-target],mat-nav-list mat-list-item,mat-nav-list [mat-list-item]'
  ) || (!!composedClosest(element, 'nav,[role="navigation"]') &&
    element.matches('button,[role="button"],[aria-controls]'));
  const unsafeAction = element => {
    const text = [element.getAttribute('aria-label'), element.textContent, element.getAttribute('title')]
      .filter(Boolean).join(' ').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
    return ['add','approve','begin','buy','cancel','checkout','confirm','create','delete','deploy','destroy',
      'disable','edit','enable','execute','export','import','logout','pay','purchase','reboot',
      'reject','remove','restart','save','send','sign out','signout','start','stop','submit',
      'terminate','update','upload'].some(word => (' ' + text + ' ').includes(' ' + word + ' '));
  };
  const visibleControl = element => {
    const style = getComputedStyle(element), rect = element.getBoundingClientRect();
    if (element.closest('[hidden],[inert],[aria-hidden="true"]') ||
        style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || rect.height <= 0) return false;
    const root = element.getRootNode();
    return !root.host || visibleControl(root.host);
  };
  const routeAttribute = element => element.getAttribute('href') || element.getAttribute('data-href') ||
    element.getAttribute('data-url') || element.getAttribute('routerlink') ||
    element.getAttribute('ng-reflect-router-link') || element.getAttribute('data-route') || '';
  const controlledPanel = element => {
    const raw = element.getAttribute('aria-controls') || element.getAttribute('data-tab-target') ||
      element.getAttribute('data-bs-target') || element.getAttribute('data-target') ||
      (element.getAttribute('href') || '');
    const panel = raw.replace(/^#/, '');
    return panel && !/[\s/?!]/.test(panel) && panel.length <= 160 ? panel : '';
  };
  const isMenuExpander = element => {
    const role = element.getAttribute('role');
    if (role === 'tab' || element.matches('[data-bs-toggle="tab"],[data-toggle="tab"]')) return false;
    if (element.hasAttribute('aria-expanded') || ['menu','true','tree','listbox'].includes(element.getAttribute('aria-haspopup')) ||
        element.matches('[data-bs-toggle="collapse"],[data-bs-toggle="dropdown"],[data-toggle="collapse"],[data-toggle="dropdown"]')) return true;
    const panel = controlledPanel(element);
    const target = panel && element.getRootNode().querySelector('#' + CSS.escape(panel));
    return !!target && (target.matches('nav,[role="navigation"],[role="menu"],[role="menubar"]') ||
      !!target.querySelector('[role="menuitem"],[aria-expanded]'));
  };
  const navigationParents = element => {
    const chains = [];
    const openers = window.__portalValidatorPanelOpeners;
    for (let cursor = element.parentElement || element.getRootNode().host; cursor;
         cursor = cursor.parentElement || cursor.getRootNode().host) {
      const opener = openers?.get(cursor);
      if (opener) chains.unshift([...(opener.ancestors || []), opener.label]);
    }
    const names = [];
    for (const chain of chains) {
      // Controlled menus may be sibling/portal elements instead of physical
      // descendants of their opener. Retain the opener's observed ancestry,
      // merging only overlapping chains rather than erasing repeated names.
      let overlap = Math.min(names.length, chain.length);
      while (overlap && !names.slice(-overlap).every((label,index) => label === chain[index])) overlap -= 1;
      names.push(...chain.slice(overlap));
    }
    return names;
  };
  const describeView = element => {
    if (!isNavigationControl(element) || !visibleControl(element) || composedClosest(element, 'form') || element.hasAttribute('disabled') ||
        element.getAttribute('aria-disabled') === 'true' || element.hasAttribute('download') ||
        unsafeAction(element) || isMenuExpander(element)) return null;
    const raw = routeAttribute(element);
    if (raw && (!raw.startsWith('#') || raw.startsWith('#/') || raw.startsWith('#!/'))) return null;
    const label = controlLabel(element);
    if (!label) return null;
    const panel = controlledPanel(element);
    const target = panel && element.getRootNode().querySelector('#' + CSS.escape(panel));
    // A broken explicit target is unresolved navigation, not a speculative view.
    if (panel && !target) return null;
    if (!target && !isNavigationControl(element)) return null;
    const region = composedClosest(element, 'nav,[role="navigation"],[role="menu"],[role="tablist"]');
    const regionLabel = region && (region.getAttribute('aria-label') ||
      region.getAttribute('role') || region.tagName.toLowerCase());
    const regions = region && Array.from(region.getRootNode().querySelectorAll(
      'nav,[role="navigation"],[role="menu"],[role="tablist"]')).filter(other =>
        (other.getAttribute('aria-label') || other.getAttribute('role') || other.tagName.toLowerCase()) === regionLabel);
    const regionIdentity = region && regionLabel + ':' + regions.indexOf(region);
    const scope = rootScope(element.getRootNode()) + (regionIdentity ? '|' + regionIdentity : '');
    // Framework-generated DOM IDs remain locators, not stable view identity.
    const identity = JSON.stringify([navigationParents(element), label, element.getAttribute('role') || 'navigation']);
    return {panel:panel || ('navigation:' + label), identity, label, id:element.id || '', kind:target ? 'panel' : 'navigation',
      scope, ancestors:JSON.stringify(navigationParents(element))};
  };
"""


DISCOVER_ROUTES_SCRIPT = r"""
async (maximumScrolls) => {
  /* NAVIGATION_DOM_HELPERS */
  const values = [];
  const seen = new Set();
  const baselinePanels = window.__portalValidatorBaselinePanels || new Set();
  const rememberBaseline = !window.__portalValidatorBaselinePanels;
  window.__portalValidatorBaselinePanels = baselinePanels;
  // A persistent global tab is one view even when a sibling hash route
  // changes location. Recreated controls in another rendered route retain
  // that route's own context; no random DOM identifier enters the identity.
  window.__portalValidatorViewSourceUrls ||= new WeakMap();
  const collect = () => {
    for (const root of navigationRoots()) {
      // Panels are real UI views, not invented HTTP/hash routes. Discover
      // them without clicking: the normal validation loop owns activation,
      // request attribution, readiness and the existing read-only policy.
      for (const element of root.querySelectorAll(viewSelector)) {
        const view = describeView(element);
        if (!view) continue;
        const panel = view.scope + '\0' + view.identity;
        if (rememberBaseline && (element.getAttribute('aria-selected') === 'true' ||
            ['page','true'].includes(element.getAttribute('aria-current')) ||
            element.classList.contains('active'))) baselinePanels.add(panel);
        if (baselinePanels.has(panel)) continue;
        const ariaLabel = (element.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
        const label = (ariaLabel || element.textContent || element.getAttribute('title') || '')
          .replace(/\s+/g, ' ').trim().slice(0, 160);
        if (!label) continue;
        const key = 'view:' + panel;
        if (seen.has(key)) continue;
        seen.add(key);
        if (!window.__portalValidatorViewSourceUrls.has(element))
          window.__portalValidatorViewSourceUrls.set(element, window.location.href);
        values.push({url: window.__portalValidatorViewSourceUrls.get(element), label, source:'ui-tab',
          accessibleName:ariaLabel, labelSource:ariaLabel ? 'aria-label' : 'visible-text',
          safetyLabel:[ariaLabel, element.textContent, element.getAttribute('title')].filter(Boolean).join(' '),
          navigationHierarchy:navigationParents(element), viewControl:view});
      }
      for (const element of root.querySelectorAll(routeSelector)) {
        const raw = routeAttribute(element);
        if (!raw) continue;
        let url;
        try { url = new URL(raw, document.baseURI).href; } catch (_) { continue; }
        if (seen.has(url)) continue;
        seen.add(url);
        const labelledBy = (element.getAttribute('aria-labelledby') || '').split(/\s+/)
          .map(id => document.getElementById(id)?.textContent || '').join(' ').replace(/\s+/g, ' ').trim();
        const ariaLabel = (element.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
        const visibleLabel = (element.textContent || '').replace(/\s+/g, ' ').trim();
        const titleLabel = (element.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
        const label = (ariaLabel || labelledBy || visibleLabel || titleLabel).slice(0, 160);
        values.push({
          url,
          label,
          accessibleName: (ariaLabel || labelledBy || '').slice(0, 160),
          labelSource: ariaLabel ? 'aria-label' : labelledBy ? 'aria-labelledby' :
            visibleLabel ? 'visible-text' : titleLabel ? 'title' : 'none',
          navigationHierarchy:navigationParents(element),
          source: element.hasAttribute('download') ? 'download' :
            (element.getAttribute('role') || element.tagName.toLowerCase())
        });
      }
    }
  };
  collect();
  const scrollables = navigationRoots().flatMap(root => Array.from(root.querySelectorAll(
    'nav, [role="navigation"], [role="menu"], [role="menubar"]'
  ))).filter(element => element.scrollHeight > element.clientHeight && element.clientHeight > 0);
  const originalPositions = scrollables.map(element => element.scrollTop);
  for (let step = 0; step < maximumScrolls; step += 1) {
    let moved = false;
    for (const element of scrollables) {
      const before = element.scrollTop;
      element.scrollTop = Math.min(element.scrollHeight, before + element.clientHeight);
      moved = moved || element.scrollTop !== before;
    }
    if (!moved) break;
    await new Promise(resolve => setTimeout(resolve, 50));
    collect();
  }
  scrollables.forEach((element, index) => { element.scrollTop = originalPositions[index]; });
  for (const observed of (window.__portalValidatorObservedRoutes || [])) {
    // The init-script's document baseline is not a history transition. In
    // particular, do not fabricate a SPA activation for an embedded document.
    if (typeof observed === 'object' && observed.mode === 'document') continue;
    const url = typeof observed === 'string' ? observed : observed.url;
    if (!url) continue;
    if (!seen.has(url)) {
      seen.add(url);
      values.push({url, label: '', source: 'browser-history', observerMode: observed.mode || 'history'});
    }
  }
  return values;
}
""".replace("/* NAVIGATION_DOM_HELPERS */", NAVIGATION_DOM_HELPERS)


EXPAND_SAFE_NAVIGATION_SCRIPT = r"""
({reset, inspectOnly}) => {
  /* NAVIGATION_DOM_HELPERS */
  const dangerous = new Set([
    'add','approve','begin','buy','cancel','checkout','confirm','create','delete','deploy','destroy',
    'disable','edit','enable','execute','export','import','logout','pay','purchase','reboot',
    'reject','remove','restart','save','send','sign out','signout','start','stop','submit',
    'terminate','update','upload'
  ]);
  const selector = [
    'nav [aria-expanded="false"][aria-controls]',
    '[role="navigation"] [aria-expanded="false"][aria-controls]',
    '[role="menu"] [aria-expanded="false"][aria-controls]',
    'aside [aria-expanded="false"][aria-controls]',
    '[role="tab"][aria-selected="false"][aria-controls]',
    '[aria-haspopup="menu"][aria-expanded="false"]',
    '[role="menuitem"]', '[role="tab"]',
    'nav [data-bs-target]', '[role="navigation"] [data-bs-target]',
    'nav [data-target]', '[role="navigation"] [data-target]'
  ].join(',');
  // This set lives only for one bounded expansion pass. Retain it between
  // steps so Python can observe lazy panel requests and collect transient
  // links before opening the next mutually exclusive menu.
  if (reset || !window.__portalValidatorVisitedControls) {
    window.__portalValidatorVisitedControls = new WeakSet();
  }
  const visited = window.__portalValidatorVisitedControls;
  const controls = () => {
    const values = [];
    const visit = (root) => {
      for (const element of root.querySelectorAll(selector + ',' + viewSelector)) {
        // A collapsed child may precede its opener in DOM order. Do not mark
        // it visited until it is visible and can actually be inspected.
        const raw = routeAttribute(element);
        if (!visited.has(element) && visibleControl(element) &&
            (isNavigationControl(element) || element.matches(selector)) &&
            (!raw || (raw.startsWith('#') && !raw.startsWith('#/') && !raw.startsWith('#!/'))) &&
            !describeView(element)) values.push(element);
      }
      for (const element of root.querySelectorAll('*')) {
        if (element.shadowRoot) visit(element.shadowRoot);
      }
    };
    visit(document);
    return values;
  };
  let activated = 0;
  let skipped = 0;
  let inspected = 0;
  const transitions = [];
  if (inspectOnly) return {remaining:controls().length};
  while (activated < 1 && inspected < 25) {
    const candidates = controls();
    if (!candidates.length) break;
    const element = candidates[0];
    visited.add(element);
    inspected += 1;
    const ariaLabel = (element.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
    const visibleLabel = (element.textContent || '').replace(/\s+/g, ' ').trim();
    const titleLabel = (element.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
    const label = (ariaLabel || visibleLabel || titleLabel).slice(0, 160);
    const normalizedLabel = `${ariaLabel} ${visibleLabel} ${titleLabel}`
      .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
    const style = getComputedStyle(element);
    const bounds = element.getBoundingClientRect();
    const unsafe = composedClosest(element, 'form') || !isMenuExpander(element) || element.hasAttribute('disabled') ||
      element.getAttribute('aria-disabled') === 'true' || element.hasAttribute('href') ||
      element.hasAttribute('data-href') || element.hasAttribute('data-url') ||
      element.hasAttribute('routerlink') || element.hasAttribute('ng-reflect-router-link') || element.hasAttribute('data-route') ||
      !label || style.display === 'none' || style.visibility === 'hidden' ||
      bounds.width <= 0 || bounds.height <= 0 ||
      Array.from(dangerous).some(word =>
        (' ' + normalizedLabel.replace(/[^a-z0-9]+/g, ' ').trim() + ' ').includes(' ' + word + ' '));
    if (unsafe) { skipped += 1; continue; }
    const panel = controlledPanel(element);
    const targetPanel = panel && element.getRootNode().querySelector('#' + CSS.escape(panel));
    if (targetPanel) {
      window.__portalValidatorPanelOpeners ||= new WeakMap();
      window.__portalValidatorPanelOpeners.set(targetPanel, {label, ancestors:navigationParents(element)});
    }
    // Return the observed element without dispatching inside evaluate(). A
    // document navigation could destroy that execution context after click,
    // and retrying the entire script would repeat a natural request.
    return {activated:0, skipped, inspected, transitions, remaining:controls().length,
      element, before:location.href, label, accessibleName:ariaLabel.slice(0,160),
      labelSource:ariaLabel ? 'aria-label' : visibleLabel ? 'visible-text' : titleLabel ? 'title' : 'none'};
  }
  return {activated, skipped, inspected, transitions, remaining:controls().length};
}
""".replace("/* NAVIGATION_DOM_HELPERS */", NAVIGATION_DOM_HELPERS)


MENU_REVEALED_SCRIPT = r"""
(element) => {
  /* NAVIGATION_DOM_HELPERS */
  const panel = controlledPanel(element);
  const target = panel && element.getRootNode().querySelector('#' + CSS.escape(panel));
  return {expanded:element.getAttribute('aria-expanded') === 'true',
    panelVisible:!!target && visibleControl(target)};
}
""".replace("/* NAVIGATION_DOM_HELPERS */", NAVIGATION_DOM_HELPERS)


async def _expand_one_menu(page, reset: bool, timeout_ms: int) -> dict[str, Any]:
    handle = await evaluate_dom(
        page, EXPAND_SAFE_NAVIGATION_SCRIPT, {"reset": reset}, handle=True, timeout_ms=timeout_ms,
    )
    element_handle = None
    try:
        result = await handle.evaluate("value => { const {element, ...metadata} = value; return metadata; }")
        element_handle = await handle.get_property("element")
        element = element_handle.as_element()
        if element is None:
            return result
        # Hover-first supports CSS/JS dropdowns without an unnecessary click.
        # Neither action is retried after dispatch, even if it navigates away.
        try:
            before = await element.evaluate(MENU_REVEALED_SCRIPT)
            await element.hover(timeout=timeout_ms)
            revealed = await element.evaluate(MENU_REVEALED_SCRIPT)
            if not ((revealed["expanded"] and not before["expanded"]) or
                    (revealed["panelVisible"] and not before["panelVisible"])):
                await element.click(timeout=timeout_ms)
                revealed = await element.evaluate(MENU_REVEALED_SCRIPT)
            result["menus_expanded"] = int(
                (revealed["expanded"] and not before["expanded"]) or
                (revealed["panelVisible"] and not before["panelVisible"])
            )
        except Exception as error:
            if not context_replacement_error(error):
                raise
            await page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
        result["activated"] = 1
        after = page.url
        if after != result.get("before"):
            result["transitions"] = [{
                "url": after, "label": result["label"], "accessibleName": result["accessibleName"],
                "labelSource": result["labelSource"], "source": "safe-click",
            }]
        return result
    finally:
        if element_handle is not None:
            await element_handle.dispose()
        await handle.dispose()


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


SEMANTIC_ROUTE_ACTIVATION_SCRIPT = r"""
({target, expectedLabel, source}) => {
  /* NAVIGATION_DOM_HELPERS */
  const candidate = new URL(target, document.baseURI);
  const dangerous = new Set([
    'add','approve','begin','buy','cancel','checkout','confirm','create','delete','deploy','destroy',
    'disable','edit','enable','execute','export','import','logout','pay','purchase','reboot',
    'reject','remove','restart','save','send','sign out','signout','start','stop','submit',
    'terminate','update','upload'
  ]);
  const elements = navigationRoots().flatMap(root => Array.from(root.querySelectorAll(routeSelector + ',' + viewSelector)));
  const expected = (expectedLabel || '').replace(/\s+/g, ' ').trim().toLowerCase();
  const matches = [];
  for (let index = 0; index < elements.length && index < 500; index += 1) {
    const element = elements[index];
    if (!visibleControl(element)) continue;
    const label = (
      element.getAttribute('aria-label') || element.textContent || element.getAttribute('title') || ''
    ).replace(/\s+/g, ' ').trim().toLowerCase();
    const safetyLabel = [element.getAttribute('aria-label'), element.textContent,
      element.getAttribute('title')].filter(Boolean).join(' ')
      .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
    if (Array.from(dangerous).some(word =>
      (' ' + safetyLabel.replace(/[^a-z0-9]+/g, ' ').trim() + ' ').includes(' ' + word + ' '))) continue;
    if (composedClosest(element, 'form') || element.hasAttribute('disabled') ||
        element.getAttribute('aria-disabled') === 'true') continue;
    const raw = routeAttribute(element);
    let urlMatches = false;
    if (raw) {
      try {
        const resolved = new URL(raw, document.baseURI);
        urlMatches = resolved.origin === candidate.origin &&
          resolved.pathname === candidate.pathname && resolved.search === candidate.search &&
          resolved.hash === candidate.hash;
      } catch (_) {}
    }
    const role = (element.getAttribute('role') || '').toLowerCase();
    const semanticControl = source === 'safe-click' && expected && label === expected &&
      (['tab', 'menuitem'].includes(role) || (role === '' && element.hasAttribute('aria-controls')));
    if (urlMatches || semanticControl) matches.push(element);
  }
  return matches.find(element => controlLabel(element).toLowerCase() === expected) || matches[0] || null;
}
""".replace("/* NAVIGATION_DOM_HELPERS */", NAVIGATION_DOM_HELPERS)


async def activate_semantic_route(
    page,
    url: str,
    *,
    label: str | None,
    source: str | None,
    timeout_ms: int,
) -> bool:
    """Use the closest safe user-navigation equivalent when it is unambiguous."""
    handle = await evaluate_dom(
        page,
        SEMANTIC_ROUTE_ACTIVATION_SCRIPT,
        {"target": url, "expectedLabel": label or "", "source": source or ""},
        handle=True, timeout_ms=timeout_ms,
    )
    try:
        candidate = handle.as_element()
        if candidate is None:
            return False
        # Once attempted, a click failure must propagate. Retrying another
        # control or falling back to goto could duplicate a natural POST.
        await candidate.click(timeout=min(timeout_ms, 5000))
        return True
    finally:
        await handle.dispose()


async def expand_safe_navigation(
    page,
    maximum: int,
    *,
    wait_after_action: Callable[[], Awaitable[object]] | None = None,
    maximum_scrolls: int = 3,
    on_routes_discovered: Callable[[list[DiscoveredRoute]], Awaitable[None]] | None = None,
    timeout_ms: int = 5000,
) -> dict[str, object]:
    """Observe each safe panel before opening the next; never guess route URLs.

    The caller supplies its existing deadline/network observation policy. This
    prevents a slow lazy menu from being mistaken for an exhausted route set,
    without inventing a second timeout or weakening read-only interception.
    """
    maximum = max(0, min(int(maximum), 1500))
    totals: dict[str, object] = {"activated": 0, "skipped": 0, "inspected": 0, "menus_expanded": 0, "routes": []}
    routes: list[DiscoveredRoute] = []
    # Collect the initially open panel as well as every subsequently opened
    # panel. A final-document-only snapshot loses accordion/tab branches.
    routes.extend(await discover_page_routes(page, maximum_scrolls))
    if on_routes_discovered is not None:
        await on_routes_discovered(routes.copy())
    while int(totals["activated"]) < maximum and int(totals["inspected"]) < max(25, maximum * 5):
        result = await _expand_one_menu(page, reset=int(totals["inspected"]) == 0, timeout_ms=timeout_ms)
        for key in ("activated", "skipped", "inspected", "menus_expanded"):
            totals[key] = int(totals[key]) + int(result.get(key, 0))
        transition_routes: list[DiscoveredRoute] = []
        for item in result.get("transitions", []):
            if isinstance(item, dict) and isinstance(item.get("url"), str):
                transition_routes.append(DiscoveredRoute(
                    url=item["url"],
                    label=str(item.get("label") or "")[:160],
                    source="safe-click",
                    navigation_mode=SAFE_CLICK_NAVIGATION,
                    discovery_type="SAFE_CLICK",
                    label_source=str(item.get("labelSource") or "none")[:32],
                    accessible_name=str(item.get("accessibleName") or "")[:160] or None,
                ))
        routes.extend(transition_routes)
        if transition_routes and on_routes_discovered is not None:
            await on_routes_discovered(transition_routes)
        if not result.get("activated"):
            if not result.get("inspected"):
                break
            continue
        immediate_routes = await discover_page_routes(page, maximum_scrolls)
        routes.extend(immediate_routes)
        if on_routes_discovered is not None:
            await on_routes_discovered(immediate_routes)
        if wait_after_action is not None:
            await wait_after_action()
        panel_routes = await discover_page_routes(page, maximum_scrolls)
        routes.extend(panel_routes)
        if on_routes_discovered is not None:
            await on_routes_discovered(panel_routes)
    unique: dict[str, DiscoveredRoute] = {}
    for route in routes:
        key = discovered_route_key(route, normalize_route_url(route.url) or route.url)
        existing = unique.get(key)
        if (existing is None or (not existing.label and route.label)
                or len(route.navigation_hierarchy) > len(existing.navigation_hierarchy)):
            unique[key] = route
    totals["routes"] = list(unique.values())
    remaining = await evaluate_dom(
        page,
        EXPAND_SAFE_NAVIGATION_SCRIPT,
        {"reset": int(totals["inspected"]) == 0, "inspectOnly": True},
    )
    totals["remaining"] = int(remaining.get("remaining", 0))
    totals["discovered"] = int(totals["inspected"]) + int(totals["remaining"])
    totals["unresolved"] = int(totals["skipped"]) + int(totals["remaining"])
    totals["limit_reached"] = bool(totals["remaining"])
    totals["view_controls"] = sum(bool(route.view_control) for route in unique.values())
    return totals


async def discover_page_routes(page, maximum_scrolls: int = 3) -> list[DiscoveredRoute]:
    """Discover one document or frame; its own URL/baseURI resolves relative links."""
    raw = await evaluate_dom(page, DISCOVER_ROUTES_SCRIPT, max(0, min(maximum_scrolls, 20)))
    document_url = page.url
    routes: list[DiscoveredRoute] = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            continue
        source = str(item.get("source") or "semantic")[:64]
        view_control = item.get("viewControl")
        if isinstance(view_control, dict):
            if dangerous_control_label(str(item.get("safetyLabel") or item.get("label") or "")):
                continue
            if getattr(page, "parent_frame", None) is not None:
                # Preserve the observed frame context. A tab inside an iframe
                # must not navigate the top-level application to the frame URL.
                view_control = {
                    **view_control,
                    "frame_url": normalize_route_url(document_url) or document_url,
                    "frame_name": str(getattr(page, "name", "") or "")[:160],
                }
        else:
            view_control = None
        navigation_mode = (
            UI_VIEW_ACTIVATION if view_control else DOWNLOAD_OBSERVED
            if item.get("source") == "download"
            else HASH_ROUTE_TRANSITION
            if item.get("observerMode") == "hash"
            else navigation_mode_for_route(item["url"], source, document_url)
        )
        routes.append(DiscoveredRoute(
            url=item["url"],
            label=str(item.get("label") or "")[:160],
            source=source,
            navigation_mode=navigation_mode,
            discovery_type=discovery_type_for(source, navigation_mode),
            label_source=str(item.get("labelSource") or "none")[:32],
            accessible_name=str(item.get("accessibleName") or "")[:160] or None,
            view_control=view_control,
            navigation_hierarchy=tuple(
                str(label)[:160] for label in item.get("navigationHierarchy", [])
                if isinstance(label, str) and label.strip()
            ),
        ))
    return routes


UI_VIEW_CONTROL_SCRIPT = r"""
({panel, identity, label, scope, id}) => {
  /* NAVIGATION_DOM_HELPERS */
  const matches = [];
  for (const root of navigationRoots()) {
    for (const element of root.querySelectorAll(viewSelector)) {
      const view = describeView(element);
      if (view && (identity ? view.identity === identity : view.panel === panel) && view.label === label &&
          (scope === undefined || view.scope === scope) && (identity || !id || element.id === id)) {
        matches.push(element);
      }
    }
  }
  return matches.length === 1 ? matches[0] : null;
}
""".replace("/* NAVIGATION_DOM_HELPERS */", NAVIGATION_DOM_HELPERS)


RESTORE_MENU_ANCESTOR_SCRIPT = r"""
(label) => {
  /* NAVIGATION_DOM_HELPERS */
  const matches = navigationRoots().flatMap(root => Array.from(root.querySelectorAll(
    viewSelector + ',[aria-expanded][aria-controls],[aria-haspopup="menu"]'
  ))).filter(element => visibleControl(element) && controlLabel(element) === label &&
    isMenuExpander(element) && !unsafeAction(element) && !composedClosest(element, 'form') &&
    !element.hasAttribute('disabled') && element.getAttribute('aria-disabled') !== 'true' && !routeAttribute(element));
  if (matches.length !== 1) return null;
  const element = matches[0], panel = controlledPanel(element);
  const target = panel && element.getRootNode().querySelector('#' + CSS.escape(panel));
  if (element.getAttribute('aria-expanded') === 'true' && target &&
      !composedClosest(target, '[hidden],[inert],[aria-hidden="true"]') &&
      getComputedStyle(target).display !== 'none' && getComputedStyle(target).visibility !== 'hidden') return 'open';
  return element;
}
""".replace("/* NAVIGATION_DOM_HELPERS */", NAVIGATION_DOM_HELPERS)


NAVIGATION_VIEW_EVIDENCE_SCRIPT = r"""
(element) => {
  /* NAVIGATION_DOM_HELPERS */
  return {url:location.href,
    text:navigationRoots().map(root => root === document ?
      (document.querySelector('main,[role="main"]') || document.body).innerText : root.textContent).join('\0'),
    selected:element.getAttribute('aria-selected') || element.getAttribute('aria-current') || ''};
}
""".replace("/* NAVIGATION_DOM_HELPERS */", NAVIGATION_DOM_HELPERS)


NAVIGATION_VIEW_COMPLETED_SCRIPT = r"""
({element, previous}) => {
  /* NAVIGATION_DOM_HELPERS */
  if (location.href !== previous.url) return true;
  const text = navigationRoots().map(root => root === document ?
    (document.querySelector('main,[role="main"]') || document.body).innerText : root.textContent).join('\0');
  if (text && text !== previous.text) return true;
  if (!element.isConnected) return false;
  const selected = element.getAttribute('aria-selected') || element.getAttribute('aria-current') || '';
  return selected !== previous.selected && ['true','page'].includes(selected);
}
""".replace("/* NAVIGATION_DOM_HELPERS */", NAVIGATION_DOM_HELPERS)


async def activate_ui_view(page, control: dict[str, str], timeout_ms: int) -> None:
    """Activate one evidenced navigation view and verify a real UI transition."""
    for label in json.loads(control.get("ancestors", "[]")):
        opener_handle = await evaluate_dom(page, RESTORE_MENU_ANCESTOR_SCRIPT, label, handle=True, timeout_ms=timeout_ms)
        try:
            opener = opener_handle.as_element()
            if opener is not None:
                before = await opener.evaluate(MENU_REVEALED_SCRIPT)
                await opener.hover(timeout=timeout_ms)
                revealed = await opener.evaluate(MENU_REVEALED_SCRIPT)
                if not ((revealed["expanded"] and not before["expanded"]) or
                        (revealed["panelVisible"] and not before["panelVisible"])):
                    await opener.click(timeout=timeout_ms)
            elif await opener_handle.json_value() != "open":
                raise RuntimeError("Discovered UI view's parent menu is not uniquely and safely activatable")
        finally:
            await opener_handle.dispose()
    handle = await evaluate_dom(page, UI_VIEW_CONTROL_SCRIPT, control, handle=True, timeout_ms=timeout_ms)
    try:
        element = handle.as_element()
        if element is None:
            raise RuntimeError("Discovered UI tab is not uniquely and safely activatable")
        control = {**control, **await element.evaluate(
            "element => {" + NAVIGATION_DOM_HELPERS + "return describeView(element);}",
        )}
        labels = await element.evaluate("e => [e.textContent,e.getAttribute('aria-label'),e.getAttribute('title')].filter(Boolean).join(' ')")
        if dangerous_control_label(labels):
            raise RuntimeError("Discovered UI tab has an unsafe action label")
        if control.get("kind") == "navigation":
            evidence = await page.evaluate(NAVIGATION_VIEW_EVIDENCE_SCRIPT, element)
            await element.click(timeout=timeout_ms)
            await page.wait_for_function(
                NAVIGATION_VIEW_COMPLETED_SCRIPT,
                arg={"element": element, "previous": evidence}, timeout=timeout_ms,
            )
            return
        evidence = await element.evaluate(r"""(e, panel) => {
          const p = e.getRootNode().querySelector('#' + CSS.escape(panel));
          const style = p && getComputedStyle(p), rect = p && p.getBoundingClientRect();
          return {requiresSelection:e.hasAttribute('aria-selected'),
            panelText:p?.innerText || '',
            wasHidden:!p || !!p.closest('[hidden],[inert],[aria-hidden="true"]') ||
              style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || rect.height <= 0};
        }""", control["panel"])
        await element.click(timeout=timeout_ms)
        await page.wait_for_function(r"""({element, panel, requiresSelection, wasHidden, panelText}) => {
          if (!element.isConnected) return false;
          const target = element.getRootNode().querySelector('#' + CSS.escape(panel));
          if (!target || target.closest('[hidden],[inert],[aria-hidden="true"]')) return false;
          const style = getComputedStyle(target), rect = target.getBoundingClientRect();
          if (style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || rect.height <= 0) return false;
          if (target.innerText && target.innerText !== panelText) return true;
          return requiresSelection ? element.getAttribute('aria-selected') === 'true' :
            wasHidden || element.classList.contains('active') || element.parentElement?.classList.contains('active');
        }""", arg={"element": element, **control, **evidence}, timeout=timeout_ms)
    finally:
        await handle.dispose()


def resolve_view_target(page, view_control: dict[str, str] | None = None):
    """Resolve an observed frame view without broadening its original boundary.

    Reuse for activation and subsequent DOM/readiness inspection so a child
    frame cannot inherit the parent application's rendered health.
    """
    if not view_control or not view_control.get("frame_url"):
        return page
    main_origin = urlsplit(page.url)
    frames = []
    for frame in page.frames:
        origin = urlsplit(frame.url)
        if (frame != page.main_frame and
            (origin.scheme, origin.hostname, origin.port) ==
            (main_origin.scheme, main_origin.hostname, main_origin.port) and
            normalize_route_url(frame.url) == view_control["frame_url"] and
            str(frame.name or "") == view_control.get("frame_name", "")):
            frames.append(frame)
    if len(frames) != 1:
        raise RuntimeError("Discovered frame view is not uniquely available in the same-origin application")
    return frames[0]


async def perform_route_navigation(
    page,
    url: str,
    mode: str,
    timeout_ms: int,
    *,
    label: str | None = None,
    source: str | None = None,
    view_control: dict[str, str] | None = None,
    on_popup: Callable[[Any], Awaitable[None]] | None = None,
):
    """Navigate a document or transition an existing SPA document.

    Playwright correctly returns no Response for same-document transitions; callers use
    the returned boolean as the navigation signal instead of fabricating an HTTP result.
    """
    if mode == UI_VIEW_ACTIVATION:
        if view_control is None:
            raise RuntimeError("UI view activation requires an observed tab control")
        if view_control.get("frame_url"):
            await activate_ui_view(resolve_view_target(page, view_control), view_control, timeout_ms)
            return None, True, "SAME_ORIGIN_FRAME_UI_CONTROL"
        response = None
        if normalize_route_url(page.url) != normalize_route_url(url):
            current, target = urlsplit(page.url), urlsplit(url)
            if (current.scheme, current.netloc, current.path, current.query) == (
                target.scheme, target.netloc, target.path, target.query,
            ):
                await page.evaluate(SAME_DOCUMENT_TRANSITION_SCRIPT, {"target": url, "mode": HASH_ROUTE_TRANSITION})
                await page.wait_for_function("target => location.href === target", arg=url, timeout=timeout_ms)
            else:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            if response is not None:
                # Returning from a history-based panel may reload the source
                # document. Capture its initially selected panel BEFORE the
                # next click; otherwise that baseline becomes a false extra
                # inactive view after the application changes selection.
                await discover_page_routes(page, 0)
        await activate_ui_view(page, view_control, timeout_ms)
        return response, True, "UI_TAB_CONTROL"
    if mode == SEMANTIC_LINK_NAVIGATION:
        responses = []
        popups = []
        navigation_observed = asyncio.Event()
        document_ready = asyncio.Event()
        committed_response = None
        ready_response = None

        def document_response(response):
            if response.request.is_navigation_request() and response.frame == page.main_frame:
                responses.append(response)
                document_ready.clear()
                navigation_observed.set()

        def observe_popup(popup):
            popups.append(popup)
            navigation_observed.set()

        def document_committed(frame):
            nonlocal committed_response
            if frame == page.main_frame and responses:
                committed_response = responses[-1]

        def document_loaded():
            nonlocal ready_response
            # A second navigation can receive headers before the preceding
            # document's DOMContentLoaded. Never reuse that older document's
            # readiness for a response that has not committed yet.
            if responses and committed_response is responses[-1]:
                ready_response = committed_response
                document_ready.set()

        async def completed_document():
            # Response headers precede document commit. Observe the NEW
            # document's readiness rather than reading the old page's already
            # satisfied load state. This also supports same-URL reloads.
            deadline = asyncio.get_running_loop().time() + timeout_ms / 1000
            try:
                while True:
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        raise TimeoutError("Document readiness deadline expired")
                    await asyncio.wait_for(document_ready.wait(), timeout=remaining)
                    if ready_response is responses[-1]:
                        return ready_response, False, "SEMANTIC_CONTROL"
            except TimeoutError as exc:
                raise RuntimeError("Semantic document navigation did not reach DOMContentLoaded") from exc

        page.on("response", document_response)
        page.on("popup", observe_popup)
        page.on("framenavigated", document_committed)
        page.on("domcontentloaded", document_loaded)
        try:
            before_url = page.url
            activated = await activate_semantic_route(page, url, label=label, source=source, timeout_ms=timeout_ms)
            if activated:
                # A real click preserves router handlers and their natural API
                # traffic. Never replay a request or synthesize an HTTP status.
                if not responses and not popups:
                    # A popup event is delivered after its first response,
                    # which can be later than click() returning. Waiting only
                    # for the opener URL falsely times out successful windows.
                    movement = asyncio.create_task(retry_dom_operation(
                        page, lambda: page.wait_for_function(
                            "previous => window.location.href !== previous",
                            arg=before_url, timeout=timeout_ms,
                        ), timeout_ms=timeout_ms,
                    ))
                    observed = asyncio.create_task(navigation_observed.wait())
                    try:
                        done, _ = await asyncio.wait(
                            (movement, observed), timeout=timeout_ms / 1000,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if not done:
                            raise TimeoutError("Semantic link produced no observed document, popup or route transition")
                        if movement in done and not navigation_observed.is_set():
                            movement.result()
                    except TimeoutError as exc:
                        # Both observer and DOM deadlines mean the same thing:
                        # this single click produced no proven navigation. Do
                        # not retry it or mislabel it as the outer route budget.
                        raise RuntimeError(
                            "Semantic link produced no observed document, popup or route transition"
                        ) from exc
                    finally:
                        for task in (movement, observed):
                            if not task.done():
                                task.cancel()
                        await asyncio.gather(movement, observed, return_exceptions=True)
                if responses:
                    return await completed_document()
                if popups:
                    if len(popups) != 1 or on_popup is None:
                        raise RuntimeError("Semantic navigation opened a window without a unique approved inspection target")
                    popup = popups[0]
                    await popup.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
                    await on_popup(popup)
                    return None, False, "POPUP_DOCUMENT"
                await page.wait_for_function(
                    # HTTP redirects may commit only the final URL, never the
                    # requested href. Wait for real movement, then retain any
                    # document response and let the caller's central final
                    # scope/authentication policy evaluate that destination.
                    "previous => window.location.href !== previous",
                    arg=before_url, timeout=timeout_ms,
                )
                if responses:
                    # A handler may schedule a real document navigation after
                    # click() returns. Preserve its observed HTTP/TLS evidence.
                    return await completed_document()
                return None, True, "SEMANTIC_CONTROL"
        finally:
            page.remove_listener("response", document_response)
            page.remove_listener("popup", observe_popup)
            page.remove_listener("framenavigated", document_committed)
            page.remove_listener("domcontentloaded", document_loaded)
    if mode == POPUP_NAVIGATION:
        # Its document was naturally opened by the application. Reloading it
        # in the primary page loses window-local session/view state and can
        # repeat authentication POSTs. The caller supplies the observed page.
        if page.is_closed() or normalize_route_url(page.url) != normalize_route_url(url):
            raise RuntimeError("Observed popup document is no longer available at its discovered destination")
        await page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
        return None, False, "OBSERVED_POPUP_DOCUMENT"
    if mode in DOCUMENT_NAVIGATIONS:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        if response is None:
            raise RuntimeError("Document navigation completed without an HTTP response")
        return response, False, "DOCUMENT"
    if mode not in SAME_DOCUMENT_NAVIGATIONS:
        raise RuntimeError("Unsupported navigation mode")
    activated = await activate_semantic_route(
        page,
        url,
        label=label,
        source=source,
        timeout_ms=timeout_ms,
    )
    transitioned = activated or await page.evaluate(
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
    return None, True, "SEMANTIC_CONTROL" if activated else "SYNTHETIC_FALLBACK"
