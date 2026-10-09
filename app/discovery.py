from __future__ import annotations

import re
import hashlib
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
    "add", "approve", "buy", "cancel", "checkout", "confirm", "create", "delete",
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


def discovered_route_key(route: DiscoveredRoute, canonical_url: str) -> str:
    """Keep a real URL separate from a UI panel's non-URL coverage identity."""
    if route.view_control:
        panel = route.view_control["panel"]
        digest = hashlib.sha256(f"{canonical_url}\0{panel}".encode()).hexdigest()[:24]
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
    result = await page.evaluate(ROUTE_NAME_EVIDENCE_SCRIPT)
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


DISCOVER_ROUTES_SCRIPT = r"""
async (maximumScrolls) => {
  const values = [];
  const seen = new Set();
  const baselinePanels = window.__portalValidatorBaselinePanels || new Set();
  const rememberBaseline = !window.__portalValidatorBaselinePanels;
  window.__portalValidatorBaselinePanels = baselinePanels;
  const selectors = [
    'a[href]', 'area[href]', '[role="link"][href]', '[role="link"][data-href]',
    'nav [data-url]', '[role="navigation"] [data-url]', '[role="menuitem"][data-href]',
    '[role="tab"][data-href]', '[routerlink]',
    'nav [data-route]', '[role="navigation"] [data-route]',
    '[role="menuitem"][data-route]', '[role="tab"][data-route]'
  ];
  const roots = () => {
    const values = [document];
    for (let index = 0; index < values.length; index += 1) {
      for (const element of values[index].querySelectorAll('*')) {
        if (element.shadowRoot) values.push(element.shadowRoot);
      }
    }
    return values;
  };
  const collect = () => {
    for (const root of roots()) {
      // Panels are real UI views, not invented HTTP/hash routes. Discover
      // them without clicking: the normal validation loop owns activation,
      // request attribution, readiness and the existing read-only policy.
      for (const element of root.querySelectorAll(
        '[role="tab"], [data-bs-toggle="tab"], [data-toggle="tab"]'
      )) {
        const raw = element.getAttribute('href') || '';
        // A declared router URL is already covered by normal URL navigation.
        // Do not also enqueue it as a second UI view and dispatch its POST twice.
        if (raw.startsWith('#/') || raw.startsWith('#!/') ||
            ['data-href','data-url','routerlink','data-route'].some(name => element.hasAttribute(name))) continue;
        const target = element.getAttribute('aria-controls') ||
          element.getAttribute('data-bs-target') || element.getAttribute('data-target') ||
          (raw.startsWith('#') ? raw : '');
        const panel = target.replace(/^#/, '');
        if (!panel || /[\s/?!]/.test(panel) || panel.length > 160 ||
            (raw && !raw.startsWith('#')) || !root.querySelector('#' + CSS.escape(panel))) continue;
        if (element.closest('form') || element.hasAttribute('disabled') ||
            element.getAttribute('aria-disabled') === 'true' || element.hasAttribute('download')) continue;
        const style = getComputedStyle(element), rect = element.getBoundingClientRect();
        if (element.closest('[hidden],[inert],[aria-hidden="true"]') ||
            style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || rect.height <= 0) continue;
        if (rememberBaseline && (element.getAttribute('aria-selected') === 'true' ||
            element.classList.contains('active'))) baselinePanels.add(panel);
        if (baselinePanels.has(panel)) continue;
        const ariaLabel = (element.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
        const label = (ariaLabel || element.textContent || element.getAttribute('title') || '')
          .replace(/\s+/g, ' ').trim().slice(0, 160);
        if (!label) continue;
        const key = 'view:' + panel;
        if (seen.has(key)) continue;
        seen.add(key);
        values.push({url: window.location.href, label, source:'ui-tab',
          accessibleName:ariaLabel, labelSource:ariaLabel ? 'aria-label' : 'visible-text',
          safetyLabel:[ariaLabel, element.textContent, element.getAttribute('title')].filter(Boolean).join(' '),
          viewControl:{panel, label, id:element.id || ''}});
      }
      for (const element of root.querySelectorAll(selectors.join(','))) {
        const raw = element.getAttribute('href') || element.getAttribute('data-href') ||
          element.getAttribute('data-url') || element.getAttribute('routerlink') ||
          element.getAttribute('data-route');
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
          source: element.hasAttribute('download') ? 'download' :
            (element.getAttribute('role') || element.tagName.toLowerCase())
        });
      }
    }
  };
  collect();
  const scrollables = roots().flatMap(root => Array.from(root.querySelectorAll(
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
"""


EXPAND_SAFE_NAVIGATION_SCRIPT = r"""
async ({reset}) => {
  const dangerous = new Set([
    'add','approve','buy','cancel','checkout','confirm','create','delete','deploy','destroy',
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
    '[role="menuitem"]', '[role="tab"]'
  ].join(',');
  // This set lives only for one bounded expansion pass. Retain it between
  // steps so Python can observe lazy panel requests and collect transient
  // links before opening the next mutually exclusive menu.
  if (reset || !window.__portalValidatorVisitedControls) {
    window.__portalValidatorVisitedControls = new WeakSet();
  }
  const visited = window.__portalValidatorVisitedControls;
  const visible = element => {
    const style = getComputedStyle(element);
    const bounds = element.getBoundingClientRect();
    return !element.closest('[hidden], [inert], [aria-hidden="true"]') &&
      style.display !== 'none' && style.visibility !== 'hidden' &&
      bounds.width > 0 && bounds.height > 0;
  };
  const controls = () => {
    const values = [];
    const visit = (root) => {
      for (const element of root.querySelectorAll(selector)) {
        // A collapsed child may precede its opener in DOM order. Do not mark
        // it visited until it is visible and can actually be inspected.
        if (!visited.has(element) && visible(element)) values.push(element);
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
    const unsafe = element.closest('form') || element.hasAttribute('disabled') ||
      element.getAttribute('aria-disabled') === 'true' || element.hasAttribute('href') ||
      element.hasAttribute('data-href') || element.hasAttribute('data-url') ||
      element.hasAttribute('routerlink') || element.hasAttribute('data-route') ||
      !label || style.display === 'none' || style.visibility === 'hidden' ||
      bounds.width <= 0 || bounds.height <= 0 ||
      Array.from(dangerous).some(word =>
        (' ' + normalizedLabel.replace(/[^a-z0-9]+/g, ' ').trim() + ' ').includes(' ' + word + ' '));
    // Tabs with a real controlled panel are queued independently. Clicking
    // them here would issue their natural POST twice and attribute it to the
    // parent instead of the view. Menu expanders remain discovery actions.
    const panel = (element.getAttribute('aria-controls') || element.getAttribute('data-bs-target') ||
      element.getAttribute('data-target') || element.getAttribute('href') || '').replace(/^#/, '');
    if (element.getAttribute('role') === 'tab' && panel && !/[\s/?!]/.test(panel) &&
        element.getRootNode().querySelector('#' + CSS.escape(panel))) continue;
    if (unsafe) { skipped += 1; continue; }
    const before = window.location.href;
    element.click();
    await new Promise(resolve => setTimeout(resolve, 50));
    const after = window.location.href;
    if (after !== before) {
      transitions.push({
        url: after,
        label,
        accessibleName: ariaLabel.slice(0, 160),
        labelSource: ariaLabel ? 'aria-label' : visibleLabel ? 'visible-text' :
          titleLabel ? 'title' : 'none',
        source: 'safe-click'
      });
    }
    activated += 1;
  }
  return {activated, skipped, inspected, transitions};
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


SEMANTIC_ROUTE_ACTIVATION_SCRIPT = r"""
({target, expectedLabel, source}) => {
  const candidate = new URL(target, document.baseURI);
  const dangerous = new Set([
    'add','approve','buy','cancel','checkout','confirm','create','delete','deploy','destroy',
    'disable','edit','enable','execute','export','import','logout','pay','purchase','reboot',
    'reject','remove','restart','save','send','sign out','signout','start','stop','submit',
    'terminate','update','upload'
  ]);
  const selector = [
    'a[href]', 'area[href]', '[role="link"][href]', '[role="link"][data-href]',
    'nav [data-url]', '[role="navigation"] [data-url]', '[role="menuitem"][data-href]',
    '[role="tab"][data-href]', '[routerlink]',
    'nav [data-route]', '[role="navigation"] [data-route]',
    '[role="menuitem"][data-route]', '[role="tab"][data-route]',
    '[role="menuitem"]', '[role="tab"]', 'nav button[aria-controls]',
    '[role="navigation"] button[aria-controls]', '[role="menuitem"][aria-controls]',
    '[role="tab"][aria-controls]'
  ].join(',');
  const elements = [];
  const visit = (root) => {
    for (const element of root.querySelectorAll(selector)) elements.push(element);
    for (const element of root.querySelectorAll('*')) {
      if (element.shadowRoot) visit(element.shadowRoot);
    }
  };
  visit(document);
  const expected = (expectedLabel || '').replace(/\s+/g, ' ').trim().toLowerCase();
  const matches = [];
  for (let index = 0; index < elements.length && index < 500; index += 1) {
    const element = elements[index];
    const label = (
      element.getAttribute('aria-label') || element.textContent || element.getAttribute('title') || ''
    ).replace(/\s+/g, ' ').trim().toLowerCase();
    const safetyLabel = [element.getAttribute('aria-label'), element.textContent,
      element.getAttribute('title')].filter(Boolean).join(' ')
      .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
    if (Array.from(dangerous).some(word =>
      (' ' + safetyLabel.replace(/[^a-z0-9]+/g, ' ').trim() + ' ').includes(' ' + word + ' '))) continue;
    if (element.closest('form') || element.hasAttribute('disabled') ||
        element.getAttribute('aria-disabled') === 'true') continue;
    const raw = element.getAttribute('href') || element.getAttribute('data-href') ||
      element.getAttribute('data-url') || element.getAttribute('routerlink') ||
      element.getAttribute('data-route');
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
    if (urlMatches || semanticControl) matches.push(index);
  }
  return matches;
}
"""


async def activate_semantic_route(
    page,
    url: str,
    *,
    label: str | None,
    source: str | None,
    timeout_ms: int,
) -> bool:
    """Use the closest safe user-navigation equivalent when it is unambiguous."""
    indexes = await page.evaluate(
        SEMANTIC_ROUTE_ACTIVATION_SCRIPT,
        {"target": url, "expectedLabel": label or "", "source": source or ""},
    )
    if not isinstance(indexes, list) or not indexes:
        return False
    selector = ",".join((
        "a[href]", "area[href]", '[role="link"][href]',
        '[role="link"][data-href]', "nav [data-url]",
        '[role="navigation"] [data-url]', '[role="menuitem"][data-href]',
        '[role="tab"][data-href]', '[routerlink]',
        'nav [data-route]', '[role="navigation"] [data-route]',
        '[role="menuitem"][data-route]', '[role="tab"][data-route]',
        '[role="menuitem"]', '[role="tab"]', "nav button[aria-controls]",
        '[role="navigation"] button[aria-controls]',
        '[role="menuitem"][aria-controls]', '[role="tab"][aria-controls]',
    ))
    # Playwright CSS locators pierce open shadow roots, matching discovery behavior.
    candidates = page.locator(selector)
    for index in indexes:
        candidate = candidates.nth(int(index))
        if await candidate.is_visible():
            # Once attempted, a click failure must propagate. Retrying another
            # control or falling back to goto could duplicate a natural POST.
            await candidate.click(timeout=min(timeout_ms, 5000))
            return True
    return False


async def expand_safe_navigation(
    page,
    maximum: int,
    *,
    wait_after_action: Callable[[], Awaitable[object]] | None = None,
    maximum_scrolls: int = 3,
    on_routes_discovered: Callable[[list[DiscoveredRoute]], Awaitable[None]] | None = None,
) -> dict[str, object]:
    """Observe each safe panel before opening the next; never guess route URLs.

    The caller supplies its existing deadline/network observation policy. This
    prevents a slow lazy menu from being mistaken for an exhausted route set,
    without inventing a second timeout or weakening read-only interception.
    """
    maximum = max(0, min(int(maximum), 50))
    totals: dict[str, object] = {"activated": 0, "skipped": 0, "inspected": 0, "routes": []}
    routes: list[DiscoveredRoute] = []
    # Collect the initially open panel as well as every subsequently opened
    # panel. A final-document-only snapshot loses accordion/tab branches.
    routes.extend(await discover_page_routes(page, maximum_scrolls))
    if on_routes_discovered is not None:
        await on_routes_discovered(routes.copy())
    while int(totals["activated"]) < maximum and int(totals["inspected"]) < max(25, maximum * 5):
        result = await page.evaluate(
            EXPAND_SAFE_NAVIGATION_SCRIPT, {"reset": int(totals["inspected"]) == 0},
        )
        for key in ("activated", "skipped", "inspected"):
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
        if existing is None or (not existing.label and route.label):
            unique[key] = route
    totals["routes"] = list(unique.values())
    return totals


async def discover_page_routes(page, maximum_scrolls: int = 3) -> list[DiscoveredRoute]:
    """Discover one document or frame; its own URL/baseURI resolves relative links."""
    raw = await page.evaluate(DISCOVER_ROUTES_SCRIPT, max(0, min(maximum_scrolls, 20)))
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
        ))
    return routes


UI_VIEW_CONTROL_SCRIPT = r"""
({panel, label}) => {
  const roots = [document];
  const matches = [];
  for (let i = 0; i < roots.length; i++) {
    const root = roots[i];
    for (const element of root.querySelectorAll('*')) {
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
    for (const element of root.querySelectorAll(
      '[role="tab"], [data-bs-toggle="tab"], [data-toggle="tab"]'
    )) {
      if (element.closest('form') || element.hasAttribute('disabled') ||
          element.getAttribute('aria-disabled') === 'true') continue;
      const raw = element.getAttribute('href') || '';
      if (raw && !raw.startsWith('#')) continue;
      const controlled = (element.getAttribute('aria-controls') ||
        element.getAttribute('data-bs-target') || element.getAttribute('data-target') || raw).replace(/^#/, '');
      const name = (element.getAttribute('aria-label') || element.textContent ||
        element.getAttribute('title') || '').replace(/\s+/g, ' ').trim().slice(0,160);
      const style = getComputedStyle(element), rect = element.getBoundingClientRect();
      if (controlled === panel && name === label && !element.closest('[hidden],[inert],[aria-hidden="true"]') &&
          style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0) {
        matches.push(element);
      }
    }
  }
  return matches.length === 1 ? matches[0] : null;
}
"""


async def activate_ui_view(page, control: dict[str, str], timeout_ms: int) -> None:
    """Activate one evidenced tab, never a form or a speculative button."""
    handle = await page.evaluate_handle(UI_VIEW_CONTROL_SCRIPT, control)
    try:
        element = handle.as_element()
        if element is None:
            raise RuntimeError("Discovered UI tab is not uniquely and safely activatable")
        labels = await element.evaluate("e => [e.textContent,e.getAttribute('aria-label'),e.getAttribute('title')].filter(Boolean).join(' ')")
        if dangerous_control_label(labels):
            raise RuntimeError("Discovered UI tab has an unsafe action label")
        evidence = await element.evaluate(r"""(e, panel) => {
          const p = e.getRootNode().querySelector('#' + CSS.escape(panel));
          const style = p && getComputedStyle(p), rect = p && p.getBoundingClientRect();
          return {requiresSelection:e.hasAttribute('aria-selected'),
            wasHidden:!p || !!p.closest('[hidden],[inert],[aria-hidden="true"]') ||
              style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || rect.height <= 0};
        }""", control["panel"])
        await element.click(timeout=timeout_ms)
        await page.wait_for_function(r"""({element, panel, requiresSelection, wasHidden}) => {
          if (!element.isConnected) return false;
          const target = element.getRootNode().querySelector('#' + CSS.escape(panel));
          if (!target || target.closest('[hidden],[inert],[aria-hidden="true"]')) return false;
          const style = getComputedStyle(target), rect = target.getBoundingClientRect();
          if (style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || rect.height <= 0) return false;
          return requiresSelection ? element.getAttribute('aria-selected') === 'true' :
            wasHidden || element.classList.contains('active') || element.parentElement?.classList.contains('active');
        }""", arg={"element": element, **control, **evidence}, timeout=timeout_ms)
    finally:
        await handle.dispose()


async def perform_route_navigation(
    page,
    url: str,
    mode: str,
    timeout_ms: int,
    *,
    label: str | None = None,
    source: str | None = None,
    view_control: dict[str, str] | None = None,
):
    """Navigate a document or transition an existing SPA document.

    Playwright correctly returns no Response for same-document transitions; callers use
    the returned boolean as the navigation signal instead of fabricating an HTTP result.
    """
    if mode == UI_VIEW_ACTIVATION:
        if view_control is None:
            raise RuntimeError("UI view activation requires an observed tab control")
        response = None
        if normalize_route_url(page.url) != normalize_route_url(url):
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

        def document_response(response):
            if response.request.is_navigation_request() and response.frame == page.main_frame:
                responses.append(response)

        page.on("response", document_response)
        try:
            before_url = page.url
            activated = await activate_semantic_route(page, url, label=label, source=source, timeout_ms=timeout_ms)
            if activated:
                # A real click preserves router handlers and their natural API
                # traffic. Never replay a request or synthesize an HTTP status.
                if responses:
                    return responses[-1], False, "SEMANTIC_CONTROL"
                if before_url == url:
                    raise RuntimeError("Semantic link did not produce a document or route transition")
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
                    await page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
                    return responses[-1], False, "SEMANTIC_CONTROL"
                return None, True, "SEMANTIC_CONTROL"
        finally:
            page.remove_listener("response", document_response)
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
