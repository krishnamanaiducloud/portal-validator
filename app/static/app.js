const byId = (id) => document.getElementById(id);
const form = byId('scan-form');
const authMode = byId('auth-mode');
const authFields = byId('auth-fields');
const runButton = byId('run-button');
const results = byId('results');
const progress = byId('progress');
const toast = byId('toast');
let lastReport = null;
let profileNames = [];
let refreshProfiles = new Set();
let profileMessage = '';
let routeSort = {key:'route_name', direction:1};
let apiSort = {key:'host', direction:1};
let resourceSort = {key:'transfer_size_bytes', direction:-1};
let progressTimer = null;
let activeDrilldown = 'all';
let apiFailureOnly = false;
let activeScanId = null;
let scrollSynchronizers = [];
let inspectedRoute = null;
let inspectTrigger = null;
// Panel preferences contain dimensions only, never report or authentication data.
const panelSizes = {};

function initializeResizablePanel(kind, minimum) {
  const panel = byId(kind === 'route-results' ? 'route-results-panel' : kind);
  const handle = byId(`${kind}-resize`);
  const expand = byId(`${kind}-expand`);
  const storageKey = `portal-validator.${kind}-size`;
  let saved = {};
  try { saved = JSON.parse(sessionStorage.getItem(storageKey) || '{}') || {}; }
  catch (_) { /* Dimensions remain session-local when storage is unavailable. */ }
  const state = {height:Number.isFinite(saved.height) ? saved.height : null, expanded:saved.expanded === true};
  const maximum = () => Math.max(minimum, Math.floor(window.innerHeight * .9));
  const persist = () => {
    try { sessionStorage.setItem(storageKey, JSON.stringify(state)); }
    catch (_) { /* In-memory preferences still work without session storage. */ }
  };
  const apply = () => {
    panel.classList.toggle('expanded', state.expanded);
    if (state.expanded) panel.style.height = `${maximum()}px`;
    else if (state.height !== null) panel.style.height = `${Math.max(minimum, Math.min(maximum(), state.height))}px`;
    else panel.style.removeProperty('height');
    expand.textContent = state.expanded ? 'Collapse' : 'Expand';
    expand.setAttribute('aria-expanded', String(state.expanded));
    handle.setAttribute('aria-valuemin', String(minimum));
    handle.setAttribute('aria-valuemax', String(maximum()));
    handle.setAttribute('aria-valuenow', String(Math.round(panel.getBoundingClientRect().height || state.height || minimum)));
    refreshScrollSync();
  };
  const resize = (height) => {
    state.height = Math.max(minimum, Math.min(maximum(), Math.round(height)));
    state.expanded = false;
    apply();
    persist();
  };
  let drag = null;
  handle.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    drag = {y:event.clientY,height:panel.getBoundingClientRect().height};
    handle.setPointerCapture(event.pointerId);
    handle.focus({preventScroll:true});
    event.preventDefault();
  });
  handle.addEventListener('pointermove', (event) => {
    if (drag) resize(drag.height + event.clientY - drag.y);
  });
  const finishDrag = () => { drag = null; };
  handle.addEventListener('pointerup', finishDrag);
  handle.addEventListener('pointercancel', finishDrag);
  handle.addEventListener('lostpointercapture', finishDrag);
  handle.addEventListener('keydown', (event) => {
    const current = panel.getBoundingClientRect().height;
    const step = event.shiftKey ? 100 : 25;
    const changes = {ArrowUp:current-step,ArrowDown:current+step,Home:minimum,End:maximum()};
    if (!(event.key in changes)) return;
    event.preventDefault();
    resize(changes[event.key]);
  });
  expand.addEventListener('click', () => {
    state.expanded = !state.expanded;
    apply();
    persist();
  });
  window.addEventListener('resize', apply);
  if (window.ResizeObserver && kind === 'route-inspector') {
    // Preserve the existing native CSS resize grip as well as the accessible
    // handle. Only an explicit inline height change represents user resizing.
    new ResizeObserver(() => {
      const height = Number.parseFloat(panel.style.height);
      if (!panel.hidden && !panel.closest('dialog[open]') && !state.expanded && Number.isFinite(height) && height !== state.height) resize(height);
    }).observe(panel);
  }
  panelSizes[kind] = {apply};
  apply();
}

function closeRouteResultsFullscreen() {
  const dialog = byId('route-results-dialog');
  if (!dialog.open) return;
  dialog.close();
  byId('route-results-host').append(byId('route-results-panel'));
  byId('route-results-fullscreen').textContent = 'Full screen';
  byId('route-results-close').hidden = true;
  panelSizes['route-results'].apply();
  byId('route-results-fullscreen').focus({preventScroll:true});
}

function toggleRouteResultsFullscreen() {
  const dialog = byId('route-results-dialog');
  if (dialog.open) { closeRouteResultsFullscreen(); return; }
  dialog.append(byId('route-results-panel'));
  byId('route-results-fullscreen').textContent = 'Exit full screen';
  byId('route-results-close').hidden = false;
  dialog.showModal();
  byId('route-results-close').focus({preventScroll:true});
  refreshScrollSync();
}

const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const splitList = (value) => value.split(',').map((item) => item.trim()).filter(Boolean);
const statusClass = (value) => String(value || 'NOT_TESTED').toLowerCase().replaceAll('_', '-');
const authOutcomes = new Set(['ACCESS_RESTRICTED','AUTH_REQUIRED','AUTH_FAILED','AUTH_TIMEOUT','MFA_REQUIRED','SESSION_EXPIRED']);
const passOutcomes = new Set(['PASS','PASS_WITH_WARNINGS']);
const terminalStates = new Set(['COMPLETED','PARTIAL','FAILED','CANCELLED']);
const numericRouteKeys = new Set(['status','load_ms','api_failures','resource_failure_count','console_count','warning_findings']);
const numericApiKeys = new Set(['calls','status_2xx','status_3xx','status_4xx','status_5xx','network_failures','route_count','allowed_calls','blocked_count','application_bootstrap_phase_count','authentication_phase_count','route_validation_phase_count','session_refresh_phase_count','average_duration_ms','worst_duration_ms']);
const numericResourceKeys = new Set(['transfer_size_bytes','encoded_body_size_bytes','decoded_body_size_bytes','duration_ms','status']);

// Preferences contain column names only, never scan data or credentials. Unknown
// keys default to visible, so a newly introduced column is not silently hidden.
const tableColumns = {
  api: [
    ['method','Method','HTTP method naturally attempted by the application.',true],
    ['host','Host','Sanitized destination hostname.'],
    ['endpoint','Endpoint','Normalized sanitized API path; queries and bodies are not captured.',true],
    ['calls','Calls','Total naturally observed calls for this normalized API.'],
    ['status_2xx','2xx','Successful HTTP responses.'],
    ['status_3xx','3xx','Redirect HTTP responses.'],
    ['status_4xx','4xx','Client-error HTTP responses.'],
    ['status_5xx','5xx','Server-error HTTP responses.'],
    ['network_failures','Network','Unblocked calls that failed without a valid HTTP response.'],
    ['route_count','Routes','Number of distinct logical routes on which this API was observed.'],
    ['allowed_calls','Allowed','Calls permitted by the validator policy.'],
    ['blocked_count','Blocked','Calls prevented by the validator before reaching the target.'],
    ['application_bootstrap_phase_count','Bootstrap Calls','Calls attributed to initial application or microfrontend bootstrap.'],
    ['authentication_phase_count','Auth Calls','Calls attributed to authentication/session establishment.'],
    ['route_validation_phase_count','Route Calls','Calls attributed to normal route activation.'],
    ['session_refresh_phase_count','Refresh Calls','Recognized authentication/session/token-refresh calls; ordinary route calls are not refresh traffic.'],
    ['average_duration_ms','Average Time (ms)','Mean actual completed API response duration in milliseconds; excludes blocked and no-response calls.'],
    ['worst_duration_ms','Worst Time (ms)','Maximum actual completed API response duration in milliseconds.'],
    ['observation_outcome','Health','Aggregated API health; policy-blocked-only calls are NOT_EXECUTED.'],
    ['traffic_role','Traffic role','Evidence-based authentication, challenge, configuration, business, or unclassified traffic; independent of request authorization.'],
    ['policies','Policy','Observed read-only approval/block decisions. No bodies are retained; explicit GraphQL query rules inspect operation types in memory.'],
  ],
  route: [
    ['classification','Status','PASS and PASS_WITH_WARNINGS both count as healthy routes.'],
    ['route_name','Route Name','Route name derived from navigation labels or safe metadata.'],
    ['display_path','Path','Sanitized logical portal route.',true],
    ['navigation_type','Navigation','How the route was activated.'],
    ['status','Document HTTP','Main-document HTTP response, or N/A for a same-document SPA transition.'],
    ['load_ms','Time','Application performance time, excluding intentional validator observation; inspect route timings for the precise basis.'],
    ['api_failures','API','API health for naturally observed route activity.'],
    ['resource_failure_count','Resources','Observed subresource health; separate from main navigation.'],
    ['console_count','Console','JavaScript console/page-error health.'],
    ['authentication_status','Auth','Authentication/session classification.'],
    ['tls_status','TLS','Verified browser TLS trust; not an origin-certificate inspection claim.'],
    ['warning_findings','Warnings','Count and drill-down of sanitized non-fatal findings.'],
    ['details','Details','Route evidence and timing breakdown.'],
  ],
  resource: [
    ['type','Type','Naturally observed browser resource type.'],
    ['host','Host','Sanitized destination hostname.'],
    ['path','Resource','Sanitized resource path; no additional download is made.',true],
    ['transfer_size_bytes','Transfer','Browser transfer bytes, including headers where available. N/A means unknown.'],
    ['encoded_body_size_bytes','Encoded','Compressed response body bytes where available.'],
    ['decoded_body_size_bytes','Decoded','Decompressed response body bytes where available.'],
    ['duration_ms','Duration','Browser-observed resource duration in milliseconds.'],
    ['route','Routes','Logical route on which the resource was observed.'],
    ['status','Status','Observed HTTP status; N/A means no response status was available.'],
    ['size_categories','Size warning','Warnings evaluated against the effective UI-configured byte thresholds.'],
    ['health','Health','Failed resource observations do not automatically fail main-document navigation.'],
  ],
};
const columnPreferences = {};
const tablePagination = Object.fromEntries(['route','api','resource'].map((kind) => [kind, {page:0,size:50,key:''}]));

function paginateTable(kind, items) {
  const state = tablePagination[kind];
  const controls = kind === 'route' ? ['result-search','result-filter','navigation-filter'] : kind === 'api' ? ['api-search','api-method-filter','api-status-filter','api-policy-filter','api-route-filter','api-role-filter','api-failed-only'] : ['resource-search','resource-type-filter','resource-route-filter','resource-status-filter','resource-failed-only','resource-large-only'];
  const filters = controls.map((id) => { const input = byId(id); return input.type === 'checkbox' ? input.checked : input.value; });
  const sort = kind === 'route' ? routeSort : kind === 'api' ? apiSort : resourceSort;
  const key = JSON.stringify([filters,sort,activeDrilldown,apiFailureOnly,items.map((item) => item.route_id || item.canonical_route || item.url || [item.method,item.host,item.endpoint,item.path])]);
  if (key !== state.key) { state.page = 0; state.key = key; }
  const pages = Math.max(1, Math.ceil(items.length / state.size));
  state.page = Math.min(state.page, pages - 1);
  const start = state.page * state.size;
  byId(`${kind}-page-status`).textContent = items.length ? `${start + 1}–${Math.min(start + state.size, items.length)} of ${items.length} · Page ${state.page + 1} of ${pages}` : '0 records';
  byId(`${kind}-page-prev`).disabled = state.page === 0;
  byId(`${kind}-page-next`).disabled = state.page + 1 >= pages;
  return items.slice(start, start + state.size);
}

function loadColumnPreferences(kind) {
  try {
    const value = JSON.parse(localStorage.getItem(`portal-validator.${kind}-columns`) || '{}');
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  } catch (_) { return {}; }
}

function applyColumnVisibility(kind) {
  const columns = tableColumns[kind];
  const table = byId(`${kind}-table-wrap`).querySelector('table');
  columns.forEach(([key,,,required], index) => table.classList.toggle(`hide-column-${index + 1}`, !required && columnPreferences[kind][key] === false));
  document.querySelectorAll(`[data-column-kind="${kind}"]`).forEach((input) => { input.checked = input.disabled || columnPreferences[kind][input.dataset.columnKey] !== false; });
  refreshScrollSync();
}

function saveColumnPreferences(kind) {
  try { localStorage.setItem(`portal-validator.${kind}-columns`, JSON.stringify(columnPreferences[kind])); }
  catch (_) { /* Session-only preferences still work when browser storage is disabled. */ }
  applyColumnVisibility(kind);
}

function setupTableControls(kind) {
  columnPreferences[kind] = loadColumnPreferences(kind);
  const tools = document.querySelector(kind === 'api' ? '.api-tools' : kind === 'resource' ? '.resource-tools' : '.report-tools');
  const headers = document.querySelectorAll(`#${kind}-table-wrap th`);
  tableColumns[kind].forEach(([key,label,description], index) => {
    const header = headers[index];
    if (!header) return;
    header.title = description;
    const button = header.querySelector('button');
    if (button) button.textContent = label;
    else header.textContent = label;
  });
  const controls = document.createElement('div');
  controls.className = 'table-controls';
  controls.innerHTML = `<details class="columns-control" id="${kind}-columns"><summary>Columns</summary><div class="columns-panel"><div class="column-actions"><button type="button" data-column-action="all">Select all</button><button type="button" data-column-action="clear">Clear all</button><button type="button" data-column-action="reset">Reset default</button></div><p>Identifying columns remain visible.</p>${tableColumns[kind].map(([key,label,description,required]) => `<label title="${escapeHtml(description)}"><input type="checkbox" data-column-kind="${kind}" data-column-key="${key}" ${required ? 'disabled' : ''}> ${escapeHtml(label)}</label>`).join('')}</div></details><label class="field density-control"><span>Density</span><select id="${kind}-density" aria-label="${kind === 'api' ? 'API' : kind === 'resource' ? 'Resource' : 'Route'} table density"><option value="compact">Compact</option><option value="comfortable">Comfortable</option></select></label>`;
  tools.append(controls);
  controls.querySelectorAll('[data-column-kind]').forEach((input) => input.addEventListener('change', () => {
    columnPreferences[kind][input.dataset.columnKey] = input.checked;
    saveColumnPreferences(kind);
  }));
  controls.querySelectorAll('[data-column-action]').forEach((button) => button.addEventListener('click', () => {
    const action = button.dataset.columnAction;
    columnPreferences[kind] = action === 'reset' ? {} : Object.fromEntries(tableColumns[kind].map(([key,,,required]) => [key, Boolean(required || action === 'all')]));
    saveColumnPreferences(kind);
  }));
  const table = byId(`${kind}-table-wrap`).querySelector('table');
  table.dataset.density = 'compact';
  const pager = document.createElement('div');
  pager.className = 'table-pagination';
  pager.innerHTML = `<label class="field"><span>Rows per page</span><select id="${kind}-page-size" aria-label="${kind} rows per page"><option>25</option><option selected>50</option><option>100</option><option>250</option></select></label><button type="button" class="secondary" id="${kind}-page-prev">Previous</button><span id="${kind}-page-status" role="status" aria-live="polite"></span><button type="button" class="secondary" id="${kind}-page-next">Next</button>`;
  byId(`${kind}-table-wrap`).after(pager);
  const render = kind === 'route' ? renderRows : kind === 'api' ? renderApiInventory : renderResourceDetails;
  byId(`${kind}-page-size`).addEventListener('change', (event) => { tablePagination[kind].size = Number(event.target.value); tablePagination[kind].page = 0; render(); });
  byId(`${kind}-page-prev`).addEventListener('click', () => { tablePagination[kind].page -= 1; render(); });
  byId(`${kind}-page-next`).addEventListener('click', () => { tablePagination[kind].page += 1; render(); });
  byId(`${kind}-density`).addEventListener('change', (event) => { table.dataset.density = event.target.value; refreshScrollSync(); });
  applyColumnVisibility(kind);
}

function addReadPostOperation() {
  const row = document.createElement('div');
  row.className = 'read-post-operation';
  row.innerHTML = '<label class="field"><span>Method</span><select class="operation-method" aria-label="Approved method"><option>POST</option></select></label><label class="field"><span>Host</span><input class="operation-host" placeholder="api.example.net" autocomplete="off" required></label><label class="field"><span>Path type</span><select class="operation-path-type"><option value="path">Exact path</option><option value="path_pattern">Bounded pattern</option></select></label><label class="field"><span>Path</span><input class="operation-path" placeholder="/v1/search" autocomplete="off" required></label><label class="field"><span>Description (optional)</span><input class="operation-description" maxlength="200" placeholder="Owner-approved read operation"></label><button type="button" class="secondary remove-operation">Remove</button>';
  row.querySelector('.remove-operation').addEventListener('click', () => row.remove());
  const graphql = document.createElement('label');
  graphql.className = 'filter-check';
  graphql.innerHTML = '<input type="checkbox" class="operation-graphql"> GraphQL queries only';
  graphql.title = 'Require an explicit GraphQL query; mutations, subscriptions and unverified persisted operations remain blocked. Bodies are never logged or replayed.';
  row.querySelector('.remove-operation').before(graphql);
  byId('read-post-operations').append(row);
}

function approvedReadPostOperations() {
  const rows = [...document.querySelectorAll('.read-post-operation')];
  if (rows.length > 100) throw new Error('At most 100 read-only POST operations may be approved.');
  return rows.map((row) => {
    const host = row.querySelector('.operation-host').value.trim().toLowerCase().replace(/\.$/, '');
    const path = row.querySelector('.operation-path').value.trim();
    const pathType = row.querySelector('.operation-path-type').value;
    if (!host || /[\s/?#@:*]/.test(host) || !/^[a-z0-9.-]+$/.test(host) || host.split('.').some((label) => !label || label.startsWith('-') || label.endsWith('-'))) throw new Error('Approved POST host must be an exact hostname, without a scheme, credentials, port or wildcard.');
    if (!path.startsWith('/') || /[\s?#*\\]/.test(path) || path.includes('//') || path.split('/').some((part) => ['.','..'].includes(part))) throw new Error('Approved POST path must be a normalized absolute path without queries, wildcards, or traversal.');
    if (pathType === 'path_pattern') {
      const segments = path.split('/').filter(Boolean);
      if (segments.filter((segment) => segment !== '{segment}').length < 2 || segments.some((segment) => /[{}]/.test(segment) && segment !== '{segment}')) throw new Error('A bounded POST pattern requires at least two literal path segments and only {segment} placeholders.');
    } else if (/[{}]/.test(path)) throw new Error('Use Bounded pattern for {segment} placeholders.');
    const description = row.querySelector('.operation-description').value.trim();
    return {method:'POST',host,[pathType]:path,...(description ? {description} : {}),...(row.querySelector('.operation-graphql').checked ? {graphql_queries_only:true} : {})};
  });
}

function phaseConfiguration() {
  const configuration = {};
  const fields = {navigation_timeout_ms:'navigation-timeout',authentication_timeout_ms:'authentication-timeout',api_timeout_ms:'api-timeout',readiness_timeout_ms:'readiness-timeout',concurrency_limit:'concurrency-limit'};
  for (const [name,id] of Object.entries(fields)) {
    const input = byId(id);
    if (!input.value.trim()) continue;
    const value = Number(input.value);
    if (!Number.isInteger(value) || value < Number(input.min) || value > Number(input.max)) throw new Error(`${input.closest('label').querySelector('span').textContent} must be an integer between ${input.min} and ${input.max}.`);
    configuration[name] = value;
  }
  const readiness = byId('readiness-selector').value.trim();
  if (readiness) configuration.readiness_selector = readiness;
  const hosts = splitList(byId('authentication-hosts').value);
  if (hosts.length) configuration.authentication_hosts = hosts;
  return configuration;
}

function notify(message, isError = false) {
  toast.textContent = message;
  toast.className = `toast show${isError ? ' error' : ''}`;
  window.setTimeout(() => { toast.className = 'toast'; }, 5200);
}

function sanitizedResponseText(value) {
  return String(value || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 300);
}

async function requestJson(url, options = {}, operation = 'Request') {
  const response = await fetch(url, options);
  const contentType = (response.headers.get('content-type') || '').toLowerCase();
  const raw = await response.text();
  let data = null;
  if (contentType.includes('application/json') && raw) {
    try { data = JSON.parse(raw); }
    catch (_) { data = null; }
  }
  if (!response.ok) {
    const status = `${response.status}${response.statusText ? ` ${response.statusText}` : ''}`;
    let reason = data && typeof data.detail === 'string' ? data.detail : sanitizedResponseText(raw);
    if (response.status === 504) reason = 'The gateway ended this request before it completed. Retry the operation or contact the platform team if short status requests also time out.';
    const error = new Error(`${operation} failed · HTTP ${status}${reason ? ` · ${reason}` : ''}`);
    error.status = response.status;
    throw error;
  }
  if (!contentType.includes('application/json') || data === null) {
    throw new Error(`${operation} failed · The server returned an unexpected non-JSON response.`);
  }
  return data;
}

function renderAuthFields() {
  const profileOptions = profileNames.length
    ? `<option value="">Choose a profile</option>${profileNames.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}${refreshProfiles.has(name) ? ' · auto refresh' : ''}</option>`).join('')}`
    : '<option value="" disabled selected>No valid profiles mounted</option>';
  const profileHelp = profileMessage || 'Profiles are discovered from the read-only /auth mount.';
  const templates = {
    none: '<div class="empty-auth">No credentials will be sent. Best for public portals.</div>',
    basic: '<div class="field-grid"><label class="field"><span>Username</span><input id="auth-username" autocomplete="username"></label><label class="field"><span>Password</span><input id="auth-password" type="password" autocomplete="current-password"></label></div>',
    bearer: '<label class="field"><span>Bearer token</span><input id="auth-token" type="password" autocomplete="off" placeholder="Token is never stored or returned"></label>',
    headers: '<label class="field"><span>Custom headers</span><textarea id="auth-headers" rows="4" placeholder="X-API-Key: value&#10;X-Portal-Context: validation"></textarea><small>One header per line. Unsafe transport headers are blocked.</small></label>',
    cookies: '<label class="field"><span>Session cookies</span><textarea id="auth-cookies" rows="4" placeholder="session_id=value&#10;portal_context=value"></textarea><small>One name=value pair per line, scoped to approved portal hosts.</small></label>',
    storage_state: `<label class="field"><span>Mounted SSO profile</span><select id="auth-profile" ${profileNames.length ? '' : 'disabled'}>${profileOptions}</select><small>${escapeHtml(profileHelp)} A companion profile.refresh.json enables silent browser refresh; refreshed state stays private in the pod.</small></label>`,
  };
  authFields.innerHTML = templates[authMode.value];
}

function readHeaders() {
  const headers = {};
  for (const line of (byId('auth-headers')?.value || '').split('\n')) {
    if (!line.trim()) continue;
    const index = line.indexOf(':');
    if (index < 1) throw new Error('A custom header line is invalid. Use Name: value.');
    headers[line.slice(0, index).trim()] = line.slice(index + 1).trim();
  }
  return headers;
}

function readCookies() {
  return (byId('auth-cookies')?.value || '').split('\n').filter((line) => line.trim()).map((line) => {
    const index = line.indexOf('=');
    if (index < 1) throw new Error('A cookie line is invalid. Use name=value.');
    return {name: line.slice(0, index).trim(), value: line.slice(index + 1).trim()};
  });
}

function authenticationPayload() {
  const mode = authMode.value;
  if (mode === 'basic') return {mode, username: byId('auth-username').value, password: byId('auth-password').value};
  if (mode === 'bearer') return {mode, token: byId('auth-token').value};
  if (mode === 'headers') return {mode, headers: readHeaders()};
  if (mode === 'cookies') return {mode, cookies: readCookies()};
  if (mode === 'storage_state') return {mode, storage_profile: byId('auth-profile').value};
  return {mode: 'none'};
}

function clearTransientCredentials() {
  ['auth-password','auth-token','auth-headers','auth-cookies'].forEach((id) => {
    const input = byId(id);
    if (input) input.value = '';
  });
}

function routeDisplay(item) {
  try {
    const parsed = new URL(item.url);
    return {host:item.host || item.hostname || parsed.host, path:item.display_path || item.route_display_path || `${parsed.pathname}${parsed.search}${parsed.hash}` || '/'};
  } catch (_) { return {host:'', path:item.url}; }
}

function compareValues(left, right, numeric) {
  if (numeric) return Number(left ?? -1) - Number(right ?? -1);
  return String(left ?? '').localeCompare(String(right ?? ''), undefined, {numeric:true, sensitivity:'base'});
}

function updateAriaSort(selector, state, attribute) {
  document.querySelectorAll(selector).forEach((button) => {
    const active = button.dataset[attribute] === state.key;
    button.closest('th').setAttribute('aria-sort', active ? (state.direction === 1 ? 'ascending' : 'descending') : 'none');
  });
}

function matchesOutcome(item, filter) {
  if (filter === 'all') return true;
  if (filter === 'failure') return !passOutcomes.has(item.classification) && !authOutcomes.has(item.classification);
  if (filter === 'auth') return authOutcomes.has(item.classification);
  return item.classification === filter;
}

function matchesDrilldown(item) {
  if (['all','discovered','validated'].includes(activeDrilldown)) return true;
  if (activeDrilldown === 'healthy') return passOutcomes.has(item.classification);
  if (activeDrilldown === 'warnings') return item.classification === 'PASS_WITH_WARNINGS';
  if (activeDrilldown === 'failed') return !passOutcomes.has(item.classification) && !authOutcomes.has(item.classification) && item.page_load_status !== 'NOT_TESTED';
  if (activeDrilldown === 'auth') return authOutcomes.has(item.classification);
  if (activeDrilldown === 'not-tested') return item.page_load_status === 'NOT_TESTED';
  if (activeDrilldown === 'api-failures') return Number(item.api_failures || 0) > 0;
  if (activeDrilldown === 'resource-failures') return Number(item.resource_failure_count || 0) > 0;
  if (activeDrilldown === 'console') return (item.console_errors?.length || 0) + (item.page_errors?.length || 0) > 0;
  if (activeDrilldown === 'slow') return Boolean(item.slow);
  if (activeDrilldown === 'read-only') return Number(item.read_only_blocks || 0) > 0;
  if (activeDrilldown === 'security') return item.security_headers_status === 'WARNING';
  return true;
}

function findingsMarkup(item) {
  if (!item.finding_details?.length) return '<p class="empty-detail">No findings for this route.</p>';
  return `<ul class="finding-list">${item.finding_details.map((finding) => `<li class="severity-${statusClass(finding.severity)}"><strong>${escapeHtml(finding.type)}</strong><span>${escapeHtml(finding.message)}</span>${finding.resource ? `<code>${escapeHtml(finding.resource)}</code>` : ''}${finding.count > 1 ? `<em>×${escapeHtml(finding.count)}</em>` : ''}</li>`).join('')}</ul>`;
}

function detailSection(title, value) {
  if (value === undefined || value === null || (Array.isArray(value) && !value.length)) return '';
  return `<details class="technical-detail"><summary>${escapeHtml(title)}</summary><pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre></details>`;
}

// Diagnostics are selected from the server-sanitized report only. Never read
// credential form inputs, browser storage, or an arbitrary full route object.
function routeDiagnostics(item) {
  return {
    overview: {route_name:item.route_name || item.route_label,classification:item.classification,validation_status:item.validation_status,warning_reasons:routeWarnings(item),finding_details:item.finding_details},
    page_load: {status:item.page_load_status,http_status:item.http_status_display ?? item.status ?? null,render_status:item.render_status,failure_dimension:item.failure_dimension,failure_reason:item.failure_reason},
    navigation: {requested_url:item.requested_url,discovered_url:item.discovered_url,final_url:item.final_url,redirects:item.redirects,type:item.navigation_type,status:item.navigation_status,identity:{route_id:item.route_id,view_type:item.view_type,canonical_route:item.canonical_route,display_path:item.display_path,origin:item.origin,host:item.host,pathname:item.pathname,query_sanitized:item.query_sanitized,fragment:item.fragment,spa_route:item.spa_route,route_name:item.route_name,route_name_source:item.route_name_source,route_name_confidence:item.route_name_confidence,discovery_sources:item.discovery_sources,duplicate_discovery_count:item.duplicate_discovery_count,depth:item.depth}},
    authentication: {status:item.authentication_status,stage:item.authentication_stage},
    apis: {status:item.api_status,coverage:item.api_coverage,observed:item.apis_observed,application_observed:item.application_apis_observed,blocked:item.blocked_api_attempts,failures:item.api_failures,requests:item.api_requests,read_only_status:item.read_only_status,read_only_blocks:item.read_only_blocks},
    resources: {status:item.resource_status,failures:item.resource_failure_count,observations:item.resources,failed_resources:item.failed_resources,frames:item.frames,external_links:item.external_links},
    console: {status:item.console_status,messages:item.console_errors,page_errors:item.page_errors},
    tls: {status:item.tls_status,basis:item.tls_basis},
    security_headers: {status:item.security_headers_status,findings:item.security_headers},
    performance: {application_navigation_ms:item.application_navigation_ms ?? item.navigation_ms,application_settle_ms:item.application_settle_ms,validator_overhead_ms:item.validator_overhead_ms,validator_observation_ms:item.validator_observation_ms,total_validation_ms:item.total_validation_ms,application_load_ms:item.application_load_ms,render_health:item.render_health,timings:item.timings},
  };
}

function inspectSection(title, value) {
  const entries = Object.entries(value || {}).filter(([,entry]) => entry !== undefined);
  const content = entries.length ? `<dl>${entries.map(([key,entry]) => `<div><dt>${escapeHtml(key.replaceAll('_', ' '))}</dt><dd>${entry !== null && typeof entry === 'object' ? `<pre>${escapeHtml(JSON.stringify(entry, null, 2))}</pre>` : escapeHtml(entry ?? 'Not recorded')}</dd></div>`).join('')}</dl>` : '<p class="empty-detail">No observations recorded.</p>';
  return `<section class="inspect-section"><h4>${escapeHtml(title)}</h4>${content}</section>`;
}

function showRouteInspector(item, trigger) {
  closeRouteInspector(false);
  inspectedRoute = routeDiagnostics(item);
  inspectTrigger = trigger;
  trigger.setAttribute('aria-expanded', 'true');
  const panel = byId('route-inspector');
  const title = item.route_name || item.route_label || item.display_path || 'Route';
  byId('route-inspector-title').textContent = `Inspect: ${title}`;
  byId('route-inspector-content').innerHTML = [
    inspectSection('1. Overview', inspectedRoute.overview),
    inspectSection('2. Page load', inspectedRoute.page_load),
    inspectSection('3. Navigation', inspectedRoute.navigation),
    inspectSection('4. Authentication', inspectedRoute.authentication),
    inspectSection('5. APIs', inspectedRoute.apis),
    inspectSection('6. Resources', inspectedRoute.resources),
    inspectSection('7. Console', inspectedRoute.console),
    inspectSection('8. TLS', inspectedRoute.tls),
    inspectSection('9. Security headers', inspectedRoute.security_headers),
    inspectSection('Performance', inspectedRoute.performance),
    `<details class="inspect-raw"><summary>10. Raw sanitized diagnostics</summary><pre>${escapeHtml(JSON.stringify(inspectedRoute, null, 2))}</pre></details>`,
  ].join('');
  panel.hidden = false;
  panelSizes['route-inspector'].apply();
  if (byId('route-results-dialog').open) toggleInspectorFullscreen();
  byId('route-inspector-content').scrollTop = 0;
  panel.scrollIntoView({block:'nearest'});
  byId('route-inspector-close').focus({preventScroll:true});
}

function closeRouteInspector(restoreFocus = true) {
  const panel = byId('route-inspector');
  const dialog = byId('route-inspector-dialog');
  if (dialog.open) dialog.close();
  byId('route-inspector-host').append(panel);
  panel.hidden = true;
  byId('route-inspector-fullscreen').textContent = 'Full screen';
  inspectTrigger?.setAttribute('aria-expanded', 'false');
  if (restoreFocus && inspectTrigger?.isConnected) inspectTrigger.focus({preventScroll:true});
  inspectTrigger = null;
  inspectedRoute = null;
  byId('route-inspector-content').replaceChildren();
}

function toggleInspectorFullscreen() {
  const dialog = byId('route-inspector-dialog');
  const panel = byId('route-inspector');
  if (dialog.open) {
    dialog.close();
    byId('route-inspector-host').append(panel);
    byId('route-inspector-fullscreen').textContent = 'Full screen';
  } else {
    dialog.append(panel);
    dialog.showModal();
    byId('route-inspector-fullscreen').textContent = 'Exit full screen';
  }
  panelSizes['route-inspector'].apply();
  byId('route-inspector-fullscreen').focus({preventScroll:true});
}

function downloadDiagnostics(value, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], {type:'application/json'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function routeWarnings(item) {
  if (item.classification === 'PASS') return [];
  if (Array.isArray(item.warning_reasons)) return item.warning_reasons;
  // Compatibility for saved reports generated before structured warning reasons.
  return (item.finding_details || [])
    .filter((finding) => !['ERROR','CRITICAL','FAIL'].includes(String(finding.severity || '').toUpperCase()))
    .map((finding) => ({code:finding.type,description:finding.message,severity:finding.severity,affected_component:finding.resource || 'ROUTE',evidence:undefined}));
}

function warningReasonsMarkup(item) {
  const warnings = routeWarnings(item);
  if (!warnings.length) return '<p class="empty-detail">No non-blocking warning reasons were recorded.</p>';
  return `<ul class="finding-list warning-reasons">${warnings.map((warning) => `<li><strong>${escapeHtml(warning.code || 'OTHER_NON_BLOCKING_WARNING')}</strong><span>${escapeHtml(warning.description || warning.message || 'Non-blocking warning')}</span><small>${escapeHtml(warning.severity || 'WARNING')} · ${escapeHtml(warning.affected_component || 'ROUTE')}</small>${warning.threshold != null ? `<small>Configured threshold: ${escapeHtml(typeof warning.threshold === 'object' ? `${warning.threshold.value ?? 'N/A'} ${warning.threshold.unit || ''}` : warning.threshold)}</small>` : ''}${warning.evidence != null ? detailSection('Safe evidence', warning.evidence) : ''}</li>`).join('')}</ul>`;
}

function showRouteWarnings(item) {
  byId('evidence-title').textContent = `Warnings (${routeWarnings(item).length}): ${item.display_path || routeDisplay(item).path}`;
  byId('evidence-content').innerHTML = `<p class="warning-health-note">Non-blocking warnings: this route remains healthy.</p>${warningReasonsMarkup(item)}`;
  byId('evidence-panel').hidden = false;
  scrollAndFocus(byId('evidence-panel'));
}

function renderRows() {
  if (!lastReport) return;
  const query = byId('result-search').value.trim().toLowerCase();
  const filter = byId('result-filter').value;
  const navigationFilter = byId('navigation-filter').value;
  let rows = [...lastReport.results].map((item) => ({...item, warning_findings:routeWarnings(item).length, console_count:(item.console_errors?.length || 0) + (item.page_errors?.length || 0)})).filter((item) => {
    const haystack = `${item.url} ${item.route_name || ''} ${item.display_path || ''} ${item.document_title || item.title || ''} ${item.navigation_label || item.route_label || ''} ${item.classification} ${item.failure_reason || ''}`.toLowerCase();
    return (!query || haystack.includes(query)) && matchesOutcome(item, filter) && matchesDrilldown(item) && (navigationFilter === 'all' || item.navigation_type === navigationFilter);
  });
  rows.sort((left, right) => {
    const key = routeSort.key;
    const leftValue = key === 'route_name' ? (left.route_name || left.route_label) : key === 'display_path' ? routeDisplay(left).path : left[key];
    const rightValue = key === 'route_name' ? (right.route_name || right.route_label) : key === 'display_path' ? routeDisplay(right).path : right[key];
    return compareValues(leftValue, rightValue, numericRouteKeys.has(key)) * routeSort.direction;
  });
  updateAriaSort('[data-sort]', routeSort, 'sort');
  rows = paginateTable('route', rows);
  closeRouteInspector(false);
  byId('result-list').innerHTML = rows.map((item) => {
    const route = routeDisplay(item);
    const failure = item.failure_reason ? `<small class="failure-reason"><b>${escapeHtml(item.failure_dimension || 'VALIDATION')}</b>${escapeHtml(item.failure_reason)}</small>` : '';
    return `<tr class="route-row outcome-${statusClass(item.classification)}"><td><span class="outcome-badge ${statusClass(item.classification)}">${escapeHtml(item.classification)}</span>${failure}</td><td class="route-name-cell"><strong>${escapeHtml(item.route_name || item.route_label || 'Unnamed route')}</strong><small>${escapeHtml(item.route_name_source || 'FALLBACK')}</small></td><td class="route-cell"><span>${escapeHtml(route.host)}</span><code>${escapeHtml(route.path)}</code></td><td><span class="dimension-state ${statusClass(item.navigation_status)}">${escapeHtml(item.navigation_type || 'DOCUMENT_NAVIGATION')}</span></td><td><strong class="http-status">${escapeHtml(item.http_status_display ?? item.status ?? 'N/A')}</strong></td><td><span class="time-value ${item.slow ? 'slow' : ''}">${escapeHtml(item.load_ms ?? '—')} ms</span></td><td><span class="dimension-state ${statusClass(item.api_status)}">${escapeHtml(item.api_status)}</span></td><td><span class="dimension-state ${statusClass(item.resource_status)}">${escapeHtml(item.resource_status)}</span></td><td><span class="dimension-state ${statusClass(item.console_status)}">${escapeHtml(item.console_status)}</span></td><td><span class="dimension-state ${statusClass(item.authentication_status)}">${escapeHtml(item.authentication_status)}</span></td><td><span class="dimension-state ${statusClass(item.tls_status)}">${escapeHtml(item.tls_status)}</span></td><td><strong>${escapeHtml(item.warning_findings || 0)}</strong></td><td><button type="button" class="secondary route-inspect" aria-expanded="false" aria-controls="route-inspector" aria-label="Inspect ${escapeHtml(item.route_name || item.display_path || 'route')}">Inspect</button></td></tr>`;
  }).join('') || '<tr><td colspan="13" class="empty-table">No routes match this filter.</td></tr>';
  byId('result-list').querySelectorAll('.route-row').forEach((row, index) => {
    const item = rows[index];
    const inspect = row.querySelector('.route-inspect');
    inspect.addEventListener('click', () => showRouteInspector(item, inspect));
    const warnings = routeWarnings(item);
    if (!Number(item.warning_findings || 0)) return;
    const cell = row.children[11];
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'warning-count';
    button.textContent = item.warning_findings;
    button.setAttribute('aria-label', `Show ${item.warning_findings} warnings for ${item.route_name || item.display_path || 'route'}`);
    const warningDescription = warnings.map((warning) => warning.description || warning.message || warning.code).join('\n');
    button.title = warningDescription;
    button.addEventListener('click', () => showRouteWarnings(item));
    cell.replaceChildren(button);
    const summary = document.createElement('small');
    summary.className = 'warning-summary';
    summary.textContent = [...new Set(warnings.map((warning) => String(warning.code || 'WARNING').toLowerCase().replaceAll('_', ' ')))].join(', ');
    summary.title = warningDescription;
    cell.append(summary);
    if (item.classification === 'PASS_WITH_WARNINGS') {
      const badge = row.querySelector('.outcome-badge');
      badge.tabIndex = 0; badge.setAttribute('role', 'button');
      badge.textContent = `PASS WITH WARNINGS (${warnings.length})`;
      badge.title = warningDescription;
      badge.addEventListener('click', () => showRouteWarnings(item));
      badge.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); showRouteWarnings(item); } });
    }
  });
  refreshScrollSync();
}

function updateApiRouteFilter(inventory) {
  const select = byId('api-route-filter');
  if (!select) return;
  const current = select.value;
  const routes = [...new Set(inventory.flatMap((item) => item.routes_using_endpoint || []))].sort();
  select.innerHTML = `<option value="all">All routes</option>${routes.map((route) => `<option value="${escapeHtml(route)}">${escapeHtml(route)}</option>`).join('')}`;
  if (routes.includes(current)) select.value = current;
}

function updateApiMethodFilter(inventory) {
  const select = byId('api-method-filter');
  const current = select.value;
  const methods = [...new Set(['GET','POST',...inventory.map((item) => item.method).filter(Boolean)])].sort();
  select.innerHTML = `<option value="all">All methods</option>${methods.map((method) => `<option value="${escapeHtml(method)}">${escapeHtml(method)}</option>`).join('')}`;
  if (methods.includes(current)) select.value = current;
}

function apiDisplayPolicies(item) {
  // Reports retain legacy internal names for compatibility. Normalize only the
  // presentation/filter boundary; this does not grant any request approval.
  const aliases = {APPROVED_READ_POST:'APPROVED_READ_ONLY',APPROVED_READ_REQUEST:'APPROVED_READ_ONLY',BLOCKED_MUTATION:'READ_ONLY_BLOCKED',READ_ONLY_BLOCK:'READ_ONLY_BLOCKED'};
  const names = [...(Array.isArray(item.policy_classifications) ? item.policy_classifications : []),...(Array.isArray(item.policies) ? item.policies : []),...Object.keys(item.classification_counts || {})];
  return [...new Set(names.filter((name) => typeof name === 'string').map((name) => aliases[name] || name))].sort();
}

function renderApiInventory() {
  const inventory = lastReport?.api_inventory || [];
  const posts = lastReport?.summary?.post_summary || {};
  [['observed_calls','Observed POST'],['approved_read_only_calls','Approved read-only POST'],['executed_approved_calls','Executed approved POST']].forEach(([key,label]) => {
    const value = Number.isFinite(posts[key]) ? posts[key] : 'Not recorded';
    byId(`post-summary-${key}`).textContent = String(value);
    byId(`post-summary-${key}`).setAttribute('aria-label', `${label}: ${value}`);
  });
  const roleFilter = byId('api-role-filter');
  const previousRole = roleFilter.value;
  const roles = [...new Set(inventory.map((item) => item.traffic_role || 'UNCLASSIFIED'))].sort();
  roleFilter.innerHTML = `<option value="all">All traffic</option>${roles.map((role) => `<option value="${escapeHtml(role)}">${escapeHtml(role)}</option>`).join('')}`;
  if (roles.includes(previousRole)) roleFilter.value = previousRole;
  const search = byId('api-search').value.trim().toLowerCase();
  const method = byId('api-method-filter').value;
  const health = byId('api-status-filter').value;
  const policy = byId('api-policy-filter').value;
  const trafficRole = roleFilter.value;
  const route = byId('api-route-filter')?.value || 'all';
  const failedOnly = apiFailureOnly || byId('api-failed-only').checked;
  let visible = inventory.filter((item) => {
    const outcome = item.observation_outcome || (item.health === 'DEGRADED' ? 'WARNING' : item.health);
    const policies = apiDisplayPolicies(item);
    const targetFailure = Number(item.status_4xx || 0) + Number(item.status_5xx || 0) + Number(item.network_failures || 0) + Number(item.response_body_failures || 0) > 0;
    return (!search || `${item.host} ${item.endpoint}`.toLowerCase().includes(search))
      && (method === 'all' || item.method === method)
      && (health === 'all' || outcome === health)
      && (trafficRole === 'all' || (item.traffic_role || 'UNCLASSIFIED') === trafficRole)
      && (policy === 'all' || (policy === 'blocked' ? Number(item.blocked_count || 0) > 0 : policy === 'approved-post' ? item.method === 'POST' && policies.includes('APPROVED_READ_ONLY') : policy === 'target-failures' ? targetFailure : Number(item.allowed_calls ?? item.calls ?? 0) > 0))
      && (route === 'all' || (item.routes_using_endpoint || []).includes(route))
      && (!failedOnly || ['FAILED','WARNING'].includes(outcome));
  });
  visible.sort((left, right) => compareValues(left[apiSort.key], right[apiSort.key], numericApiKeys.has(apiSort.key)) * apiSort.direction);
  updateAriaSort('[data-api-sort]', apiSort, 'apiSort');
  byId('api-count').textContent = visible.length === inventory.length ? `${inventory.length} unique APIs observed` : `${visible.length} of ${inventory.length} unique APIs observed`;
  visible = paginateTable('api', visible);
  byId('api-list').innerHTML = visible.map((item, index) => {
    const outcome = item.observation_outcome || (item.health === 'DEGRADED' ? 'WARNING' : item.health);
    // The observation outcome distinguishes a blocked attempt from a sent
    // request that was canceled or remained incomplete. Legacy aggregate
    // health must not erase that execution evidence.
    const healthLabel = outcome;
    const numbers = [item.calls,item.status_2xx,item.status_3xx,item.status_4xx,item.status_5xx,item.network_failures,item.route_count,item.allowed_calls ?? Math.max(0, Number(item.calls || 0) - Number(item.blocked_count || 0)),item.blocked_count || 0,item.application_bootstrap_phase_count || 0,item.authentication_phase_count || 0,item.route_validation_phase_count ?? item.validation_phase_count ?? 0,item.session_refresh_phase_count || 0,item.average_duration_ms ?? 'N/A',item.worst_duration_ms ?? 'N/A'];
    const policies = apiDisplayPolicies(item);
    return `<tr><td><strong>${escapeHtml(item.method)}</strong></td><td>${escapeHtml(item.host)}</td><td><button class="api-endpoint" type="button" data-api-index="${index}" title="${escapeHtml(item.endpoint)}">${escapeHtml(item.endpoint)}</button></td>${numbers.map((value) => `<td>${escapeHtml(value)}</td>`).join('')}<td><span class="dimension-state ${statusClass(healthLabel)}">${escapeHtml(healthLabel)}</span></td><td class="api-role-cell">${escapeHtml(item.traffic_role || 'UNCLASSIFIED')}</td><td class="api-policy-cell">${escapeHtml(policies.join(', ') || 'N/A')}</td></tr>`;
  }).join('') || `<tr><td colspan="21" class="empty-table">${method === 'POST' && !inventory.some((item) => item.method === 'POST') ? 'No POST requests were observed for this scan.' : failedOnly || policy === 'target-failures' ? 'No target API failures match these filters.' : 'No API requests match these filters.'}</td></tr>`;
  byId('api-list').querySelectorAll('[data-api-index]').forEach((button) => button.addEventListener('click', () => {
    const item = visible[Number(button.dataset.apiIndex)];
    showEvidence(`${item.method} ${item.host}${item.endpoint}`, item);
    byId('evidence-content').insertAdjacentHTML('afterbegin', inspectSection('Request lifecycle', {traffic_role:item.traffic_role || 'UNCLASSIFIED',traffic_roles:item.traffic_roles,observed:item.observed_calls ?? item.calls ?? null,allowed:item.allowed_calls ?? null,blocked:item.blocked_calls ?? item.blocked_count ?? null,sent:item.sent_calls ?? null,responded:item.responded_calls ?? null,completed:item.completed_calls ?? null,failed:item.failed_calls ?? null,canceled:item.canceled_calls ?? null,incomplete:item.incomplete_calls ?? null}));
  }));
  refreshScrollSync();
}

function formatBytes(value) {
  if (value === undefined || value === null || !Number.isFinite(Number(value))) return 'N/A';
  if (Number(value) < 1024) return `${Number(value)} B`;
  if (Number(value) < 1048576) return `${(Number(value) / 1024).toFixed(1)} KiB`;
  return `${(Number(value) / 1048576).toFixed(2)} MiB`;
}

function resourceIsFailed(item) {
  return Boolean(item.failed || item.failure_category || item.failure) || Number(item.status || 0) >= 400;
}

function renderResourceDetails() {
  const details = lastReport?.resource_details || [];
  const filter = byId('resource-type-filter').value;
  const largeOnly = byId('resource-large-only').checked;
  const search = byId('resource-search').value.trim().toLowerCase();
  const route = byId('resource-route-filter').value;
  const status = byId('resource-status-filter').value;
  const failedOnly = byId('resource-failed-only').checked;
  const knownTypes = new Set(['image','script','stylesheet','font','xhr','fetch']);
  let visible = details.filter((item) => {
    const type = String(item.type || item.resource_type || '').toLowerCase();
    return (filter === 'all' || (filter === 'failed' ? resourceIsFailed(item) : filter === 'api' ? ['xhr','fetch'].includes(type) : filter === 'other' ? !knownTypes.has(type) : type === filter))
      && (!search || `${item.host} ${item.path || item.endpoint || ''} ${item.content_type || ''}`.toLowerCase().includes(search))
      && (route === 'all' || item.route === route)
      && (status === 'all' || (status === 'unknown' ? item.status == null : Math.floor(Number(item.status) / 100) === Number(status)))
      && (!failedOnly || resourceIsFailed(item))
      && (!largeOnly || Boolean(item.size_categories?.length));
  }).sort((left, right) => compareValues(left[resourceSort.key], right[resourceSort.key], numericResourceKeys.has(resourceSort.key)) * resourceSort.direction);
  updateAriaSort('[data-resource-sort]', resourceSort, 'resourceSort');
  byId('resource-count').textContent = `${visible.length} of ${details.length} resource observations`;
  visible = paginateTable('resource', visible);
  byId('resource-list').innerHTML = visible.map((item) => `<tr><td>${escapeHtml(item.type || item.resource_type || 'OTHER')}</td><td>${escapeHtml(item.host || '')}</td><td class="resource-path" title="${escapeHtml(item.content_type || 'Content type unavailable')}"><code>${escapeHtml(item.path || item.endpoint || item.url || '')}</code></td><td>${escapeHtml(formatBytes(item.transfer_size_bytes))}</td><td>${escapeHtml(formatBytes(item.encoded_body_size_bytes))}</td><td>${escapeHtml(formatBytes(item.decoded_body_size_bytes))}</td><td>${escapeHtml(item.duration_ms == null ? 'N/A' : `${item.duration_ms} ms`)}</td><td class="resource-path">${escapeHtml(item.route || '')}</td><td>${escapeHtml(item.status ?? 'N/A')}</td><td title="${escapeHtml(item.warning_threshold_bytes == null ? 'No size warning' : `Configured threshold: ${formatBytes(item.warning_threshold_bytes)}`)}">${escapeHtml((item.size_categories || []).join(', ') || '—')}</td><td><span class="dimension-state ${resourceIsFailed(item) ? 'warning' : 'pass'}">${resourceIsFailed(item) ? 'WARNING' : 'OBSERVED'}</span></td></tr>`).join('') || '<tr><td colspan="11" class="empty-table">No observed resources match these filters.</td></tr>';
  refreshScrollSync();
}

function renderResourceSummary() {
  const details = lastReport?.resource_details || [];
  const summary = lastReport?.resource_summary || {};
  const routeSelect = byId('resource-route-filter');
  const currentRoute = routeSelect.value;
  const routes = [...new Set(details.map((item) => item.route).filter(Boolean))].sort();
  routeSelect.innerHTML = `<option value="all">All routes</option>${routes.map((route) => `<option value="${escapeHtml(route)}">${escapeHtml(route)}</option>`).join('')}`;
  if (routes.includes(currentRoute)) routeSelect.value = currentRoute;
  const measurable = details.filter((item) => item.transfer_size_bytes != null);
  const total = summary.total_transfer_size_bytes ?? (measurable.length ? measurable.reduce((sum,item) => sum + Number(item.transfer_size_bytes),0) : null);
  const cards = [
    ['Resources Observed',summary.resources_observed ?? details.length],
    ['Total Transfer',formatBytes(total)],
    ['Large Resources',summary.large_resources ?? details.filter((item) => item.size_categories?.length).length],
    ['Large Images',summary.large_images ?? details.filter((item) => item.size_categories?.includes('LARGE_IMAGE')).length],
    ['Large JS Bundles',summary.large_js_bundles ?? details.filter((item) => item.size_categories?.includes('LARGE_JS_BUNDLE')).length],
    ['Large CSS / Fonts',summary.large_css_fonts ?? details.filter((item) => item.size_categories?.includes('LARGE_CSS_FONT') || ['STYLESHEET','FONT'].includes(String(item.type || '').toUpperCase()) && item.size_categories?.length).length],
    ['Resource Failures',summary.resource_failures ?? details.filter(resourceIsFailed).length],
  ];
  byId('resource-summary').innerHTML = cards.map(([label,value]) => `<div class="resource-card"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></div>`).join('');
  const transferCard = byId('resource-summary').children[1];
  transferCard.title = `${summary.resources_with_transfer_size ?? measurable.length} of ${summary.resources_observed ?? details.length} resource observations expose transfer bytes; missing sizes are excluded, so this is a measured subtotal.`;
  renderResourceDetails();
}

function renderSecurityRecommendations() {
  const recommendations = lastReport?.security_recommendations || [];
  byId('security-list').innerHTML = recommendations.map((item) => `<article class="recommendation"><div><span>${escapeHtml(item.severity || 'RECOMMENDATION')}</span><strong>${escapeHtml(item.header || item.type)}</strong></div><p>Recommended content security protection is missing from ${escapeHtml(item.affected_document_count || 0)} document${item.affected_document_count === 1 ? '' : 's'}.</p><dl><dt>Impact</dt><dd>${escapeHtml(item.impact || 'NON_BLOCKING')}</dd><dt>Affected documents</dt><dd>${escapeHtml(item.affected_document_count || 0)}</dd></dl></article>`).join('') || '<p class="empty-detail">No document-level security recommendations were observed.</p>';
  byId('security-raw').textContent = JSON.stringify(recommendations, null, 2);
}

function showEvidence(title, evidence) {
  byId('evidence-title').textContent = title;
  byId('evidence-content').innerHTML = `<pre>${escapeHtml(JSON.stringify(evidence, null, 2))}</pre>`;
  byId('evidence-panel').hidden = false;
  scrollAndFocus(byId('evidence-panel'));
}

function scrollAndFocus(element) {
  element.scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block:'start'});
  if (element.hasAttribute('tabindex')) element.focus({preventScroll:true});
}

function activateSummary(action, value, button) {
  document.querySelectorAll('.metric').forEach((card) => card.classList.remove('selected'));
  button.classList.add('selected');
  activeDrilldown = action;
  apiFailureOnly = action === 'api-failures';
  byId('api-failed-only').checked = apiFailureOnly;
  renderRows();
  renderApiInventory();
  if (action === 'apis' || action === 'api-failures') scrollAndFocus(byId('api-inventory'));
  else if (action === 'security') scrollAndFocus(byId('security-recommendations'));
  else if (action === 'resources') scrollAndFocus(byId('resource-inventory'));
  else if (['discovered','validated','not-tested'].includes(action) && lastReport.coverage) showEvidence('Scan coverage', lastReport.coverage);
  else if (Number(value) === 0) showEvidence('No matching evidence', {message:`No ${action.replaceAll('-', ' ')} were observed during this scan.`});
}

function terminationMessage(coverage) {
  const validated = Number(coverage.routes_validated || 0);
  const discovered = Number(coverage.routes_discovered || validated);
  const notTested = Number(coverage.routes_not_tested ?? coverage.routes_remaining ?? 0);
  const reasons = {MAX_ROUTES_REACHED:'Maximum route limit reached.',SCAN_TIMEOUT:'Total scan time budget was exhausted.',USER_CANCELLED:'The scan was cancelled.',MAX_DEPTH_REACHED:'Maximum discovery depth was reached.',DISCOVERY_EXHAUSTED:'All eligible discovered routes were processed.',AUTHENTICATION_INCOMPLETE:'Authentication did not reach an authorized application page.',AUTH_REQUIRED:'Authentication is required before application coverage can be evaluated.',SESSION_EXPIRED:'The authenticated session expired.',ACCESS_RESTRICTED:'The target restricted browser access; application coverage is limited.',NAVIGATION_BLOCKED:'Navigation was blocked by policy.'};
  return `${reasons[coverage.termination_reason] || coverage.termination_reason || 'Scan finished.'} ${validated} of ${discovered} discovered routes were validated. ${notTested} routes were not tested.`;
}

function renderReport(report) {
  lastReport = report;
  Object.values(tablePagination).forEach((state) => { state.page = 0; state.key = ''; });
  try { byId('result-title').textContent = new URL(report.target).hostname; }
  catch (_) { byId('result-title').textContent = 'Portal health'; }
  const scanDuration = report.summary.total_scan_duration_ms ?? report.scan_timing?.total_scan_ms ?? report.summary.duration_ms;
  const duration = scanDuration > 1000 ? `${(scanDuration / 1000).toFixed(1)}s` : `${scanDuration}ms`;
  const notTested = report.summary.routes_not_tested ?? report.summary.not_tested ?? 0;
  const summaryMetrics = [
    ['Discovered routes', report.summary.routes_discovered, '', 'discovered'], ['Validated routes', report.summary.routes_validated, '', 'validated'], ['Healthy', report.summary.healthy_routes, 'good', 'healthy'], ['Passed with warnings', report.summary.routes_with_warnings, report.summary.routes_with_warnings ? 'warn' : '', 'warnings'], ['Failed', report.summary.failed_pages, report.summary.failed_pages ? 'bad' : 'good', 'failed'], ['Auth issues', report.summary.auth_issues, report.summary.auth_issues ? 'auth' : '', 'auth'], ['Not tested', notTested, notTested ? 'warn' : 'good', 'not-tested'], ['Unique APIs observed', report.summary.unique_apis || 0, '', 'apis'], ['API failures', report.summary.api_failures, report.summary.api_failures ? 'bad' : 'good', 'api-failures'], ['Resources observed', report.summary.unique_resources || 0, '', 'resources'], ['Resource failures', report.summary.resource_failures, report.summary.resource_failures ? 'warn' : 'good', 'resource-failures'], ['Console issues', report.summary.console_failures || 0, report.summary.console_failures ? 'warn' : 'good', 'console'], ['Slow routes', report.summary.slow_pages, report.summary.slow_pages ? 'warn' : 'good', 'slow'], ['Read-only blocks', report.summary.read_only_blocks, report.summary.read_only_blocks ? 'warn' : 'good', 'read-only'], ['Security recommendations', report.summary.security_recommendations || 0, report.summary.security_recommendations ? 'warn' : 'good', 'security'], ['Scan duration', duration, '', 'validated'],
  ];
  byId('summary').innerHTML = summaryMetrics.map(([label, value, kind, action]) => `<button type="button" class="metric ${kind}" data-summary-action="${action}" aria-label="Show ${escapeHtml(label)} evidence"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></button>`).join('');
  byId('summary').querySelectorAll('[data-summary-action]').forEach((button) => button.addEventListener('click', () => activateSummary(button.dataset.summaryAction, button.querySelector('strong').textContent, button)));
  const coverage = report.coverage || {};
  const coverageStatus = coverage.coverage_status || coverage.scan_completeness || 'UNKNOWN';
  const executionStatus = coverage.execution_status || 'FINISHED';
  byId('coverage').innerHTML = `<strong>Coverage: ${escapeHtml(coverageStatus)}</strong><span>Execution: ${escapeHtml(executionStatus)}. ${escapeHtml(terminationMessage(coverage))}</span>`;
  byId('scan-diagnostics-content').innerHTML = `${detailSection('Effective scan configuration', report.scan_configuration || report.scan_config || {})}${detailSection('Scan timing breakdown', report.scan_timing || report.scan_timings || {})}`;
  byId('raw-report').textContent = JSON.stringify(report, null, 2);
  activeDrilldown = 'all';
  apiFailureOnly = false;
  byId('api-failed-only').checked = false;
  // A filter left over from a previous scan must not silently hide new POST
  // observations. Column/density preferences remain separate and persistent.
  ['result-filter','navigation-filter','api-method-filter','api-status-filter','api-policy-filter','api-route-filter','api-role-filter','resource-type-filter','resource-route-filter','resource-status-filter'].forEach((id) => { if (byId(id)) byId(id).value = 'all'; });
  ['result-search','api-search','resource-search'].forEach((id) => { byId(id).value = ''; });
  ['resource-failed-only','resource-large-only'].forEach((id) => { byId(id).checked = false; });
  updateApiMethodFilter(report.api_inventory || []);
  updateApiRouteFilter(report.api_inventory || []);
  renderRows();
  renderApiInventory();
  renderResourceSummary();
  renderSecurityRecommendations();
  results.hidden = false;
  panelSizes['route-results'].apply();
  scrollAndFocus(results);
}

function startProgress() {
  const started = Date.now();
  progress.hidden = false;
  byId('progress-state').textContent = 'QUEUED';
  byId('progress-route').textContent = '';
  progressTimer = window.setInterval(() => { byId('progress-time').textContent = `${Math.round((Date.now() - started) / 1000)}s elapsed`; }, 1000);
}

function updateProgress(status) {
  byId('progress-state').textContent = `${status.state} · ${status.validated} validated · ${status.discovered} discovered · ${status.healthy} healthy · ${status.failed} failed`;
  byId('progress-route').textContent = status.current_route ? `Current: ${status.current_route}` : '';
}

function stopProgress() {
  if (progressTimer) window.clearInterval(progressTimer);
  progressTimer = null;
  progress.hidden = true;
  activeScanId = null;
}

async function pollScan(scanId) {
  let transientFailures = 0;
  while (true) {
    let status;
    try {
      status = await requestJson(`/api/scans/${encodeURIComponent(scanId)}`, {}, 'Scan status request');
      transientFailures = 0;
    } catch (error) {
      transientFailures += 1;
      if (transientFailures >= 3) throw error;
      byId('progress-state').textContent = `Connection interrupted · retrying ${transientFailures}/3`;
      await new Promise((resolve) => window.setTimeout(resolve, 1500));
      continue;
    }
    updateProgress(status);
    if (terminalStates.has(status.state)) {
      if (status.state === 'FAILED') throw new Error(status.error || 'Scan failed before producing a report.');
      return requestJson(`/api/scans/${encodeURIComponent(scanId)}/report`, {}, 'Scan report request');
    }
    await new Promise((resolve) => window.setTimeout(resolve, 1000));
  }
}

function setupScrollSync() {
  scrollSynchronizers.forEach((item) => item.observer?.disconnect());
  scrollSynchronizers = [];
  document.querySelectorAll('[data-scroll-for]').forEach((top) => {
    top.tabIndex = 0;
    const wrap = byId(top.dataset.scrollFor);
    const table = wrap?.querySelector('table');
    if (!wrap || !table) return;
    let syncing = false;
    const update = () => {
      const overflow = wrap.scrollWidth > wrap.clientWidth + 1;
      top.hidden = !overflow;
      top.firstElementChild.style.width = `${wrap.scrollWidth}px`;
      if (overflow) top.scrollLeft = wrap.scrollLeft;
    };
    top.addEventListener('scroll', () => { if (!syncing) { syncing = true; wrap.scrollLeft = top.scrollLeft; syncing = false; } });
    wrap.addEventListener('scroll', () => { if (!syncing) { syncing = true; top.scrollLeft = wrap.scrollLeft; syncing = false; } });
    const observer = window.ResizeObserver ? new ResizeObserver(update) : null;
    observer?.observe(wrap); observer?.observe(table);
    scrollSynchronizers.push({top, wrap, table, observer, update});
    update();
  });
}

function refreshScrollSync() {
  window.requestAnimationFrame(() => scrollSynchronizers.forEach((item) => item.update()));
}

if (!byId('api-route-filter')) {
  const label = document.createElement('label');
  label.className = 'field';
  label.innerHTML = '<span>Observed on route</span><select id="api-route-filter"><option value="all">All routes</option></select>';
  document.querySelector('.api-tools')?.append(label);
}

const apiPolicyHeader = document.createElement('th');
apiPolicyHeader.textContent = 'Policy';
const apiRoleHeader = document.createElement('th');
apiRoleHeader.textContent = 'Traffic role';
document.querySelector('#api-table-wrap thead tr').append(apiRoleHeader);
document.querySelector('#api-table-wrap thead tr').append(apiPolicyHeader);
const apiRoleLabel = document.createElement('label');
apiRoleLabel.className = 'field';
apiRoleLabel.innerHTML = '<span>Traffic role</span><select id="api-role-filter"><option value="all">All traffic</option></select>';
document.querySelector('.api-tools').append(apiRoleLabel);
const postSummary = document.createElement('dl');
postSummary.className = 'api-post-summary';
postSummary.setAttribute('aria-label', 'Observed POST request counts across the complete scan');
postSummary.innerHTML = [['observed_calls','Observed POST'],['approved_read_only_calls','Approved read-only POST'],['executed_approved_calls','Executed approved POST']].map(([key,label]) => `<div><dt>${label}</dt><dd id="post-summary-${key}">Not recorded</dd></div>`).join('');
document.querySelector('.api-tools').before(postSummary);
byId('api-policy-filter').insertAdjacentHTML('beforeend', '<option value="approved-post">Approved read-only POST</option><option value="target-failures">Target failures</option>');
setupTableControls('route');
setupTableControls('api');
setupTableControls('resource');
initializeResizablePanel('route-results', 280);
initializeResizablePanel('route-inspector', 260);
byId('route-results-fullscreen').addEventListener('click', toggleRouteResultsFullscreen);
byId('route-results-close').addEventListener('click', closeRouteResultsFullscreen);
byId('route-results-dialog').addEventListener('cancel', (event) => { event.preventDefault(); closeRouteResultsFullscreen(); });
byId('add-read-post').addEventListener('click', addReadPostOperation);
byId('resource-type-filter').addEventListener('change', renderResourceDetails);
byId('resource-large-only').addEventListener('change', renderResourceDetails);
['resource-search','resource-route-filter','resource-status-filter','resource-failed-only'].forEach((id) => byId(id).addEventListener(id === 'resource-search' ? 'input' : 'change', renderResourceDetails));

authMode.addEventListener('change', renderAuthFields);
byId('result-search').addEventListener('input', renderRows);
byId('result-filter').addEventListener('change', renderRows);
byId('navigation-filter').addEventListener('change', renderRows);
['api-search','api-method-filter','api-status-filter','api-policy-filter','api-route-filter','api-role-filter','api-failed-only'].forEach((id) => byId(id)?.addEventListener(id === 'api-search' ? 'input' : 'change', () => { if (id === 'api-failed-only') apiFailureOnly = false; renderApiInventory(); }));
byId('evidence-close').addEventListener('click', () => { byId('evidence-panel').hidden = true; });
byId('route-inspector-close').addEventListener('click', () => closeRouteInspector());
byId('route-inspector-fullscreen').addEventListener('click', toggleInspectorFullscreen);
byId('route-inspector-dialog').addEventListener('cancel', (event) => { event.preventDefault(); closeRouteInspector(); });
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !byId('route-inspector').hidden) { event.preventDefault(); closeRouteInspector(); }
});
byId('route-inspector-copy').addEventListener('click', async () => {
  if (!inspectedRoute) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(inspectedRoute, null, 2));
    notify('Sanitized route diagnostics copied.');
  } catch (_) { notify('Clipboard unavailable. Download sanitized diagnostics instead.', true); }
});
byId('route-inspector-download').addEventListener('click', () => {
  if (inspectedRoute) downloadDiagnostics(inspectedRoute, 'portal-route-diagnostics.json');
});
document.querySelectorAll('[data-sort]').forEach((button) => button.addEventListener('click', () => { const key = button.dataset.sort; routeSort = {key, direction:routeSort.key === key ? -routeSort.direction : 1}; renderRows(); }));
document.querySelectorAll('[data-api-sort]').forEach((button) => button.addEventListener('click', () => { const key = button.dataset.apiSort; apiSort = {key, direction:apiSort.key === key ? -apiSort.direction : 1}; renderApiInventory(); }));
document.querySelectorAll('[data-resource-sort]').forEach((button) => button.addEventListener('click', () => { const key = button.dataset.resourceSort; resourceSort = {key, direction:resourceSort.key === key ? -resourceSort.direction : 1}; renderResourceDetails(); }));
byId('cancel-button').addEventListener('click', async () => {
  if (!activeScanId) return;
  byId('cancel-button').disabled = true;
  try { await requestJson(`/api/scans/${encodeURIComponent(activeScanId)}/cancel`, {method:'POST'}, 'Cancel scan request'); notify('Cancellation requested. The current route will finish safely.'); }
  catch (error) { notify(error.message, true); }
  finally { byId('cancel-button').disabled = false; }
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if ([...document.querySelectorAll('.read-post-operation input[required]')].some((input) => !input.validity.valid)) byId('read-post-settings').open = true;
  if (!form.reportValidity()) return;
  let payload;
  try {
    payload = {target:byId('target').value.trim(),max_pages:Number(byId('pages').value),max_depth:Number(byId('depth').value),max_redirects:Number(byId('redirects').value),timeout_ms:Number(byId('timeout').value),total_timeout_ms:Number(byId('total-timeout').value),check_links:byId('links').checked,check_console:byId('console').checked,check_resources:byId('resources').checked,check_performance:byId('performance').checked,check_security_headers:byId('headers').checked,allow_subdomains:byId('subdomains').checked,allow_private_networks:byId('private-network').checked,portal_hosts:splitList(byId('portal-hosts').value),resource_hosts:splitList(byId('resource-hosts').value),credential_hosts:splitList(byId('credential-hosts').value),query_parameter_policy:byId('query-policy').value,allowed_query_parameters:splitList(byId('query-parameters').value),slow_page_threshold_ms:Number(byId('slow-threshold').value),render_settle_ms:Number(byId('render-settle').value),max_navigation_actions:Number(byId('navigation-actions').value),max_discovery_scrolls:Number(byId('discovery-scrolls').value),authentication:authenticationPayload(),allow_mutations:false};
    payload.approved_read_post_operations = approvedReadPostOperations();
    Object.assign(payload, phaseConfiguration());
    payload.large_resource_threshold_bytes = Number(byId('large-resource-threshold').value) * 1024;
    payload.large_image_threshold_bytes = Number(byId('large-image-threshold').value) * 1024;
    payload.large_js_threshold_bytes = Number(byId('large-js-threshold').value) * 1024;
    payload.large_css_font_threshold_bytes = Number(byId('large-css-font-threshold').value) * 1024;
    payload.min_observation_ms = Number(byId('min-observation').value);
    payload.network_quiet_ms = Number(byId('network-quiet').value);
  } catch (error) { notify(error.message, true); return; }
  clearTransientCredentials();
  runButton.disabled = true;
  runButton.querySelector('span').textContent = 'Validating…';
  startProgress();
  try {
    const created = await requestJson('/api/scans', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)}, 'Scan request');
    activeScanId = created.scan_id;
    const report = await pollScan(activeScanId);
    renderReport(report);
    const coverage = report.coverage || {};
    notify(`Execution finished · Coverage: ${coverage.coverage_status || coverage.scan_completeness || 'UNKNOWN'} · ${report.summary.routes_validated ?? report.pages} routes validated`);
  } catch (error) { notify(error.message || 'Validation failed', true); }
  finally { stopProgress(); runButton.disabled = false; runButton.querySelector('span').textContent = 'Run validation'; }
});

byId('download-button').addEventListener('click', () => {
  if (!lastReport) return;
  downloadDiagnostics(lastReport, `portal-validation-${lastReport.run_id}.json`);
});

setupScrollSync();
requestJson('/api/auth-profiles', {}, 'Authentication profile request').then((data) => {
  profileNames = data.profiles || [];
  refreshProfiles = new Set(data.refresh_enabled_profiles || []);
  profileMessage = data.message || '';
  if (Number.isInteger(data.maximum_concurrent_scans) && data.maximum_concurrent_scans > 0) {
    byId('concurrency-limit').max = data.maximum_concurrent_scans;
    byId('concurrency-limit').placeholder = `Deployment default (${data.maximum_concurrent_scans})`;
  }
  renderAuthFields();
}).catch(() => renderAuthFields());
