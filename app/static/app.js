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
let routeSort = {key:'route', direction:1};
let apiSort = {key:'host', direction:1};
let progressTimer = null;
let activeDrilldown = 'all';
let apiFailureOnly = false;
let activeScanId = null;
let scrollSynchronizers = [];

const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const splitList = (value) => value.split(',').map((item) => item.trim()).filter(Boolean);
const statusClass = (value) => String(value || 'NOT_TESTED').toLowerCase().replaceAll('_', '-');
const authOutcomes = new Set(['ACCESS_RESTRICTED','AUTH_REQUIRED','AUTH_FAILED','AUTH_TIMEOUT','MFA_REQUIRED','SESSION_EXPIRED']);
const passOutcomes = new Set(['PASS','PASS_WITH_WARNINGS']);
const terminalStates = new Set(['COMPLETED','PARTIAL','FAILED','CANCELLED']);
const numericRouteKeys = new Set(['status','load_ms','api_failures','resource_failure_count','console_count','warning_findings']);
const numericApiKeys = new Set(['calls','status_2xx','status_3xx','status_4xx','status_5xx','network_failures','route_count','average_duration_ms','worst_duration_ms']);

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
    return {host:item.hostname || parsed.host, path:item.route_display_path || `${parsed.pathname}${parsed.search}${parsed.hash}` || '/'};
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
  if (activeDrilldown === 'healthy') return Boolean(item.passed);
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

function renderRows() {
  if (!lastReport) return;
  const query = byId('result-search').value.trim().toLowerCase();
  const filter = byId('result-filter').value;
  const navigationFilter = byId('navigation-filter').value;
  const rows = [...lastReport.results].map((item) => ({...item, console_count:(item.console_errors?.length || 0) + (item.page_errors?.length || 0)})).filter((item) => {
    const haystack = `${item.url} ${item.title || ''} ${item.route_label || ''} ${item.classification}`.toLowerCase();
    return (!query || haystack.includes(query)) && matchesOutcome(item, filter) && matchesDrilldown(item) && (navigationFilter === 'all' || item.navigation_type === navigationFilter);
  });
  rows.sort((left, right) => {
    const key = routeSort.key;
    return compareValues(key === 'route' ? left.url : left[key], key === 'route' ? right.url : right[key], numericRouteKeys.has(key)) * routeSort.direction;
  });
  updateAriaSort('[data-sort]', routeSort, 'sort');
  byId('result-list').innerHTML = rows.map((item) => {
    const route = routeDisplay(item);
    const detail = {requested_url:item.requested_url,final_url:item.final_url,redirects:item.redirects,navigation_type:item.navigation_type,tls_basis:item.tls_basis,render_health:item.render_health,api_requests:item.api_requests,resources:item.resources,failed_resources:item.failed_resources,frames:item.frames,security_headers:item.security_headers,external_links:item.external_links};
    return `<tr class="route-row outcome-${statusClass(item.classification)}"><td><span class="outcome-badge ${statusClass(item.classification)}">${escapeHtml(item.classification)}</span></td><td class="route-cell"><strong>${escapeHtml(item.title || item.route_label || route.path)}</strong><span>${escapeHtml(route.host)}</span><code>${escapeHtml(route.path)}</code></td><td><span class="dimension-state ${statusClass(item.navigation_status)}">${escapeHtml(item.navigation_type || 'DOCUMENT_NAVIGATION')}</span></td><td><strong class="http-status">${escapeHtml(item.http_status_display ?? item.status ?? 'N/A')}</strong></td><td><span class="time-value ${item.slow ? 'slow' : ''}">${escapeHtml(item.load_ms ?? '—')} ms</span></td><td><span class="dimension-state ${statusClass(item.api_status)}">${escapeHtml(item.api_status)}</span></td><td><span class="dimension-state ${statusClass(item.resource_status)}">${escapeHtml(item.resource_status)}</span></td><td><span class="dimension-state ${statusClass(item.console_status)}">${escapeHtml(item.console_status)}</span></td><td><span class="dimension-state ${statusClass(item.authentication_status)}">${escapeHtml(item.authentication_status)}</span></td><td><span class="dimension-state ${statusClass(item.tls_status)}">${escapeHtml(item.tls_status)}</span></td><td><strong>${escapeHtml(item.warning_findings || 0)}</strong></td><td><details class="route-detail"><summary>Inspect</summary><div class="detail-drawer"><div class="result-overview"><div><span>Page load</span><strong class="state ${statusClass(item.page_load_status)}">${escapeHtml(item.page_load_status)}</strong></div><div><span>Validation</span><strong class="state ${statusClass(item.validation_status)}">${escapeHtml(item.validation_status)}</strong></div><div><span>Render</span><strong class="state ${statusClass(item.render_status)}">${escapeHtml(item.render_status)}</strong></div><div><span>TLS</span><strong class="state ${statusClass(item.tls_status)}">${escapeHtml(item.tls_status)}</strong></div><div><span>Security headers</span><strong class="state ${statusClass(item.security_headers_status)}">${escapeHtml(item.security_headers_status)}</strong></div><div><span>Read-only</span><strong class="state ${statusClass(item.read_only_status)}">${escapeHtml(item.read_only_status)}</strong></div><div><span>Navigation</span><strong>${escapeHtml(item.navigation_type || 'DOCUMENT_NAVIGATION')}</strong></div><div><span>Discovery</span><strong>${escapeHtml(item.route_source || 'route')}</strong></div><div><span>Depth</span><strong>${escapeHtml(item.depth)}</strong></div></div><h3>Findings</h3>${findingsMarkup(item)}${detailSection('Navigation and redirects', {requested_url:item.requested_url,final_url:item.final_url,redirects:item.redirects})}${detailSection('API / XHR', item.api_requests)}${detailSection('Resources', item.resources)}${detailSection('Console', {console:item.console_errors,page_errors:item.page_errors})}${detailSection('Security headers', item.security_headers)}${detailSection('Performance', item.render_health)}${detailSection('Read-only safety', {status:item.read_only_status,blocks:item.read_only_blocks})}<details class="technical-detail"><summary>Technical route data</summary><pre>${escapeHtml(JSON.stringify(detail, null, 2))}</pre></details></div></details></td></tr>`;
  }).join('') || '<tr><td colspan="12" class="empty-table">No routes match this filter.</td></tr>';
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

function renderApiInventory() {
  const inventory = lastReport?.api_inventory || [];
  const search = byId('api-search').value.trim().toLowerCase();
  const method = byId('api-method-filter').value;
  const health = byId('api-status-filter').value;
  const route = byId('api-route-filter')?.value || 'all';
  const failedOnly = apiFailureOnly || byId('api-failed-only').checked;
  const visible = inventory.filter((item) => (!search || `${item.host} ${item.endpoint}`.toLowerCase().includes(search)) && (method === 'all' || item.method === method) && (health === 'all' || item.health === health) && (route === 'all' || (item.routes_using_endpoint || []).includes(route)) && (!failedOnly || item.health !== 'HEALTHY'));
  visible.sort((left, right) => compareValues(left[apiSort.key], right[apiSort.key], numericApiKeys.has(apiSort.key)) * apiSort.direction);
  updateAriaSort('[data-api-sort]', apiSort, 'apiSort');
  byId('api-count').textContent = visible.length === inventory.length ? `${inventory.length} APIs` : `${visible.length} of ${inventory.length} APIs`;
  byId('api-list').innerHTML = visible.map((item, index) => `<tr><td><strong>${escapeHtml(item.method)}</strong></td><td>${escapeHtml(item.host)}</td><td><button class="api-endpoint" type="button" data-api-index="${index}" title="${escapeHtml(item.endpoint)}">${escapeHtml(item.endpoint)}</button></td><td>${escapeHtml(item.calls)}</td><td>${escapeHtml(item.status_2xx)}</td><td>${escapeHtml(item.status_3xx)}</td><td>${escapeHtml(item.status_4xx)}</td><td>${escapeHtml(item.status_5xx)}</td><td>${escapeHtml(item.network_failures)}</td><td>${escapeHtml(item.route_count)}</td><td>${escapeHtml(item.average_duration_ms ?? 'N/A')}</td><td>${escapeHtml(item.worst_duration_ms ?? 'N/A')}</td><td><span class="dimension-state ${statusClass(item.health)}">${escapeHtml(item.health)}</span></td></tr>`).join('') || `<tr><td colspan="13" class="empty-table">${failedOnly ? 'No API failures were observed during this scan.' : 'No API requests match these filters.'}</td></tr>`;
  byId('api-list').querySelectorAll('[data-api-index]').forEach((button) => button.addEventListener('click', () => {
    const item = visible[Number(button.dataset.apiIndex)];
    showEvidence(`${item.method} ${item.host}${item.endpoint}`, item);
  }));
  refreshScrollSync();
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
  else if (action === 'resources') showEvidence('Observed resource inventory', lastReport.resource_inventory || []);
  else if (['discovered','validated','not-tested'].includes(action) && lastReport.coverage) showEvidence('Scan coverage', lastReport.coverage);
  else if (Number(value) === 0) showEvidence('No matching evidence', {message:`No ${action.replaceAll('-', ' ')} were observed during this scan.`});
}

function terminationMessage(coverage) {
  const validated = Number(coverage.routes_validated || 0);
  const discovered = Number(coverage.routes_discovered || validated);
  const notTested = Number(coverage.routes_not_tested ?? coverage.routes_remaining ?? 0);
  const reasons = {MAX_ROUTES_REACHED:'Maximum route limit reached.',SCAN_TIMEOUT:'Total scan time budget was exhausted.',USER_CANCELLED:'The scan was cancelled.',MAX_DEPTH_REACHED:'Maximum discovery depth was reached.',DISCOVERY_EXHAUSTED:'All eligible discovered routes were processed.'};
  return `${reasons[coverage.termination_reason] || coverage.termination_reason || 'Scan finished.'} ${validated} of ${discovered} discovered routes were validated. ${notTested} routes were not tested.`;
}

function renderReport(report) {
  lastReport = report;
  try { byId('result-title').textContent = new URL(report.target).hostname; }
  catch (_) { byId('result-title').textContent = 'Portal health'; }
  const duration = report.summary.duration_ms > 1000 ? `${(report.summary.duration_ms / 1000).toFixed(1)}s` : `${report.summary.duration_ms}ms`;
  const notTested = report.summary.routes_not_tested ?? report.summary.not_tested ?? 0;
  const summaryMetrics = [
    ['Discovered', report.summary.routes_discovered, '', 'discovered'], ['Validated', report.summary.routes_validated, '', 'validated'], ['Healthy', report.summary.healthy_routes, 'good', 'healthy'], ['Recommendations', report.summary.routes_with_warnings, report.summary.routes_with_warnings ? 'warn' : '', 'warnings'], ['Failed', report.summary.failed_pages, report.summary.failed_pages ? 'bad' : 'good', 'failed'], ['Auth issues', report.summary.auth_issues, report.summary.auth_issues ? 'auth' : '', 'auth'], ['Not tested', notTested, notTested ? 'warn' : 'good', 'not-tested'], ['Unique APIs', report.summary.unique_apis || 0, '', 'apis'], ['API failures', report.summary.api_failures, report.summary.api_failures ? 'bad' : 'good', 'api-failures'], ['Resources', report.summary.unique_resources || 0, '', 'resources'], ['Resource failures', report.summary.resource_failures, report.summary.resource_failures ? 'warn' : 'good', 'resource-failures'], ['Console', report.summary.console_failures || 0, report.summary.console_failures ? 'warn' : 'good', 'console'], ['Slow routes', report.summary.slow_pages, report.summary.slow_pages ? 'warn' : 'good', 'slow'], ['Read-only blocks', report.summary.read_only_blocks, report.summary.read_only_blocks ? 'warn' : 'good', 'read-only'], ['Security', report.summary.security_recommendations || 0, report.summary.security_recommendations ? 'warn' : 'good', 'security'], ['Scan time', duration, '', 'validated'],
  ];
  byId('summary').innerHTML = summaryMetrics.map(([label, value, kind, action]) => `<button type="button" class="metric ${kind}" data-summary-action="${action}" aria-label="Show ${escapeHtml(label)} evidence"><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></button>`).join('');
  byId('summary').querySelectorAll('[data-summary-action]').forEach((button) => button.addEventListener('click', () => activateSummary(button.dataset.summaryAction, button.querySelector('strong').textContent, button)));
  const coverage = report.coverage || {};
  byId('coverage').innerHTML = `<strong>${escapeHtml(coverage.scan_completeness || 'UNKNOWN')} SCAN</strong><span>${escapeHtml(terminationMessage(coverage))}</span>`;
  byId('raw-report').textContent = JSON.stringify(report, null, 2);
  activeDrilldown = 'all';
  apiFailureOnly = false;
  byId('api-failed-only').checked = false;
  updateApiRouteFilter(report.api_inventory || []);
  renderRows();
  renderApiInventory();
  renderSecurityRecommendations();
  results.hidden = false;
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

authMode.addEventListener('change', renderAuthFields);
byId('result-search').addEventListener('input', renderRows);
byId('result-filter').addEventListener('change', renderRows);
byId('navigation-filter').addEventListener('change', renderRows);
['api-search','api-method-filter','api-status-filter','api-route-filter','api-failed-only'].forEach((id) => byId(id)?.addEventListener(id === 'api-search' ? 'input' : 'change', () => { if (id === 'api-failed-only') apiFailureOnly = false; renderApiInventory(); }));
byId('evidence-close').addEventListener('click', () => { byId('evidence-panel').hidden = true; });
document.querySelectorAll('[data-sort]').forEach((button) => button.addEventListener('click', () => { const key = button.dataset.sort; routeSort = {key, direction:routeSort.key === key ? -routeSort.direction : 1}; renderRows(); }));
document.querySelectorAll('[data-api-sort]').forEach((button) => button.addEventListener('click', () => { const key = button.dataset.apiSort; apiSort = {key, direction:apiSort.key === key ? -apiSort.direction : 1}; renderApiInventory(); }));
byId('cancel-button').addEventListener('click', async () => {
  if (!activeScanId) return;
  byId('cancel-button').disabled = true;
  try { await requestJson(`/api/scans/${encodeURIComponent(activeScanId)}/cancel`, {method:'POST'}, 'Cancel scan request'); notify('Cancellation requested. The current route will finish safely.'); }
  catch (error) { notify(error.message, true); }
  finally { byId('cancel-button').disabled = false; }
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  let payload;
  try {
    payload = {target:byId('target').value.trim(),max_pages:Number(byId('pages').value),max_depth:Number(byId('depth').value),max_redirects:Number(byId('redirects').value),timeout_ms:Number(byId('timeout').value),total_timeout_ms:Number(byId('total-timeout').value),check_links:byId('links').checked,check_console:byId('console').checked,check_resources:byId('resources').checked,check_performance:byId('performance').checked,check_security_headers:byId('headers').checked,allow_subdomains:byId('subdomains').checked,allow_private_networks:byId('private-network').checked,portal_hosts:splitList(byId('portal-hosts').value),resource_hosts:splitList(byId('resource-hosts').value),credential_hosts:splitList(byId('credential-hosts').value),query_parameter_policy:byId('query-policy').value,allowed_query_parameters:splitList(byId('query-parameters').value),slow_page_threshold_ms:Number(byId('slow-threshold').value),render_settle_ms:Number(byId('render-settle').value),max_navigation_actions:Number(byId('navigation-actions').value),max_discovery_scrolls:Number(byId('discovery-scrolls').value),authentication:authenticationPayload(),allow_mutations:false};
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
    notify(`Validation complete · ${report.pages} route${report.pages === 1 ? '' : 's'} checked`);
  } catch (error) { notify(error.message || 'Validation failed', true); }
  finally { stopProgress(); runButton.disabled = false; runButton.querySelector('span').textContent = 'Run validation'; }
});

byId('download-button').addEventListener('click', () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type:'application/json'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `portal-validation-${lastReport.run_id}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

setupScrollSync();
requestJson('/api/auth-profiles', {}, 'Authentication profile request').then((data) => {
  profileNames = data.profiles || [];
  refreshProfiles = new Set(data.refresh_enabled_profiles || []);
  profileMessage = data.message || '';
  renderAuthFields();
}).catch(() => renderAuthFields());
