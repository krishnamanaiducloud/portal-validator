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
let sortState = {key:'route', direction:1};
let progressTimer = null;

const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const splitList = (value) => value.split(',').map((item) => item.trim()).filter(Boolean);
const statusClass = (value) => String(value || 'NOT_TESTED').toLowerCase().replaceAll('_', '-');
const authOutcomes = new Set(['AUTH_REQUIRED','AUTH_FAILED','AUTH_TIMEOUT','MFA_REQUIRED','SESSION_EXPIRED']);
const passOutcomes = new Set(['PASS','PASS_WITH_WARNINGS']);

function notify(message, isError = false) {
  toast.textContent = message;
  toast.className = `toast show${isError ? ' error' : ''}`;
  window.setTimeout(() => { toast.className = 'toast'; }, 4200);
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
    if (index < 1) throw new Error(`Invalid header line: ${line}`);
    headers[line.slice(0, index).trim()] = line.slice(index + 1).trim();
  }
  return headers;
}

function readCookies() {
  return (byId('auth-cookies')?.value || '').split('\n').filter((line) => line.trim()).map((line) => {
    const index = line.indexOf('=');
    if (index < 1) throw new Error(`Invalid cookie line: ${line}`);
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

function routeDisplay(item) {
  try {
    const parsed = new URL(item.url);
    return {host:parsed.host, path:`${parsed.pathname}${parsed.search}${parsed.hash}` || '/'};
  } catch (_) { return {host:'', path:item.url}; }
}

function matchesOutcome(item, filter) {
  if (filter === 'all') return true;
  if (filter === 'failure') return !passOutcomes.has(item.classification) && !authOutcomes.has(item.classification);
  if (filter === 'auth') return authOutcomes.has(item.classification);
  return item.classification === filter;
}

function findingsMarkup(item) {
  if (!item.finding_details?.length) return '<p class="empty-detail">No findings for this route.</p>';
  return `<ul class="finding-list">${item.finding_details.map((finding) => `<li class="severity-${statusClass(finding.severity)}"><strong>${escapeHtml(finding.type)}</strong><span>${escapeHtml(finding.message)}</span>${finding.resource ? `<code>${escapeHtml(finding.resource)}</code>` : ''}${finding.count > 1 ? `<em>×${escapeHtml(finding.count)}</em>` : ''}</li>`).join('')}</ul>`;
}

function renderRows() {
  if (!lastReport) return;
  const query = byId('result-search').value.trim().toLowerCase();
  const filter = byId('result-filter').value;
  const rows = [...lastReport.results].filter((item) => {
    const haystack = `${item.url} ${item.title || ''} ${item.route_label || ''} ${item.classification}`.toLowerCase();
    return (!query || haystack.includes(query)) && matchesOutcome(item, filter);
  });
  rows.sort((left, right) => {
    const key = sortState.key;
    const leftValue = key === 'route' ? left.url : (left[key] ?? '');
    const rightValue = key === 'route' ? right.url : (right[key] ?? '');
    return String(leftValue).localeCompare(String(rightValue), undefined, {numeric:true}) * sortState.direction;
  });
  byId('result-list').innerHTML = rows.map((item) => {
    const route = routeDisplay(item);
    const signals = [
      item.api_failures ? `${item.api_failures} API` : '',
      item.resource_failure_count ? `${item.resource_failure_count} resource` : '',
      item.console_errors?.length ? `${item.console_errors.length} console` : '',
      item.read_only_blocks ? `${item.read_only_blocks} blocked` : '',
    ].filter(Boolean);
    const detail = {
      requested_url:item.requested_url, final_url:item.final_url, redirects:item.redirects,
      render_health:item.render_health, api_requests:item.api_requests, failed_resources:item.failed_resources,
      frames:item.frames, security_headers:item.security_headers, external_links:item.external_links,
    };
    return `<tr class="route-row outcome-${statusClass(item.classification)}">
      <td class="route-cell"><strong>${escapeHtml(item.route_label || item.title || route.path)}</strong><span>${escapeHtml(route.host)}</span><code>${escapeHtml(route.path)}</code></td>
      <td><span class="outcome-badge ${statusClass(item.classification)}">${escapeHtml(item.classification)}</span></td>
      <td><strong class="http-status">${escapeHtml(item.status ?? '—')}</strong></td>
      <td><span class="time-value ${item.slow ? 'slow' : ''}">${escapeHtml(item.load_ms ?? '—')} ms</span></td>
      <td><div class="signal-list">${signals.length ? signals.map((signal) => `<span>${escapeHtml(signal)}</span>`).join('') : '<span class="quiet">Clean</span>'}</div></td>
      <td><details class="route-detail"><summary>Inspect</summary><div class="detail-drawer"><div class="result-overview"><div><span>Page load</span><strong class="state ${statusClass(item.page_load_status)}">${escapeHtml(item.page_load_status)}</strong></div><div><span>Validation</span><strong class="state ${statusClass(item.validation_status)}">${escapeHtml(item.validation_status)}</strong></div><div><span>TLS</span><strong class="state ${statusClass(item.tls_status)}">${escapeHtml(item.tls_status)}</strong></div><div><span>Security headers</span><strong class="state ${statusClass(item.security_headers_status)}">${escapeHtml(item.security_headers_status)}</strong></div><div><span>Discovery</span><strong>${escapeHtml(item.route_source || 'route')}</strong></div><div><span>Depth</span><strong>${escapeHtml(item.depth)}</strong></div></div><h3>Findings</h3>${findingsMarkup(item)}<details class="technical-detail"><summary>Technical route data</summary><pre>${escapeHtml(JSON.stringify(detail, null, 2))}</pre></details></div></details></td>
    </tr>`;
  }).join('') || '<tr><td colspan="6" class="empty-table">No routes match this filter.</td></tr>';
}

function renderReport(report) {
  lastReport = report;
  try { byId('result-title').textContent = new URL(report.target).hostname; }
  catch (_) { byId('result-title').textContent = 'Portal health'; }
  const duration = report.summary.duration_ms > 1000 ? `${(report.summary.duration_ms / 1000).toFixed(1)}s` : `${report.summary.duration_ms}ms`;
  const summaryMetrics = [
    ['Discovered', report.summary.routes_discovered, ''], ['Validated', report.summary.routes_validated, ''],
    ['Healthy', report.summary.healthy_routes, 'good'], ['Warnings', report.summary.routes_with_warnings, report.summary.routes_with_warnings ? 'warn' : ''],
    ['Failed', report.summary.failed_pages, report.summary.failed_pages ? 'bad' : 'good'], ['Auth issues', report.summary.auth_issues, report.summary.auth_issues ? 'auth' : ''],
    ['API failures', report.summary.api_failures, report.summary.api_failures ? 'bad' : 'good'], ['Resource failures', report.summary.resource_failures, report.summary.resource_failures ? 'warn' : 'good'],
    ['Slow routes', report.summary.slow_pages, report.summary.slow_pages ? 'warn' : 'good'], ['Read-only blocks', report.summary.read_only_blocks, report.summary.read_only_blocks ? 'warn' : 'good'],
    ['Scan time', duration, ''],
  ];
  byId('summary').innerHTML = summaryMetrics.map(([label, value, kind]) => `<div class="metric ${kind}"><strong>${escapeHtml(value)}</strong><span>${label}</span></div>`).join('');
  byId('raw-report').textContent = JSON.stringify(report, null, 2);
  renderRows();
  results.hidden = false;
  results.scrollIntoView({behavior:'smooth', block:'start'});
}

function startProgress() {
  const started = Date.now();
  progress.hidden = false;
  progressTimer = window.setInterval(() => {
    const elapsed = Math.round((Date.now() - started) / 1000);
    byId('progress-time').textContent = `One session · read-only validation · ${elapsed}s elapsed`;
  }, 1000);
}

function stopProgress() {
  if (progressTimer) window.clearInterval(progressTimer);
  progressTimer = null;
  progress.hidden = true;
}

authMode.addEventListener('change', renderAuthFields);
byId('result-search').addEventListener('input', renderRows);
byId('result-filter').addEventListener('change', renderRows);
document.querySelectorAll('[data-sort]').forEach((button) => button.addEventListener('click', () => {
  const key = button.dataset.sort;
  sortState = {key, direction:sortState.key === key ? -sortState.direction : 1};
  renderRows();
}));

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  let payload;
  try {
    payload = {
      target:byId('target').value.trim(), max_pages:Number(byId('pages').value), max_depth:Number(byId('depth').value), max_redirects:Number(byId('redirects').value), timeout_ms:Number(byId('timeout').value), total_timeout_ms:Number(byId('total-timeout').value),
      check_links:byId('links').checked, check_console:byId('console').checked, check_resources:byId('resources').checked, check_performance:byId('performance').checked, check_security_headers:byId('headers').checked,
      allow_subdomains:byId('subdomains').checked, allow_private_networks:byId('private-network').checked, portal_hosts:splitList(byId('portal-hosts').value), resource_hosts:splitList(byId('resource-hosts').value),
      query_parameter_policy:byId('query-policy').value, allowed_query_parameters:splitList(byId('query-parameters').value), slow_page_threshold_ms:Number(byId('slow-threshold').value), render_settle_ms:Number(byId('render-settle').value), max_navigation_actions:Number(byId('navigation-actions').value),
      authentication:authenticationPayload(), allow_mutations:false,
    };
  } catch (error) { notify(error.message, true); return; }
  runButton.disabled = true;
  runButton.querySelector('span').textContent = 'Validating…';
  startProgress();
  try {
    const response = await fetch('/api/scan', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(payload)});
    const report = await response.json();
    if (!response.ok) throw new Error(typeof report.detail === 'string' ? report.detail : 'Validation failed');
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

fetch('/api/auth-profiles').then((response) => response.json()).then((data) => {
  profileNames = data.profiles || [];
  refreshProfiles = new Set(data.refresh_enabled_profiles || []);
  profileMessage = data.message || '';
  renderAuthFields();
}).catch(renderAuthFields);
