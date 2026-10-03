const byId = (id) => document.getElementById(id);
const form = byId('scan-form');
const authMode = byId('auth-mode');
const authFields = byId('auth-fields');
const runButton = byId('run-button');
const results = byId('results');
const toast = byId('toast');
let lastReport = null;
let profileNames = [];
let profileMessage = '';

const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const splitList = (value) => value.split(',').map((item) => item.trim()).filter(Boolean);
const statusClass = (value) => String(value || 'NOT_TESTED').toLowerCase().replaceAll('_', '-');

function notify(message, isError = false) {
  toast.textContent = message;
  toast.className = `toast show${isError ? ' error' : ''}`;
  window.setTimeout(() => { toast.className = 'toast'; }, 4200);
}

function renderAuthFields() {
  const profileOptions = profileNames.length
    ? `<option value="">Choose a profile</option>${profileNames.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join('')}`
    : '<option value="" disabled selected>No valid profiles mounted</option>';
  const profileHelp = profileMessage || 'Profiles are discovered from the read-only /auth mount.';
  const templates = {
    none: '<div class="empty-auth">No credentials will be sent. Best for public portals.</div>',
    basic: '<div class="field-grid"><label class="field"><span>Username</span><input id="auth-username" autocomplete="username"></label><label class="field"><span>Password</span><input id="auth-password" type="password" autocomplete="current-password"></label></div>',
    bearer: '<label class="field"><span>Bearer token</span><input id="auth-token" type="password" autocomplete="off" placeholder="Token is never stored or returned"></label>',
    headers: '<label class="field"><span>Custom headers</span><textarea id="auth-headers" rows="4" placeholder="X-API-Key: value&#10;X-Portal-Context: validation"></textarea><small>One header per line. Unsafe transport headers are blocked.</small></label>',
    cookies: '<label class="field"><span>Session cookies</span><textarea id="auth-cookies" rows="4" placeholder="session_id=value&#10;portal_context=value"></textarea><small>One name=value pair per line, scoped to the target hostname.</small></label>',
    storage_state: `<label class="field"><span>Mounted SSO profile</span><select id="auth-profile" ${profileNames.length ? '' : 'disabled'}>${profileOptions}</select><small>${escapeHtml(profileHelp)} Profiles must be approved Playwright storage state mounted read-only under /auth.</small></label>`,
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

function renderReport(report) {
  lastReport = report;
  byId('result-title').textContent = new URL(report.target).hostname;
  const duration = report.summary.duration_ms > 1000 ? `${(report.summary.duration_ms / 1000).toFixed(1)}s` : `${report.summary.duration_ms}ms`;
  const summaryMetrics = [
    ['Pages', report.pages, ''],
    ['Loaded', report.summary.loaded, 'good'],
    ['Passed', report.summary.passed_pages, 'good'],
    ['Passed with warnings', report.summary.pass_with_warnings, report.summary.pass_with_warnings ? 'warn' : ''],
    ['Failed', report.summary.failed_pages, report.summary.failed_pages ? 'bad' : 'good'],
    ['Auth required', report.summary.auth_required_pages, report.summary.auth_required_pages ? 'auth' : ''],
    ['Warnings', report.summary.warning_findings, report.summary.warning_findings ? 'warn' : ''],
    ['Errors', report.summary.error_findings, report.summary.error_findings ? 'bad' : ''],
    ['Findings', report.summary.total_findings, ''],
    ['Validation failures', report.summary.validation_failures, report.summary.validation_failures ? 'bad' : 'good'],
    ['Total load time', duration, ''],
  ];
  byId('summary').innerHTML = summaryMetrics.map(([label, value, kind]) => `<div class="metric ${kind}"><strong>${escapeHtml(value)}</strong><span>${label}</span></div>`).join('');

  byId('result-list').innerHTML = report.results.map((item) => {
    const loadStatus = item.page_load_status || 'FAILED_TO_LOAD';
    const validationStatus = item.validation_status || 'NOT_TESTED';
    const httpStatus = item.status ?? 'NOT_TESTED';
    const details = {
      classification: item.classification,
      requested_url: item.requested_url,
      final_url: item.final_url,
      redirect_count: item.redirect_count,
      redirects: item.redirects,
      external_links_found: item.external_links_found,
      external_links: item.external_links,
      error: item.error,
      tls_basis: item.tls_basis,
      tls_detail: item.tls_detail,
      tls: item.tls,
      finding_details: item.finding_details,
      finding_occurrences: item.finding_occurrences,
      console_errors: item.console_errors,
      failed_resources: item.failed_resources,
      missing_security_headers: item.missing_security_headers,
      security_headers: item.security_headers,
    };
    const category = item.category ? `<div><span>Category</span><strong>${escapeHtml(item.category)}</strong></div>` : '';
    return `<details class="result-item outcome-${statusClass(item.classification)} load-${statusClass(loadStatus)} validation-${statusClass(validationStatus)}">
      <summary><span class="result-dot"></span><span class="result-url">${escapeHtml(item.url)}</span><span class="result-meta">${escapeHtml(item.findings)} findings &middot; ${escapeHtml(item.load_ms ?? '—')}ms</span></summary>
      <div class="result-detail">
        <div class="result-overview">
          <div><span>Page Load</span><strong class="state ${statusClass(loadStatus)}">${escapeHtml(loadStatus)}</strong></div>
          <div><span>HTTP</span><strong>${escapeHtml(httpStatus)}</strong></div>
          <div><span>Validation</span><strong class="state ${statusClass(validationStatus)}">${escapeHtml(validationStatus)}</strong></div>
          <div><span>Classification</span><strong class="state ${statusClass(item.classification)}">${escapeHtml(item.classification)}</strong></div>
          <div><span>TLS</span><strong class="state ${statusClass(item.tls_status)}">${escapeHtml(item.tls_status)}</strong></div>
          <div><span>Security Headers</span><strong class="state ${statusClass(item.security_headers_status)}">${escapeHtml(item.security_headers_status)}</strong></div>
          <div><span>Findings</span><strong>${escapeHtml(item.findings)}</strong></div>
          ${category}
        </div>
        <pre>${escapeHtml(JSON.stringify(details, null, 2))}</pre>
      </div>
    </details>`;
  }).join('');
  results.hidden = false;
  results.scrollIntoView({behavior:'smooth', block:'start'});
}

authMode.addEventListener('change', renderAuthFields);
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  let payload;
  try {
    payload = {
      target:byId('target').value.trim(), max_pages:Number(byId('pages').value), max_depth:Number(byId('depth').value), max_redirects:Number(byId('redirects').value), timeout_ms:Number(byId('timeout').value), total_timeout_ms:Number(byId('total-timeout').value),
      check_links:byId('links').checked, check_console:byId('console').checked, check_resources:byId('resources').checked, check_performance:byId('performance').checked, check_security_headers:byId('headers').checked,
      allow_subdomains:byId('subdomains').checked, allow_private_networks:byId('private-network').checked, resource_hosts:splitList(byId('resource-hosts').value), authentication:authenticationPayload(),
      allow_mutations:byId('mutations').checked, mutation_acknowledged:byId('mutation-ack').checked, mutation_endpoint_allowlist:splitList(byId('mutation-paths').value),
    };
  } catch (error) { notify(error.message, true); return; }
  runButton.disabled = true;
  runButton.querySelector('span').textContent = 'Validating...';
  try {
    const response = await fetch('/api/scan', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(payload)});
    const report = await response.json();
    if (!response.ok) throw new Error(typeof report.detail === 'string' ? report.detail : 'Validation failed');
    renderReport(report);
    notify(`Validation complete \u00b7 ${report.pages} page${report.pages === 1 ? '' : 's'} checked`);
  } catch (error) { notify(error.message || 'Validation failed', true); }
  finally { runButton.disabled = false; runButton.querySelector('span').textContent = 'Run validation'; }
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
  profileMessage = data.message || '';
  renderAuthFields();
}).catch(renderAuthFields);
