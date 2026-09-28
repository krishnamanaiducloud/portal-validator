const byId = (id) => document.getElementById(id);
const form = byId('scan-form');
const authMode = byId('auth-mode');
const authFields = byId('auth-fields');
const runButton = byId('run-button');
const results = byId('results');
const toast = byId('toast');
let lastReport = null;
let profileNames = [];

const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const splitList = (value) => value.split(',').map((item) => item.trim()).filter(Boolean);

function notify(message, isError = false) {
  toast.textContent = message;
  toast.className = `toast show${isError ? ' error' : ''}`;
  window.setTimeout(() => { toast.className = 'toast'; }, 4200);
}

function renderAuthFields() {
  const templates = {
    none: '<div class="empty-auth">No credentials will be sent. Best for public portals.</div>',
    basic: '<div class="field-grid"><label class="field"><span>Username</span><input id="auth-username" autocomplete="username"></label><label class="field"><span>Password</span><input id="auth-password" type="password" autocomplete="current-password"></label></div>',
    bearer: '<label class="field"><span>Bearer token</span><input id="auth-token" type="password" autocomplete="off" placeholder="Token is never stored or returned"></label>',
    headers: '<label class="field"><span>Custom headers</span><textarea id="auth-headers" rows="4" placeholder="X-API-Key: value&#10;X-Portal-Context: validation"></textarea><small>One header per line. Unsafe transport headers are blocked.</small></label>',
    cookies: '<label class="field"><span>Session cookies</span><textarea id="auth-cookies" rows="4" placeholder="session_id=value&#10;portal_context=value"></textarea><small>One name=value pair per line, scoped to the target hostname.</small></label>',
    storage_state: `<label class="field"><span>Mounted SSO profile</span><select id="auth-profile"><option value="">Choose a profile</option>${profileNames.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join('')}</select><small>Mount Playwright state as /auth/&lt;profile&gt;.json.</small></label>`,
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
  byId('summary').innerHTML = [['Pages',report.pages,''],['Passed',report.summary.passed,'good'],['Needs attention',report.summary.failed,report.summary.failed?'bad':'good'],['Total load time',duration,'']].map(([label,value,kind]) => `<div class="metric ${kind}"><strong>${escapeHtml(value)}</strong><span>${label}</span></div>`).join('');
  byId('result-list').innerHTML = report.results.map((item) => {
    const detail = {error:item.error,console_errors:item.console_errors,failed_resources:item.failed_resources,missing_security_headers:item.missing_security_headers,security_headers:item.security_headers};
    return `<details class="result-item ${item.passed?'pass':''}"><summary><span class="result-dot"></span><span class="result-url">${escapeHtml(item.url)}</span><span class="result-meta">${escapeHtml(item.status||'ERR')} · ${escapeHtml(item.load_ms??'—')}ms</span></summary><div class="result-detail"><pre>${escapeHtml(JSON.stringify(detail,null,2))}</pre></div></details>`;
  }).join('');
  results.hidden = false;
  results.scrollIntoView({behavior:'smooth',block:'start'});
}

authMode.addEventListener('change', renderAuthFields);
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  let payload;
  try {
    payload = {
      target:byId('target').value.trim(),max_pages:Number(byId('pages').value),max_depth:Number(byId('depth').value),timeout_ms:Number(byId('timeout').value),
      check_links:byId('links').checked,check_console:byId('console').checked,check_resources:byId('resources').checked,check_performance:byId('performance').checked,check_security_headers:byId('headers').checked,
      allow_subdomains:byId('subdomains').checked,allow_private_networks:byId('private-network').checked,resource_hosts:splitList(byId('resource-hosts').value),authentication:authenticationPayload(),
      allow_mutations:byId('mutations').checked,mutation_acknowledged:byId('mutation-ack').checked,mutation_endpoint_allowlist:splitList(byId('mutation-paths').value),
    };
  } catch (error) { notify(error.message,true); return; }
  runButton.disabled = true; runButton.querySelector('span').textContent = 'Validating…';
  try {
    const response = await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
    const report = await response.json();
    if (!response.ok) throw new Error(typeof report.detail === 'string' ? report.detail : 'Validation failed');
    renderReport(report); notify(`Validation complete · ${report.pages} page${report.pages===1?'':'s'} checked`);
  } catch (error) { notify(error.message||'Validation failed',true); }
  finally { runButton.disabled=false; runButton.querySelector('span').textContent='Run validation'; }
});

byId('download-button').addEventListener('click', () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport,null,2)],{type:'application/json'});
  const link = document.createElement('a');
  link.href=URL.createObjectURL(blob); link.download=`portal-validation-${lastReport.run_id}.json`; link.click(); URL.revokeObjectURL(link.href);
});

fetch('/api/auth-profiles').then((response) => response.json()).then((data) => { profileNames=data.profiles||[]; renderAuthFields(); }).catch(renderAuthFields);
