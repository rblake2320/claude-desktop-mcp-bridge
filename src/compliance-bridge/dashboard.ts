/**
 * Compliance Navigator - MCP App Dashboard
 *
 * Generates a single-file HTML dashboard served via MCP resources/read.
 * The dashboard provides a UI to operate the full compliance workflow:
 *   scan → audit packet → remediation plan → tickets (dry-run → approve → execute) → verify chain
 *
 * No external dependencies. All CSS and JS are inlined.
 */

export interface DashboardOptions {
  repoPath: string;
  runId?: string;
  /** Whether GH_TOKEN is set (controls GitHub ticket buttons) */
  hasGhToken: boolean;
  /** Whether Jira env vars are set */
  hasJiraConfig: boolean;
  serverVersion: string;
}

export function generateDashboardHtml(opts: DashboardOptions): string {
  const { repoPath, runId, hasGhToken, hasJiraConfig, serverVersion } = opts;
  const repoName = repoPath.replace(/\\/g, '/').split('/').filter(Boolean).slice(-2).join('/');
  const runIdDisplay = runId ?? '(none — run a scan first)';
  const ghDisabled = !hasGhToken;
  const jiraDisabled = !hasJiraConfig;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compliance Navigator Dashboard</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #242836;
    --border: #2e3345;
    --text: #e1e4ed;
    --text-muted: #8b90a0;
    --accent: #6c8aff;
    --accent-hover: #5a7aff;
    --green: #3dd68c;
    --yellow: #f0c040;
    --red: #f06060;
    --orange: #f0a040;
    --radius: 8px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    padding: 24px;
    max-width: 1200px;
    margin: 0 auto;
  }
  h1 { font-size: 1.5rem; font-weight: 600; }
  h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 12px; }

  /* Header */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  .header-left { display: flex; align-items: center; gap: 12px; }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .badge-version { background: var(--surface2); color: var(--text-muted); }

  /* Context bar */
  .context-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    padding: 12px 16px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 20px;
    font-size: 0.9rem;
  }
  .context-item { display: flex; gap: 6px; }
  .context-label { color: var(--text-muted); }
  .context-value { font-weight: 600; font-family: monospace; font-size: 0.85rem; }

  /* Tabs */
  .tab-bar {
    display: flex;
    gap: 4px;
    margin-bottom: 20px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0;
  }
  .tab {
    padding: 8px 16px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
  }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  /* Cards */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
    margin-bottom: 16px;
  }
  .card-title {
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-bottom: 12px;
  }

  /* Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface2);
    color: var(--text);
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 500;
    transition: all 0.15s;
  }
  .btn:hover:not(:disabled) { background: var(--border); }
  .btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .btn-primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
  }
  .btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
  .btn-danger {
    background: transparent;
    border-color: var(--red);
    color: var(--red);
  }
  .btn-danger:hover:not(:disabled) { background: rgba(240,96,96,0.1); }
  .btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }

  /* Workflow steps */
  .workflow {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
  }
  .step {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 16px 12px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    text-align: center;
  }
  .step-num {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8rem;
    font-weight: 700;
    background: var(--border);
    color: var(--text-muted);
  }
  .step-num.done { background: var(--green); color: #000; }
  .step-num.active { background: var(--accent); color: #fff; }
  .step-label { font-size: 0.8rem; color: var(--text-muted); }

  /* Output */
  .output-area {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px;
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    font-size: 0.8rem;
    white-space: pre-wrap;
    max-height: 500px;
    overflow-y: auto;
    color: var(--text-muted);
    min-height: 80px;
  }

  /* Stats grid */
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
  }
  .stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 12px;
    background: var(--surface2);
    border-radius: var(--radius);
  }
  .stat-value { font-size: 1.5rem; font-weight: 700; }
  .stat-label { font-size: 0.75rem; color: var(--text-muted); }

  /* Severity badges */
  .sev-critical { color: var(--red); }
  .sev-high { color: var(--orange); }
  .sev-medium { color: var(--yellow); }
  .sev-low { color: var(--accent); }
  .sev-info { color: var(--text-muted); }

  /* Table */
  .findings-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }
  .findings-table th {
    text-align: left;
    padding: 8px;
    border-bottom: 1px solid var(--border);
    color: var(--text-muted);
    font-weight: 600;
  }
  .findings-table td {
    padding: 8px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  .findings-table tr:hover { background: var(--surface2); }

  /* Alert */
  .alert {
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 0.85rem;
    margin-bottom: 12px;
  }
  .alert-warn {
    background: rgba(240,192,64,0.1);
    border: 1px solid rgba(240,192,64,0.3);
    color: var(--yellow);
  }
  .alert-info {
    background: rgba(108,138,255,0.1);
    border: 1px solid rgba(108,138,255,0.3);
    color: var(--accent);
  }
  .alert-success {
    background: rgba(61,214,140,0.1);
    border: 1px solid rgba(61,214,140,0.3);
    color: var(--green);
  }
  .alert-error {
    background: rgba(240,96,96,0.1);
    border: 1px solid rgba(240,96,96,0.3);
    color: var(--red);
  }

  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .hidden { display: none !important; }
</style>
</head>
<body>
<div id="cn-dashboard">
  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>Compliance Navigator</h1>
      <span class="badge badge-version">v${escapeHtml(serverVersion)}</span>
    </div>
  </div>

  <!-- Context Bar -->
  <div class="context-bar">
    <div class="context-item">
      <span class="context-label">Repo:</span>
      <span class="context-value" id="ctx-repo">${escapeHtml(repoName)}</span>
    </div>
    <div class="context-item">
      <span class="context-label">Full Path:</span>
      <span class="context-value" id="ctx-path">${escapeHtml(repoPath)}</span>
    </div>
    <div class="context-item">
      <span class="context-label">Run ID:</span>
      <span class="context-value" id="ctx-runid">${escapeHtml(runIdDisplay)}</span>
    </div>
    <div class="context-item">
      <span class="context-label">GitHub:</span>
      <span class="context-value" style="color: ${ghDisabled ? 'var(--red)' : 'var(--green)'}">
        ${ghDisabled ? 'GH_TOKEN not set' : 'Connected'}
      </span>
    </div>
    <div class="context-item">
      <span class="context-label">Jira:</span>
      <span class="context-value" style="color: ${jiraDisabled ? 'var(--text-muted)' : 'var(--green)'}">
        ${jiraDisabled ? 'Not configured' : 'Connected'}
      </span>
    </div>
  </div>

  ${ghDisabled ? `<div class="alert alert-warn">GitHub ticket creation is disabled because GH_TOKEN environment variable is not set. Set it to enable ticket creation.</div>` : ''}

  <!-- Tabs -->
  <div class="tab-bar">
    <button class="tab active" data-tab="actions">Actions</button>
    <button class="tab" data-tab="findings">Findings</button>
    <button class="tab" data-tab="evidence">Evidence</button>
    <button class="tab" data-tab="audit-log">Audit Log</button>
  </div>

  <!-- Actions Tab -->
  <div class="tab-panel active" id="panel-actions">
    <div class="card">
      <div class="card-title">Compliance Workflow</div>
      <div class="workflow">
        <div class="step" id="step-1">
          <div class="step-num" id="step-num-1">1</div>
          <strong>Scan Repo</strong>
          <span class="step-label">gitleaks + npm audit + checkov</span>
          <button class="btn btn-primary" id="btn-scan" onclick="runAction('scan')">Run Scan</button>
        </div>
        <div class="step" id="step-2">
          <div class="step-num" id="step-num-2">2</div>
          <strong>Audit Packet</strong>
          <span class="step-label">Generate structured report</span>
          <button class="btn" id="btn-packet" onclick="runAction('packet')" disabled>Generate</button>
        </div>
        <div class="step" id="step-3">
          <div class="step-num" id="step-num-3">3</div>
          <strong>Remediation Plan</strong>
          <span class="step-label">Prioritized fix steps</span>
          <button class="btn" id="btn-remediation" onclick="runAction('remediation')" disabled>Plan</button>
        </div>
        <div class="step" id="step-4">
          <div class="step-num" id="step-num-4">4</div>
          <strong>Tickets (Dry Run)</strong>
          <span class="step-label">Preview issues</span>
          <button class="btn" id="btn-tickets-dry" onclick="runAction('tickets-dry')" disabled>Dry Run</button>
        </div>
        <div class="step" id="step-5">
          <div class="step-num" id="step-num-5">5</div>
          <strong>Approve Plan</strong>
          <span class="step-label">Sign off on tickets</span>
          <button class="btn" id="btn-approve" onclick="runAction('approve')" disabled>Approve</button>
        </div>
        <div class="step" id="step-6">
          <div class="step-num" id="step-num-6">6</div>
          <strong>Execute Tickets</strong>
          <span class="step-label">Create real issues</span>
          <button class="btn btn-danger" id="btn-tickets-exec" onclick="runAction('tickets-exec')" disabled>Execute</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Audit Chain</div>
      <div class="btn-row">
        <button class="btn" id="btn-verify" onclick="runAction('verify')">Verify Audit Chain</button>
      </div>
      <div id="verify-result"></div>
    </div>

    <div class="card">
      <div class="card-title">Output</div>
      <div id="action-status" class="hidden"></div>
      <div class="output-area" id="output">Waiting for action...</div>
    </div>
  </div>

  <!-- Findings Tab -->
  <div class="tab-panel" id="panel-findings">
    <div id="findings-empty" class="card">
      <div class="alert alert-info">No scan results yet. Run a scan from the Actions tab to see findings.</div>
    </div>
    <div id="findings-content" class="hidden">
      <div class="stats" id="severity-stats"></div>
      <div class="card">
        <div class="card-title">Findings</div>
        <table class="findings-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Scanner</th>
              <th>Title</th>
              <th>File</th>
              <th>SOC2 Controls</th>
            </tr>
          </thead>
          <tbody id="findings-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Evidence Tab -->
  <div class="tab-panel" id="panel-evidence">
    <div id="evidence-empty" class="card">
      <div class="alert alert-info">No evidence artifacts yet. Run a scan and generate an audit packet to see evidence.</div>
    </div>
    <div id="evidence-content" class="hidden">
      <div class="card">
        <div class="card-title">Scanner Statuses</div>
        <div id="scanner-statuses"></div>
      </div>
      <div class="card">
        <div class="card-title">Coverage (Scanner Reach)</div>
        <div id="coverage-display"></div>
      </div>
      <div class="card">
        <div class="card-title">ROI Estimate</div>
        <div id="roi-display"></div>
      </div>
      <div class="card">
        <div class="card-title">Manifest</div>
        <div class="output-area" id="manifest-display">No manifest available.</div>
      </div>
    </div>
  </div>

  <!-- Audit Log Tab -->
  <div class="tab-panel" id="panel-audit-log">
    <div class="card">
      <div class="card-title">Hash-Chained Audit Log</div>
      <div class="alert alert-info" style="margin-bottom:12px">
        This log is hash-chained (SHA-256). Use "Verify Audit Chain" in the Actions tab to check integrity.
      </div>
      <div class="output-area" id="audit-log-display">No audit log entries loaded. Verify the chain to see status.</div>
    </div>
  </div>
</div>

<script>
(function() {
  // State
  const state = {
    repoPath: ${safeJsonEmbed(repoPath)},
    runId: ${runId ? safeJsonEmbed(runId) : 'null'},
    hasGhToken: ${hasGhToken},
    hasJiraConfig: ${hasJiraConfig},
    planId: null,
    approvedPlanId: null,
    scanResult: null,
    completedSteps: new Set(),
  };

  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('panel-' + tab.dataset.tab).classList.add('active');
    });
  });

  // MCP tool caller (placeholder for MCP App integration)
  // In MCP App context, tools are called via the parent MCP client.
  // This dashboard is informational — actual tool calls go through the MCP protocol.
  // The functions below format tool call instructions for copy/paste or MCP App dispatch.

  function formatToolCall(toolName, args) {
    return JSON.stringify({ method: 'tools/call', params: { name: toolName, arguments: args } }, null, 2);
  }

  function setOutput(text, type) {
    const el = document.getElementById('output');
    el.textContent = text;
    const status = document.getElementById('action-status');
    if (type) {
      status.className = 'alert alert-' + type;
      status.classList.remove('hidden');
      if (type === 'success') status.textContent = 'Action completed successfully.';
      else if (type === 'error') status.textContent = 'Action failed. See output below.';
      else status.textContent = 'Action in progress...';
    } else {
      status.classList.add('hidden');
    }
  }

  function markStep(num, status) {
    const el = document.getElementById('step-num-' + num);
    el.className = 'step-num' + (status === 'done' ? ' done' : status === 'active' ? ' active' : '');
    if (status === 'done') state.completedSteps.add(num);
  }

  function enableButton(id, enabled) {
    document.getElementById(id).disabled = !enabled;
  }

  function updateRunId(newRunId) {
    state.runId = newRunId;
    document.getElementById('ctx-runid').textContent = newRunId;
  }

  function updateFindings(scanResult) {
    state.scanResult = scanResult;
    const findings = scanResult.findings || [];
    const counts = scanResult.countsBySeverity || {};

    // Stats
    const statsEl = document.getElementById('severity-stats');
    const sevs = [
      { key: 'critical', label: 'Critical', cls: 'sev-critical' },
      { key: 'high', label: 'High', cls: 'sev-high' },
      { key: 'medium', label: 'Medium', cls: 'sev-medium' },
      { key: 'low', label: 'Low', cls: 'sev-low' },
      { key: 'info', label: 'Info', cls: 'sev-info' },
    ];
    statsEl.innerHTML = sevs.map(s =>
      '<div class="stat"><span class="stat-value ' + s.cls + '">' + (counts[s.key] || 0) + '</span><span class="stat-label">' + s.label + '</span></div>'
    ).join('');

    // Table
    const tbody = document.getElementById('findings-tbody');
    tbody.innerHTML = findings.slice(0, 100).map(f =>
      '<tr>' +
        '<td class="sev-' + esc(f.severity) + '">' + esc(f.severity).toUpperCase() + '</td>' +
        '<td>' + esc(f.scanner) + '</td>' +
        '<td>' + esc(f.title) + '</td>' +
        '<td style="font-family:monospace;font-size:0.78rem">' + esc(f.file || '-') + '</td>' +
        '<td>' + (f.soc2 ? esc(f.soc2.controls.join(', ')) : '-') + '</td>' +
      '</tr>'
    ).join('');

    document.getElementById('findings-empty').classList.add('hidden');
    document.getElementById('findings-content').classList.remove('hidden');
  }

  function updateEvidence(scanResult) {
    // Scanner statuses
    const statusEl = document.getElementById('scanner-statuses');
    const statuses = scanResult.scannerStatuses || [];
    statusEl.innerHTML = statuses.map(s => {
      const color = s.status === 'ok' ? 'var(--green)' : s.status === 'missing' ? 'var(--red)' : 'var(--yellow)';
      return '<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">' +
        '<span style="color:' + color + ';font-weight:600">' + esc(s.status).toUpperCase() + '</span>' +
        '<span>' + esc(s.scanner) + '</span>' +
        (s.version ? '<span style="color:var(--text-muted)">v' + esc(s.version) + '</span>' : '') +
        (s.message ? '<span style="color:var(--text-muted)">(' + esc(s.message) + ')</span>' : '') +
      '</div>';
    }).join('');

    // Coverage
    const cov = scanResult.controlCoverage || {};
    const covEl = document.getElementById('coverage-display');
    covEl.innerHTML =
      '<div class="stats">' +
        '<div class="stat"><span class="stat-value">' + (cov.coveragePct || 0) + '%</span><span class="stat-label">Current Reach</span></div>' +
        '<div class="stat"><span class="stat-value">' + (cov.coveragePctPotential || 0) + '%</span><span class="stat-label">Potential Reach</span></div>' +
        '<div class="stat"><span class="stat-value">' + (cov.coveragePctFull || 0) + '%</span><span class="stat-label">Full Reach (all scanners)</span></div>' +
      '</div>' +
      '<div style="font-size:0.78rem;color:var(--text-muted)">Coverage = scanner reach (controls where findings were detected), NOT compliance status.</div>';

    // ROI
    const roi = scanResult.roiEstimate || {};
    const roiEl = document.getElementById('roi-display');
    roiEl.innerHTML =
      '<div class="stats">' +
        '<div class="stat"><span class="stat-value">' + (roi.hoursSavedConservative || 0) + 'h</span><span class="stat-label">Conservative</span></div>' +
        '<div class="stat"><span class="stat-value">' + (roi.hoursSaved || 0) + 'h</span><span class="stat-label">Midpoint</span></div>' +
        '<div class="stat"><span class="stat-value">' + (roi.hoursSavedLikely || 0) + 'h</span><span class="stat-label">Likely</span></div>' +
      '</div>' +
      '<div style="font-size:0.78rem;color:var(--text-muted)">' + esc(roi.basis || 'Estimates use configurable defaults, NOT validated measurements.') + '</div>';

    // Manifest
    const manifestEl = document.getElementById('manifest-display');
    manifestEl.textContent = JSON.stringify(scanResult.manifest || {}, null, 2);

    document.getElementById('evidence-empty').classList.add('hidden');
    document.getElementById('evidence-content').classList.remove('hidden');
  }

  function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // Actions
  window.runAction = function(action) {
    switch (action) {
      case 'scan': {
        markStep(1, 'active');
        setOutput('Scan requested.\\n\\nCall this tool via MCP:\\n\\n' +
          formatToolCall('compliance.scan_repo', { repoPath: state.repoPath }), 'info');
        // Simulate enabling next steps after scan completes
        // In real MCP App context, the client calls the tool and updates the dashboard
        enableButton('btn-packet', true);
        enableButton('btn-remediation', true);
        if (state.hasGhToken || state.hasJiraConfig) enableButton('btn-tickets-dry', true);
        markStep(1, 'done');
        break;
      }
      case 'packet': {
        markStep(2, 'active');
        const args = { repoPath: state.repoPath };
        if (state.runId) args.runId = state.runId;
        setOutput('Audit packet requested.\\n\\n' + formatToolCall('compliance.generate_audit_packet', args), 'info');
        markStep(2, 'done');
        break;
      }
      case 'remediation': {
        markStep(3, 'active');
        const args = { repoPath: state.repoPath };
        if (state.runId) args.runId = state.runId;
        setOutput('Remediation plan requested.\\n\\n' + formatToolCall('compliance.plan_remediation', args), 'info');
        markStep(3, 'done');
        break;
      }
      case 'tickets-dry': {
        markStep(4, 'active');
        const args = { repoPath: state.repoPath, dryRun: true };
        if (state.runId) args.runId = state.runId;
        setOutput('Ticket dry-run requested.\\n\\n' + formatToolCall('compliance.create_tickets', args), 'info');
        enableButton('btn-approve', true);
        markStep(4, 'done');
        break;
      }
      case 'approve': {
        markStep(5, 'active');
        const planId = state.planId || '<planId from dry-run>';
        setOutput('Approval requested.\\n\\nPlease provide your name and the planId from the dry-run:\\n\\n' +
          formatToolCall('compliance.approve_ticket_plan', {
            repoPath: state.repoPath,
            planId: planId,
            approvedBy: '<your-name>'
          }), 'info');
        enableButton('btn-tickets-exec', true);
        markStep(5, 'done');
        break;
      }
      case 'tickets-exec': {
        markStep(6, 'active');
        const approvedPlanId = state.approvedPlanId || '<approvedPlanId>';
        setOutput('Ticket execution requested.\\n\\nRequires approved plan ID:\\n\\n' +
          formatToolCall('compliance.create_tickets', {
            repoPath: state.repoPath,
            dryRun: false,
            approvedPlanId: approvedPlanId,
          }), 'info');
        markStep(6, 'done');
        break;
      }
      case 'verify': {
        setOutput('Audit chain verification requested.\\n\\n' +
          formatToolCall('compliance.verify_audit_chain', {}), 'info');
        break;
      }
    }
  };

  // Expose update functions for MCP App integration
  window.cnDashboard = {
    updateRunId,
    updateFindings,
    updateEvidence,
    markStep,
    enableButton,
    setOutput,
    getState: () => ({ ...state }),
    setPlanId: (id) => { state.planId = id; },
    setApprovedPlanId: (id) => { state.approvedPlanId = id; enableButton('btn-tickets-exec', true); },
  };
})();
</script>
</div>
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Escape a value for safe embedding inside a <script> tag via JSON.stringify.
 * JSON.stringify alone does NOT prevent </script> breakout at the HTML parser level.
 * We also escape U+2028/U+2029 (line separators that break JS in some engines).
 */
function safeJsonEmbed(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}
