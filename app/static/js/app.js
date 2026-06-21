/**
 * PHISHGUARD NEXUS — Enterprise SPA
 * Hash-based routing, API integration, UI management.
 */
function renderAnalysis(result) {

    console.log("RENDER START");

    try {

        console.log("1");

        // existing code

        console.log("2");

        document.getElementById("scan-risk-score").textContent =
            result.risk_score;

        console.log("3");

        document.getElementById("scan-authenticity-score").textContent =
            authScore != null ? authScore + '/100' : '—';

        console.log("4");

        document.getElementById("scan-fraud-confidence").textContent =
            result.fraud_confidence + "%";

        console.log("5");

        document.getElementById("scan-verdict").textContent =
            result.verdict;

        console.log("6");

        document.getElementById("scan-decision").textContent =
            result.decision;

        console.log("7");

    } catch(err) {

        console.error("RENDER FAILED");
        console.error(err);

    }
}
(function() {
  'use strict';

  const API = '/api/v1';
  let token = localStorage.getItem('pn_token') || null;
  let user = null;

  // ── Toast system ──
  const toastContainer = document.getElementById('toast-container');
  function showToast(msg, type = 'info') {
    const icons = { success: '✓', error: '✗', info: 'ℹ' };
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<span>${icons[type] || 'ℹ'}</span> ${msg}`;
    toastContainer.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 3500);
  }

  // ── API helper ──
  async function api(method, path, body = null) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (token) opts.headers['Authorization'] = `Bearer ${token}`;
    if (body) opts.body = JSON.stringify(body);
    try {
      const res = await fetch(`${API}${path}`, opts);
      if (res.status === 401) { token = null; localStorage.removeItem('pn_token'); showToast('Session expired. Please log in.', 'error'); }
      if (!res.ok) { const err = await res.json().catch(() => ({ detail: res.statusText })); throw new Error(err.detail || 'API error'); }
      return await res.json();
    } catch (e) {
      if (e.message !== 'Session expired. Please log in.') showToast(e.message, 'error');
      throw e;
    }
  }

  // ── Auth UI ──
  function updateAuthUI() {
    const btn = document.getElementById('login-btn');
    if (!btn) return;
    if (token && user) {
      btn.innerHTML = `<span class="nav-icon">👤</span><span class="nav-text">${user.full_name || user.username}</span>`;
      btn.onclick = window.logout;
    } else {
      btn.innerHTML = `<span class="nav-icon">👤</span><span class="nav-text">Sign In</span>`;
      btn.onclick = window.showLogin;
    }
  }

  // Restore token from localStorage on load
  (function restoreToken() {
    const saved = localStorage.getItem('pn_token');
    if (saved) {
      token = saved;
      try {
        const payload = JSON.parse(atob(saved.split('.')[1]));
        user = { username: payload.sub, role: payload.role, full_name: payload.sub === 'admin' ? 'Security Admin' : payload.sub };
      } catch (_) {
        token = null;
        localStorage.removeItem('pn_token');
      }
    }
    updateAuthUI();
  })();

  // ── Login ──
  window.showLogin = function() {
    document.getElementById('login-overlay').style.display = 'flex';
  };

  window.hideLogin = function() {
    document.getElementById('login-overlay').style.display = 'none';
  };

  window.doLogin = async function() {
    const username = document.getElementById('login-user').value;
    const password = document.getElementById('login-pass').value;
    if (!username || !password) { showToast('Enter credentials', 'error'); return; }
    try {
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);
      const res = await fetch(`${API}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData,
      });
      if (!res.ok) throw new Error('Invalid credentials');
      const data = await res.json();
      token = data.access_token;
      user = data.user;
      localStorage.setItem('pn_token', token);
      updateAuthUI();
      showToast(`Welcome, ${user.full_name || user.username}`, 'success');
      window.hideLogin();
      navigate('dashboard');
    } catch (e) {
      showToast('Login failed: ' + e.message, 'error');
    }
  };

  window.logout = function() {
    token = null;
    user = null;
    localStorage.removeItem('pn_token');
    updateAuthUI();
    showToast('Logged out', 'info');
    navigate('home');
  };

  // ── Routing ──
  function getPage() {
    return window.location.hash.replace('#', '') || 'home';
  }

  function getBasePage(page) {
    // e.g. "investigations/abc-123" -> "investigations"
    return page.split('/')[0];
  }

  function navigate(page) {
    window.location.hash = page;
  }

  window.navigate = navigate;

  window.addEventListener('hashchange', render);
  window.addEventListener('load', render);

  // ── Page renderers ──
  function render() {
    const page = getPage();
    const basePage = getBasePage(page);
    document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
    const target = document.getElementById(`page-${basePage}`);
    if (target) target.classList.add('active');

    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const nav = document.querySelector(`.nav-item[data-page="${basePage}"]`);
    if (nav) nav.classList.add('active');

    updateAuthUI();

    // Reset data-loaded flags when navigating away so detail views can refresh
    if (basePage !== 'investigations') {
      const invLoaded = document.getElementById('inv-loaded');
      if (invLoaded) invLoaded.dataset.loaded = '0';
    }

    const loaders = {
      home: loadHome,
      dashboard: loadDashboard,
      upload: loadUpload,
      investigations: loadInvestigations,
      compliance: loadCompliance,
      analytics: loadAnalytics,
      reports: loadReports,
      settings: loadSettings,
    };
    if (loaders[basePage]) loaders[basePage]();
  }

  // ── HOME (static landing page — no dynamic data needed) ──
  function loadHome() {}

  // ── DASHBOARD ──
  async function loadDashboard() {
    if (document.getElementById('dash-loaded').dataset.loaded === '1') return;

    const [exec, threats] = await Promise.all([
      api('GET', '/dashboard/executive').catch(() => null),
      api('GET', '/dashboard/live-threats?limit=10').catch(() => null),
    ]);

    const total = exec ? exec.high_risk + exec.medium_risk + exec.low_risk : 0;

    animateKPI('kpi-scanned', exec?.total_documents_scanned || 0);
    animateKPI('kpi-fraud', exec?.fraud_detected || 0);
    animateKPI('kpi-highrisk', exec?.high_risk || 0);
    animateKPI('kpi-compliance', exec?.compliance_alerts || 0);
    animateKPI('kpi-avgscore', total ? Math.round((exec.high_risk * 90 + exec.medium_risk * 50) / total) : 0);

    const riskScore = total ? Math.round((exec.high_risk * 90 + exec.medium_risk * 50) / total) : 0;
    renderRiskGauge(riskScore);

    // Risk distribution chart
    if (exec?.risk_distribution) {
      renderDoughnutChart('risk-dist-chart', {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        values: [exec.risk_distribution.critical || 0, exec.risk_distribution.high || 0, exec.risk_distribution.medium || 0, exec.risk_distribution.low || 0],
        colors: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
      });
    }

    // Trend chart
    if (exec?.trend_analysis && exec.trend_analysis.length) {
      renderLineChart('trend-chart', {
        labels: exec.trend_analysis.slice(-14).map(t => t.date?.slice(5) || ''),
        datasets: [
          { label: 'Fraud', data: exec.trend_analysis.slice(-14).map(t => t.fraud || 0), color: '#ef4444' },
          { label: 'Compliance', data: exec.trend_analysis.slice(-14).map(t => t.compliance || 0), color: '#f59e0b' },
          { label: 'Scans', data: exec.trend_analysis.slice(-14).map(t => t.scans || 0), color: '#06b6d4' },
        ],
      });
    }

    // Recent scans
    const scansBody = document.getElementById('recent-scans-body');
    if (scansBody && exec?.recent_scans) {
      scansBody.innerHTML = exec.recent_scans.slice(0, 5).map(s => `
        <div class="dash-scan-item flex items-center justify-between p-2 rounded hover:bg-white/5 cursor-pointer ${s.scan_id === currentDashboardScanId ? 'selected bg-primary/10 border border-primary/30' : ''}" data-scan-id="${s.scan_id || ''}" onclick="window.selectDashboardScan('${s.scan_id || ''}')">
          <div class="flex items-center gap-2 min-w-0">
            <span class="material-symbols-outlined text-sm text-on-surface-variant">description</span>
            <span class="text-xs text-on-surface-variant truncate max-w-[140px]">${s.source || s.scan_id?.slice(0, 12) || '—'}</span>
          </div>
          <span class="text-[10px] font-semibold px-2 py-0.5 rounded ${s.risk === 'HIGH' ? 'bg-error/20 text-error' : s.risk === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-tertiary/20 text-tertiary'}">${s.risk || 'LOW'}</span>
        </div>
      `).join('');
    }

    // Live threats
    const threatsBody = document.getElementById('live-threats-body');
    if (threatsBody) {
      if (threats?.length) {
        threatsBody.innerHTML = threats.slice(0, 5).map(t => {
          const risk = t.risk_score > 0.7 ? 'HIGH' : t.risk_score > 0.4 ? 'MEDIUM' : 'LOW';
          return `
          <div class="flex items-center justify-between p-2 rounded hover:bg-white/5">
            <div class="flex items-center gap-2 min-w-0">
              <span class="w-1.5 h-1.5 rounded-full ${risk === 'HIGH' ? 'bg-error' : risk === 'MEDIUM' ? 'bg-yellow-500' : 'bg-tertiary'}"></span>
              <span class="text-xs text-on-surface-variant truncate max-w-[140px]">${t.domain || t.source || 'Unknown'}</span>
            </div>
            <span class="text-[10px] font-semibold px-2 py-0.5 rounded ${risk === 'HIGH' ? 'bg-error/20 text-error' : risk === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-tertiary/20 text-tertiary'}">${risk}</span>
          </div>
        `}).join('');
      } else {
        threatsBody.innerHTML = '<div class="text-on-surface-variant/50 text-xs text-center py-6">No active threats</div>';
      }
    }

    // Executive decision panel
    if (exec) {
      const prob = exec.high_risk > 0 ? Math.min(exec.high_risk / Math.max(exec.total_documents_scanned, 1) * 100, 100).toFixed(1) + '%' : '—';
      document.getElementById('exec-fraud-prob').textContent = prob;
      document.getElementById('exec-compliance').textContent = exec.compliance_alerts > 5 ? 'Severe' : exec.compliance_alerts > 0 ? 'Moderate' : '—';
      document.getElementById('exec-regulatory').textContent = exec.high_risk > 5 ? 'Critical' : exec.high_risk > 0 ? 'Elevated' : '—';
    }

    // Set the current dashboard scan ID from the most recent scan
    if (exec?.recent_scans?.length) {
      currentDashboardScanId = exec.recent_scans[0].scan_id || null;
      // Highlight the selected scan in the recent scans list
      document.querySelectorAll('#recent-scans-body .dash-scan-item').forEach(el => {
        el.classList.toggle('selected', el.dataset.scanId === currentDashboardScanId);
      });
    } else {
      currentDashboardScanId = null;
    }
    initDashboardDecisionButtons();

    document.getElementById('dash-loaded').dataset.loaded = '1';
  }

  function animateKPI(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const duration = 1000;
    const start = performance.now();
    const startVal = 0;
    function tick(now) {
      const p = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(startVal + (target - startVal) * eased).toLocaleString();
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function renderRiskGauge(score) {
    const gauge = document.getElementById('risk-gauge-fill');
    const scoreEl = document.getElementById('risk-gauge-score');
    const labelEl = document.getElementById('risk-gauge-label');
    if (!gauge) return;

    const r = 45;
    const circ = 2 * Math.PI * r;
    const pct = Math.min(score / 100, 1);
    const offset = circ * (1 - pct);

    let color, label, bgClass;
    if (score <= 30) { color = '#4edea3'; label = 'Safe'; bgClass = 'bg-tertiary/20 border-tertiary/30 text-tertiary'; }
    else if (score <= 60) { color = '#f6e05e'; label = 'Review'; bgClass = 'bg-yellow-500/20 border-yellow-500/30 text-yellow-500'; }
    else if (score <= 80) { color = '#f97316'; label = 'Suspicious'; bgClass = 'bg-orange-500/20 border-orange-500/30 text-orange-500'; }
    else { color = '#ffb4ab'; label = 'High Risk'; bgClass = 'bg-error/20 border-error/30 text-error'; }

    gauge.style.stroke = color;
    gauge.style.strokeDasharray = circ;
    gauge.style.strokeDashoffset = offset;
    scoreEl.textContent = score;
    scoreEl.style.color = color;
    labelEl.textContent = label;
    labelEl.className = `px-4 py-1.5 rounded-full text-xs font-bold tracking-widest uppercase mb-3 ${bgClass}`;
  }

  // ── UPLOAD ──
  function loadUpload() {
    if (document.getElementById('upload-loaded').dataset.loaded === '1') return;
    setupUploadZone();
    document.getElementById('upload-loaded').dataset.loaded = '1';
  }

  function setupUploadZone() {
    const zone = document.getElementById('upload-zone');
    const input = document.getElementById('file-input');
    if (!zone) return;

    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', (e) => {
      e.preventDefault();
      zone.classList.remove('dragover');
      if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
    });
    input.addEventListener('change', () => {
      if (input.files.length) handleFile(input.files[0]);
    });
  }

  function handleFile(file) {
    if (file.size === 0) {
      showToast('Empty file — please select a valid document', 'error');
      resetUpload();
      return;
    }
    document.getElementById('upload-zone').style.display = 'none';
    document.getElementById('scan-pipeline').style.display = 'flex';
    document.getElementById('file-name').textContent = file.name;
    runPipeline(file);
  }

  async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${API}/upload`, { method: 'POST', headers, body: formData });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      const detail = err.detail || err;
      if (detail && detail.risk_score !== undefined) {
        // Structured error — render as fraud result
        console.log('[Upload] Structured error response:', detail);
        return detail;
      }
      throw new Error(detail.message || detail || 'Upload failed');
    }
    return await res.json();
  }

  function clearScanResults() {
    const ids = [
      'scan-evidence-summary', 'scan-findings', 'scan-recommendations',
      'scan-contributions', 'scan-verdict-evidence', 'scan-fabrication-list',
    ];
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '';
    });
    const textIds = [
      'scan-risk-score', 'scan-fraud-confidence', 'scan-verdict', 'scan-decision',
      'scan-authenticity-score', 'scan-raw-score', 'scan-normalized-score',
      'scan-human-decision',
    ];
    textIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '—';
    });
    // Hide verdict & fabrication panels
    const hideIds = ['scan-verdict-panel', 'scan-fabrication-card'];
    hideIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });
  }

  async function runPipeline(file) {
    const steps = [
      { id: 'step-meta' },
      { id: 'step-ela' },
      { id: 'step-ocr' },
      { id: 'step-numeric' },
      { id: 'step-sig' },
      { id: 'step-compliance' },
    ];

    // Start the real upload in parallel with the animation
    const uploadPromise = uploadFile(file);

    for (const step of steps) {
      const el = document.getElementById(step.id);
      if (!el) continue;
      el.className = 'flex items-center gap-4 p-4 bg-surface-container rounded-lg border active-step';
      el.classList.add('active');
      el.querySelector('.step-status').textContent = 'Scanning...';
      await sleep(300 + Math.random() * 200);
      el.classList.remove('active');
      el.classList.add('done');
      el.querySelector('.step-status').textContent = 'Complete';
    }

    document.getElementById('scan-results').style.display = 'block';
    const completeEl = document.getElementById('scan-complete');
    completeEl.querySelector('.flex-1').textContent = '✓ Analysis Complete';
    completeEl.className = 'flex items-center gap-4 p-4 bg-surface-container rounded-lg border done-step';
    completeEl.classList.add('done');

    try {
      const result = await uploadPromise;

      // Structured error rendered as fraud result (e.g., corrupted PDF)
      if (result.error) {
        console.log('[Upload] Structured error — rendering as fraud result:', result.error);
        showToast(result.message || 'Document rejected', 'error');
        const banner = document.getElementById('scan-error-banner');
        if (banner) {
          banner.style.display = 'flex';
          const titleEl = document.getElementById('scan-error-banner-title');
          const msgEl = document.getElementById('scan-error-banner-message');
          if (titleEl) titleEl.textContent = result.verdict || 'Corrupted Document Detected';
          if (msgEl) msgEl.textContent = result.override_reason || result.message || 'This file could not be processed.';
        }
      } else {
        const banner = document.getElementById('scan-error-banner');
        if (banner) banner.style.display = 'none';
      }

      clearScanResults();

      console.log('UPLOAD RESULT:', result);
      console.log('risk_score:', result.risk_score);
      console.log('authenticity_score:', result.authenticity_score);
      console.log('fraud_confidence:', result.fraud_confidence);
      console.log('verdict:', result.verdict);
      console.log('decision:', result.decision);
      console.log('severity:', result.severity);

      // ── Risk Score ──
      const score = result.risk_score;
      const authScore = result.authenticity_score != null ? Math.round(result.authenticity_score) : null;
      let scoreColor, scoreLabel;
      if (score >= 50) { scoreColor = '#ffb4ab'; scoreLabel = 'High Risk'; }
      else if (score >= 20) { scoreColor = '#f6e05e'; scoreLabel = 'Review Required'; }
      else { scoreColor = '#4edea3'; scoreLabel = 'Safe'; }

      const riskScoreEl = document.getElementById('scan-risk-score');
      riskScoreEl.textContent = score ?? '—';
      riskScoreEl.style.color = scoreColor;
      const riskLabelEl = document.getElementById('scan-risk-label');
      if (riskLabelEl) riskLabelEl.textContent = result.severity ?? result.verdict ?? '—';

      // ── Fraud Confidence ──
      const fc = result.fraud_confidence != null ? result.fraud_confidence : 0;
      const fcEl = document.getElementById('scan-fraud-confidence');
      fcEl.textContent = (fc ?? 0) + '%';
      fcEl.style.color = fc >= 70 ? '#ffb4ab' : fc >= 40 ? '#f6e05e' : '#4edea3';

      // ── Verdict KPI ──
      const verdict = result.verdict || result.severity || '—';
      const verdictEl = document.getElementById('scan-verdict');
      verdictEl.textContent = verdict;
      verdictEl.style.color = scoreColor;

      // ── Decision ──
      const decision = result.decision || 'REVIEW';
      const decEl = document.getElementById('scan-decision');
      decEl.textContent = decision;
      let decColor, decBg;
      if (decision === 'REJECT') { decColor = '#ffb4ab'; decBg = 'rgba(255,180,171,0.1)'; }
      else if (decision === 'ESCALATE') { decColor = '#f97316'; decBg = 'rgba(249,115,22,0.1)'; }
      else if (decision === 'REVIEW') { decColor = '#f6e05e'; decBg = 'rgba(246,224,94,0.1)'; }
      else { decColor = '#4edea3'; decBg = 'rgba(78,222,163,0.1)'; }
      decEl.style.color = decColor;
      document.getElementById('scan-decision-panel').style.background = decBg;

      // ── Decision Card ──
      const decisionCard = document.getElementById('scan-decision-card');
      if (decision && decision !== 'APPROVE') {
        decisionCard.style.display = 'block';
        document.getElementById('scan-decision-card-value').textContent = decision;
        document.getElementById('scan-decision-card-value').style.color = decColor;
        document.getElementById('scan-decision-card-confidence').textContent = `Confidence: ${fc}%`;
        const reasonText = decision === 'REJECT' ? 'Multiple authenticity failures detected — document cannot be trusted.'
          : decision === 'ESCALATE' ? 'Medium-to-high risk indicators require manual expert review before further processing.'
          : decision === 'REVIEW' ? 'Some minor anomalies found — review recommended before proceeding.'
          : 'No decision reason available.';
        document.getElementById('scan-decision-card-reason').textContent = reasonText;
      } else {
        decisionCard.style.display = 'none';
      }

      // ── Risk Escalation Override ──
      const overrideCard = document.getElementById('scan-override-card');
      if (result.override_reason) {
        overrideCard.style.display = 'block';
        document.getElementById('scan-original-score').textContent = result.original_score != null ? result.original_score.toFixed(1) + '/100' : '—';
        document.getElementById('scan-escalated-score').textContent = result.risk_score + '/100';
        document.getElementById('scan-override-rule').textContent = result.override_reason;
      } else {
        overrideCard.style.display = 'none';
      }

      // ── Evidence Summary ──
      const evidenceEl = document.getElementById('scan-evidence-summary');
      const evidenceBullets = [];
      if (result.findings) {
        result.findings.forEach(f => {
          const txt = f.finding || '';
          const sev = f.severity || 'LOW';
          // Pull evidence snippets from each finding's evidence array
          (f.evidence || []).forEach(e => {
            const snippet = (e.snippet || '').trim();
            if (snippet) {
              evidenceBullets.push({ text: snippet, isWarning: sev === 'HIGH' || sev === 'CRITICAL' || sev === 'MEDIUM' });
            }
          });
          // Also add the finding itself when it has meaningful content
          if (txt && !txt.startsWith('✓')) {
            const isWarning = sev === 'HIGH' || sev === 'CRITICAL' || sev === 'MEDIUM';
            if (!evidenceBullets.some(b => b.text === txt)) {
              evidenceBullets.push({ text: txt, isWarning });
            }
          }
        });
      }
      let hasEvidenceBullets = evidenceBullets.length > 0;
      if (hasEvidenceBullets) {
        evidenceEl.innerHTML = evidenceBullets.map(b => `
          <div class="flex items-center gap-2 text-sm">
            <span class="material-symbols-outlined ${b.isWarning ? 'text-error' : 'text-tertiary'}" style="font-size:16px">${b.isWarning ? 'warning' : 'check_circle'}</span>
            <span class="${b.isWarning ? 'text-white/90' : 'text-on-surface-variant'}">${b.text}</span>
          </div>
        `).join('');
      } else {
        evidenceEl.innerHTML = '';
      }

      // ── Bank Authenticity Checks ──
      let hasAnyBankEvidence = false;
      const bankCheckState = { bank_name: false, ifsc: true, account_number: true, branch: true, customer_id: true, currency_inr: true, no_template: true };
      if (result.findings) {
        result.findings.forEach(f => {
          const txt = f.finding || '';
          (f.evidence || []).forEach(e => {
            const s = e.snippet || '';
            if (s.includes('Missing IFSC')) { hasAnyBankEvidence = true; bankCheckState.bank_name = true; bankCheckState.ifsc = false; }
            if (s.includes('Missing Account Number')) { hasAnyBankEvidence = true; bankCheckState.bank_name = true; bankCheckState.account_number = false; }
            if (s.includes('Missing Branch')) { hasAnyBankEvidence = true; bankCheckState.bank_name = true; bankCheckState.branch = false; }
            if (s.includes('Missing Customer ID') || s.includes('Missing Customer Id')) { hasAnyBankEvidence = true; bankCheckState.bank_name = true; bankCheckState.customer_id = false; }
            if (s.includes('TEMPLATE.NET') || s.includes('Public template') || s.includes('template')) { hasAnyBankEvidence = true; bankCheckState.no_template = false; }
            if (s.includes('Currency mismatch') || s.includes('non-INR') || s.includes('foreign currency')) { hasAnyBankEvidence = true; bankCheckState.currency_inr = false; }
            if (s.includes('Bank Name:') || s.includes('Bank:')) { hasAnyBankEvidence = true; bankCheckState.bank_name = true; }
          });
          if (txt.includes('Document Authenticity Validation') || txt.includes('Banking Authenticity')) {
            hasAnyBankEvidence = true;
          }
        });
      }
      const bankCheckList = [
        { label: 'Bank Name Present', key: 'bank_name' },
        { label: 'IFSC Code Present', key: 'ifsc' },
        { label: 'Account Number Present', key: 'account_number' },
        { label: 'Branch Present', key: 'branch' },
        { label: 'Customer ID Present', key: 'customer_id' },
        { label: 'INR Currency', key: 'currency_inr' },
        { label: 'No Template Watermark', key: 'no_template' },
      ];
      const bankChecksPassed = hasAnyBankEvidence ? bankCheckList.filter(c => bankCheckState[c.key]).length : 0;
      const bankCheckTotal = hasAnyBankEvidence ? bankCheckList.length : 0;
      const authenticityFromChecks = bankCheckTotal > 0 ? Math.round(bankChecksPassed / bankCheckTotal * 100) : (result.authenticity_score != null ? result.authenticity_score : 0);
      if (hasAnyBankEvidence) {
        evidenceEl.innerHTML += `
          <div class="mt-4 pt-4 border-t border-white/10">
            <div class="text-xs text-on-surface-variant mb-3 font-semibold uppercase tracking-widest">Bank Authenticity Checks (${bankChecksPassed}/${bankCheckList.length})</div>
            <div class="space-y-1">
              ${bankCheckList.map(c => {
                const ok = bankCheckState[c.key];
                return `
                  <div class="flex items-center gap-2 text-sm">
                    <span class="material-symbols-outlined ${ok ? 'text-tertiary' : 'text-error'}" style="font-size:16px">${ok ? 'check_circle' : 'cancel'}</span>
                    <span class="${ok ? 'text-on-surface-variant' : 'text-white/90'}">${c.label}</span>
                  </div>`;
              }).join('')}
            </div>
          </div>
        `;
      }

      // ── Verdict Panel ──
      const verdictPanel = document.getElementById('scan-verdict-panel');
      if (result.verdict && result.risk_score >= 20) {
        verdictPanel.style.display = 'block';
        document.getElementById('scan-verdict-label').textContent = result.verdict;
        document.getElementById('scan-verdict-label').style.color = scoreColor;
        document.getElementById('scan-verdict-confidence').textContent = fc + '%';
        const authScoreDisplay = (result.authenticity_score != null ? result.authenticity_score : authenticityFromChecks) + '/100';
        document.getElementById('scan-verdict-authenticity').textContent = authScoreDisplay;
        // Top evidence items
        const topEvidenceEl = document.getElementById('scan-verdict-evidence');
        const topItems = [];
        if (result.findings) {
          result.findings.forEach(f => {
            (f.evidence || []).forEach(e => {
              const snip = e.snippet || '';
              snip.split('\n').forEach(line => {
                const trimmed = line.trim();
                if (trimmed && trimmed.startsWith('✓')) {
                  if (!topItems.includes(trimmed)) {
                    topItems.push(trimmed);
                  }
                }
              });
            });
          });
        }
        if (topItems.length) {
          topEvidenceEl.innerHTML = topItems.slice(0, 6).map((item, i) =>
            `<div class="text-sm text-on-surface-variant flex items-start gap-2"><span class="text-primary font-mono flex-shrink-0">${i + 1}.</span><span>${item.replace('✓ ', '')}</span></div>`
          ).join('');
        } else {
          topEvidenceEl.innerHTML = '<div class="text-sm text-on-surface-variant">No evidence recorded.</div>';
        }
      } else {
        verdictPanel.style.display = 'none';
      }

      // ── Fabrication Indicators ──
      const fabCard = document.getElementById('scan-fabrication-card');
      if (result.fabrication_indicators && result.fabrication_indicators.detected > 0) {
        fabCard.style.display = 'block';
        const fi = result.fabrication_indicators;
        document.getElementById('scan-fabrication-count').textContent = fi.detected + '/' + fi.total;
        const listEl = document.getElementById('scan-fabrication-list');
        listEl.innerHTML = (fi.items || []).map(ind => `
          <div class="flex items-center gap-2 text-sm">
            <span class="material-symbols-outlined text-error" style="font-size:16px">warning</span>
            <span class="text-white">${ind}</span>
          </div>
        `).join('');
      } else {
        fabCard.style.display = 'none';
      }

          // ── Authenticity Score KPI ──
          const finalAuthScore = authScore != null ? authScore : (result.authenticity_score != null ? Math.round(result.authenticity_score) : authenticityFromChecks);
          const authScoreEl = document.getElementById('scan-authenticity-score');
          authScoreEl.textContent = (finalAuthScore ?? 0) + '/100';
          authScoreEl.style.color = finalAuthScore <= 30 ? '#ffb4ab' : finalAuthScore <= 60 ? '#f6e05e' : '#4edea3';

      // ── Contribution Breakdown ──
      const contribEl = document.getElementById('scan-contributions');

      if (result.risk_categories?.length) {
        const categories = result.risk_categories;
        contribEl.innerHTML = categories.map(c => {
          const pts = c.score.toFixed(1);
          const weightPct = ((c.weight || 0) * 100).toFixed(0);
          return `
          <div class="flex justify-between items-center text-sm py-1">
            <span class="text-on-surface-variant">${c.label} <span class="text-white/30 text-xs">(${weightPct}%)</span></span>
            <span class="text-primary font-mono font-bold">+${pts}</span>
          </div>`;
        }).join('');

        const rawSum = Math.min(categories.reduce((s, c) => s + c.score, 0), 100);
        document.getElementById('scan-raw-score').textContent = rawSum.toFixed(1) + '/100';
        document.getElementById('scan-normalized-score').textContent = score + '/100';
      } else if (result.findings?.length) {
        const contribMap = {};
        result.findings.forEach(f => {
          const sc = f.score_contribution || 0;
          const cat = f.category || 'Unknown';
          if (!contribMap[cat]) {
            contribMap[cat] = { label: cat, points: 0 };
          }
          contribMap[cat].points += sc;
        });
        const contributions = Object.values(contribMap);
        contribEl.innerHTML = contributions.map(c => {
          const pts = c.points.toFixed(1);
          return `
          <div class="flex justify-between items-center text-sm py-1">
            <span class="text-on-surface-variant">${c.label}</span>
            <span class="text-primary font-mono font-bold">+${pts}</span>
          </div>`;
        }).join('');
        const rawScore = Math.min(contributions.reduce((s, c) => s + c.points, 0), 100);
        document.getElementById('scan-raw-score').textContent = rawScore.toFixed(1) + '/100';
        document.getElementById('scan-normalized-score').textContent = score + '/100';
      } else {
        contribEl.innerHTML = '<div class="text-xs text-on-surface-variant">No contribution data available</div>';
        document.getElementById('scan-raw-score').textContent = '—';
        document.getElementById('scan-normalized-score').textContent = score;
      }

      // ── Detailed Findings ──
      const findingsEl = document.getElementById('scan-findings');
      if (result.findings?.length) {
        findingsEl.innerHTML = result.findings.map(f => {
          const borderCls = f.severity === 'CRITICAL' ? 'border-error' : f.severity === 'HIGH' ? 'border-orange-500' : f.severity === 'MEDIUM' ? 'border-blue-500' : 'border-tertiary';
          const isExtended = f.severity === 'CRITICAL' || f.severity === 'HIGH';
          // Build evidence detail rows
          let evidenceHtml = '';
          if (f.evidence && f.evidence.length) {
            const lines = [];
            f.evidence.forEach(e => {
              const snippet = e.snippet || '';
              snippet.split('\n').forEach(line => {
                const trimmed = line.trim();
                if (trimmed) {
                  lines.push(trimmed);
                }
              });
            });
            if (lines.length) {
              evidenceHtml = lines.map(l => `<div class="text-xs font-mono text-on-surface-variant pl-2 border-l-2 border-white/10 py-0.5">${l.startsWith('•') ? l : '• ' + l}</div>`).join('');
            }
          }
          return `
          <div class="finding-card glass-panel rounded-xl border-l-4 ${borderCls}">
            <div class="p-4 flex items-start gap-3 cursor-pointer" onclick="this.nextElementSibling.classList.toggle('hidden')">
              <div class="flex-1">
                <div class="text-sm font-semibold text-white">${f.finding}</div>
                <div class="flex gap-2 mt-1 flex-wrap">
                  <span class="text-[10px] px-2 py-0.5 rounded ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'bg-error/20 text-error' : f.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-blue-500/20 text-blue-500'} font-semibold">${f.severity}</span>
                  <span class="text-[10px] text-on-surface-variant">${f.category}</span>
                  <span class="text-[10px] text-primary">+${f.score_contribution != null ? f.score_contribution.toFixed(1) : '0'} pts</span>
                </div>
              </div>
              ${evidenceHtml ? '<span class="material-symbols-outlined text-on-surface-variant text-lg flex-shrink-0 mt-0.5">expand_more</span>' : ''}
            </div>
            ${evidenceHtml ? `<div class="px-4 pb-4 space-y-1 ${isExtended ? '' : 'hidden'}">${evidenceHtml}</div>` : ''}
          </div>`;
        }).join('');
      } else {
        findingsEl.innerHTML = '<div class="text-center py-8 text-on-surface-variant"><span class="material-symbols-outlined text-4xl block mb-2">check_circle</span>No anomalies detected</div>';
      }

      // ── Recommendations ──
      const recsEl = document.getElementById('scan-recommendations');
      if (result.recommendations?.length) {
        recsEl.innerHTML = result.recommendations.map(r => `<li class="text-sm text-on-surface-variant">${r}</li>`).join('');
      } else {
        recsEl.innerHTML = '<li class="text-sm text-on-surface-variant">No recommendations available</li>';
      }

      // ── Score Evolution ──
      renderScoreEvolution(result, score);

      // ── Radar Chart ──
      renderRadarChart(result);

      // ── Compliance Impact ──
      renderComplianceImpact(result);

      // ── Model Explainability ──
      renderExplainability(result);

      // ── Investigation Timeline ──
      renderTimeline(result);

      // ── Human Override ──
      renderHumanOverride(result);

      // ── Similar Cases ──
      renderSimilarCases(result);
      renderExtractedFields(result);

      showToast('Analysis complete', 'success');

      // Store scan ID so dashboard buttons can reference it
      if (result.scan_id) {
        window._lastUploadScanId = result.scan_id;
      }

      // Force dashboard to refresh on next visit
      const dashLoaded = document.getElementById('dash-loaded');
      if (dashLoaded) {
        dashLoaded.dataset.loaded = '0';
        // If dashboard is the active page, reload it now
        if (document.getElementById('page-dashboard')?.classList.contains('active')) {
          loadDashboard();
        }
      }

    } catch (err) {
      console.error('runPipeline error:', err);
      showToast('Analysis encountered an issue — partial results shown', 'error');
    }
  }

  window.resetUpload = function() {
    document.getElementById('upload-zone').style.display = 'block';
    document.getElementById('scan-pipeline').style.display = 'none';
    document.getElementById('scan-results').style.display = 'none';
    document.getElementById('file-input').value = '';
    document.querySelectorAll('.pending-step, .done-step, .active-step').forEach(s => {
      s.className = 'flex items-center gap-4 p-4 bg-surface-container rounded-lg border border-white/5';
      const status = s.querySelector('.step-status');
      if (status) status.textContent = 'Pending';
    });
    // Reset auxiliary cards
    const decPanel = document.getElementById('scan-decision-panel');
    if (decPanel) decPanel.style.background = '';
    const decCard = document.getElementById('scan-decision-card');
    if (decCard) decCard.style.display = 'none';
    const ovrCard = document.getElementById('scan-override-card');
    if (ovrCard) ovrCard.style.display = 'none';
    const vPanel = document.getElementById('scan-verdict-panel');
    if (vPanel) vPanel.style.display = 'none';
    const fCard = document.getElementById('scan-fabrication-card');
    if (fCard) fCard.style.display = 'none';
    const errBanner = document.getElementById('scan-error-banner');
    if (errBanner) errBanner.style.display = 'none';
    // Reset new panels
    ['scan-evolution-card', 'scan-radar-card', 'scan-compliance-card', 'scan-explain-card', 'scan-timeline-card', 'scan-override-human-card', 'scan-similar-card', 'scan-extracted-card'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });
    const humanDecisionRow = document.getElementById('scan-human-decision-row');
    if (humanDecisionRow) humanDecisionRow.style.display = 'none';
    const humanDecisionEl = document.getElementById('scan-human-decision');
    if (humanDecisionEl) humanDecisionEl.textContent = '—';
    const humanReasonEl = document.getElementById('scan-human-reason');
    if (humanReasonEl) { humanReasonEl.style.display = 'none'; humanReasonEl.textContent = ''; }
  };

  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  // ── INVESTIGATIONS ──
  async function loadInvestigations() {
    const loadedEl = document.getElementById('inv-loaded');

    // If detail view requested, show it
    if (window.location.hash.startsWith('#investigations/')) {
      const scanId = window.location.hash.replace('#investigations/', '').split('?')[0];
      renderInvestigationDetail(scanId);
      return;
    }

    if (loadedEl && loadedEl.dataset.loaded === '1') return;

    try {
      const headers = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const res = await fetch('/api/v1/investigations?limit=50', { headers });
      if (!res.ok) {
        console.warn('Investigations API failed:', res.status);
        const container = document.getElementById('investigations-list');
        if (container) {
          container.innerHTML = '<div class="text-center py-12 text-on-surface-variant col-span-2"><span class="material-symbols-outlined text-5xl block mb-3">folder_off</span>Could not load investigations. Sign in to view.</div>';
        }
        if (loadedEl) loadedEl.dataset.loaded = '1';
        return;
      }
      const resp = await res.json();
      const cases = resp.cases || [];
      const container = document.getElementById('investigations-list');
      if (!container) return;

      // Update KPI stats
      const totalEl = document.getElementById('inv-total');
      const highEl = document.getElementById('inv-high');
      const openEl = document.getElementById('inv-open');
      if (totalEl) totalEl.textContent = cases.length;
      if (highEl) highEl.textContent = cases.filter(c => c.risk === 'HIGH').length;
      if (openEl) openEl.textContent = cases.filter(c => c.status === 'Open').length;

      if (!cases.length) {
        container.innerHTML = '<div class="text-center py-12 text-on-surface-variant col-span-2"><span class="material-symbols-outlined text-5xl block mb-3">folder_off</span>No investigations yet. Upload a document to begin.</div>';
        if (loadedEl) loadedEl.dataset.loaded = '1';
        return;
      }

      container.innerHTML = cases.map(t => {
        const riskCls = t.risk === 'HIGH' ? 'bg-error/20 text-error border-error/30' : t.risk === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-500 border-yellow-500/30' : 'bg-tertiary/20 text-tertiary border-tertiary/30';
        const statusCls = t.status === 'Open' ? 'bg-primary/10 text-primary border-primary/30' : t.status === 'Under Review' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/30' : t.status === 'Escalated' ? 'bg-error/10 text-error border-error/30' : 'bg-tertiary/10 text-tertiary border-tertiary/30';
        const timeAgo = t.timestamp ? timeSince(new Date(t.timestamp)) : '—';
        const topF = (t.top_findings || []).slice(0, 3);
        return `
        <div class="investigation-card glass-panel p-5 rounded-xl hover:border-primary/20 transition-all cursor-pointer" onclick="window.openInvestigation('${t.scan_id}')">
          <div class="flex items-start justify-between mb-3">
            <div class="min-w-0 flex-1">
              <div class="text-sm font-semibold text-white truncate">${t.filename || t.scan_id?.slice(0, 12) || 'Unknown'}</div>
              ${topF.length ? `<div class="text-[11px] text-on-surface-variant mt-1.5 leading-relaxed">${topF.map(f => `<span class="block">• ${f}</span>`).join('')}</div>` : `<div class="text-xs text-on-surface-variant mt-0.5">${t.fraud_type || 'Document Upload'}</div>`}
            </div>
            <div class="flex gap-1.5 flex-shrink-0 ml-3">
              <span class="text-[10px] font-bold px-2 py-0.5 rounded border ${riskCls}">${t.risk}</span>
              <span class="text-[10px] font-bold px-2 py-0.5 rounded border ${statusCls}">${t.status}</span>
            </div>
          </div>
          <div class="flex items-center justify-between text-[10px] text-on-surface-variant/60 mt-2 pt-2 border-t border-white/5">
            <span>🕐 ${timeAgo}</span>
            <div class="flex gap-3">
              <span>Score: ${t.risk_score || '?'}/100</span>
              <span>⚠ ${t.compliance_count || 0}</span>
              ${t.analyst ? `<span>👤 ${t.analyst}</span>` : ''}
            </div>
          </div>
        </div>`;
      }).join('');
      if (loadedEl) loadedEl.dataset.loaded = '1';
    } catch (err) {
      console.error('loadInvestigations error:', err);
      if (loadedEl) loadedEl.dataset.loaded = '1';
    }
  }

  // ── Investigation Detail View ──
  window.openInvestigation = function(scanId) {
    window.location.hash = `investigations/${scanId}`;
  };

  window.closeInvestigationDetail = function() {
    document.getElementById('inv-loaded').dataset.loaded = '0';
    window.location.hash = 'investigations';
  };

  async function renderInvestigationDetail(scanId) {
    const container = document.getElementById('investigations-list');
    if (!container) return;
    document.getElementById('inv-loaded').dataset.loaded = '1';

    try {
      const data = await api('GET', `/investigations/${scanId}`);
      const riskCls = data.risk === 'HIGH' ? 'text-error border-error/30' : data.risk === 'MEDIUM' ? 'text-yellow-500 border-yellow-500/30' : 'text-tertiary border-tertiary/30';
      const statusCls = data.status === 'Open' ? 'text-primary border-primary/30' : data.status === 'Under Review' ? 'text-yellow-500 border-yellow-500/30' : data.status === 'Escalated' ? 'text-error border-error/30' : 'text-tertiary border-tertiary/30';
      const timeAgo = data.timestamp ? timeSince(new Date(data.timestamp)) : '—';
      const riskScore = data.risk_score || 0;

      // Executive decision
      const decision = data.decision || 'Pending';
      const decisionCls = decision === 'Reject' ? 'bg-error/20 text-error border-error/30' : decision === 'Manual Review' ? 'bg-yellow-500/20 text-yellow-500 border-yellow-500/30' : 'bg-tertiary/20 text-tertiary border-tertiary/30';
      const decisionIcon = decision === 'Reject' ? 'block' : decision === 'Manual Review' ? 'rate_review' : 'check_circle';

      container.innerHTML = `
      <div class="col-span-2">
        <!-- Back button -->
        <button class="flex items-center gap-2 text-on-surface-variant hover:text-primary mb-4 text-sm cursor-pointer" onclick="window.closeInvestigationDetail()">
          <span class="material-symbols-outlined text-lg">arrow_back</span>
          Back to Investigations
        </button>

        <!-- Header with Executive Decision -->
        <div class="glass-panel rounded-xl p-6 mb-4">
          <div class="flex items-start justify-between mb-4">
            <div class="min-w-0 flex-1">
              <h3 class="text-lg font-bold text-white">${data.filename}</h3>
              <p class="text-xs text-on-surface-variant mt-1">Scan ID: ${data.scan_id?.slice(0, 20) || '—'}…</p>
            </div>
            <div class="flex gap-2 flex-shrink-0 ml-4">
              <span class="text-xs font-bold px-2 py-1 rounded border ${riskCls}">${data.risk}</span>
              <span class="text-xs font-bold px-2 py-1 rounded border ${statusCls}">${data.status}</span>
            </div>
          </div>

          <!-- Executive Decision Banner -->
          <div class="rounded-xl p-4 mb-4 ${decision === 'Reject' ? 'bg-error/10 border border-error/20' : decision === 'Manual Review' ? 'bg-yellow-500/10 border border-yellow-500/20' : 'bg-tertiary/10 border border-tertiary/20'}">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-3">
                <span class="material-symbols-outlined text-2xl ${decision === 'Reject' ? 'text-error' : decision === 'Manual Review' ? 'text-yellow-500' : 'text-tertiary'}">${decisionIcon}</span>
                <div>
                  <div class="text-sm font-bold text-white">Recommended Decision: ${decision}</div>
                  <div class="text-xs text-on-surface-variant">Based on risk score (${riskScore}/100) and ${data.compliance_alerts?.length || 0} compliance alerts</div>
                </div>
              </div>
              <span class="text-3xl font-bold ${decision === 'Reject' ? 'text-error' : decision === 'Manual Review' ? 'text-yellow-500' : 'text-tertiary'}">${riskScore}</span>
            </div>
            ${data.decision_reasons?.length ? `<div class="flex gap-2 mt-3 flex-wrap">${data.decision_reasons.map(r => `<span class="px-2 py-0.5 bg-white/5 rounded text-[10px] text-on-surface-variant">${r}</span>`).join('')}</div>` : ''}
          </div>

          <div class="grid grid-cols-5 gap-3 text-xs text-on-surface-variant">
            <div><span class="text-primary">Uploaded</span><br>${timeAgo}</div>
            <div><span class="text-primary">Confidence</span><br>${data.confidence ? (data.confidence * 100).toFixed(1) + '%' : '—'}</div>
            <div><span class="text-primary">Compliance</span><br>${data.compliance_alerts?.length || 0} alerts</div>
            <div><span class="text-primary">Findings</span><br>${data.findings?.length || 0}</div>
            <div><span class="text-primary">Risk Score</span><br>${riskScore}/100</div>
          </div>
          ${data.notes ? `<div class="mt-4 p-3 bg-surface-container rounded-lg text-xs text-on-surface-variant">📝 ${data.notes}</div>` : ''}
        </div>

        <!-- Risk Category Breakdown -->
        ${data.risk_categories?.length ? `
        <div class="glass-panel rounded-xl p-5 mb-4">
          <h4 class="text-xs font-bold text-on-surface-variant uppercase tracking-widest mb-3">Risk Breakdown</h4>
          <div class="space-y-2">
            ${data.risk_categories.map(rc => {
              const barWidth = Math.max(rc.score, 2);
              const barCls = rc.score >= 60 ? 'bg-error' : rc.score >= 30 ? 'bg-yellow-500' : 'bg-primary';
              return `
              <div class="flex items-center gap-3">
                <span class="text-[10px] text-on-surface-variant w-36 flex-shrink-0">${rc.label}</span>
                <div class="flex-1 bg-white/5 rounded-full h-2 overflow-hidden">
                  <div class="h-full rounded-full ${barCls} transition-all" style="width: ${barWidth}%"></div>
                </div>
                <span class="text-[11px] font-mono text-white w-12 text-right">${rc.score.toFixed(1)}</span>
              </div>`;
            }).join('')}
            <div class="border-t border-white/5 pt-2 mt-2">
              <div class="flex items-center gap-3">
                <span class="text-[10px] font-bold text-white w-36 flex-shrink-0">Total</span>
                <div class="flex-1 bg-white/5 rounded-full h-3 overflow-hidden">
                  <div class="h-full rounded-full ${riskScore >= 60 ? 'bg-error' : riskScore >= 30 ? 'bg-yellow-500' : 'bg-primary'}" style="width: ${Math.max(riskScore, 2)}%"></div>
                </div>
                <span class="text-[11px] font-bold text-white w-12 text-right">${riskScore}</span>
              </div>
            </div>
          </div>
        </div>` : ''}

        <!-- Action buttons -->
        <div class="flex gap-3 mb-4 flex-wrap items-center">
          <select id="case-status-select" class="px-3 py-2 bg-surface-container border border-white/10 rounded-lg text-xs text-on-surface outline-none">
            <option value="Open" ${data.status === 'Open' ? 'selected' : ''}>Open</option>
            <option value="Under Review" ${data.status === 'Under Review' ? 'selected' : ''}>Under Review</option>
            <option value="Escalated" ${data.status === 'Escalated' ? 'selected' : ''}>Escalated</option>
            <option value="Closed" ${data.status === 'Closed' ? 'selected' : ''}>Closed</option>
          </select>
          <input id="case-analyst-input" class="px-3 py-2 bg-surface-container border border-white/10 rounded-lg text-xs text-on-surface outline-none w-40" placeholder="Assign analyst" value="${data.assigned_to || ''}">
          <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:brightness-110 transition-all cursor-pointer" onclick="window.updateCaseStatus('${scanId}')">Update Case</button>
          <button class="px-4 py-2 bg-surface-container text-on-surface rounded-lg text-xs font-bold hover:brightness-110 transition-all cursor-pointer border border-white/10" onclick="window.downloadReport('${scanId}', 'pdf')">📄 PDF</button>
          <button class="px-4 py-2 bg-surface-container text-on-surface rounded-lg text-xs font-bold hover:brightness-110 transition-all cursor-pointer border border-white/10" onclick="window.downloadReport('${scanId}', 'csv')">📊 CSV</button>
          <button class="px-4 py-2 bg-surface-container text-on-surface rounded-lg text-xs font-bold hover:brightness-110 transition-all cursor-pointer border border-white/10" onclick="window.downloadReport('${scanId}', 'json')">📋 JSON</button>
          ${data.recommendations?.length ? `
          <div class="flex gap-1.5 flex-wrap">
            ${data.recommendations.slice(0, 3).map(r => `<span class="px-2 py-1 bg-primary/5 text-[10px] text-primary rounded border border-primary/10">${r}</span>`).join('')}
          </div>` : ''}
        </div>

        <!-- Tabs -->
        <div class="flex gap-1 mb-4 border-b border-white/10">
          <button class="tab-btn px-4 py-2 text-xs font-semibold text-on-surface-variant hover:text-white border-b-2 border-transparent active-tab cursor-pointer" data-tab="findings" onclick="switchInvestigationTab('findings')">Findings (${data.findings?.length || 0})</button>
          <button class="tab-btn px-4 py-2 text-xs font-semibold text-on-surface-variant hover:text-white border-b-2 border-transparent cursor-pointer" data-tab="compliance" onclick="switchInvestigationTab('compliance')">Compliance (${data.compliance_alerts?.length || 0})</button>
          <button class="tab-btn px-4 py-2 text-xs font-semibold text-on-surface-variant hover:text-white border-b-2 border-transparent cursor-pointer" data-tab="audit" onclick="switchInvestigationTab('audit')">Audit Trail</button>
          <button class="tab-btn px-4 py-2 text-xs font-semibold text-on-surface-variant hover:text-white border-b-2 border-transparent cursor-pointer" data-tab="evidence" onclick="switchInvestigationTab('evidence')">Evidence</button>
        </div>

        <!-- Tab Content -->
        <div id="inv-tab-content">
          ${renderFindingsTab(data.findings || [], data)}
        </div>

        <!-- Evidence Modal -->
        <div id="evidence-modal" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/60 backdrop-blur-sm" onclick="if (event.target === this) closeEvidenceModal()">
          <div class="bg-surface-container border border-white/10 rounded-xl p-6 max-w-lg w-full mx-4 max-h-[80vh] overflow-y-auto" onclick="event.stopPropagation()">
            <div class="flex items-center justify-between mb-4">
              <h4 class="text-sm font-bold text-white" id="evidence-modal-title">Evidence Details</h4>
              <button class="text-on-surface-variant hover:text-white cursor-pointer" onclick="closeEvidenceModal()"><span class="material-symbols-outlined">close</span></button>
            </div>
            <div id="evidence-modal-body"></div>
          </div>
        </div>
      </div>`;
    } catch (e) {
      container.innerHTML = `<div class="col-span-2 text-center py-12 text-on-surface-variant"><span class="material-symbols-outlined text-5xl block mb-3">error</span>Failed to load investigation: ${e.message}</div>`;
    }
  }

  // ── Evidence Modal ──
  window.showEvidenceModal = function(finding) {
    const modal = document.getElementById('evidence-modal');
    const title = document.getElementById('evidence-modal-title');
    const body = document.getElementById('evidence-modal-body');
    if (!modal || !body) return;
    title.textContent = 'Finding: ' + (finding.finding || '').slice(0, 60);
    body.innerHTML = `
      <div class="space-y-4">
        <div class="p-3 bg-surface rounded-lg">
          <div class="text-xs text-on-surface-variant mb-1">Full Description</div>
          <div class="text-sm text-white">${finding.finding || '—'}</div>
        </div>
        <div class="grid grid-cols-2 gap-3 text-xs">
          <div class="p-3 bg-surface rounded-lg">
            <div class="text-on-surface-variant mb-0.5">Category</div>
            <div class="text-white font-semibold">${finding.category || '—'}</div>
          </div>
          <div class="p-3 bg-surface rounded-lg">
            <div class="text-on-surface-variant mb-0.5">Severity</div>
            <div class="${finding.severity === 'HIGH' ? 'text-error' : 'text-yellow-500'} font-semibold">${finding.severity || '—'}</div>
          </div>
          <div class="p-3 bg-surface rounded-lg">
            <div class="text-on-surface-variant mb-0.5">Confidence</div>
            <div class="text-white font-semibold">${finding.confidence ? (finding.confidence * 100).toFixed(0) + '%' : '—'}</div>
          </div>
          <div class="p-3 bg-surface rounded-lg">
            <div class="text-on-surface-variant mb-0.5">Score Contribution</div>
            <div class="text-white font-semibold">${finding.score_contribution != null ? finding.score_contribution.toFixed(1) : '—'}</div>
          </div>
        </div>
        ${finding.evidence?.length ? `
        <div>
          <div class="text-xs font-bold text-on-surface-variant uppercase tracking-widest mb-2">Evidence (${finding.evidence.length})</div>
          ${finding.evidence.map((e, i) => `
          <div class="p-3 bg-surface rounded-lg mb-2 border-l-2 border-primary/30">
            <div class="text-xs font-mono text-white whitespace-pre-wrap">${e.snippet || '—'}</div>
            <div class="flex gap-3 mt-2 text-[10px] text-on-surface-variant">
              ${e.field ? `<span>Field: ${e.field}</span>` : ''}
              ${e.expected ? `<span>Expected: ${e.expected}</span>` : ''}
              ${e.confidence != null ? `<span>Confidence: ${(e.confidence * 100).toFixed(0)}%</span>` : ''}
              ${e.page_ref ? `<span>Page: ${e.page_ref}</span>` : ''}
            </div>
          </div>`).join('')}
        </div>` : '<div class="p-3 bg-surface rounded-lg text-xs text-on-surface-variant">No supporting evidence recorded for this finding.</div>'}
      </div>`;
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  };

  window.closeEvidenceModal = function() {
    const modal = document.getElementById('evidence-modal');
    if (!modal) return;
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  };

  // ── Report Download ──
  window.downloadReport = function(scanId, format) {
    const link = document.createElement('a');
    link.href = `${API}/investigations/${scanId}/report?format=${format}`;
    link.target = '_blank';
    // Fetch with auth header, create blob URL
    fetch(link.href, {
      headers: { 'Authorization': `Bearer ${token}` },
    }).then(res => {
      if (!res.ok) throw new Error('Report generation failed');
      return res.blob();
    }).then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `investigation_${scanId.slice(0, 12)}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast(`Report downloaded as ${format.toUpperCase()}`, 'success');
    }).catch(e => {
      showToast('Failed to download report: ' + e.message, 'error');
    });
  };

  function renderFindingsTab(findings, data) {
    if (!findings.length) return '<div class="text-center py-8 text-on-surface-variant">No findings recorded.</div>';
    return findings.map(f => {
      const sevCls = f.severity === 'HIGH' || f.severity === 'CRITICAL' ? 'border-l-red-500' : f.severity === 'MEDIUM' ? 'border-l-yellow-500' : 'border-l-blue-500';
      const hasEvidence = f.evidence?.length > 0;
      return `
      <div class="finding-card glass-panel p-4 rounded-xl border-l-4 ${sevCls} mb-3 ${hasEvidence ? 'cursor-pointer hover:border-primary/30 transition-all' : ''}" ${hasEvidence ? `onclick="window.showEvidenceModal(${JSON.stringify(f).replace(/"/g, '&quot;')})"` : ''}>
        <div class="flex items-start justify-between">
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-white">${f.finding}</div>
            <div class="flex gap-2 mt-1.5 flex-wrap">
              <span class="text-[10px] px-2 py-0.5 rounded ${f.severity === 'HIGH' ? 'bg-error/20 text-error' : f.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-blue-500/20 text-blue-500'} font-semibold">${f.severity}</span>
              <span class="text-[10px] text-on-surface-variant">${f.category}</span>
              <span class="text-[10px] text-on-surface-variant">${f.confidence ? (f.confidence * 100).toFixed(0) + '% confidence' : ''}</span>
              ${f.score_contribution ? `<span class="text-[10px] text-primary">+${f.score_contribution.toFixed(1)} pts</span>` : ''}
            </div>
          </div>
          ${hasEvidence ? '<span class="material-symbols-outlined text-primary text-lg flex-shrink-0 ml-2">open_in_full</span>' : ''}
        </div>
        ${hasEvidence ? `
        <div class="mt-3 flex gap-1.5 flex-wrap">
          ${f.evidence.slice(0, 3).map((e, i) => `
          <span class="px-2 py-0.5 bg-surface-container rounded text-[10px] font-mono text-on-surface-variant border border-white/5 max-w-[200px] truncate">${e.field || 'evidence'}${i + 1}: ${(e.snippet || '').slice(0, 40)}${(e.snippet || '').length > 40 ? '…' : ''}</span>
          `).join('')}
          ${f.evidence.length > 3 ? `<span class="px-2 py-0.5 text-[10px] text-primary">+${f.evidence.length - 3} more</span>` : ''}
        </div>` : ''}
      </div>`;
    }).join('');
  }

  window.switchInvestigationTab = function(tab) {
    const content = document.getElementById('inv-tab-content');
    if (!content) return;
    document.querySelectorAll('.tab-btn').forEach(b => {
      b.classList.toggle('active-tab', b.dataset.tab === tab);
      if (b.dataset.tab === tab) {
        b.classList.add('text-white', 'border-primary');
      } else {
        b.classList.remove('text-white', 'border-primary');
      }
    });
    // Content was already rendered in renderInvestigationDetail
    // For audit trail, re-render differently
    if (tab === 'audit') {
      const scanId = window.location.hash.replace('#investigations/', '').split('?')[0];
      renderAuditTab(scanId);
    } else if (tab === 'compliance') {
      const scanId = window.location.hash.replace('#investigations/', '').split('?')[0];
      renderComplianceTab(scanId);
    } else if (tab === 'evidence') {
      const scanId = window.location.hash.replace('#investigations/', '').split('?')[0];
      renderEvidenceTab(scanId);
    } else {
      // Re-render findings from cached data
      api('GET', `/investigations/${window.location.hash.replace('#investigations/', '').split('?')[0]}`).then(d => {
        content.innerHTML = renderFindingsTab(d.findings || []);
      }).catch(() => {});
    }
  };

  async function renderComplianceTab(scanId) {
    const content = document.getElementById('inv-tab-content');
    if (!content) return;
    try {
      const data = await api('GET', `/investigations/${scanId}`);
      const alerts = data.compliance_alerts || [];
      if (!alerts.length) {
        content.innerHTML = '<div class="text-center py-8 text-on-surface-variant"><span class="material-symbols-outlined text-4xl block mb-2">verified</span>No compliance alerts for this document.</div>';
        return;
      }
      const sevColor = { 'CRITICAL': 'border-red-500', 'HIGH': 'border-orange-500', 'MEDIUM': 'border-yellow-500', 'LOW': 'border-blue-500' };
      const sevLabel = { 'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low' };
      content.innerHTML = alerts.map(a => {
        const violation = a.finding_description || a.finding_type || 'No description';
        return `
        <div class="glass-panel p-4 rounded-xl border-l-4 ${sevColor[a.compliance_severity] || 'border-gray-500'} mb-3">
          <div class="flex items-start justify-between mb-2">
            <div>
              <div class="text-sm font-bold text-white">${a.regulation}</div>
              <div class="text-[11px] text-on-surface-variant mt-0.5">Source: ${data.filename || 'Unknown'}</div>
            </div>
            <span class="px-2 py-0.5 text-[10px] font-bold rounded ${a.compliance_severity === 'CRITICAL' || a.compliance_severity === 'HIGH' ? 'bg-error/20 text-error' : 'bg-yellow-500/20 text-yellow-500'}">${sevLabel[a.compliance_severity] || a.compliance_severity}</span>
          </div>
          <div class="p-3 bg-error/5 rounded-lg text-xs text-on-surface mb-2">Violation: ${violation}</div>
          <div class="grid grid-cols-2 gap-3 text-xs mb-2">
            <div class="p-2 bg-surface-container rounded">
              <div class="text-on-surface-variant text-[10px]">Reference</div>
              <div class="text-white font-semibold">${a.reference?.slice(0, 50) || '—'}</div>
            </div>
            <div class="p-2 bg-surface-container rounded">
              <div class="text-on-surface-variant text-[10px]">Required Action</div>
              <div class="text-white">${a.required_action || '—'}</div>
            </div>
          </div>
          ${a.risk_impact ? `<div class="mt-2 p-2 bg-surface-container rounded text-xs text-on-surface-variant">⚠ ${a.risk_impact}</div>` : ''}
          ${a.timeline ? `<div class="mt-1 flex items-center gap-1 text-[10px] text-primary"><span class="material-symbols-outlined text-xs">schedule</span> Timeline: ${a.timeline}</div>` : ''}
          ${a.responsible_party ? `<div class="mt-1 text-[10px] text-on-surface-variant">Responsible: ${a.responsible_party}</div>` : ''}
        </div>`;
      }).join('');
    } catch (_) {
      content.innerHTML = '<div class="text-center py-8 text-on-surface-variant">Failed to load compliance data.</div>';
    }
  }

  async function renderAuditTab(scanId) {
    const content = document.getElementById('inv-tab-content');
    if (!content) return;
    try {
      const data = await api('GET', `/investigations/${scanId}`);
      const trail = data.audit_trail || [];
      content.innerHTML = '<div class="relative pl-6 border-l-2 border-white/10 space-y-6 py-4">' +
        trail.map((a, i) => {
          const icons = ['upload_file', 'text_snippet', 'dataset', 'calculate', 'policy', 'monitoring', 'check_circle'];
          const icon = icons[i] || 'circle';
          return `
          <div class="relative">
            <div class="absolute -left-[25px] w-10 h-10 rounded-full bg-surface-container border-2 ${a.status === 'completed' ? 'border-primary' : 'border-yellow-500'} flex items-center justify-center">
              <span class="material-symbols-outlined text-sm ${a.status === 'completed' ? 'text-primary' : 'text-yellow-500'}">${icon}</span>
            </div>
            <div class="ml-4">
              <div class="text-sm font-semibold text-white">${a.step}</div>
              <div class="text-xs text-on-surface-variant">${a.timestamp ? timeSince(new Date(a.timestamp)) : 'Just now'} · ${a.status}</div>
            </div>
          </div>`;
        }).join('') +
      '</div>';
    } catch (_) {
      content.innerHTML = '<div class="text-center py-8 text-on-surface-variant">Failed to load audit trail.</div>';
    }
  }

  async function renderEvidenceTab(scanId) {
    const content = document.getElementById('inv-tab-content');
    if (!content) return;
    try {
      const data = await api('GET', `/investigations/${scanId}`);
      const extractedText = data.extracted_text || '';
      const docMeta = data.document_meta || {};
      const fraudPatterns = docMeta.fraud_patterns || [];

      let html = '<div class="space-y-4">';

      // OCR Text
      html += `
      <div class="glass-panel p-4 rounded-xl">
        <h4 class="text-xs font-bold text-on-surface-variant uppercase tracking-widest mb-2">OCR Extract</h4>
        ${extractedText ? `<pre class="text-xs font-mono text-on-surface bg-surface-container p-3 rounded-lg overflow-x-auto whitespace-pre-wrap max-h-64 overflow-y-auto">${escHtml(extractedText)}</pre>` : '<div class="text-xs text-on-surface-variant">No extracted text available.</div>'}
      </div>`;

      // Document Metadata
      html += `
      <div class="glass-panel p-4 rounded-xl">
        <h4 class="text-xs font-bold text-on-surface-variant uppercase tracking-widest mb-2">Document Properties</h4>
        <div class="grid grid-cols-2 gap-3 text-xs">
          <div class="p-2 bg-surface-container rounded"><span class="text-on-surface-variant">Filename</span><br><span class="text-white">${escHtml(docMeta.filename || '—')}</span></div>
          <div class="p-2 bg-surface-container rounded"><span class="text-on-surface-variant">Size</span><br><span class="text-white">${docMeta.size_kb ? docMeta.size_kb.toFixed(1) + ' KB' : '—'}</span></div>
          <div class="p-2 bg-surface-container rounded"><span class="text-on-surface-variant">Pages</span><br><span class="text-white">${docMeta.page_count || '1'}</span></div>
          <div class="p-2 bg-surface-container rounded"><span class="text-on-surface-variant">Sources</span><br><span class="text-white">${(docMeta.sources || []).join(', ') || '—'}</span></div>
        </div>
      </div>`;

      // Anomaly Evidence
      const anomalyFindings = (data.findings || []).filter(f => f.category === 'anomaly' || f.category === 'Behavioural Pattern Analysis');
      if (anomalyFindings.length) {
        html += '<div class="glass-panel p-4 rounded-xl"><h4 class="text-xs font-bold text-on-surface-variant uppercase tracking-widest mb-2">Anomaly Evidence</h4>';
        anomalyFindings.forEach(f => {
          const ev = f.evidence || [];
          html += `<div class="mb-3 p-3 bg-surface-container rounded-lg">
            <div class="text-xs text-on-surface mb-1">${escHtml(f.finding.slice(0, 120))}</div>`;
          if (ev.length) {
            ev.forEach(e => {
              html += `<div class="text-[10px] font-mono text-on-surface-variant mt-1">${escHtml(e.snippet || '')}</div>`;
            });
          }
          html += '</div>';
        });
        html += '</div>';
      }

      // Fraud Patterns
      if (fraudPatterns.length) {
        html += '<div class="glass-panel p-4 rounded-xl"><h4 class="text-xs font-bold text-on-surface-variant uppercase tracking-widest mb-2">Fraud Pattern Evidence</h4>';
        fraudPatterns.forEach(p => {
          html += `<div class="mb-2 p-3 bg-surface-container rounded-lg">
            <div class="flex items-center justify-between mb-1">
              <span class="text-xs font-semibold text-white">${escHtml(p.pattern || '')}</span>
              <span class="text-[10px] px-2 py-0.5 rounded ${p.severity === 'HIGH' ? 'bg-error/20 text-error' : 'bg-yellow-500/20 text-yellow-500'}">${p.severity || 'MEDIUM'}</span>
            </div>
            <div class="text-[10px] text-on-surface-variant">${escHtml(p.description || '')}</div>
            <div class="text-[10px] font-mono text-primary mt-1">${escHtml(p.evidence || '')}</div>
          </div>`;
        });
        html += '</div>';
      }

      html += '</div>';
      content.innerHTML = html;
    } catch (_) {
      content.innerHTML = '<div class="text-center py-8 text-on-surface-variant">Failed to load evidence data.</div>';
    }
  }

  function escHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  window.updateCaseStatus = async function(scanId) {
    const status = document.getElementById('case-status-select').value;
    const assignedTo = document.getElementById('case-analyst-input').value;
    try {
      await api('PUT', `/investigations/${scanId}/status?status=${status}&assigned_to=${encodeURIComponent(assignedTo)}`);
      showToast(`Case updated to ${status}`, 'success');
      renderInvestigationDetail(scanId);
    } catch (e) {
      showToast('Failed to update: ' + e.message, 'error');
    }
  };

  function timeSince(date) {
    const sec = Math.floor((new Date() - date) / 1000);
    if (sec < 60) return 'just now';
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hrs = Math.floor(min / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  }

  // ── COMPLIANCE ──
  async function loadCompliance() {
    if (document.getElementById('comp-loaded').dataset.loaded === '1') return;

    try {
      // Get count from executive dashboard (now uses real compliance_alerts table)
      const exec = await api('GET', '/dashboard/executive').catch(() => null);
      const count = exec?.compliance_alerts || 0;
      document.getElementById('comp-total').textContent = count;

      // Get detailed alerts from the compliance/alerts endpoint
      const alertsResp = await api('GET', '/compliance/alerts?limit=20&days=30').catch(() => null);
      const alerts = alertsResp?.alerts || [];

      // Update severity counts
      const criticalCount = alerts.filter(a => a.compliance_severity === 'CRITICAL').length;
      const highCount = alerts.filter(a => a.compliance_severity === 'HIGH').length;
      const compCritical = document.getElementById('comp-critical');
      const compHigh = document.getElementById('comp-high');
      if (compCritical) compCritical.textContent = criticalCount;
      if (compHigh) compHigh.textContent = highCount;

      const list = document.getElementById('compliance-findings-list');
      if (list) {
        if (alerts.length) {
          const severityColor = {
            'CRITICAL': 'border-red-500',
            'HIGH': 'border-orange-500',
            'MEDIUM': 'border-yellow-500',
            'LOW': 'border-blue-500',
          };
          list.innerHTML = alerts.map(a => {
            // Extract evidence snippet from finding_description if it contains one
            let evidence = a.evidence || a.extracted_text || '';
            if (!evidence && a.finding_description) {
              const match = a.finding_description.match(/"(.*?)"/);
              evidence = match ? match[1] : '';
            }
            return `
            <div class="finding-card glass-panel p-4 rounded-xl border-l-4 ${severityColor[a.compliance_severity] || 'border-error'} flex items-start gap-3">
              <div class="flex-1">
                <div class="text-sm font-semibold text-white">${a.regulation}</div>
                <div class="text-xs text-on-surface-variant mt-0.5">${a.finding_description || a.finding_type || ''}</div>
                ${evidence ? `<div class="mt-2 p-2 bg-surface-container rounded text-xs font-mono text-on-surface-variant">🔍 ${evidence}</div>` : ''}
                <div class="flex gap-2 mt-2">
                  <span class="px-2 py-0.5 text-[10px] font-semibold rounded ${a.compliance_severity === 'CRITICAL' || a.compliance_severity === 'HIGH' ? 'bg-error/20 text-error' : 'bg-warning/20 text-warning'}">${a.compliance_severity}</span>
                  <span class="px-2 py-0.5 text-[10px] font-semibold rounded bg-white/5 text-on-surface-variant">${a.reference}</span>
                </div>
                ${a.risk_impact ? `<div class="mt-1 p-2 bg-error/5 rounded text-xs text-on-surface-variant">⚠ ${a.risk_impact}</div>` : ''}
                ${a.required_action ? `<div class="text-xs text-on-surface-variant mt-1">Action: ${a.required_action}</div>` : ''}
                ${a.timeline ? `<div class="text-xs text-primary mt-1">Timeline: ${a.timeline}</div>` : ''}
              </div>
            </div>`;
          }).join('');
        } else {
          list.innerHTML = '<div class="text-center py-8 text-on-surface-variant"><span class="material-symbols-outlined text-4xl block mb-2">verified</span>No compliance findings</div>';
        }
      }
    } catch (_) {}
    document.getElementById('comp-loaded').dataset.loaded = '1';
  }

  // ── ANALYTICS ──
  async function loadAnalytics() {
    if (document.getElementById('analytics-loaded').dataset.loaded === '1') return;

    try {
      const [riskTrends, exec, chartData] = await Promise.all([
        api('GET', '/dashboard/risk-trends').catch(() => null),
        api('GET', '/dashboard/executive').catch(() => null),
        api('GET', '/dashboard/charts/scan_volume').catch(() => null),
      ]);

      // Risk trend chart
      if (riskTrends?.length) {
        renderLineChart('chart-risk-trend', {
          labels: riskTrends.slice(-14).map(t => t.date?.slice(5) || ''),
          datasets: [
            { label: 'Avg Risk Score', data: riskTrends.slice(-14).map(t => t.avg_score || 0), color: '#06b6d4', fill: true },
            { label: 'Max Risk', data: riskTrends.slice(-14).map(t => t.max_score || 0), color: '#ef4444' },
          ],
        });
      }

      // Fraud detection trend
      if (exec?.trend_analysis) {
        renderBarChart('chart-fraud-trend', {
          labels: exec.trend_analysis.slice(-10).map(t => t.date?.slice(5) || ''),
          datasets: [
            { label: 'Fraud Detected', data: exec.trend_analysis.slice(-10).map(t => t.fraud || 0), color: '#ef4444' },
            { label: 'Compliance Alerts', data: exec.trend_analysis.slice(-10).map(t => t.compliance || 0), color: '#f59e0b' },
          ],
        });
      }

      // Risk distribution
      if (exec?.risk_distribution) {
        renderDoughnutChart('chart-risk-dist', {
          labels: ['Critical', 'High', 'Medium', 'Low'],
          values: [exec.risk_distribution.critical || 0, exec.risk_distribution.high || 0, exec.risk_distribution.medium || 0, exec.risk_distribution.low || 0],
          colors: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
        });
      }

      // Scan volume chart
      if (chartData) {
        renderLineChart('chart-scan-volume', {
          labels: chartData.labels || [],
          datasets: (chartData.datasets || []).map(ds => ({
            label: ds.label || 'Scans',
            data: ds.data || [],
            color: ds.borderColor || '#06b6d4',
            fill: true,
          })),
        });
      }

      if (exec) {
        document.getElementById('analytics-threats').textContent = exec.fraud_detected || 0;
        document.getElementById('analytics-campaigns').textContent = exec.high_risk || 0;
        document.getElementById('analytics-zeroday').textContent = exec.compliance_alerts || 0;
        document.getElementById('analytics-endpoints').textContent = exec.total_documents_scanned || 0;
      }

      // Risk category breakdown chart (radar/bar)
      renderRiskCategoryChart();

      // Recent investigations for analytics
      renderAnalyticsRecentInvestigations();
    } catch (_) {}
    document.getElementById('analytics-loaded').dataset.loaded = '1';
  }

  async function renderRiskCategoryChart() {
    const canvas = document.getElementById('chart-risk-categories');
    if (!canvas) return;
    try {
      const inv = await api('GET', '/investigations?limit=20');
      const cases = inv.cases || [];
      // Collect category data from latest completed scan
      const catMap = {};
      for (const c of cases.slice(0, 5)) {
        const detail = await api('GET', `/investigations/${c.scan_id}`).catch(() => null);
        if (detail?.risk_categories) {
          detail.risk_categories.forEach(rc => {
            catMap[rc.key] = catMap[rc.key] || { label: rc.label, scores: [] };
            catMap[rc.key].scores.push(rc.score);
          });
        }
      }
      const labels = Object.keys(catMap).map(k => catMap[k].label);
      const values = Object.keys(catMap).map(k => catMap[k].scores.reduce((a, b) => a + b, 0) / catMap[k].scores.length || 0);
      if (labels.length) {
        renderBarChart('chart-risk-categories', {
          labels,
          datasets: [{ label: 'Avg Score', data: values, color: '#06b6d4' }],
        });
      } else {
        // Fallback: show anonymous scan data
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
      }
    } catch (_) {}
  }

  async function renderAnalyticsRecentInvestigations() {
    const container = document.getElementById('analytics-recent-investigations');
    if (!container) return;
    try {
      const inv = await api('GET', '/investigations?limit=10');
      const cases = inv.cases || [];
      if (!cases.length) {
        container.innerHTML = '<div class="text-xs text-on-surface-variant text-center py-10">No investigations yet.</div>';
        return;
      }
      container.innerHTML = cases.map(c => `
        <div class="flex items-center justify-between py-2 border-b border-white/5 cursor-pointer hover:bg-white/5 px-2 rounded transition-all" onclick="window.navigate('investigations'); setTimeout(() => window.openInvestigation('${c.scan_id}'), 100)">
          <div class="min-w-0">
            <div class="text-xs font-semibold text-white truncate">${c.filename || c.scan_id?.slice(0, 12)}</div>
            <div class="text-[10px] text-on-surface-variant">${c.fraud_type || 'Upload'}</div>
          </div>
          <span class="text-[10px] px-2 py-0.5 rounded font-semibold ${c.risk === 'HIGH' ? 'bg-error/20 text-error' : c.risk === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-tertiary/20 text-tertiary'}">${c.risk}</span>
        </div>
      `).join('');
    } catch (_) {
      container.innerHTML = '<div class="text-xs text-on-surface-variant text-center py-10">Failed to load.</div>';
    }
  }

  // ── REPORTS ──
  function loadReports() {
    if (document.getElementById('reports-loaded').dataset.loaded === '1') return;
    // Static report list
    const reports = [
      { name: 'Executive Summary — Q2 2026', date: '2026-06-10', icon: '📊' },
      { name: 'Fraud Detection Overview', date: '2026-06-09', icon: '🔍' },
      { name: 'Compliance Audit Report', date: '2026-06-08', icon: '⚖️' },
      { name: 'Weekly Risk Assessment', date: '2026-06-07', icon: '📋' },
      { name: 'Anomaly Detection Log', date: '2026-06-06', icon: '📈' },
      { name: 'Signature Verification Audit', date: '2026-06-05', icon: '✍️' },
    ];
    const container = document.getElementById('reports-list');
    if (container) {
      container.innerHTML = reports.map(r => `
        <div class="glass-panel p-4 rounded-xl flex items-center justify-between hover:border-primary/20 transition-all cursor-pointer" onclick="window.showToast('Report download initiated', 'info')">
          <div class="flex items-center gap-3">
            <span class="text-xl">${r.icon}</span>
            <div>
              <div class="text-sm font-medium text-white">${r.name}</div>
              <div class="text-xs text-on-surface-variant">${r.date}</div>
            </div>
          </div>
          <button class="px-4 py-1.5 border border-white/10 text-on-surface rounded-lg text-xs font-semibold hover:bg-white/5 transition-all">Download</button>
        </div>
      `).join('');
    }
    document.getElementById('reports-loaded').dataset.loaded = '1';
  }

  // ── SETTINGS ──
  function loadSettings() {
    if (document.getElementById('settings-loaded').dataset.loaded === '1') return;

    // Load current compliance mapping state from backend
    api('GET', '/settings/compliance-mapping').then(r => {
      const toggle = document.querySelector('.toggle[data-setting="compliance-mapping"]');
      if (toggle && r) {
        const enabled = r.enabled !== false;
        toggle.dataset.active = enabled ? 'true' : 'false';
        if (enabled) toggle.classList.add('active');
        else toggle.classList.remove('active');
      }
    }).catch(() => {});

    document.querySelectorAll('.toggle').forEach(t => {
      t.addEventListener('click', () => {
        const active = t.dataset.active === 'true';
        t.dataset.active = active ? 'false' : 'true';
        t.classList.toggle('active');

        const setting = t.dataset.setting;
        if (setting === 'compliance-mapping') {
          const enabled = t.dataset.active === 'true';
          api('PUT', `/settings/compliance-mapping?enabled=${enabled}`).catch(() => {});
          showToast(`Compliance mapping ${enabled ? 'enabled' : 'disabled'}`, 'success');
        } else {
          showToast(`Setting updated`, 'success');
        }
      });
      // Sync visual state on first load
      if (t.dataset.active === 'true') t.classList.add('active');
    });
    document.getElementById('settings-loaded').dataset.loaded = '1';
  }

  // ── Score Evolution ──
  function renderScoreEvolution(result, totalScore) {
    const card = document.getElementById('scan-evolution-card');
    const steps = document.getElementById('scan-evolution-steps');
    const total = document.getElementById('scan-evolution-total');
    if (!card || !steps) return;
    const cats = result.risk_categories || [];
    if (!cats.length) return;
    card.style.display = 'block';
    let cumulative = 0;
    steps.innerHTML = cats.map(rc => {
      cumulative += rc.score;
      return `<div class="flex items-center gap-3">
        <span class="text-[10px] text-on-surface-variant w-32 flex-shrink-0">${rc.label}</span>
        <div class="flex-1 bg-white/5 rounded-full h-2 overflow-hidden">
          <div class="h-full rounded-full ${rc.score >= 60 ? 'bg-error' : rc.score >= 30 ? 'bg-yellow-500' : 'bg-primary'} transition-all" style="width:${Math.max(rc.score, 2)}%"></div>
        </div>
        <span class="text-[11px] font-mono text-white w-12 text-right">+${rc.score.toFixed(1)}</span>
      </div>`;
    }).join('');
    total.innerHTML = `<div class="flex items-center justify-between pt-2"><span class="text-xs font-bold text-white">Total Risk Score</span><span class="text-lg font-bold font-mono ${totalScore >= 60 ? 'text-error' : totalScore >= 30 ? 'text-yellow-500' : 'text-primary'}">${totalScore.toFixed(1)}</span></div>`;
  }

  // ── Radar Chart ──
  function renderRadarChart(result) {
    const card = document.getElementById('scan-radar-card');
    const canvas = document.getElementById('scan-radar-chart');
    if (!card || !canvas || !window.Chart) return;
    const cats = result.risk_categories || [];
    if (!cats.length) return;
    card.style.display = 'block';
    if (canvas._chart) canvas._chart.destroy();
    canvas._chart = new Chart(canvas.getContext('2d'), {
      type: 'radar',
      data: {
        labels: cats.map(c => c.label),
        datasets: [{
          label: 'Risk Score',
          data: cats.map(c => c.score),
          backgroundColor: 'rgba(6,182,212,0.15)',
          borderColor: '#06b6d4',
          borderWidth: 2,
          pointBackgroundColor: cats.map(c => c.score >= 60 ? '#ef4444' : c.score >= 30 ? '#f59e0b' : '#06b6d4'),
          pointRadius: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          r: {
            beginAtZero: true,
            max: 100,
            ticks: { color: '#64748b', backdropColor: 'transparent', font: { size: 9 } },
            grid: { color: 'rgba(148,163,184,0.1)' },
            angleLines: { color: 'rgba(148,163,184,0.1)' },
            pointLabels: { color: '#94a3b8', font: { size: 10 } },
          },
        },
      },
    });
  }

  // ── Compliance Impact ──
  function renderComplianceImpact(result) {
    const card = document.getElementById('scan-compliance-card');
    const rows = document.getElementById('scan-compliance-rows');
    if (!card || !rows) return;
    const findings = result.findings || [];
    const complianceFindings = findings.filter(f => f.category === 'compliance' || f.finding?.toLowerCase().includes('compliance') || f.finding?.toLowerCase().includes('regulation') || f.finding?.toLowerCase().includes('rbi'));
    if (!complianceFindings.length) return;
    card.style.display = 'block';
    rows.innerHTML = complianceFindings.map(f => {
      const sev = f.severity || 'MEDIUM';
      const sevCls = sev === 'HIGH' || sev === 'CRITICAL' ? 'border-l-red-500' : sev === 'MEDIUM' ? 'border-l-yellow-500' : 'border-l-blue-500';
      return `<div class="p-3 bg-surface-container rounded-lg border-l-4 ${sevCls}">
        <div class="flex items-center justify-between mb-1">
          <span class="text-xs font-semibold text-white">${f.finding || 'Compliance finding'}</span>
          <span class="text-[10px] px-1.5 py-0.5 rounded ${sev === 'HIGH' || sev === 'CRITICAL' ? 'bg-error/20 text-error' : 'bg-yellow-500/20 text-yellow-500'} font-semibold">${sev}</span>
        </div>
        ${f.confidence != null ? `<div class="text-[10px] text-on-surface-variant">Confidence: ${(f.confidence * 100).toFixed(0)}% · Impact: +${(f.score_contribution || 0).toFixed(1)} pts</div>` : ''}
      </div>`;
    }).join('');
  }

  // ── Model Explainability ──
  function renderExplainability(result) {
    const card = document.getElementById('scan-explain-card');
    const contrib = document.getElementById('scan-explain-contrib');
    if (!card || !contrib) return;
    const cats = result.risk_categories || [];
    if (!cats.length) return;
    card.style.display = 'block';
    const totalCats = cats.reduce((s, c) => s + c.score, 0) || 1;
    const sorted = [...cats].sort((a, b) => b.score - a.score);
    contrib.innerHTML = sorted.map((rc, i) => {
      const pct = ((rc.score / totalCats) * 100).toFixed(1);
      const barCls = rc.score >= 60 ? 'bg-error' : rc.score >= 30 ? 'bg-yellow-500' : 'bg-primary';
      const bars = i === 0 ? '<div class="text-[10px] text-primary font-semibold mt-1">Top contributor</div>' : '';
      return `<div class="p-3 bg-surface-container rounded-lg">
        <div class="flex items-center justify-between mb-1">
          <span class="text-xs text-white">${rc.label}</span>
          <span class="text-[11px] font-mono text-on-surface-variant">${rc.score.toFixed(1)} pts (${pct}%)</span>
        </div>
        <div class="bg-white/5 rounded-full h-1.5 overflow-hidden">
          <div class="h-full rounded-full ${barCls}" style="width:${Math.max(rc.score, 2)}%"></div>
        </div>
        ${bars}
      </div>`;
    }).join('');
  }

  // ── Investigation Timeline ──
  function renderTimeline(result) {
    const card = document.getElementById('scan-timeline-card');
    const steps = document.getElementById('scan-timeline-steps');
    if (!card || !steps) return;
    card.style.display = 'block';
    const timeline = result.audit_trail || result.timeline || result.steps || [];
    const items = timeline.length ? timeline : [
      { step: 'Document Received', status: 'completed', timestamp: result.timestamp || new Date().toISOString() },
      { step: 'OCR Processing', status: 'completed' },
      { step: 'Bank Validation', status: 'completed' },
      { step: 'Template Detection', status: 'completed' },
      { step: 'Risk Aggregation', status: 'completed' },
      { step: 'Compliance Check', status: result.findings?.some(f => f.category === 'compliance') ? 'completed' : 'completed' },
      { step: 'Final Decision', status: 'completed' },
    ];
    const icons = ['upload_file', 'text_snippet', 'account_balance', 'description', 'monitoring', 'policy', 'check_circle'];
    steps.innerHTML = items.map((item, i) => {
      const icon = icons[i] || 'circle';
      return `<div class="flex items-center gap-3 py-2 border-l-2 ${item.status === 'completed' ? 'border-primary/40' : 'border-white/10'} pl-4 relative">
        <span class="material-symbols-outlined text-sm ${item.status === 'completed' ? 'text-primary' : 'text-on-surface-variant'}">${icon}</span>
        <span class="text-xs text-white">${item.step}</span>
        <span class="text-[10px] text-on-surface-variant ml-auto">${item.timestamp ? timeSince(new Date(item.timestamp)) : item.status === 'completed' ? 'Done' : 'Pending'}</span>
      </div>`;
    }).join('');
  }

  // ── Human Override ──
  function renderHumanOverride(result) {
    const card = document.getElementById('scan-override-human-card');
    const aiDecision = document.getElementById('scan-ai-decision');
    if (!card || !aiDecision) return;
    currentScanId = result.scan_id || result.scanId || '';
    // Skip override card for non-persisted results (e.g., corrupted PDF errors)
    if (!currentScanId) {
      card.style.display = 'none';
      return;
    }
    card.style.display = 'block';
    aiDecision.textContent = result.decision || result.verdict || 'Pending';
    aiDecision.className = 'font-display-lg text-display-lg text-3xl ' + ((result.decision === 'Reject' || result.verdict === 'Fraudulent') ? 'text-error' : (result.decision === 'Manual Review') ? 'text-yellow-500' : 'text-tertiary');
    const statusEl = document.getElementById('decision-status');
    if (statusEl) { statusEl.textContent = ''; statusEl.className = 'text-xs text-on-surface-variant'; }
    initDecisionButtons();
    setButtonsDisabled(false);
  }

  // ── Similar Cases ──
  function renderSimilarCases(result) {
    const card = document.getElementById('scan-similar-card');
    const list = document.getElementById('scan-similar-list');
    if (!card || !list) return;
    card.style.display = 'block';
    const cats = result.risk_categories || [];
    const profile = cats.map(c => c.score.toFixed(0)).join('-');
    list.innerHTML = `<div class="text-xs text-on-surface-variant text-center py-4">Similar cases will appear here as the database grows. Risk profile signature: <span class="font-mono text-primary">${profile}</span></div>`;
  }

  // ── Extracted Fields ──
  function renderExtractedFields(result) {
    const card = document.getElementById('scan-extracted-card');
    const container = document.getElementById('scan-extracted-fields');
    if (!card || !container) return;
    const fields = result.extracted_fields;
    if (!fields || !Object.keys(fields).length) {
      card.style.display = 'none';
      return;
    }
    card.style.display = 'block';
    container.innerHTML = Object.entries(fields).map(([key, val]) => `
      <div class="p-3 bg-surface-container rounded-lg">
        <div class="text-xs text-on-surface-variant mb-1">${key}</div>
        <div class="text-sm text-white font-semibold">${val}</div>
      </div>
    `).join('');
  }

  // ── Export Report ──
  window.exportReport = function() {
    const results = document.getElementById('scan-results');
    if (!results) return;
    window.print();
  };

  // ── Evidence Viewer Modal ──
  window.showEvidenceViewer = function(title, bodyHTML) {
    const modal = document.getElementById('evidence-viewer-modal');
    const titleEl = document.getElementById('evidence-viewer-title');
    const bodyEl = document.getElementById('evidence-viewer-body');
    if (!modal) return;
    if (titleEl) titleEl.textContent = title || 'Evidence Details';
    if (bodyEl) bodyEl.innerHTML = bodyHTML || '<p class="text-sm text-on-surface-variant">No details available.</p>';
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  };

  window.closeEvidenceViewer = function() {
    const modal = document.getElementById('evidence-viewer-modal');
    if (!modal) return;
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  };

  // ── Decision Buttons (Human Override) ──
  let currentScanId = null;
  let currentDashboardScanId = null;
  const DECISION_MAP = {
    'approve-btn': 'APPROVED',
    'review-btn': 'UNDER_REVIEW',
    'reject-btn': 'REJECTED',
    'escalate-btn': 'ESCALATED',
  };
  const DECISION_BUTTONS = ['approve-btn', 'review-btn', 'reject-btn', 'escalate-btn'];
  const DASHBOARD_DECISION_MAP = {
    'dash-approve-btn': 'APPROVED',
    'dash-review-btn': 'UNDER_REVIEW',
    'dash-reject-btn': 'REJECTED',
  };
  const DASHBOARD_DECISION_BUTTONS = ['dash-approve-btn', 'dash-review-btn', 'dash-reject-btn'];

  function initDecisionButtons() {
    DECISION_BUTTONS.forEach(id => {
      const btn = document.getElementById(id);
      if (!btn) {
        console.warn(`[Decision] Button #${id} not found in DOM`);
        return;
      }
      if (btn.dataset.listenerAttached === 'true') return;
      btn.addEventListener('click', handleDecisionClick);
      btn.dataset.listenerAttached = 'true';
      console.log(`[Decision] Listener attached to #${id}`);
    });
  }

  async function handleDecisionClick(e) {
    const btn = e.currentTarget;
    const decision = DECISION_MAP[btn.id];
    const statusEl = document.getElementById('decision-status');

    console.log(`[Decision] "${btn.id}" clicked → decision: "${decision}"`);

    if (!currentScanId) {
      console.error('[Decision] No scan_id available');
      if (statusEl) { statusEl.textContent = 'No active scan session'; statusEl.className = 'text-xs text-error'; }
      showToast('No active scan session', 'error');
      return;
    }

    // Disable buttons while request is running
    setButtonsDisabled(true);
    console.log('[Decision] Buttons disabled — request in progress');

    statusEl.textContent = `Submitting ${decision}...`;
    statusEl.className = 'text-xs text-on-surface-variant';
    console.log(`[Decision] Sending decision scan_id="${currentScanId}" decision="${decision}"`);

    try {
      const res = await fetch('/api/v1/human-decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: currentScanId, decision }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `HTTP ${res.status}`);
      }

      const data = await res.json();
      console.log('[Decision] Decision saved:', data);
      showToast('Decision saved', 'success');
      statusEl.textContent = `✓ Decision: ${decision}`;
      statusEl.className = 'text-xs text-tertiary';

      // Update the Human Decision display
      const humanDecisionRow = document.getElementById('scan-human-decision-row');
      if (humanDecisionRow) humanDecisionRow.style.display = 'flex';
      const humanDecisionEl = document.getElementById('scan-human-decision');
      if (humanDecisionEl) {
        humanDecisionEl.textContent = decision;
        humanDecisionEl.className = 'font-display-lg text-display-lg text-3xl text-tertiary';
      }
      const decisionReasonEl = document.getElementById('scan-human-reason');
      if (decisionReasonEl) {
        decisionReasonEl.textContent = 'Override Reason: Manual Verification';
        decisionReasonEl.style.display = 'block';
      }
    } catch (err) {
      console.error('[Decision] Error:', err);
      showToast('Failed to save decision: ' + err.message, 'error');
      statusEl.textContent = `✗ Failed: ${err.message}`;
      statusEl.className = 'text-xs text-error';
    } finally {
      setButtonsDisabled(false);
      console.log('[Decision] Buttons re-enabled');
    }
  }

  function setButtonsDisabled(disabled) {
    DECISION_BUTTONS.forEach(id => {
      const btn = document.getElementById(id);
      if (btn) btn.disabled = disabled;
    });
  }

  // ── Dashboard Decision Buttons ──
  function initDashboardDecisionButtons() {
    let scanId = currentDashboardScanId;
    if (!scanId && window._lastUploadScanId) {
      scanId = window._lastUploadScanId;
    }
    DASHBOARD_DECISION_BUTTONS.forEach(id => {
      const btn = document.getElementById(id);
      if (!btn) return;
      btn.disabled = !scanId;
      if (btn.dataset.listenerAttached === 'true') return;
      btn.addEventListener('click', handleDashboardDecisionClick);
      btn.dataset.listenerAttached = 'true';
    });
  }

  window.selectDashboardScan = function(scanId) {
    currentDashboardScanId = scanId || null;
    document.querySelectorAll('#recent-scans-body .dash-scan-item').forEach(el => {
      el.classList.toggle('selected', el.dataset.scanId === scanId);
      if (el.dataset.scanId === scanId) {
        el.classList.add('bg-primary/10', 'border', 'border-primary/30');
      } else {
        el.classList.remove('bg-primary/10', 'border', 'border-primary/30');
      }
    });
    initDashboardDecisionButtons();
    showToast(`Scan ${scanId ? scanId.slice(0, 12) + '…' : ''} selected`, 'info');
  };

  async function handleDashboardDecisionClick(e) {
    const btn = e.currentTarget;
    const decision = DASHBOARD_DECISION_MAP[btn.id];
    let scanId = currentDashboardScanId;
    if (!scanId && window._lastUploadScanId) {
      scanId = window._lastUploadScanId;
    }

    if (!scanId) {
      showToast('No scan selected — upload a document first', 'error');
      return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="material-symbols-outlined">hourglass_top</span> SUBMITTING...';

    try {
      const res = await fetch('/api/v1/human-decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId, decision }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      showToast(`Decision ${decision} saved for ${scanId.slice(0, 12)}`, 'success');

      // Reset button text
      const label = Object.keys(DASHBOARD_DECISION_MAP).find(k => DASHBOARD_DECISION_MAP[k] === decision) || '';
      const originalLabels = { 'dash-approve-btn': 'APPROVE', 'dash-review-btn': 'REVIEW', 'dash-reject-btn': 'REJECT' };
      btn.innerHTML = originalLabels[btn.id] || decision;
      btn.disabled = false;

      // Mark the selected scan in the recent scans list
      document.querySelectorAll('#recent-scans-body .dash-scan-item').forEach(el => {
        el.classList.toggle('selected', el.dataset.scanId === scanId);
      });

      // Reload dashboard panels to reflect decision
      setTimeout(() => loadDashboard(), 1000);
    } catch (err) {
      showToast('Failed to save decision: ' + err.message, 'error');
      const originalLabels = { 'dash-approve-btn': 'APPROVE', 'dash-review-btn': 'REVIEW', 'dash-reject-btn': 'REJECT' };
      btn.innerHTML = originalLabels[btn.id] || decision;
      btn.disabled = false;
    }
  }

  // ── Chart.js Renderers ──
  function renderLineChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !window.Chart) return;
    const ctx = canvas.getContext('2d');
    if (canvas._chart) canvas._chart.destroy();

    canvas._chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels,
        datasets: data.datasets.map(ds => ({
          label: ds.label,
          data: ds.data,
          borderColor: ds.color,
          backgroundColor: ds.fill ? ds.color + '20' : 'transparent',
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: ds.color,
          fill: !!ds.fill,
          tension: 0.4,
        })),
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
        scales: {
          x: { ticks: { color: '#64748b', maxTicksLimit: 10 }, grid: { color: 'rgba(148,163,184,0.05)' } },
          y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(148,163,184,0.05)' }, beginAtZero: true },
        },
      },
    });
  }

  function renderBarChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !window.Chart) return;
    const ctx = canvas.getContext('2d');
    if (canvas._chart) canvas._chart.destroy();

    canvas._chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: data.labels,
        datasets: data.datasets.map(ds => ({
          label: ds.label,
          data: ds.data,
          backgroundColor: ds.color + '40',
          borderColor: ds.color,
          borderWidth: 1,
          borderRadius: 4,
        })),
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
        scales: {
          x: { ticks: { color: '#64748b' }, grid: { display: false } },
          y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(148,163,184,0.05)' }, beginAtZero: true },
        },
      },
    });
  }

  function renderDoughnutChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !window.Chart) return;
    const ctx = canvas.getContext('2d');
    if (canvas._chart) canvas._chart.destroy();

    canvas._chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: data.labels,
        datasets: [{
          data: data.values,
          backgroundColor: data.colors.map(c => c + '80'),
          borderColor: data.colors,
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#94a3b8', font: { size: 11 }, padding: 12 },
          },
        },
      },
    });
  }

})();
