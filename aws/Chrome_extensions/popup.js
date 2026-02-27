/**
 * PhishGuard Popup - Compact Apple Design
 * Status Viewer with Live Scan
 */

document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements - Views
  const scanningView = document.getElementById('scanning-view');
  const resultView = document.getElementById('result-view');
  const errorView = document.getElementById('error-view');

  // Result Elements
  const statusCard = document.getElementById('status-card');
  const statusIcon = document.getElementById('status-icon');
  const statusLabel = document.getElementById('status-label');
  const statusConfidence = document.getElementById('status-confidence');
  
  const urlText = document.getElementById('url-text');
  const scanningUrl = document.getElementById('scanning-url');
  
  const scoreValue = document.getElementById('score-value');
  const scoreFill = document.getElementById('score-fill');
  
  const mlScore = document.getElementById('ml-score');
  const graphScore = document.getElementById('graph-score');
  const sslStatus = document.getElementById('ssl-status');
  const domainAge = document.getElementById('domain-age');
  
  const reasonsSection = document.getElementById('reasons-section');
  const reasonsList = document.getElementById('reasons-list');
  
  const errorText = document.getElementById('error-text');
  
  // Action Buttons
  const rescanBtn = document.getElementById('rescan-btn');
  const detailsBtn = document.getElementById('details-btn');
  const settingsBtn = document.getElementById('settings-btn');

  // Show scanning state
  showScanning();

  try {
    // Get current active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url) {
      showError('No active page found');
      return;
    }

    // Skip chrome:// and extension:// URLs
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
      showError('Cannot scan browser pages');
      return;
    }

    // Set scanning URL
    scanningUrl.textContent = truncateUrl(tab.url, 35);
    urlText.textContent = truncateUrl(tab.url, 30);
    urlText.title = tab.url;

    // Trigger fresh scan via background script
    const scanResult = await triggerScan(tab.id, tab.url);
    
    if (scanResult && scanResult.success) {
      showResult(tab.url, scanResult.data);
    } else if (scanResult && scanResult.error) {
      // Try to show cached result if available
      const cached = await chrome.storage.local.get('lastScan');
      if (cached.lastScan && cached.lastScan.url === tab.url) {
        showResult(tab.url, cached.lastScan.result);
      } else {
        showError(scanResult.error);
      }
    } else {
      showError('Scan failed');
    }

  } catch (error) {
    console.error('[PhishGuard] Popup error:', error);
    showError(error.message || 'Connection error');
  }

  // Button Event Listeners
  rescanBtn.addEventListener('click', async () => {
    showScanning();
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        scanningUrl.textContent = truncateUrl(tab.url, 35);
        const scanResult = await triggerScan(tab.id, tab.url);
        if (scanResult && scanResult.success) {
          showResult(tab.url, scanResult.data);
        } else {
          showError(scanResult?.error || 'Scan failed');
        }
      }
    } catch (error) {
      showError(error.message);
    }
  });

  detailsBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: 'dashboard/index.html' });
  });

  settingsBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: 'settings.html' });
  });

  // View Functions
  function showScanning() {
    scanningView.classList.remove('hidden');
    resultView.classList.add('hidden');
    errorView.classList.add('hidden');
  }

  function showError(message = 'Unable to connect to backend') {
    scanningView.classList.add('hidden');
    resultView.classList.add('hidden');
    errorView.classList.remove('hidden');
    errorText.textContent = message;
  }

  function showResult(url, result) {
    scanningView.classList.add('hidden');
    resultView.classList.remove('hidden');
    errorView.classList.add('hidden');

    // Determine risk level
    const risk = (result.risk || 'UNKNOWN').toUpperCase();
    const confidence = result.confidence !== undefined ? (result.confidence * 100).toFixed(0) : 0;
    
    // Update status card
    statusCard.className = 'status-card';
    
    if (risk === 'HIGH' || risk === 'CRITICAL') {
      statusCard.classList.add('danger');
      statusIcon.textContent = '⛔';
      statusLabel.textContent = 'DANGER';
    } else if (risk === 'MEDIUM') {
      statusCard.classList.add('warning');
      statusIcon.textContent = '⚠️';
      statusLabel.textContent = 'WARNING';
    } else {
      statusCard.classList.add('safe');
      statusIcon.textContent = '✓';
      statusLabel.textContent = 'SAFE';
    }
    
    statusConfidence.textContent = `${confidence}% confidence`;

    // Update URL
    urlText.textContent = truncateUrl(url, 30);
    urlText.title = url;

    // Update score
    const riskScore = result.risk_score || (result.domain_risk + result.content_risk) / 2 * 100 || 0;
    scoreValue.textContent = `${riskScore.toFixed(0)}%`;
    
    scoreFill.className = 'score-fill';
    if (riskScore < 30) {
      scoreFill.classList.add('low');
    } else if (riskScore < 70) {
      scoreFill.classList.add('medium');
    } else {
      scoreFill.classList.add('high');
    }
    scoreFill.style.width = `${riskScore}%`;

    // Update metrics (extract from result)
    const mlScoreVal = result.content_risk ? (result.content_risk * 100).toFixed(0) + '%' : 'N/A';
    const graphScoreVal = result.domain_risk ? (result.domain_risk * 100).toFixed(0) + '%' : 'N/A';
    
    mlScore.textContent = mlScoreVal;
    mlScore.className = 'metric-value ' + getScoreClass(result.content_risk);
    
    graphScore.textContent = graphScoreVal;
    graphScore.className = 'metric-value ' + getScoreClass(result.domain_risk);

    // SSL Status
    const sslValid = result.ssl_valid !== false;
    sslStatus.textContent = sslValid ? '✓' : '✗';
    sslStatus.className = 'metric-value ' + (sslValid ? 'safe' : 'danger');

    // Domain Age
    const age = result.domain_age_days;
    if (age !== undefined && age !== null) {
      if (age < 7) {
        domainAge.textContent = '<7d';
        domainAge.className = 'metric-value danger';
      } else if (age < 30) {
        domainAge.textContent = `${Math.floor(age)}d`;
        domainAge.className = 'metric-value warning';
      } else if (age < 365) {
        domainAge.textContent = `${Math.floor(age / 30)}mo`;
        domainAge.className = 'metric-value';
      } else {
        domainAge.textContent = `${Math.floor(age / 365)}yr`;
        domainAge.className = 'metric-value safe';
      }
    } else {
      domainAge.textContent = '?';
      domainAge.className = 'metric-value';
    }

    // Update reasons
    if (result.reasons && result.reasons.length > 0) {
      reasonsSection.classList.remove('hidden');
      reasonsList.innerHTML = '';
      
      // Show max 3 reasons
      result.reasons.slice(0, 3).forEach(reason => {
        const li = document.createElement('li');
        li.textContent = reason;
        
        // Add appropriate class based on reason content
        const reasonLower = reason.toLowerCase();
        if (reasonLower.includes('danger') || reasonLower.includes('high') || reasonLower.includes('critical')) {
          li.classList.add('danger');
        } else if (reasonLower.includes('warning') || reasonLower.includes('medium') || reasonLower.includes('caution')) {
          li.classList.add('warning');
        } else if (reasonLower.includes('safe') || reasonLower.includes('low') || reasonLower.includes('ok')) {
          li.classList.add('safe');
        }
        
        reasonsList.appendChild(li);
      });
    } else {
      reasonsSection.classList.add('hidden');
    }

    // Save to storage for caching
    chrome.storage.local.set({
      lastScan: {
        url: url,
        result: result,
        timestamp: Date.now()
      }
    });
  }

  function getScoreClass(score) {
    if (!score) return '';
    if (score > 0.7) return 'danger';
    if (score > 0.3) return 'warning';
    return 'safe';
  }

  function truncateUrl(url, maxLength) {
    try {
      const urlObj = new URL(url);
      let display = urlObj.hostname + urlObj.pathname;
      if (display.length > maxLength) {
        display = display.substring(0, maxLength - 3) + '...';
      }
      return display;
    } catch {
      return url.length > maxLength ? url.substring(0, maxLength - 3) + '...' : url;
    }
  }

  /**
   * Trigger scan via background script
   */
  async function triggerScan(tabId, url) {
    return new Promise((resolve) => {
      // First inject content script to extract features
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: extractPageFeatures
      }, (results) => {
        if (chrome.runtime.lastError) {
          console.error('[PhishGuard] Script injection failed:', chrome.runtime.lastError);
          resolve({ success: false, error: 'Cannot access page' });
          return;
        }

        const features = results && results[0] && results[0].result;
        
        if (!features) {
          resolve({ success: false, error: 'Failed to extract page data' });
          return;
        }

        // Send to background for backend scan
        chrome.runtime.sendMessage(
          {
            type: 'SCAN_PAGE',
            payload: {
              url: url,
              ...features
            }
          },
          (response) => {
            if (chrome.runtime.lastError) {
              console.error('[PhishGuard] Scan failed:', chrome.runtime.lastError);
              resolve({ success: false, error: chrome.runtime.lastError.message });
              return;
            }

            if (response && response.risk) {
              resolve({ success: true, data: response });
            } else {
              resolve({ success: false, error: 'Invalid response' });
            }
          }
        );
      });
    });
  }

  /**
   * Feature extraction function (runs in page context)
   */
  function extractPageFeatures() {
    const body = document.body;
    const text = body ? (body.innerText || body.textContent || '').slice(0, 2000) : '';
    
    return {
      text_snippet: text,
      password_fields: document.querySelectorAll('input[type="password"]').length,
      hidden_inputs: document.querySelectorAll('input[type="hidden"]').length,
      external_links: document.querySelectorAll('a[href^="http"]').length,
      iframe_count: document.querySelectorAll('iframe').length,
      form_count: document.querySelectorAll('form').length,
      has_login_indicators: document.querySelectorAll('input[type="password"]').length > 0,
      suspicious_keywords_found: [],
      timestamp: Date.now()
    };
  }
});
