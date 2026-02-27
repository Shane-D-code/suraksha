// PhishGuard Gmail Scanner - Email Phishing Detection
(() => {
  'use strict';

  const SCAN_CACHE = new Map();
  const CACHE_TTL = 300000; // 5 minutes

  /**
   * Generate hash for message content
   */
  async function hashMessage(content) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Check if message was recently scanned
   */
  async function isCached(messageHash) {
    const cached = SCAN_CACHE.get(messageHash);
    if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
      return cached.result;
    }
    SCAN_CACHE.delete(messageHash);
    return null;
  }

  /**
   * Cache scan result
   */
  function cacheResult(messageHash, result) {
    SCAN_CACHE.set(messageHash, {
      result,
      timestamp: Date.now()
    });
  }

  /**
   * Extract email data from Gmail DOM
   */
  function extractEmailData() {
    try {
      // Gmail email container
      const emailContainer = document.querySelector('[role="main"]');
      if (!emailContainer) return null;

      // Subject line
      const subjectElement = emailContainer.querySelector('h2');
      const subject = subjectElement ? subjectElement.textContent.trim() : '';

      // Sender information
      const senderElement = emailContainer.querySelector('[email]');
      const senderEmail = senderElement ? senderElement.getAttribute('email') : '';
      const senderName = senderElement ? senderElement.getAttribute('name') || senderElement.textContent.trim() : '';

      // Email body
      const bodyElement = emailContainer.querySelector('[data-message-id] .a3s, [data-message-id] div[dir="ltr"]');
      const bodyText = bodyElement ? bodyElement.innerText.trim() : '';

      // Extract all links
      const links = [];
      const linkElements = emailContainer.querySelectorAll('a[href]');
      linkElements.forEach(link => {
        const href = link.getAttribute('href');
        if (href && href.startsWith('http')) {
          links.push({
            url: href,
            text: link.textContent.trim(),
            display: link.href
          });
        }
      });

      // Check for forms (rare in email but possible)
      const formCount = emailContainer.querySelectorAll('form').length;

      return {
        type: 'EMAIL_SCAN',
        platform: 'gmail',
        sender: {
          email: senderEmail,
          name: senderName
        },
        subject,
        body_text: bodyText.slice(0, 2000), // Limit to 2000 chars
        links,
        form_count: formCount,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('[PhishGuard Gmail] Extraction error:', error);
      return null;
    }
  }

  /**
   * Inject inline warning above email content
   */
  function injectInlineWarning(emailData, riskResult) {
    // Remove existing warning
    const existingWarning = document.getElementById('phishguard-email-warning');
    if (existingWarning) {
      existingWarning.remove();
    }

    const { risk, confidence, reasons = [] } = riskResult;

    // Only show warnings for MEDIUM and HIGH
    if (risk === 'LOW') return;

    const emailContainer = document.querySelector('[role="main"]');
    if (!emailContainer) return;

    const warning = document.createElement('div');
    warning.id = 'phishguard-email-warning';
    warning.style.cssText = `
      background: ${risk === 'HIGH' ? '#ffebee' : '#fff3e0'};
      border-left: 4px solid ${risk === 'HIGH' ? '#d32f2f' : '#ff9800'};
      padding: 16px;
      margin: 16px;
      border-radius: 4px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      position: relative;
      z-index: 1000;
    `;

    const icon = risk === 'HIGH' ? '🚨' : '⚠️';
    const title = risk === 'HIGH' ? 'Phishing Threat Detected' : 'Suspicious Email Detected';
    const color = risk === 'HIGH' ? '#c62828' : '#e65100';

    let html = `
      <div style="display: flex; align-items: start; gap: 12px;">
        <div style="font-size: 24px;">${icon}</div>
        <div style="flex: 1;">
          <div style="font-weight: 600; color: ${color}; margin-bottom: 8px;">
            ${title}
          </div>
          <div style="color: #555; margin-bottom: 8px;">
            This email shows suspicious indicators. Exercise caution before clicking any links or providing information.
          </div>
    `;

    if (reasons.length > 0) {
      html += `
        <div style="margin-top: 12px;">
          <div style="font-weight: 600; color: #333; margin-bottom: 6px; font-size: 13px;">
            Why this was flagged:
          </div>
          <ul style="margin: 0; padding-left: 20px; color: #555; font-size: 13px;">
            ${reasons.map(r => `<li style="margin: 4px 0;">${r}</li>`).join('')}
          </ul>
        </div>
      `;
    }

    html += `
          <div style="margin-top: 12px; display: flex; gap: 8px;">
            <button id="phishguard-report-btn" style="
              background: ${color};
              color: white;
              border: none;
              padding: 6px 12px;
              border-radius: 4px;
              cursor: pointer;
              font-size: 12px;
              font-weight: 600;
            ">Report Phishing</button>
            <button id="phishguard-dismiss-btn" style="
              background: transparent;
              color: ${color};
              border: 1px solid ${color};
              padding: 6px 12px;
              border-radius: 4px;
              cursor: pointer;
              font-size: 12px;
              font-weight: 600;
            ">Dismiss</button>
          </div>
        </div>
      </div>
    `;

    warning.innerHTML = html;

    // Insert at top of email container
    const insertPoint = emailContainer.querySelector('[data-message-id]') || emailContainer.firstChild;
    if (insertPoint) {
      insertPoint.parentNode.insertBefore(warning, insertPoint);
    } else {
      emailContainer.insertBefore(warning, emailContainer.firstChild);
    }

    // Event listeners
    document.getElementById('phishguard-report-btn')?.addEventListener('click', () => {
      reportPhishing(emailData, riskResult);
    });

    document.getElementById('phishguard-dismiss-btn')?.addEventListener('click', () => {
      warning.remove();
    });

    console.log(`[PhishGuard Gmail] Inline warning displayed: ${risk}`);
  }

  /**
   * Report phishing to backend
   */
  function reportPhishing(emailData, riskResult) {
    chrome.runtime.sendMessage({
      type: 'REPORT_PHISHING',
      payload: {
        platform: 'gmail',
        sender: emailData.sender,
        subject: emailData.subject,
        risk: riskResult.risk,
        confidence: riskResult.confidence,
        timestamp: Date.now()
      }
    });

    alert('Thank you for reporting this phishing attempt. Our team will investigate.');
  }

  /**
   * Scan email content
   */
  async function scanEmail(emailData) {
    if (!emailData || !emailData.body_text) return;

    // Generate hash for caching
    const messageHash = await hashMessage(emailData.body_text + emailData.subject);
    
    // Check cache
    const cached = await isCached(messageHash);
    if (cached) {
      console.log('[PhishGuard Gmail] Using cached result');
      injectInlineWarning(emailData, cached);
      return;
    }

    console.log('[PhishGuard Gmail] Scanning email...');
    console.log('[PhishGuard Gmail] Subject:', emailData.subject);
    console.log('[PhishGuard Gmail] Sender:', emailData.sender.email);
    console.log('[PhishGuard Gmail] Links:', emailData.links.length);

    // Run local AI inference
    if (window.phishGuardLocalAI) {
      const localResult = await window.phishGuardLocalAI.runInference(
        emailData.body_text + ' ' + emailData.subject,
        {
          external_links: emailData.links.length,
          form_count: emailData.form_count
        }
      );

      console.log(`[PhishGuard Gmail] Local AI: ${localResult.local_risk} (${localResult.local_confidence})`);

      // Hybrid decision
      if (localResult.local_risk === 'LOW' && localResult.local_confidence > 0.7) {
        // Trust local AI, no warning needed
        const result = {
          risk: 'LOW',
          confidence: localResult.local_confidence,
          reasons: [],
          source: 'local_only'
        };
        cacheResult(messageHash, result);
        return;
      }

      // For MEDIUM/HIGH, verify with backend
      if (localResult.local_risk === 'MEDIUM' || localResult.local_risk === 'HIGH') {
        chrome.runtime.sendMessage({
          type: 'SCAN_EMAIL',
          payload: {
            ...emailData,
            local_result: localResult
          }
        }, (response) => {
          if (chrome.runtime.lastError) {
            console.warn('[PhishGuard Gmail] Backend unavailable, using local result');
            const fallbackResult = {
              risk: localResult.local_risk,
              confidence: localResult.local_confidence,
              reasons: ['Backend unavailable - Local AI assessment'],
              source: 'local_fallback'
            };
            cacheResult(messageHash, fallbackResult);
            injectInlineWarning(emailData, fallbackResult);
            return;
          }

          if (response) {
            console.log(`[PhishGuard Gmail] Backend verdict: ${response.risk}`);
            cacheResult(messageHash, response);
            injectInlineWarning(emailData, response);
          }
        });
      }
    }
  }

  /**
   * Intercept link clicks
   */
  function setupLinkInterception() {
    document.addEventListener('click', async (e) => {
      const link = e.target.closest('a[href]');
      if (!link) return;

      const href = link.getAttribute('href');
      if (!href || !href.startsWith('http')) return;

      // Check if link is in email container
      const emailContainer = link.closest('[role="main"]');
      if (!emailContainer) return;

      // Check if link was flagged as risky
      const emailData = extractEmailData();
      if (!emailData) return;

      const messageHash = await hashMessage(emailData.body_text + emailData.subject);
      const cached = await isCached(messageHash);

      if (cached && (cached.risk === 'HIGH' || cached.risk === 'MEDIUM')) {
        e.preventDefault();
        e.stopPropagation();

        const proceed = confirm(
          `⚠️ PhishGuard Warning\n\n` +
          `This link is in an email flagged as ${cached.risk} risk.\n\n` +
          `URL: ${href}\n\n` +
          `Are you sure you want to proceed?`
        );

        if (proceed) {
          console.log('[PhishGuard Gmail] User proceeded to risky link');
          window.open(href, '_blank');
        } else {
          console.log('[PhishGuard Gmail] User cancelled risky link');
        }
      }
    }, true);
  }

  /**
   * Observe email changes
   */
  function observeEmailChanges() {
    let lastEmailHash = null;
    let scanTimeout = null;

    const observer = new MutationObserver(() => {
      // Debounce scanning
      clearTimeout(scanTimeout);
      scanTimeout = setTimeout(async () => {
        const emailData = extractEmailData();
        if (!emailData || !emailData.body_text) return;

        // Check if this is a new email
        const currentHash = await hashMessage(emailData.body_text + emailData.subject);
        if (currentHash === lastEmailHash) return;

        lastEmailHash = currentHash;
        scanEmail(emailData);
      }, 500);
    });

    // Observe main content area
    const mainContent = document.querySelector('[role="main"]');
    if (mainContent) {
      observer.observe(mainContent, {
        childList: true,
        subtree: true
      });
      console.log('[PhishGuard Gmail] Email observer active');
    }

    // Also scan current email if present
    setTimeout(() => {
      const emailData = extractEmailData();
      if (emailData) {
        scanEmail(emailData);
      }
    }, 1000);
  }

  // Initialize
  if (window.location.hostname === 'mail.google.com') {
    console.log('[PhishGuard Gmail] Scanner initialized');
    
    // Wait for Gmail to load
    const initInterval = setInterval(() => {
      if (document.querySelector('[role="main"]')) {
        clearInterval(initInterval);
        observeEmailChanges();
        setupLinkInterception();
      }
    }, 1000);

    // Cleanup after 30 seconds if Gmail doesn't load
    setTimeout(() => clearInterval(initInterval), 30000);
  }
})();
