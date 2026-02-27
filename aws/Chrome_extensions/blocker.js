// PhishGuard Blocker - Active Defense System
(() => {
  'use strict';

  const OVERLAY_ID = 'phishguard-overlay';
  const BANNER_ID = 'phishguard-banner';

  /**
   * Create full-screen block overlay for HIGH risk
   */
  function triggerBlockOverlay(response) {
    // Prevent duplicate overlays
    if (document.getElementById(OVERLAY_ID)) return;

    console.log('[PhishGuard] Blocking page...');

    const { risk, confidence, reasons = [] } = response;

    // Create overlay container
    const overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    overlay.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100vw !important;
      height: 100vh !important;
      background: rgba(0, 0, 0, 0.95) !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    `;

    // Create content card
    const card = document.createElement('div');
    card.style.cssText = `
      background: white !important;
      border-radius: 12px !important;
      padding: 40px !important;
      max-width: 600px !important;
      width: 90% !important;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5) !important;
      text-align: center !important;
    `;

    // Warning icon
    const icon = document.createElement('div');
    icon.style.cssText = `
      font-size: 64px !important;
      margin-bottom: 20px !important;
    `;
    icon.textContent = '🛑';

    // Title
    const title = document.createElement('h1');
    title.style.cssText = `
      color: #d32f2f !important;
      font-size: 28px !important;
      margin: 0 0 16px 0 !important;
      font-weight: 600 !important;
    `;
    title.textContent = 'Phishing Threat Detected';

    // Subtitle
    const subtitle = document.createElement('p');
    subtitle.style.cssText = `
      color: #666 !important;
      font-size: 16px !important;
      margin: 0 0 24px 0 !important;
      line-height: 1.5 !important;
    `;
    subtitle.textContent = 'This website has been identified as a potential security threat and has been blocked for your protection.';

    // Risk info
    const riskInfo = document.createElement('div');
    riskInfo.style.cssText = `
      background: #fff3e0 !important;
      border-left: 4px solid #ff9800 !important;
      padding: 16px !important;
      margin: 24px 0 !important;
      text-align: left !important;
      border-radius: 4px !important;
    `;

    const riskLabel = document.createElement('div');
    riskLabel.style.cssText = `
      font-weight: 600 !important;
      color: #e65100 !important;
      margin-bottom: 8px !important;
      font-size: 14px !important;
    `;
    riskLabel.textContent = `Threat Level: ${risk} ${confidence ? `(${confidence} confidence)` : ''}`;

    riskInfo.appendChild(riskLabel);

    // Reasons list
    if (reasons.length > 0) {
      const reasonsTitle = document.createElement('div');
      reasonsTitle.style.cssText = `
        font-weight: 600 !important;
        color: #333 !important;
        margin: 16px 0 8px 0 !important;
        font-size: 14px !important;
      `;
      reasonsTitle.textContent = 'Why this page was blocked:';

      const reasonsList = document.createElement('ul');
      reasonsList.style.cssText = `
        margin: 8px 0 0 0 !important;
        padding-left: 20px !important;
        color: #555 !important;
        font-size: 14px !important;
        line-height: 1.6 !important;
      `;

      reasons.forEach(reason => {
        const li = document.createElement('li');
        li.textContent = reason;
        li.style.cssText = `margin: 4px 0 !important;`;
        reasonsList.appendChild(li);
      });

      riskInfo.appendChild(reasonsTitle);
      riskInfo.appendChild(reasonsList);
    } else {
      const fallback = document.createElement('div');
      fallback.style.cssText = `
        color: #555 !important;
        font-size: 14px !important;
        margin-top: 8px !important;
      `;
      fallback.textContent = 'Multiple suspicious indicators detected.';
      riskInfo.appendChild(fallback);
    }

    // Button container
    const buttonContainer = document.createElement('div');
    buttonContainer.style.cssText = `
      display: flex !important;
      gap: 12px !important;
      margin-top: 32px !important;
      justify-content: center !important;
    `;

    // Go Back button (primary)
    const backButton = document.createElement('button');
    backButton.style.cssText = `
      background: #1976d2 !important;
      color: white !important;
      border: none !important;
      padding: 12px 32px !important;
      border-radius: 6px !important;
      font-size: 16px !important;
      font-weight: 600 !important;
      cursor: pointer !important;
      transition: background 0.2s !important;
    `;
    backButton.textContent = 'Go Back to Safety';
    backButton.onmouseover = () => {
      backButton.style.background = '#1565c0 !important';
    };
    backButton.onmouseout = () => {
      backButton.style.background = '#1976d2 !important';
    };
    backButton.onclick = () => {
      window.history.back();
    };

    // Proceed Anyway button (danger)
    const proceedButton = document.createElement('button');
    proceedButton.style.cssText = `
      background: transparent !important;
      color: #d32f2f !important;
      border: 2px solid #d32f2f !important;
      padding: 12px 32px !important;
      border-radius: 6px !important;
      font-size: 16px !important;
      font-weight: 600 !important;
      cursor: pointer !important;
      transition: all 0.2s !important;
    `;
    proceedButton.textContent = 'Proceed Anyway';
    proceedButton.onmouseover = () => {
      proceedButton.style.background = '#d32f2f !important';
      proceedButton.style.color = 'white !important';
    };
    proceedButton.onmouseout = () => {
      proceedButton.style.background = 'transparent !important';
      proceedButton.style.color = '#d32f2f !important';
    };
    proceedButton.onclick = () => {
      handleUserOverride(response);
    };

    // Assemble card
    card.appendChild(icon);
    card.appendChild(title);
    card.appendChild(subtitle);
    card.appendChild(riskInfo);
    buttonContainer.appendChild(backButton);
    buttonContainer.appendChild(proceedButton);
    card.appendChild(buttonContainer);

    // Assemble overlay
    overlay.appendChild(card);

    // Disable page interaction
    document.body.style.pointerEvents = 'none';
    document.body.style.overflow = 'hidden';

    // Inject overlay
    document.documentElement.appendChild(overlay);

    // Enable overlay interaction
    overlay.style.pointerEvents = 'auto';

    // Protect overlay from removal
    protectOverlay(overlay);
  }

  /**
   * Show warning banner for MEDIUM risk
   */
  function showWarningBanner(response) {
    // Prevent duplicate banners
    if (document.getElementById(BANNER_ID)) return;

    console.log('[PhishGuard] Showing warning banner');

    const { risk, confidence, reasons = [] } = response;

    const banner = document.createElement('div');
    banner.id = BANNER_ID;
    banner.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      background: #ff9800 !important;
      color: white !important;
      padding: 16px 20px !important;
      z-index: 2147483646 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: space-between !important;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2) !important;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
      font-size: 14px !important;
    `;

    const content = document.createElement('div');
    content.style.cssText = `
      display: flex !important;
      align-items: center !important;
      gap: 12px !important;
      flex: 1 !important;
    `;

    const icon = document.createElement('span');
    icon.textContent = '⚠️';
    icon.style.cssText = `font-size: 20px !important;`;

    const message = document.createElement('span');
    message.style.cssText = `font-weight: 500 !important;`;
    message.textContent = 'This page shows suspicious signals. Proceed with caution.';

    const detailsButton = document.createElement('button');
    detailsButton.style.cssText = `
      background: rgba(255, 255, 255, 0.2) !important;
      color: white !important;
      border: 1px solid white !important;
      padding: 6px 12px !important;
      border-radius: 4px !important;
      cursor: pointer !important;
      font-size: 12px !important;
      margin-left: 12px !important;
    `;
    detailsButton.textContent = 'View Details';
    detailsButton.onclick = () => {
      const details = reasons.length > 0 
        ? `Suspicious indicators:\n\n${reasons.map(r => `• ${r}`).join('\n')}`
        : 'Multiple suspicious indicators detected.';
      alert(details);
    };

    const dismissButton = document.createElement('button');
    dismissButton.style.cssText = `
      background: transparent !important;
      color: white !important;
      border: none !important;
      font-size: 24px !important;
      cursor: pointer !important;
      padding: 0 8px !important;
      line-height: 1 !important;
    `;
    dismissButton.textContent = '×';
    dismissButton.onclick = () => {
      banner.remove();
    };

    content.appendChild(icon);
    content.appendChild(message);
    content.appendChild(detailsButton);
    banner.appendChild(content);
    banner.appendChild(dismissButton);

    document.body.appendChild(banner);
  }

  /**
   * Handle user override of block
   */
  async function handleUserOverride(response) {
    console.log('[PhishGuard] User override triggered');

    const url = window.location.href;

    // Remove overlay
    const overlay = document.getElementById(OVERLAY_ID);
    if (overlay) {
      overlay.remove();
    }

    // Restore page interaction
    document.body.style.pointerEvents = '';
    document.body.style.overflow = '';

    // Store override in session to prevent re-blocking
    try {
      await chrome.storage.session.set({
        [`override_${url}`]: {
          timestamp: Date.now(),
          original_risk: response.risk
        }
      });
    } catch (error) {
      console.warn('[PhishGuard] Session storage error:', error);
    }

    // Send feedback to backend
    chrome.runtime.sendMessage({
      type: 'USER_OVERRIDE',
      payload: {
        url,
        original_risk: response.risk,
        confidence: response.confidence,
        user_override: true,
        timestamp: Date.now()
      }
    });
  }

  /**
   * Protect overlay from removal by page scripts
   */
  function protectOverlay(overlay) {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
          for (const node of mutation.removedNodes) {
            if (node === overlay) {
              console.warn('[PhishGuard] Overlay removal detected, re-injecting...');
              document.documentElement.appendChild(overlay);
            }
          }
        }
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: false
    });
  }

  /**
   * Check if URL was already overridden in this session
   */
  async function isOverridden(url) {
    try {
      const result = await chrome.storage.session.get(`override_${url}`);
      return !!result[`override_${url}`];
    } catch (error) {
      return false;
    }
  }

  /**
   * Decision engine - route based on risk level
   */
  async function handleRiskDecision(response) {
    if (!response || !response.risk) return;

    const url = window.location.href;

    // Check if user already overrode this page
    const overridden = await isOverridden(url);
    if (overridden) {
      console.log('[PhishGuard] Page previously overridden, skipping block');
      return;
    }

    const risk = response.risk.toUpperCase();

    if (risk === 'HIGH') {
      triggerBlockOverlay(response);
    } else if (risk === 'MEDIUM') {
      showWarningBanner(response);
    }
    // LOW risk - do nothing
  }

  // Export to global scope for content.js
  window.phishGuardBlocker = {
    handleRiskDecision
  };
})();
