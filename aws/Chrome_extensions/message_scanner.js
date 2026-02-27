// PhishGuard Message Scanner - Messaging Platform Phishing Detection
(() => {
  'use strict';

  const SCAN_CACHE = new Map();
  const CACHE_TTL = 300000; // 5 minutes
  const SCANNED_MESSAGES = new WeakSet();

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
   * Detect platform
   */
  function detectPlatform() {
    const hostname = window.location.hostname;
    if (hostname.includes('web.whatsapp.com')) return 'whatsapp';
    if (hostname.includes('web.telegram.org')) return 'telegram';
    if (hostname.includes('discord.com')) return 'discord';
    if (hostname.includes('slack.com')) return 'slack';
    return 'unknown';
  }

  /**
   * Extract message data from WhatsApp
   */
  function extractWhatsAppMessage(messageElement) {
    try {
      // Message text
      const textElement = messageElement.querySelector('.copyable-text span.selectable-text');
      const messageText = textElement ? textElement.innerText.trim() : '';

      if (!messageText) return null;

      // Extract links
      const links = [];
      const linkElements = messageElement.querySelectorAll('a[href]');
      linkElements.forEach(link => {
        const href = link.getAttribute('href');
        if (href && href.startsWith('http')) {
          links.push({
            url: href,
            text: link.textContent.trim()
          });
        }
      });

      // Check if message is incoming (not sent by user)
      const isIncoming = messageElement.classList.contains('message-in');

      return {
        type: 'MESSAGE_SCAN',
        platform: 'whatsapp',
        text: messageText,
        links,
        is_incoming: isIncoming,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('[PhishGuard WhatsApp] Extraction error:', error);
      return null;
    }
  }

  /**
   * Extract message data from Telegram
   */
  function extractTelegramMessage(messageElement) {
    try {
      // Message text
      const textElement = messageElement.querySelector('.text-content, .message-content');
      const messageText = textElement ? textElement.innerText.trim() : '';

      if (!messageText) return null;

      // Extract links
      const links = [];
      const linkElements = messageElement.querySelectorAll('a[href]');
      linkElements.forEach(link => {
        const href = link.getAttribute('href');
        if (href && href.startsWith('http')) {
          links.push({
            url: href,
            text: link.textContent.trim()
          });
        }
      });

      return {
        type: 'MESSAGE_SCAN',
        platform: 'telegram',
        text: messageText,
        links,
        is_incoming: true,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('[PhishGuard Telegram] Extraction error:', error);
      return null;
    }
  }

  /**
   * Extract message based on platform
   */
  function extractMessage(messageElement, platform) {
    switch (platform) {
      case 'whatsapp':
        return extractWhatsAppMessage(messageElement);
      case 'telegram':
        return extractTelegramMessage(messageElement);
      default:
        return null;
    }
  }

  /**
   * Inject inline warning in message
   */
  function injectMessageWarning(messageElement, messageData, riskResult, platform) {
    const { risk, confidence, reasons = [] } = riskResult;

    // Only show warnings for MEDIUM and HIGH
    if (risk === 'LOW') return;

    // Check if warning already exists
    if (messageElement.querySelector('.phishguard-message-warning')) return;

    const warning = document.createElement('div');
    warning.className = 'phishguard-message-warning';
    warning.style.cssText = `
      background: ${risk === 'HIGH' ? '#ffebee' : '#fff3e0'};
      border-left: 3px solid ${risk === 'HIGH' ? '#d32f2f' : '#ff9800'};
      padding: 8px 12px;
      margin: 4px 0;
      border-radius: 4px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 12px;
      line-height: 1.4;
      color: #333;
    `;

    const icon = risk === 'HIGH' ? '🚨' : '⚠️';
    const title = risk === 'HIGH' ? 'Phishing Threat' : 'Suspicious Message';

    let html = `
      <div style="display: flex; align-items: start; gap: 8px;">
        <span style="font-size: 16px;">${icon}</span>
        <div style="flex: 1;">
          <div style="font-weight: 600; margin-bottom: 4px;">${title}</div>
          <div style="font-size: 11px; color: #555;">
            This message shows suspicious indicators. Be cautious with links.
          </div>
    `;

    if (reasons.length > 0 && reasons.length <= 3) {
      html += `
        <div style="font-size: 11px; color: #666; margin-top: 4px;">
          ${reasons.slice(0, 3).join(' • ')}
        </div>
      `;
    }

    html += `
        </div>
      </div>
    `;

    warning.innerHTML = html;

    // Insert warning based on platform
    if (platform === 'whatsapp') {
      const textContainer = messageElement.querySelector('.copyable-text');
      if (textContainer) {
        textContainer.insertBefore(warning, textContainer.firstChild);
      }
    } else {
      messageElement.insertBefore(warning, messageElement.firstChild);
    }

    console.log(`[PhishGuard ${platform}] Inline warning displayed: ${risk}`);
  }

  /**
   * Scan message content
   */
  async function scanMessage(messageElement, messageData, platform) {
    if (!messageData || !messageData.text) return;

    // Skip if already scanned
    if (SCANNED_MESSAGES.has(messageElement)) return;
    SCANNED_MESSAGES.add(messageElement);

    // Generate hash for caching
    const messageHash = await hashMessage(messageData.text);
    
    // Check cache
    const cached = await isCached(messageHash);
    if (cached) {
      console.log(`[PhishGuard ${platform}] Using cached result`);
      injectMessageWarning(messageElement, messageData, cached, platform);
      return;
    }

    console.log(`[PhishGuard ${platform}] Scanning message...`);

    // Run local AI inference
    if (window.phishGuardLocalAI) {
      const localResult = await window.phishGuardLocalAI.runInference(
        messageData.text,
        {
          external_links: messageData.links.length
        }
      );

      console.log(`[PhishGuard ${platform}] Local AI: ${localResult.local_risk} (${localResult.local_confidence})`);

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
          type: 'SCAN_MESSAGE',
          payload: {
            ...messageData,
            local_result: localResult
          }
        }, (response) => {
          if (chrome.runtime.lastError) {
            console.warn(`[PhishGuard ${platform}] Backend unavailable, using local result`);
            const fallbackResult = {
              risk: localResult.local_risk,
              confidence: localResult.local_confidence,
              reasons: ['Suspicious patterns detected'],
              source: 'local_fallback'
            };
            cacheResult(messageHash, fallbackResult);
            injectMessageWarning(messageElement, messageData, fallbackResult, platform);
            return;
          }

          if (response) {
            console.log(`[PhishGuard ${platform}] Backend verdict: ${response.risk}`);
            cacheResult(messageHash, response);
            injectMessageWarning(messageElement, messageData, response, platform);
          }
        });
      }
    }
  }

  /**
   * Intercept link clicks in messages
   */
  function setupLinkInterception(platform) {
    document.addEventListener('click', async (e) => {
      const link = e.target.closest('a[href]');
      if (!link) return;

      const href = link.getAttribute('href');
      if (!href || !href.startsWith('http')) return;

      // Check if link is in a message
      const messageElement = link.closest('[data-id], .message, ._3-8er');
      if (!messageElement) return;

      // Extract message to check cache
      const messageData = extractMessage(messageElement, platform);
      if (!messageData) return;

      const messageHash = await hashMessage(messageData.text);
      const cached = await isCached(messageHash);

      if (cached && (cached.risk === 'HIGH' || cached.risk === 'MEDIUM')) {
        e.preventDefault();
        e.stopPropagation();

        const proceed = confirm(
          `⚠️ PhishGuard Warning\n\n` +
          `This link is in a message flagged as ${cached.risk} risk.\n\n` +
          `URL: ${href}\n\n` +
          `Are you sure you want to proceed?`
        );

        if (proceed) {
          console.log(`[PhishGuard ${platform}] User proceeded to risky link`);
          window.open(href, '_blank');
        } else {
          console.log(`[PhishGuard ${platform}] User cancelled risky link`);
        }
      }
    }, true);
  }

  /**
   * Observe new messages (WhatsApp)
   */
  function observeWhatsAppMessages() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) {
            // Check if it's a message
            const messages = node.classList?.contains('message-in') 
              ? [node] 
              : node.querySelectorAll?.('.message-in') || [];

            messages.forEach((messageElement) => {
              const messageData = extractWhatsAppMessage(messageElement);
              if (messageData && messageData.is_incoming) {
                // Debounce scanning
                setTimeout(() => {
                  scanMessage(messageElement, messageData, 'whatsapp');
                }, 300);
              }
            });
          }
        });
      });
    });

    // Observe chat container
    const chatContainer = document.querySelector('#main');
    if (chatContainer) {
      observer.observe(chatContainer, {
        childList: true,
        subtree: true
      });
      console.log('[PhishGuard WhatsApp] Message observer active');
    }
  }

  /**
   * Observe new messages (Telegram)
   */
  function observeTelegramMessages() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) {
            const messages = node.classList?.contains('message') 
              ? [node] 
              : node.querySelectorAll?.('.message') || [];

            messages.forEach((messageElement) => {
              const messageData = extractTelegramMessage(messageElement);
              if (messageData) {
                setTimeout(() => {
                  scanMessage(messageElement, messageData, 'telegram');
                }, 300);
              }
            });
          }
        });
      });
    });

    // Observe messages container
    const messagesContainer = document.querySelector('.messages-container, #column-center');
    if (messagesContainer) {
      observer.observe(messagesContainer, {
        childList: true,
        subtree: true
      });
      console.log('[PhishGuard Telegram] Message observer active');
    }
  }

  /**
   * Initialize scanner based on platform
   */
  function initialize() {
    const platform = detectPlatform();
    
    if (platform === 'unknown') {
      console.log('[PhishGuard] Unknown messaging platform');
      return;
    }

    console.log(`[PhishGuard ${platform}] Scanner initialized`);

    // Setup link interception
    setupLinkInterception(platform);

    // Wait for platform to load
    const initInterval = setInterval(() => {
      let ready = false;

      if (platform === 'whatsapp' && document.querySelector('#main')) {
        ready = true;
        observeWhatsAppMessages();
      } else if (platform === 'telegram' && document.querySelector('.messages-container, #column-center')) {
        ready = true;
        observeTelegramMessages();
      }

      if (ready) {
        clearInterval(initInterval);
      }
    }, 1000);

    // Cleanup after 30 seconds if platform doesn't load
    setTimeout(() => clearInterval(initInterval), 30000);
  }

  // Initialize
  initialize();
})();
