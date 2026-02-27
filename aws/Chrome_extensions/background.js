// PhishGuard Background Service Worker - API Communication Handler
// FIXED: Token expiration handling and proper async message channel management

const API_ENDPOINT = 'http://localhost:8000/api/v1/scan';
const FORENSIC_ENDPOINT = 'http://localhost:8000/api/v1/scan/forensic';
const FEEDBACK_ENDPOINT = 'http://localhost:8000/api/v1/feedback';
const REQUEST_TIMEOUT_MS = 30000; // 30 seconds for forensic analysis
const MAX_RETRIES = 3; // Retry up to 3 times
const RETRY_DELAY_MS = 1500; // Wait 1.5 seconds between retries

// JWT Token for backend authentication (auto-refreshed)
let AUTH_TOKEN = null;
let TOKEN_EXPIRY = null;

/**
 * Get fresh auth token from backend
 * Now properly handles token expiration
 */
async function getAuthToken() {
  // Check if we have a valid token
  if (AUTH_TOKEN && TOKEN_EXPIRY && Date.now() < TOKEN_EXPIRY) {
    return AUTH_TOKEN;
  }
  
  // Token is missing or expired, get a fresh one
  console.log('[PhishGuard] Getting fresh auth token...');
  
  try {
    const response = await fetch('http://localhost:8000/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'username=admin&password=admin123'
    });
    
    if (response.ok) {
      const data = await response.json();
      AUTH_TOKEN = data.access_token;
      // Set expiry to 23 hours (token is valid for 24 hours)
      TOKEN_EXPIRY = Date.now() + (23 * 60 * 60 * 1000);
      console.log('[PhishGuard] Auth token obtained successfully');
      return AUTH_TOKEN;
    } else {
      console.warn('[PhishGuard] Login failed, status:', response.status);
    }
  } catch (error) {
    console.error('[PhishGuard] Failed to get auth token:', error);
  }
  
  return null;
}

/**
 * Force refresh the auth token (call on 401 errors)
 */
async function refreshAuthToken() {
  AUTH_TOKEN = null;
  TOKEN_EXPIRY = null;
  return await getAuthToken();
}

// Cache for pre-navigation scans
const navigationCache = new Map();
const CACHE_TTL_MS = 60000; // 1 minute cache

chrome.runtime.onInstalled.addListener(() => {
  console.log('[PhishGuard] Extension installed and active');
});

// ============================================================
// RETRY HELPER FUNCTION
// ============================================================

/**
 * Retry a function with exponential backoff
 */
async function withRetry(fn, maxRetries = MAX_RETRIES, delayMs = RETRY_DELAY_MS) {
  let lastError = null;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const result = await fn();
      if (result && result.success) {
        return result;
      }
      // If result exists but not successful, treat as error
      lastError = result?.error || 'Unknown error';
    } catch (error) {
      lastError = error.message;
      console.log(`[PhishGuard] Attempt ${attempt}/${maxRetries} failed: ${error.message}`);
    }
    
    // Wait before retry (except on last attempt)
    if (attempt < maxRetries) {
      await new Promise(resolve => setTimeout(resolve, delayMs * attempt));
    }
  }
  
  return { success: false, error: lastError || 'Max retries exceeded' };
}

// ============================================================
// PRE-NAVIGATION SCANNING (Step 4 - Browser Blocking)
// ============================================================

/**
 * Handle before navigation - scan domain before page loads
 */
async function handleBeforeNavigation(details) {
  const url = details.url;
  
  // Skip chrome internal pages
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || 
      url.startsWith('about:') || url.startsWith('data:')) {
    return;
  }
  
  // Skip if already processed
  if (navigationCache.has(url)) {
    const cached = navigationCache.get(url);
    if (Date.now() - cached.timestamp < CACHE_TTL_MS) {
      if (cached.block) {
        return { cancel: true };
      }
      return;
    }
    navigationCache.delete(url);
  }
  
  try {
    // Extract domain for domain-only scan
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Quick domain-only scan for blocking with retry
    const result = await withRetry(async () => {
      return await sendToBackend({
        url: url,
        mode: 'domain_only'
      });
    });
    
    if (result && result.success) {
      const { risk, block } = result.data;
      
      // Cache the result
      navigationCache.set(url, {
        ...result.data,
        timestamp: Date.now()
      });
      
      if (block || risk === 'HIGH') {
        console.log('[PhishGuard] Blocking navigation to:', url);
        // Store for content script to show block page
        await chrome.storage.session.set({
          [`block_${url}`]: result.data
        });
        return { redirectUrl: getBlockPageUrl(url, result.data) };
      }
    }
  } catch (error) {
    console.warn('[PhishGuard] Pre-nav scan failed:', error);
  }
}

/**
 * Get block page URL with encoded data
 */
function getBlockPageUrl(originalUrl, result) {
  const encoded = btoa(JSON.stringify({
    url: originalUrl,
    result: result
  }));
  return chrome.runtime.getURL('block.html') + '?data=' + encoded;
}

/**
 * Register navigation listener
 */
function setupNavigationListener() {
  // Check if webNavigation API is available
  if (!chrome.webNavigation) {
    console.warn('[PhishGuard] Navigation listener not available: webNavigation API not found');
    return;
  }
  
  try {
    // Check if onBeforeNavigate is supported
    if (chrome.webNavigation.onBeforeNavigate) {
      chrome.webNavigation.onBeforeNavigate.addListener(
        handleBeforeNavigation,
        { urlTypes: ['http', 'https'] }
      );
      console.log('[PhishGuard] Pre-navigation scanning enabled');
    } else {
      console.warn('[PhishGuard] Navigation listener not available: onBeforeNavigate not supported');
    }
  } catch (error) {
    console.warn('[PhishGuard] Navigation listener error:', error.message || error);
  }
}

// Initialize navigation listener
setupNavigationListener();

/**
 * Get auth header with fresh token
 */
async function getAuthHeader() {
  const token = await getAuthToken();
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  };
}

/**
 * Send scan data to backend API with timeout and retry
 */
async function sendToBackend(payload) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const headers = await getAuthHeader();
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    // Validate response structure
    if (!data || typeof data.risk !== 'string') {
      throw new Error('Invalid response format from backend');
    }

    // Safe response parsing
    const safeResponse = JSON.parse(JSON.stringify(data));

    return {
      success: true,
      data: safeResponse
    };

  } catch (error) {
    clearTimeout(timeoutId);

    if (error.name === 'AbortError') {
      return {
        success: false,
        error: 'Request timeout'
      };
    }

    return {
      success: false,
      error: error.message || 'Unknown error'
    };
  }
}

/**
 * Send to backend with retry wrapper
 */
async function sendToBackendWithRetry(payload) {
  return await withRetry(() => sendToBackend(payload));
}

/**
 * Store scan result in chrome.storage
 */
async function storeScanResult(url, result) {
  try {
    await chrome.storage.local.set({
      lastScan: {
        url,
        result,
        timestamp: Date.now()
      }
    });
  } catch (error) {
    console.warn('[PhishGuard] Storage error:', error);
  }
}

/**
 * Send user override feedback to backend
 */
async function sendFeedback(payload) {
  try {
    const headers = await getAuthHeader();
    const response = await fetch(FEEDBACK_ENDPOINT, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      console.log('[PhishGuard] Feedback sent successfully');
    }
  } catch (error) {
    console.warn('[PhishGuard] Feedback send failed:', error.message);
  }
}

/**
 * Message listener - handles messages from content script
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) {
    return false;
  }

  // Handle SCAN_PAGE
  if (message.type === 'SCAN_PAGE' && message.payload) {
    (async () => {
      try {
        // Log local AI result if present
        if (message.payload.local_result) {
          const { local_risk, local_confidence, inference_time_ms } = message.payload.local_result;
          console.log(`[PhishGuard] Local AI: ${local_risk} (${local_confidence}) in ${inference_time_ms}ms`);
        }

        // Use retry wrapper
        const result = await sendToBackendWithRetry(message.payload);

        if (result.success) {
          const { risk, confidence, reasons } = result.data;

          console.log(`[PhishGuard] Backend: ${risk} (${confidence || 'N/A'})`);

          if (reasons && reasons.length > 0) {
            console.log('[PhishGuard] Reasons:', reasons);
          }

          // Store result for popup
          await storeScanResult(message.payload.url, result.data);

          // Send response back to content script
          sendResponse(result.data);
        } else {
          console.warn('[PhishGuard] Backend unavailable:', result.error);
          // Send a fallback response instead of null
          sendResponse({
            risk: 'UNKNOWN',
            confidence: 0.5,
            block: false,
            error: result.error,
            retry: true
          });
        }
      } catch (error) {
        console.error('[PhishGuard] Unexpected error:', error);
        sendResponse({
          risk: 'UNKNOWN',
          confidence: 0.5,
          block: false,
          error: error.message,
          retry: true
        });
      }
    })();

    return true;
  }

  // Handle SCAN_EMAIL
  if (message.type === 'SCAN_EMAIL' && message.payload) {
    (async () => {
      try {
        console.log(`[PhishGuard Email] Scanning email from: ${message.payload.sender?.email || 'unknown'}`);

        if (message.payload.local_result) {
          const { local_risk, local_confidence } = message.payload.local_result;
          console.log(`[PhishGuard Email] Local AI: ${local_risk} (${local_confidence})`);
        }

        const result = await sendToBackendWithRetry(message.payload);

        if (result.success) {
          const { risk, confidence, reasons } = result.data;
          console.log(`[PhishGuard Email] Backend: ${risk} (${confidence || 'N/A'})`);
          sendResponse(result.data);
        } else {
          console.warn('[PhishGuard Email] Backend unavailable:', result.error);
          sendResponse({
            risk: 'UNKNOWN',
            confidence: 0.5,
            block: false,
            error: result.error
          });
        }
      } catch (error) {
        console.error('[PhishGuard Email] Unexpected error:', error);
        sendResponse({
          risk: 'UNKNOWN',
          confidence: 0.5,
          block: false,
          error: error.message
        });
      }
    })();

    return true;
  }

  // Handle SCAN_MESSAGE
  if (message.type === 'SCAN_MESSAGE' && message.payload) {
    (async () => {
      try {
        console.log(`[PhishGuard Message] Scanning ${message.payload.platform} message`);

        if (message.payload.local_result) {
          const { local_risk, local_confidence } = message.payload.local_result;
          console.log(`[PhishGuard Message] Local AI: ${local_risk} (${local_confidence})`);
        }

        const result = await sendToBackendWithRetry(message.payload);

        if (result.success) {
          const { risk, confidence, reasons } = result.data;
          console.log(`[PhishGuard Message] Backend: ${risk} (${confidence || 'N/A'})`);
          sendResponse(result.data);
        } else {
          console.warn('[PhishGuard Message] Backend unavailable:', result.error);
          sendResponse({
            risk: 'UNKNOWN',
            confidence: 0.5,
            block: false,
            error: result.error
          });
        }
      } catch (error) {
        console.error('[PhishGuard Message] Unexpected error:', error);
        sendResponse({
          risk: 'UNKNOWN',
          confidence: 0.5,
          block: false,
          error: error.message
        });
      }
    })();

    return true;
  }

  // Handle REPORT_PHISHING
  if (message.type === 'REPORT_PHISHING' && message.payload) {
    console.log('[PhishGuard] Phishing reported:', message.payload);

    // Send report to backend
    sendFeedback({
      ...message.payload,
      type: 'phishing_report'
    }).catch(err => {
      console.warn('[PhishGuard] Report send failed:', err);
    });

    return false;
  }

  // Handle USER_OVERRIDE
  if (message.type === 'USER_OVERRIDE' && message.payload) {
    console.log('[PhishGuard] User override logged');

    // Send feedback asynchronously (no response needed)
    sendFeedback(message.payload).catch(err => {
      console.warn('[PhishGuard] Feedback error:', err);
    });

    return false;
  }

  // ============================================================
  // FORENSIC ANALYSIS (PART 1 & 2)
  // Handle FORENSIC_ANALYSIS - receives RAW signals from content.js
  // Sends to backend for ALL analysis (PART 2-5)
  // ============================================================
  if (message.type === 'FORENSIC_ANALYSIS' && message.payload) {
    (async () => {
      try {
        console.log('[PhishGuard Forensic] Received raw signals, sending to backend for analysis...');
        
        // Transform forensic signals to API format - extract URL from payload
        const urlToScan = message.payload.url_context?.page_url || message.payload.url;
        
        // Build forensic request in correct format
        const forensicRequest = {
          url: urlToScan,
          deep_analysis: true,
          extract_artifacts: true,
          check_whois: true,
          check_dns: true,
          check_ssl: true,
          check_threat_intel: true
        };
        
        console.log('[PhishGuard Forensic] Sending to backend:', forensicRequest.url);
        
        // Send to forensic endpoint with retry
        const result = await withRetry(async () => {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
          const headers = await getAuthHeader();

          const response = await fetch(FORENSIC_ENDPOINT, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(forensicRequest),
            signal: controller.signal
          });

          clearTimeout(timeoutId);

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }

          const data = await response.json();
          
          // Validate response structure
          if (!data || typeof data.risk !== 'string') {
            throw new Error('Invalid forensic response format');
          }

          return { success: true, data };
        });
        
        if (result.success) {
          const data = result.data;
          console.log(`[PhishGuard Forensic] Backend analysis: ${data.risk} (${data.confidence})`);
          console.log('[PhishGuard Forensic] Findings:', data.reasons?.length || 0);
          
          // Store result for popup
          await storeScanResult(urlToScan, data);
          
          // Send complete analysis back to content script
          sendResponse(data);
        } else {
          console.error('[PhishGuard Forensic] Analysis failed after retries:', result.error);
          sendResponse({
            risk: 'UNKNOWN',
            confidence: 0.5,
            findings: [],
            error: result.error
          });
        }
        
      } catch (error) {
        console.error('[PhishGuard Forensic] Analysis failed:', error.message);
        sendResponse({
          risk: 'UNKNOWN',
          confidence: 0.5,
          findings: [],
          error: error.message
        });
      }
    })();

    return true;
  }

  return false;
});
