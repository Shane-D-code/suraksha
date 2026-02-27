// PhishGuard Content Script - RAW Forensic Signal Extractor
// PART 1: Browser Live Forensic Agent
// This script extracts STRUCTURED FORENSIC SIGNALS ONLY.
// NO classification, NO local risk assessment, NO opinions.
// All analysis is performed by the backend intelligence engine.

(() => {
  'use strict';

  let hasScanned = false;

  // ============================================================
  // PART 1: RAW SIGNAL EXTRACTION
  // All functions extract data WITHOUT classification
  // ============================================================

  /**
   * Extract URL Context
   */
  function extractURLContext() {
    return {
      current_domain: window.location.hostname.toLowerCase(),
      page_url: window.location.href
    };
  }

  /**
   * Extract Form Analysis Signals
   * Returns RAW data only - no classification
   */
  function extractFormAnalysis() {
    const forms = document.querySelectorAll('form');
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    const passwordInIframe = document.querySelectorAll('iframe input[type="password"]');
    
    // Detect external form submission
    let externalSubmission = false;
    let submissionDomain = null;
    
    for (const form of forms) {
      const action = form.getAttribute('action');
      if (action) {
        try {
          // Absolute URL
          if (action.startsWith('http')) {
            const actionUrl = new URL(action);
            if (actionUrl.hostname !== window.location.hostname) {
              externalSubmission = true;
              submissionDomain = actionUrl.hostname;
              break;
            }
          }
          // Relative URL - same domain
        } catch (e) {
          // Invalid action, skip
        }
      }
    }
    
    return {
      login_detected: passwordInputs.length > 0,
      external_submission: externalSubmission,
      submission_domain: submissionDomain,
      hidden_inputs_count: hiddenInputs.length,
      password_in_iframe: passwordInIframe.length > 0
    };
  }

  /**
   * Extract Script & Resource Analysis Signals
   * Returns RAW counts and domains - no classification
   */
  function extractScriptAnalysis() {
    const scripts = document.querySelectorAll('script[src]');
    const scriptDomains = new Set();
    const suspiciousPatterns = ['analytics', 'tracker', 'pixel', 'click', 'stat'];
    
    const suspiciousDomains = [];
    
    for (const script of scripts) {
      try {
        const src = script.getAttribute('src');
        if (src) {
          const scriptUrl = new URL(src, window.location.href);
          scriptDomains.add(scriptUrl.hostname);
          
          // Check for suspicious patterns
          const domainLower = scriptUrl.hostname.toLowerCase();
          if (suspiciousPatterns.some(p => domainLower.includes(p))) {
            suspiciousDomains.push(scriptUrl.hostname);
          }
        }
      } catch (e) {
        // Invalid src, skip
      }
    }
    
    return {
      external_script_count: scripts.length,
      unique_script_domains: scriptDomains.size,
      suspicious_script_domains: [...new Set(suspiciousDomains)] // Dedupe
    };
  }

  /**
   * Extract DOM Manipulation Indicators
   * Returns RAW signals - no classification
   */
  function extractDOMManipulation() {
    // Check if right-click is disabled
    const rightClickDisabled = document.addEventListener 
      ? (() => {
          let disabled = false;
          const handler = (e) => { 
            disabled = true; 
            e.preventDefault();
            return false;
          };
          document.addEventListener('contextmenu', handler, { once: true });
          // Trigger a check by simulating
          document.oncontextmenu = handler;
          setTimeout(() => { document.oncontextmenu = null; }, 100);
          return disabled;
        })()
      : false;
    
    // Check for obfuscated HTML
    const bodyHTML = document.body ? document.body.innerHTML : '';
    const hasObfuscation = /(<script[^>]*>.*?eval.*?<\/script>)|(String\.fromCharCode)|(\\x[0-9a-f]{2})/i.test(bodyHTML);
    
    // Count iframes
    const iframes = document.querySelectorAll('iframe');
    
    return {
      right_click_disabled: rightClickDisabled,
      obfuscated_html_detected: hasObfuscation,
      iframe_count: iframes.length
    };
  }

  /**
   * Extract Content & Brand Indicators
   * Returns RAW signals - no classification
   */
  function extractContentAnalysis() {
    // Detect brand from page content
    const bodyText = document.body ? (document.body.innerText || '').toLowerCase() : '';
    const titleText = document.title.toLowerCase();
    const combinedText = bodyText + ' ' + titleText;
    
    // Brand detection keywords (no classification - just detection)
    const brandPatterns = {
      'paypal': /paypal/,
      'amazon': /amazon/,
      'microsoft': /microsoft|outlook|live\.com/,
      'google': /google|gmail|googledrive/,
      'apple': /apple|icloud|itunes/,
      'facebook': /facebook|meta/,
      'netflix': /netflix/,
      'bank': /bank|chase|wells Fargo|bank of america|citi/,
      'irs': /irs|tax refund|tax return/,
      'social security': /social security|ssa/,
      'amazon': /amazon|aws/,
      'microsoft': /microsoft|office 365/,
      'adobe': /adobe|creative cloud/,
    };
    
    let detectedBrand = null;
    for (const [brand, pattern] of Object.entries(brandPatterns)) {
      if (pattern.test(combinedText)) {
        detectedBrand = brand.charAt(0).toUpperCase() + brand.slice(1);
        break;
      }
    }
    
    // Calculate urgency score (0-1)
    const urgencyKeywords = [
      { word: 'urgent', weight: 1.0 },
      { word: 'immediately', weight: 0.9 },
      { word: 'verify your account', weight: 1.0 },
      { word: 'account suspended', weight: 0.9 },
      { word: 'unusual activity', weight: 0.7 },
      { word: 'click here', weight: 0.6 },
      { word: 'confirm your identity', weight: 0.8 },
      { word: 'update payment', weight: 0.7 },
      { word: 'password expire', weight: 0.6 },
      { word: 'security alert', weight: 0.7 }
    ];
    
    let urgencyScore = 0.0;
    for (const { word, weight } of urgencyKeywords) {
      if (combinedText.includes(word)) {
        urgencyScore = Math.max(urgencyScore, weight);
      }
    }
    
    // Calculate keyword density (phishing indicators)
    const phishingKeywords = [
      'verify', 'suspended', 'unusual', 'activity', 'confirm',
      'update', 'secure', 'login', 'password', 'credential',
      'immediate', 'action required', 'locked', 'expired'
    ];
    
    let keywordCount = 0;
    for (const keyword of phishingKeywords) {
      const regex = new RegExp(keyword, 'gi');
      const matches = combinedText.match(regex);
      if (matches) {
        keywordCount += matches.length;
      }
    }
    
    // Normalize to 0-1 (cap at 50 occurrences = 1.0)
    const keywordDensity = Math.min(keywordCount / 50, 1.0);
    
    return {
      brand_detected: detectedBrand,
      urgency_score: urgencyScore,
      keyword_density: keywordDensity
    };
  }

  // ============================================================
  // PART 1 MAIN: Extract ALL Raw Signals
  // Returns JSON as specified in requirements
  // ============================================================

  function extractForensicSignals() {
    try {
      // Extract all signal categories
      const urlContext = extractURLContext();
      const formAnalysis = extractFormAnalysis();
      const scriptAnalysis = extractScriptAnalysis();
      const domManipulation = extractDOMManipulation();
      const contentAnalysis = extractContentAnalysis();
      
      // Build the structured JSON output
      const forensicSignals = {
        // URL Context (required)
        url_context: urlContext,
        
        // Form Analysis
        form_analysis: formAnalysis,
        
        // Script & Resource Analysis
        script_analysis: scriptAnalysis,
        
        // DOM Manipulation
        dom_manipulation: domManipulation,
        
        // Content & Brand
        content_analysis: contentAnalysis,
        
        // Metadata
        timestamp: Date.now(),
        extension_version: '2.0.0'
      };
      
      console.log('[PhishGuard] Raw forensic signals extracted:', JSON.stringify(forensicSignals, null, 2));
      
      return forensicSignals;
      
    } catch (error) {
      console.error('[PhishGuard] Signal extraction error:', error);
      return null;
    }
  }

  // ============================================================
  // PART 1: Send to Backend
  // Sends RAW signals only - backend performs ALL analysis
  // ============================================================

  /**
   * Send raw forensic signals to backend for analysis
   * NO local classification performed
   */
  async function sendToBackend(signals) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { 
          type: 'FORENSIC_ANALYSIS', 
          payload: signals
        },
        (response) => {
          if (chrome.runtime.lastError) {
            console.error('[PhishGuard] Backend error:', chrome.runtime.lastError.message);
            resolve(null);
            return;
          }
          resolve(response);
        }
      );
    });
  }

  /**
   * Cache backend response
   */
  async function cacheResult(url, data) {
    try {
      const cacheKey = `forensic_cache_${btoa(url).slice(0, 50)}`;
      await chrome.storage.local.set({
        [cacheKey]: {
          data,
          timestamp: Date.now()
        }
      });
    } catch (error) {
      console.warn('[PhishGuard] Cache error:', error);
    }
  }

  /**
   * Get cached result
   */
  async function getCachedResult(url) {
    try {
      const cacheKey = `forensic_cache_${btoa(url).slice(0, 50)}`;
      const result = await chrome.storage.local.get(cacheKey);
      const cached = result[cacheKey];
      
      // 5 minute cache
      if (cached && (Date.now() - cached.timestamp < 300000)) {
        return cached.data;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Main execution: Extract and Send
   */
  async function runForensicExtraction() {
    if (hasScanned) return;
    hasScanned = true;
    
    const url = window.location.href;
    
    // Check cache first
    const cached = await getCachedResult(url);
    if (cached) {
      console.log('[PhishGuard] Using cached forensic result');
      if (window.phishGuardBlocker) {
        window.phishGuardBlocker.handleRiskDecision(cached);
      }
      return;
    }
    
    console.log('[PhishGuard] Extracting forensic signals...');
    
    // Extract RAW signals only
    const signals = extractForensicSignals();
    
    if (!signals) {
      console.error('[PhishGuard] Failed to extract signals');
      return;
    }
    
    // Send to backend for ALL analysis
    console.log('[PhishGuard] Sending signals to backend for analysis...');
    const result = await sendToBackend(signals);
    
    if (result) {
      console.log('[PhishGuard] Backend analysis complete:', result.risk, result.confidence);
      
      // Cache the result
      await cacheResult(url, result);
      
      // Handle the decision
      if (window.phishGuardBlocker) {
        window.phishGuardBlocker.handleRiskDecision(result);
      }
    } else {
      console.warn('[PhishGuard] Backend analysis failed - no result');
    }
  }

  // Run when page is fully loaded
  if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', runForensicExtraction, { once: true });
  } else {
    // Page already loaded
    runForensicExtraction();
  }
})();
