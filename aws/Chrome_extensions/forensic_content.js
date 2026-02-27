// PhishGuard Forensic Signal Extractor - PART 1
// Chrome Extension - Live DOM Analysis
// 
// This script extracts STRUCTURED FORENSIC SIGNALS only.
// NO classification, NO scoring, NO opinions.
// All signals are sent to backend for analysis.

(() => {
  'use strict';

  // Prevent multiple scans
  let hasScanned = false;

  // ============================================================
  // PART 1: URL CONTEXT
  // ============================================================
  
  function extractURLContext() {
    return {
      current_domain: window.location.hostname,
      page_url: window.location.href
    };
  }

  // ============================================================
  // PART 2: FORM ANALYSIS
  // ============================================================
  
  function analyzeForms() {
    const forms = document.querySelectorAll('form');
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    const iframes = document.querySelectorAll('iframe');
    
    let loginDetected = false;
    let externalSubmission = false;
    let submissionDomain = null;
    let passwordInIframe = false;
    
    // Check each form
    forms.forEach(form => {
      const action = form.getAttribute('action');
      
      // Detect login form
      const hasPassword = form.querySelector('input[type="password"]');
      const hasUsername = form.querySelector('input[type="email"], input[type="text"]');
      
      if (hasPassword || hasUsername) {
        loginDetected = true;
        
        // Check if form submits to external domain
        if (action) {
          try {
            const actionURL = new URL(action, window.location.href);
            if (actionURL.origin !== window.location.origin) {
              externalSubmission = true;
              submissionDomain = actionURL.hostname;
            }
          } catch (e) {
            // Invalid action URL
          }
        }
        
        // Check if password field is in iframe
        if (hasPassword) {
          const parentIframe = hasPassword.closest('iframe');
          if (parentIframe) {
            passwordInIframe = true;
          }
        }
      }
    });
    
    return {
      login_detected: loginDetected,
      external_submission: externalSubmission,
      submission_domain: submissionDomain,
      hidden_inputs_count: hiddenInputs.length,
      password_in_iframe: passwordInIframe
    };
  }

  // ============================================================
  // PART 3: SCRIPT & RESOURCE ANALYSIS
  // ============================================================
  
  function analyzeScripts() {
    const scripts = document.querySelectorAll('script[src]');
    const scriptDomains = new Set();
    const suspiciousDomains = [];
    
    // Known suspicious domain patterns
    const suspiciousPatterns = [
      'tracker', 'analytics', 'stat', 'counter', 'click', 
      'pixel', 'ads', 'doubleclick', 'googlesyndication'
    ];
    
    scripts.forEach(script => {
      try {
        const src = script.getAttribute('src');
        if (src) {
          const url = new URL(src, window.location.href);
          scriptDomains.add(url.hostname);
          
          // Check for suspicious patterns
          const hostnameLower = url.hostname.toLowerCase();
          if (suspiciousPatterns.some(p => hostnameLower.includes(p))) {
            suspiciousDomains.push(url.hostname);
          }
        }
      } catch (e) {
        // Invalid script src
      }
    });
    
    return {
      external_script_count: scripts.length,
      unique_script_domains: scriptDomains.size,
      suspicious_script_domains: [...new Set(suspiciousDomains)]
    };
  }

  // ============================================================
  // PART 4: DOM MANIPULATION INDICATORS
  // ============================================================
  
  function analyzeDOMManipulation() {
    // Check if right-click is disabled
    const hasOnContextMenu = document.body.getAttribute('oncontextmenu');
    const rightClickDisabled = hasOnContextMenu === 'return false' || hasOnContextMenu === 'false';
    
    // Check for obfuscated HTML
    let obfuscatedDetected = false;
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      const content = script.textContent || '';
      // Common obfuscation patterns
      if (content.includes('String.fromCharCode') && content.length > 1000) {
        obfuscatedDetected = true;
      }
      if (content.includes('eval') && content.includes('document.write')) {
        obfuscatedDetected = true;
      }
    });
    
    // Count iframes
    const iframes = document.querySelectorAll('iframe');
    
    return {
      right_click_disabled: rightClickDisabled,
      obfuscated_html_detected: obfuscatedDetected,
      iframe_count: iframes.length
    };
  }

  // ============================================================
  // PART 5: CONTENT & BRAND INDICATORS
  // ============================================================
  
  function analyzeContent() {
    const body = document.body;
    const text = (body?.innerText || body?.textContent || '').toLowerCase();
    
    // Brand detection patterns
    const brandPatterns = {
      'paypal': ['paypal', 'pay'],
      'amazon': ['amazon', 'amazon.com'],
      'microsoft': ['microsoft', 'office365', 'outlook.com'],
      'apple': ['apple', 'icloud', 'apple.com'],
      'google': ['google', 'gmail', 'google.com'],
      'facebook': ['facebook', 'meta'],
      'twitter': ['twitter', 'x.com'],
      'linkedin': ['linkedin'],
      'netflix': ['netflix'],
      'chase': ['chase', 'chase.com'],
      'bankofamerica': ['bank of america', 'bankofamerica'],
      'wellsfargo': ['wells fargo', 'wellsfargo']
    };
    
    let detectedBrand = null;
    for (const [brand, patterns] of Object.entries(brandPatterns)) {
      if (patterns.some(p => text.includes(p))) {
        detectedBrand = brand;
        break;
      }
    }
    
    // Urgency keyword detection
    const urgencyKeywords = [
      { word: 'urgent', weight: 0.9 },
      { word: 'immediately', weight: 0.8 },
      { word: 'suspended', weight: 0.7 },
      { word: 'verify', weight: 0.6 },
      { word: 'confirm', weight: 0.5 },
      { word: 'account locked', weight: 0.9 },
      { word: 'unusual activity', weight: 0.8 },
      { word: 'click here', weight: 0.6 },
      { word: 'act now', weight: 0.7 },
      { word: 'expire', weight: 0.6 }
    ];
    
    let urgencyScore = 0.0;
    
    urgencyKeywords.forEach(({ word, weight }) => {
      if (text.includes(word)) {
        urgencyScore += weight;
      }
    });
    
    // Normalize urgency score
    urgencyScore = Math.min(urgencyScore / 2.0, 1.0);
    
    // Keyword density (phishing keywords / total words)
    const phishingKeywords = [
      'verify', 'urgent', 'suspended', 'account', 'password', 'login',
      'security', 'confirm', 'update', 'validate', 'identity'
    ];
    
    const words = text.split(/\s+/).filter(w => w.length > 0);
    const totalWords = words.length;
    
    let keywordCount = 0;
    words.forEach(word => {
      if (phishingKeywords.some(k => word.includes(k))) {
        keywordCount++;
      }
    });
    
    const keywordDensity = totalWords > 0 ? keywordCount / totalWords : 0.0;
    
    return {
      brand_detected: detectedBrand,
      urgency_score: Math.round(urgencyScore * 100) / 100,
      keyword_density: Math.round(keywordDensity * 1000) / 1000
    };
  }

  // ============================================================
  // MAIN: Extract all forensic signals
  // ============================================================
  
  function extractForensicSignals() {
    try {
      const urlContext = extractURLContext();
      const formAnalysis = analyzeForms();
      const scriptAnalysis = analyzeScripts();
      const domManipulation = analyzeDOMManipulation();
      const contentAnalysis = analyzeContent();
      
      const signals = {
        url_context: urlContext,
        form_analysis: formAnalysis,
        script_analysis: scriptAnalysis,
        dom_manipulation: domManipulation,
        content_analysis: contentAnalysis,
        timestamp: Date.now(),
        extension_version: '2.0.0'
      };
      
      console.log('[PhishGuard] Forensic signals extracted');
      
      return signals;
      
    } catch (error) {
      console.error('[PhishGuard] Signal extraction error:', error);
      return null;
    }
  }

  // ============================================================
  // Send to Backend
  // ============================================================
  
  async function sendToBackend(signals) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        {
          type: 'SCAN_FORENSIC',
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

  // ============================================================
  // Run Analysis
  // ============================================================
  
  async function runForensicAnalysis() {
    if (hasScanned) return;
    hasScanned = true;
    
    console.log('[PhishGuard] Starting forensic analysis...');
    
    // Extract structured signals
    const signals = extractForensicSignals();
    
    if (!signals) {
      console.error('[PhishGuard] Failed to extract signals');
      return;
    }
    
    // Send to backend for analysis
    const result = await sendToBackend(signals);
    
    if (result) {
      console.log('[PhishGuard] Analysis result:', result);
      
      // Pass result to blocker for display
      if (window.phishGuardBlocker) {
        window.phishGuardBlocker.handleRiskDecision(result);
      }
    }
  }

  // Run when page is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runForensicAnalysis, { once: true });
  } else {
    runForensicAnalysis();
  }

})();
