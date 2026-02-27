// PhishGuard Data Extraction Utilities

/**
 * Extract page metadata
 */
export function extractMetadata() {
  return {
    url: window.location.href,
    domain: window.location.hostname,
    title: document.title || '',
    referrer: document.referrer || '',
    protocol: window.location.protocol.replace(':', '')
  };
}

/**
 * Extract DOM risk indicators
 */
export function extractDOMIndicators() {
  const forms = document.querySelectorAll('form');
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
  const iframes = document.querySelectorAll('iframe');
  const externalScripts = document.querySelectorAll('script[src]');
  const allLinks = document.querySelectorAll('a[href]');
  
  // Count external links
  const origin = window.location.origin;
  let externalLinkCount = 0;
  
  allLinks.forEach(link => {
    try {
      const href = link.getAttribute('href');
      if (href && href.startsWith('http')) {
        const linkUrl = new URL(href);
        if (linkUrl.origin !== origin) {
          externalLinkCount++;
        }
      }
    } catch (e) {
      // Invalid URL, skip
    }
  });

  return {
    form_count: forms.length,
    password_fields: passwordInputs.length,
    hidden_inputs: hiddenInputs.length,
    iframe_count: iframes.length,
    external_scripts: externalScripts.length,
    total_links: allLinks.length,
    external_links: externalLinkCount
  };
}

/**
 * Detect suspicious behavioral signals
 */
export function detectSuspiciousSignals() {
  const url = window.location.href;
  const urlLength = url.length;
  
  // Check for redirect
  const hasRedirect = document.referrer && 
    new URL(document.referrer).hostname !== window.location.hostname;
  
  // Check subdomain count
  const hostname = window.location.hostname;
  const subdomainCount = hostname.split('.').length - 2; // Subtract domain + TLD
  
  // Check for suspicious keywords in URL
  const suspiciousUrlKeywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm'];
  const urlLower = url.toLowerCase();
  const hasSuspiciousUrl = suspiciousUrlKeywords.some(keyword => urlLower.includes(keyword));
  
  return {
    loaded_via_redirect: hasRedirect,
    url_length: urlLength,
    long_url: urlLength > 100,
    subdomain_count: Math.max(0, subdomainCount),
    excessive_subdomains: subdomainCount > 3,
    suspicious_url_keywords: hasSuspiciousUrl
  };
}

/**
 * Extract and analyze visible text content
 */
export function extractTextContent() {
  // Get visible text, strip scripts and styles
  const body = document.body;
  if (!body) return { text_snippet: '', suspicious_keywords_found: [] };
  
  // Clone body to avoid modifying DOM
  const clone = body.cloneNode(true);
  
  // Remove scripts, styles, and hidden elements
  const unwanted = clone.querySelectorAll('script, style, noscript, [hidden]');
  unwanted.forEach(el => el.remove());
  
  // Get text content
  let text = clone.innerText || clone.textContent || '';
  
  // Clean whitespace
  text = text.replace(/\s+/g, ' ').trim();
  
  // Take first 2000 characters
  const textSnippet = text.slice(0, 2000);
  
  // Scan for suspicious keywords
  const suspiciousKeywords = [
    'verify',
    'urgent',
    'account suspended',
    'reset password',
    'confirm your identity',
    'unusual activity',
    'click here immediately',
    'verify your account',
    'suspended account',
    'update payment'
  ];
  
  const textLower = textSnippet.toLowerCase();
  const foundKeywords = suspiciousKeywords.filter(keyword => 
    textLower.includes(keyword)
  );
  
  return {
    text_snippet: textSnippet,
    suspicious_keywords_found: foundKeywords
  };
}

/**
 * Check if page has login indicators
 */
export function detectLoginPage() {
  const hasPasswordField = document.querySelectorAll('input[type="password"]').length > 0;
  const title = document.title.toLowerCase();
  const bodyText = (document.body?.innerText || '').toLowerCase().slice(0, 1000);
  
  const loginKeywords = ['login', 'sign in', 'log in', 'signin'];
  const hasLoginKeyword = loginKeywords.some(keyword => 
    title.includes(keyword) || bodyText.includes(keyword)
  );
  
  return {
    has_login_indicators: hasPasswordField || hasLoginKeyword,
    has_password_field: hasPasswordField
  };
}
