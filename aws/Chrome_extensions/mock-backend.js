// Mock Backend Server for PhishGuard Testing
// Run with: node mock-backend.js

import http from 'http';

const PORT = 8000;

// Simple risk calculation based on indicators
function calculateRisk(data) {
  let score = 0;
  const reasons = [];

  // Check for suspicious keywords
  if (data.suspicious_keywords_found && data.suspicious_keywords_found.length > 0) {
    score += 30;
    reasons.push(`Found suspicious keywords: ${data.suspicious_keywords_found.join(', ')}`);
  }

  // Check for password fields
  if (data.password_fields > 0) {
    score += 15;
    reasons.push('Page contains password input fields');
  }

  // Check for external links
  if (data.external_links > 5) {
    score += 20;
    reasons.push(`High number of external links: ${data.external_links}`);
  }

  // Check for long URL
  if (data.long_url) {
    score += 10;
    reasons.push('URL is unusually long');
  }

  // Check for excessive subdomains
  if (data.excessive_subdomains) {
    score += 15;
    reasons.push(`Excessive subdomains: ${data.subdomain_count}`);
  }

  // Check for iframes
  if (data.iframe_count > 0) {
    score += 10;
    reasons.push(`Page contains ${data.iframe_count} iframe(s)`);
  }

  // Check for hidden inputs
  if (data.hidden_inputs > 2) {
    score += 10;
    reasons.push(`Multiple hidden inputs: ${data.hidden_inputs}`);
  }

  // Determine risk level
  let risk, confidence;
  if (score >= 50) {
    risk = 'HIGH';
    confidence = Math.min(0.95, 0.5 + (score / 100));
  } else if (score >= 25) {
    risk = 'MEDIUM';
    confidence = 0.5 + (score / 200);
  } else {
    risk = 'LOW';
    confidence = 0.3 + (score / 300);
  }

  return { risk, confidence: parseFloat(confidence.toFixed(2)), reasons };
}

const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Handle scan endpoint
  if (req.method === 'POST' && req.url === '/scan') {
    let body = '';

    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        console.log('\n[Mock Backend] Received scan request:');
        console.log('  URL:', data.url);
        console.log('  Domain:', data.domain);
        console.log('  Forms:', data.form_count);
        console.log('  Password fields:', data.password_fields);
        console.log('  External links:', data.external_links);
        console.log('  Suspicious keywords:', data.suspicious_keywords_found);

        const result = calculateRisk(data);
        
        console.log('\n[Mock Backend] Sending response:');
        console.log('  Risk:', result.risk);
        console.log('  Confidence:', result.confidence);
        console.log('  Reasons:', result.reasons);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (error) {
        console.error('[Mock Backend] Error:', error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
  }
  // Handle feedback endpoint
  else if (req.method === 'POST' && req.url === '/feedback') {
    let body = '';

    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        console.log('\n[Mock Backend] Received user override feedback:');
        console.log('  URL:', data.url);
        console.log('  Original Risk:', data.original_risk);
        console.log('  User Override:', data.user_override);
        console.log('  Timestamp:', new Date(data.timestamp).toISOString());

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (error) {
        console.error('[Mock Backend] Error:', error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

server.listen(PORT, () => {
  console.log(`\n🛡️  PhishGuard Mock Backend Server`);
  console.log(`   Running on http://localhost:${PORT}`);
  console.log(`   Endpoints:`);
  console.log(`     POST /scan - Analyze page risk`);
  console.log(`     POST /feedback - Log user overrides\n`);
  console.log('   Waiting for requests...\n');
});
