"""
PhishGuard Enhanced Backend API Server
Integrates threat intelligence, local AI, GNN infrastructure analysis, and campaign detection
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging
from urllib.parse import urlparse
from datetime import datetime
import sys
import os

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threat_intel'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ml'))

# Try to import GNN modules
try:
    from gnn_inference import GNNInferenceEngine, get_inference_engine
    GNN_AVAILABLE = True
except ImportError as e:
    GNN_AVAILABLE = False
    logging.warning(f"GNN modules not available: {e}")

try:
    from scheduler import ThreatIntelligenceScheduler
    from feeds import CustomFeed
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    logging.warning("Threat intelligence modules not available")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize GNN inference engine
gnn_engine = None
if GNN_AVAILABLE:
    try:
        gnn_engine = get_inference_engine(
            model_path='ml/models/gnn_model.pt',
            data_dir='ml/data'
        )
        logger.info("GNN Inference Engine initialized")
    except Exception as e:
        logger.error(f"Failed to initialize GNN engine: {e}")
        gnn_engine = None

# Initialize threat intelligence (if available)
threat_scheduler = None
if THREAT_INTEL_AVAILABLE:
    try:
        threat_scheduler = ThreatIntelligenceScheduler(
            db_path='threat_intel.db',
            sync_interval_minutes=30
        )
        threat_scheduler.add_feed(CustomFeed('threat_feeds/custom_threats.txt'))
        logger.info("Threat intelligence initialized")
    except Exception as e:
        logger.error(f"Failed to initialize threat intelligence: {e}")
        threat_scheduler = None


class PhishGuardAPIHandler(BaseHTTPRequestHandler):
    """Enhanced API handler with threat intelligence"""
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/scan':
            self.handle_scan()
        elif self.path == '/feedback':
            self.handle_feedback()
        else:
            self.send_error(404, 'Not Found')
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/status':
            self.handle_status()
        elif self.path == '/threat-cache':
            self.handle_threat_cache()
        elif self.path.startswith('/gnn'):
            self.handle_gnn_request()
        else:
            self.send_error(404, 'Not Found')
    
    def handle_gnn_request(self):
        """Handle GNN-specific requests"""
        try:
            from urllib.parse import urlparse, parse_qs
            
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            
            # Parse path and query
            path = parsed.path
            
            if path == '/gnn/campaigns':
                # Get detected campaigns
                if gnn_engine:
                    campaigns = gnn_engine.detect_campaigns()
                    result = {
                        'success': True,
                        'campaigns': campaigns,
                        'count': len(campaigns)
                    }
                else:
                    result = {'success': False, 'error': 'GNN not available'}
            
            elif path == '/gnn/similar':
                # Find similar domains
                domain = query.get('domain', [None])[0]
                top_k = int(query.get('k', [5])[0])
                
                if domain and gnn_engine:
                    # First check if domain is in graph
                    if domain in gnn_engine.node_id_map:
                        idx = gnn_engine.node_id_map[domain]
                        similar = gnn_engine._find_similar_domains(idx, top_k)
                        result = {
                            'success': True,
                            'domain': domain,
                            'similar_domains': similar
                        }
                    else:
                        result = {'success': False, 'error': 'Domain not in graph'}
                else:
                    result = {'success': False, 'error': 'GNN not available or missing domain'}
            
            elif path == '/gnn/status':
                # Get GNN status
                if gnn_engine:
                    result = {
                        'success': True,
                        'status': gnn_engine.get_status()
                    }
                else:
                    result = {'success': False, 'error': 'GNN not available'}
            
            else:
                result = {'success': False, 'error': 'Unknown GNN endpoint'}
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps(result, indent=2).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"GNN request error: {e}")
            self.send_error(500, str(e))
    
    def handle_scan(self):
        """Handle scan request with threat intelligence"""
        try:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))
            
            # Extract domain from URL
            url = data.get('url', '')
            domain = self.extract_domain(url)
            
            logger.info(f"Scanning: {domain}")
            
            # Calculate risk score
            risk_result = self.calculate_risk(data, domain)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = json.dumps(risk_result)
            self.wfile.write(response.encode('utf-8'))
            
            logger.info(f"Result: {risk_result['risk']} ({risk_result['confidence']})")
            
        except Exception as e:
            logger.error(f"Scan error: {e}", exc_info=True)
            self.send_error(500, str(e))
    
    def handle_feedback(self):
        """Handle feedback/report"""
        try:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))
            
            logger.info(f"Feedback received: {data.get('type', 'unknown')}")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = json.dumps({'success': True})
            self.wfile.write(response.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Feedback error: {e}")
            self.send_error(500, str(e))
    
    def handle_status(self):
        """Handle status request"""
        try:
            status = {
                'server': 'PhishGuard API',
                'version': '6.0.0',  # Phase 6!
                'timestamp': datetime.now().isoformat(),
                'threat_intelligence': 'enabled' if threat_scheduler else 'disabled',
                'gnn_inference': 'enabled' if (GNN_AVAILABLE and gnn_engine) else 'disabled'
            }
            
            if threat_scheduler:
                status['threat_intel_status'] = threat_scheduler.get_status()
            
            if gnn_engine:
                status['gnn_status'] = gnn_engine.get_status()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = json.dumps(status, indent=2)
            self.wfile.write(response.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Status error: {e}")
            self.send_error(500, str(e))
    
    def handle_threat_cache(self):
        """Handle threat cache request"""
        try:
            cache = {
                'malicious_domains': [],
                'high_risk_patterns': [],
                'timestamp': datetime.now().isoformat()
            }
            
            if threat_scheduler:
                # Get recent threats from database
                db_stats = threat_scheduler.db.get_statistics()
                cache['total_threats'] = db_stats.get('total_domains', 0)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = json.dumps(cache)
            self.wfile.write(response.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Threat cache error: {e}")
            self.send_error(500, str(e))
    
    def extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            if not url.startswith('http'):
                url = f'http://{url}'
            parsed = urlparse(url)
            return parsed.netloc or parsed.path
        except:
            return url
    
    def calculate_risk(self, data: dict, domain: str) -> dict:
        """Calculate comprehensive risk score with GNN integration"""
        score = 0.0
        reasons = []
        
        # GNN-based infrastructure score (Phase 6)
        gnn_result = {
            'gnn_score': 0.0,
            'cluster_probability': 0.0,
            'campaign_id': None,
            'is_zero_day': False,
            'gnn_available': GNN_AVAILABLE and gnn_engine is not None
        }
        
        # Get database for zero-day detection
        db = None
        if threat_scheduler:
            db = threat_scheduler.db
        
        # 1. GNN Infrastructure Analysis (Phase 6 - NEW!)
        if gnn_engine:
            try:
                gnn_result = gnn_engine.check_domain(domain, db)
                
                gnn_score = gnn_result.get('gnn_score', 0.0)
                cluster_prob = gnn_result.get('cluster_probability', 0.0)
                
                if gnn_score > 0.5:
                    score += gnn_score * 0.35  # 35% weight for GNN
                    reasons.append(f"GNN detected infrastructure risk: {gnn_score:.2f}")
                
                if cluster_prob > 0.5:
                    score += cluster_prob * 0.15  # 15% weight for cluster
                    reasons.append(f"Part of malicious cluster (prob: {cluster_prob:.2f})")
                
                # Zero-day detection
                if gnn_result.get('is_zero_day'):
                    zero_day = gnn_result.get('zero_day_details', {})
                    for indicator in zero_day.get('threat_indicators', []):
                        reasons.append(f"Zero-day: {indicator['type']} with {indicator['count']} malicious domains")
                
            except Exception as e:
                logger.error(f"GNN inference error: {e}")
        
        # 2. Check threat intelligence database
        threat_intel_score = 0.0
        if threat_scheduler and domain:
            intel_result = threat_scheduler.check_domain(domain)
            
            if intel_result.get('in_threat_db'):
                threat_intel_score = intel_result.get('risk_score', 0.0)
                reasons.append(f"Domain found in threat database (risk: {threat_intel_score:.2f})")
                score += threat_intel_score * 0.2  # 20% weight
            else:
                # Check infrastructure risk from graph
                infra_risk = intel_result.get('infrastructure_risk', {})
                infra_score = infra_risk.get('infrastructure_score', 0.0)
                
                if infra_score > 0.3:
                    threat_intel_score = infra_score
                    score += infra_score * 0.1  # 10% weight
                    
                    for factor in infra_risk.get('risk_factors', []):
                        reasons.append(factor)
        
        # 2. Content-based analysis (NLP/keywords)
        suspicious_keywords = data.get('suspicious_keywords_found', [])
        if suspicious_keywords:
            keyword_score = min(len(suspicious_keywords) * 0.15, 0.3)
            score += keyword_score
            reasons.append(f"Found suspicious keywords: {', '.join(suspicious_keywords[:3])}")
        
        # 3. URL-based analysis
        if data.get('long_url'):
            score += 0.1
            reasons.append('URL is unusually long')
        
        if data.get('excessive_subdomains'):
            score += 0.08
            reasons.append(f"Excessive subdomains: {data.get('subdomain_count', 0)}")
        
        if data.get('suspicious_url_keywords'):
            score += 0.07
            reasons.append('Suspicious keywords in URL')
        
        # 4. DOM-based analysis
        if data.get('password_fields', 0) > 0:
            score += 0.1
            reasons.append('Page contains password input fields')
        
        if data.get('external_links', 0) > 5:
            score += 0.1
            reasons.append(f"High number of external links: {data.get('external_links')}")
        
        if data.get('hidden_inputs', 0) > 2:
            score += 0.08
            reasons.append(f"Multiple hidden inputs: {data.get('hidden_inputs')}")
        
        if data.get('iframe_count', 0) > 0:
            score += 0.06
            reasons.append(f"Page contains {data.get('iframe_count')} iframe(s)")
        
        # 5. Local AI result (if provided)
        if data.get('local_result'):
            local_risk = data['local_result'].get('local_risk', 'LOW')
            local_conf = data['local_result'].get('local_confidence', 0.0)
            
            if local_risk == 'HIGH':
                score += 0.2
            elif local_risk == 'MEDIUM':
                score += 0.1
        
        # Normalize score
        score = min(score, 1.0)
        
        # Determine risk level
        if score >= 0.7:
            risk = 'HIGH'
            confidence = score
        elif score >= 0.4:
            risk = 'MEDIUM'
            confidence = score
        else:
            risk = 'LOW'
            confidence = 1 - score
        
        return {
            'risk': risk,
            'confidence': round(confidence, 2),
            'reasons': reasons[:10],  # Limit to 10 reasons
            'threat_intel_score': round(threat_intel_score, 2) if threat_intel_score else 0.0,
            'total_score': round(score, 2),
            # Phase 6 GNN results
            'infra_gnn_score': round(gnn_result.get('gnn_score', 0.0), 2),
            'cluster_probability': round(gnn_result.get('cluster_probability', 0.0), 2),
            'campaign_id': gnn_result.get('campaign_id'),
            'is_zero_day': gnn_result.get('is_zero_day', False),
            'gnn_enabled': gnn_result.get('gnn_available', False)
        }
    
    def log_message(self, format, *args):
        """Override to use custom logging"""
        pass  # Suppress default HTTP logs


def run_server(port=8000):
    """Run the API server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, PhishGuardAPIHandler)
    
    logger.info(f"🛡️  PhishGuard Enhanced API Server")
    logger.info(f"   Running on http://localhost:{port}")
    logger.info(f"   Threat Intelligence: {'Enabled' if threat_scheduler else 'Disabled'}")
    logger.info(f"   Endpoints:")
    logger.info(f"     POST /scan - Analyze page/email/message")
    logger.info(f"     POST /feedback - Log user feedback")
    logger.info(f"     GET /status - Server status")
    logger.info(f"     GET /threat-cache - Threat intelligence cache")
    logger.info(f"\n   Waiting for requests...\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("\nShutting down server...")
        httpd.shutdown()


if __name__ == '__main__':
    run_server(8000)
