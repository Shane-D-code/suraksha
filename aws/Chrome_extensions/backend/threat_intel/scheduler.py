"""
PhishGuard Threat Intelligence Scheduler
Automated threat feed synchronization and graph updates
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict
import time

from feeds import ThreatFeedAggregator, ThreatEnricher, CustomFeed
from database import ThreatDatabase
from graph_engine import InfrastructureGraph

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatIntelligenceScheduler:
    """Manages automated threat intelligence updates"""
    
    def __init__(self, 
                 db_path: str = 'threat_intel.db',
                 sync_interval_minutes: int = 30):
        self.db = ThreatDatabase(db_path)
        self.graph = InfrastructureGraph()
        self.aggregator = ThreatFeedAggregator()
        self.sync_interval = sync_interval_minutes * 60  # Convert to seconds
        self.is_running = False
        self.last_sync = None
        self.sync_count = 0
        
    def add_feed(self, feed):
        """Add a threat feed source"""
        self.aggregator.add_feed(feed)
    
    async def sync_threats(self) -> Dict:
        """Fetch and sync threat intelligence"""
        start_time = time.time()
        logger.info("Starting threat intelligence sync...")
        
        try:
            # Fetch threats from all feeds
            threats = await self.aggregator.fetch_all()
            
            if not threats:
                logger.warning("No threats fetched")
                return {
                    'success': False,
                    'threats_processed': 0,
                    'duration': time.time() - start_time
                }
            
            # Enrich threats
            enriched_threats = []
            for threat in threats:
                enriched = await ThreatEnricher.enrich_threat(threat)
                enriched_threats.append(enriched)
            
            # Store in database
            domains_added = 0
            domains_updated = 0
            
            for threat in enriched_threats:
                # Insert domain
                domain_id = self.db.insert_domain({
                    'domain': threat['domain'],
                    'domain_hash': threat.get('domain_hash'),
                    'tld': threat.get('tld'),
                    'subdomain_count': threat.get('subdomain_count', 0),
                    'risk_score': 0.8,  # Default risk for threat feed domains
                    'confidence': threat.get('confidence', 0.8),
                    'first_seen': threat.get('first_seen')
                })
                
                if domain_id:
                    domains_added += 1
                else:
                    domains_updated += 1
                
                # Insert source
                source_id = self.db.insert_source(
                    threat['source'],
                    threat.get('confidence', 0.8)
                )
                
                # Link domain to source
                self.db.link_domain_source(domain_id, source_id)
                
                # Add to graph
                self.graph.add_domain(
                    threat['domain'],
                    risk_score=0.8,
                    source=threat['source'],
                    first_seen=threat.get('first_seen')
                )
                
                # Add IP if available
                if threat.get('ip'):
                    ip_id = self.db.insert_ip(threat['ip'])
                    self.db.link_domain_ip(domain_id, ip_id)
                    
                    self.graph.add_ip(threat['ip'])
                    self.graph.link_domain_ip(threat['domain'], threat['ip'])
            
            # Detect campaigns
            campaigns = self.graph.detect_campaigns(min_cluster_size=5)
            logger.info(f"Detected {len(campaigns)} campaigns")
            
            # Update sync metadata
            self.last_sync = datetime.now()
            self.sync_count += 1
            
            duration = time.time() - start_time
            
            result = {
                'success': True,
                'threats_processed': len(enriched_threats),
                'domains_added': domains_added,
                'domains_updated': domains_updated,
                'campaigns_detected': len(campaigns),
                'duration': duration,
                'timestamp': self.last_sync.isoformat()
            }
            
            logger.info(f"Sync completed: {len(enriched_threats)} threats processed in {duration:.2f}s")
            return result
            
        except Exception as e:
            logger.error(f"Sync failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'duration': time.time() - start_time
            }
    
    async def run_continuous(self):
        """Run continuous threat intelligence sync"""
        self.is_running = True
        logger.info(f"Starting continuous sync (interval: {self.sync_interval}s)")
        
        while self.is_running:
            try:
                # Run sync
                result = await self.sync_threats()
                
                if result['success']:
                    logger.info(f"Sync #{self.sync_count} completed successfully")
                else:
                    logger.error(f"Sync #{self.sync_count} failed")
                
                # Wait for next sync
                logger.info(f"Next sync in {self.sync_interval}s")
                await asyncio.sleep(self.sync_interval)
                
            except Exception as e:
                logger.error(f"Scheduler error: {e}", exc_info=True)
                await asyncio.sleep(60)  # Wait 1 minute on error
    
    def stop(self):
        """Stop continuous sync"""
        self.is_running = False
        logger.info("Scheduler stopped")
    
    def get_status(self) -> Dict:
        """Get scheduler status"""
        db_stats = self.db.get_statistics()
        graph_stats = self.graph.get_graph_statistics()
        
        return {
            'is_running': self.is_running,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'sync_count': self.sync_count,
            'sync_interval_minutes': self.sync_interval / 60,
            'database': db_stats,
            'graph': graph_stats,
            'feeds': self.aggregator.get_feed_status()
        }
    
    def check_domain(self, domain: str) -> Dict:
        """Check domain against threat intelligence"""
        # Check database
        db_result = self.db.get_domain_by_name(domain)
        
        if db_result:
            # Domain is in threat database
            return {
                'in_threat_db': True,
                'risk_score': db_result['risk_score'],
                'confidence': db_result['confidence'],
                'first_seen': db_result['first_seen'],
                'last_seen': db_result['last_seen']
            }
        
        # Check infrastructure relationships
        infra_risk = self.graph.calculate_infrastructure_risk(domain)
        
        return {
            'in_threat_db': False,
            'infrastructure_risk': infra_risk
        }


# Example usage and testing
async def main():
    """Example scheduler usage"""
    scheduler = ThreatIntelligenceScheduler(
        db_path='threat_intel.db',
        sync_interval_minutes=30
    )
    
    # Add feeds
    scheduler.add_feed(CustomFeed('threat_feeds/custom_threats.txt'))
    # scheduler.add_feed(PhishTankFeed())
    # scheduler.add_feed(OpenPhishFeed())
    
    # Run single sync
    logger.info("Running single sync...")
    result = await scheduler.sync_threats()
    
    print("\nSync Result:")
    for key, value in result.items():
        print(f"  {key}: {value}")
    
    # Get status
    status = scheduler.get_status()
    print("\nScheduler Status:")
    print(f"  Last Sync: {status['last_sync']}")
    print(f"  Sync Count: {status['sync_count']}")
    print(f"  Database:")
    for key, value in status['database'].items():
        print(f"    {key}: {value}")
    print(f"  Graph:")
    for key, value in status['graph'].items():
        print(f"    {key}: {value}")
    
    # Check a domain
    test_domain = 'example-phishing.com'
    check_result = scheduler.check_domain(test_domain)
    print(f"\nDomain Check ({test_domain}):")
    for key, value in check_result.items():
        print(f"  {key}: {value}")
    
    # For continuous sync (commented out for demo)
    # await scheduler.run_continuous()


if __name__ == '__main__':
    asyncio.run(main())
