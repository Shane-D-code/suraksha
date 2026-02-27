"""
PhishGuard Threat Intelligence Database
Structured storage for threat data and infrastructure relationships
"""

import sqlite3
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatDatabase:
    """Threat intelligence database manager"""
    
    def __init__(self, db_path: str = 'threat_intel.db'):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Domains table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    domain_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_name TEXT UNIQUE NOT NULL,
                    domain_hash TEXT,
                    tld TEXT,
                    subdomain_count INTEGER,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    risk_score REAL DEFAULT 0.0,
                    confidence REAL DEFAULT 0.0,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # IPs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ips (
                    ip_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    risk_score REAL DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # SSL Certificates table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS certificates (
                    cert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssl_fingerprint TEXT UNIQUE NOT NULL,
                    issuer TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Domain-IP relationships
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domain_ip_relations (
                    relation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    ip_id INTEGER,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    FOREIGN KEY (domain_id) REFERENCES domains(domain_id),
                    FOREIGN KEY (ip_id) REFERENCES ips(ip_id),
                    UNIQUE(domain_id, ip_id)
                )
            ''')
            
            # Domain-Certificate relationships
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domain_cert_relations (
                    relation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    cert_id INTEGER,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    FOREIGN KEY (domain_id) REFERENCES domains(domain_id),
                    FOREIGN KEY (cert_id) REFERENCES certificates(cert_id),
                    UNIQUE(domain_id, cert_id)
                )
            ''')
            
            # Threat sources
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_sources (
                    source_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT UNIQUE NOT NULL,
                    confidence_level REAL,
                    last_update TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Domain-Source relationships
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domain_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    source_id INTEGER,
                    reported_at TIMESTAMP,
                    FOREIGN KEY (domain_id) REFERENCES domains(domain_id),
                    FOREIGN KEY (source_id) REFERENCES threat_sources(source_id)
                )
            ''')
            
            # Campaigns table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_name TEXT,
                    cluster_size INTEGER,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    risk_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Domain-Campaign relationships
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domain_campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    campaign_id INTEGER,
                    FOREIGN KEY (domain_id) REFERENCES domains(domain_id),
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id),
                    UNIQUE(domain_id, campaign_id)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain_name ON domains(domain_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain_hash ON domains(domain_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_address ON ips(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ssl_fingerprint ON certificates(ssl_fingerprint)')
            
            logger.info("Database initialized successfully")
    
    def insert_domain(self, domain_data: Dict) -> int:
        """Insert or update domain"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if domain exists
            cursor.execute('SELECT domain_id FROM domains WHERE domain_name = ?', 
                          (domain_data['domain'],))
            existing = cursor.fetchone()
            
            if existing:
                # Update last_seen and risk_score
                cursor.execute('''
                    UPDATE domains 
                    SET last_seen = ?, risk_score = ?, confidence = ?
                    WHERE domain_id = ?
                ''', (
                    datetime.now(),
                    domain_data.get('risk_score', 0.0),
                    domain_data.get('confidence', 0.0),
                    existing['domain_id']
                ))
                return existing['domain_id']
            else:
                # Insert new domain
                cursor.execute('''
                    INSERT INTO domains (
                        domain_name, domain_hash, tld, subdomain_count,
                        first_seen, last_seen, risk_score, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    domain_data['domain'],
                    domain_data.get('domain_hash'),
                    domain_data.get('tld'),
                    domain_data.get('subdomain_count', 0),
                    domain_data.get('first_seen', datetime.now()),
                    datetime.now(),
                    domain_data.get('risk_score', 0.0),
                    domain_data.get('confidence', 0.0)
                ))
                return cursor.lastrowid
    
    def insert_source(self, source_name: str, confidence: float) -> int:
        """Insert or update threat source"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT source_id FROM threat_sources WHERE source_name = ?', 
                          (source_name,))
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute('''
                    UPDATE threat_sources 
                    SET last_update = ?, confidence_level = ?
                    WHERE source_id = ?
                ''', (datetime.now(), confidence, existing['source_id']))
                return existing['source_id']
            else:
                cursor.execute('''
                    INSERT INTO threat_sources (source_name, confidence_level, last_update)
                    VALUES (?, ?, ?)
                ''', (source_name, confidence, datetime.now()))
                return cursor.lastrowid
    
    def link_domain_source(self, domain_id: int, source_id: int):
        """Link domain to threat source"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO domain_sources (domain_id, source_id, reported_at)
                VALUES (?, ?, ?)
            ''', (domain_id, source_id, datetime.now()))
    
    def insert_ip(self, ip_address: str) -> int:
        """Insert or update IP"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT ip_id FROM ips WHERE ip_address = ?', (ip_address,))
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute('UPDATE ips SET last_seen = ? WHERE ip_id = ?',
                             (datetime.now(), existing['ip_id']))
                return existing['ip_id']
            else:
                cursor.execute('''
                    INSERT INTO ips (ip_address, first_seen, last_seen)
                    VALUES (?, ?, ?)
                ''', (ip_address, datetime.now(), datetime.now()))
                return cursor.lastrowid
    
    def link_domain_ip(self, domain_id: int, ip_id: int):
        """Link domain to IP"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO domain_ip_relations 
                (domain_id, ip_id, first_seen, last_seen)
                VALUES (?, ?, COALESCE((SELECT first_seen FROM domain_ip_relations 
                        WHERE domain_id = ? AND ip_id = ?), ?), ?)
            ''', (domain_id, ip_id, domain_id, ip_id, datetime.now(), datetime.now()))
    
    def get_domain_by_name(self, domain_name: str) -> Optional[Dict]:
        """Get domain information"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM domains WHERE domain_name = ?', (domain_name,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_domains_by_ip(self, ip_address: str) -> List[Dict]:
        """Get all domains sharing an IP"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT d.* FROM domains d
                JOIN domain_ip_relations dir ON d.domain_id = dir.domain_id
                JOIN ips i ON dir.ip_id = i.ip_id
                WHERE i.ip_address = ?
            ''', (ip_address,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_related_domains(self, domain_name: str) -> Dict:
        """Get domains related through infrastructure"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get domain ID
            cursor.execute('SELECT domain_id FROM domains WHERE domain_name = ?', (domain_name,))
            domain_row = cursor.fetchone()
            if not domain_row:
                return {'ip_related': [], 'cert_related': []}
            
            domain_id = domain_row['domain_id']
            
            # Get IP-related domains
            cursor.execute('''
                SELECT DISTINCT d.domain_name, d.risk_score
                FROM domains d
                JOIN domain_ip_relations dir1 ON d.domain_id = dir1.domain_id
                WHERE dir1.ip_id IN (
                    SELECT ip_id FROM domain_ip_relations WHERE domain_id = ?
                ) AND d.domain_id != ?
            ''', (domain_id, domain_id))
            ip_related = [dict(row) for row in cursor.fetchall()]
            
            # Get cert-related domains
            cursor.execute('''
                SELECT DISTINCT d.domain_name, d.risk_score
                FROM domains d
                JOIN domain_cert_relations dcr1 ON d.domain_id = dcr1.domain_id
                WHERE dcr1.cert_id IN (
                    SELECT cert_id FROM domain_cert_relations WHERE domain_id = ?
                ) AND d.domain_id != ?
            ''', (domain_id, domain_id))
            cert_related = [dict(row) for row in cursor.fetchall()]
            
            return {
                'ip_related': ip_related,
                'cert_related': cert_related
            }
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            cursor.execute('SELECT COUNT(*) as count FROM domains WHERE is_active = 1')
            stats['total_domains'] = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM ips')
            stats['total_ips'] = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM certificates')
            stats['total_certificates'] = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM campaigns')
            stats['total_campaigns'] = cursor.fetchone()['count']
            
            cursor.execute('SELECT AVG(risk_score) as avg FROM domains WHERE is_active = 1')
            stats['avg_risk_score'] = cursor.fetchone()['avg'] or 0.0
            
            return stats


# Example usage
if __name__ == '__main__':
    db = ThreatDatabase('test_threat_intel.db')
    
    # Insert test data
    domain_id = db.insert_domain({
        'domain': 'malicious-site.com',
        'domain_hash': 'abc123',
        'tld': 'com',
        'subdomain_count': 0,
        'risk_score': 0.9,
        'confidence': 0.85
    })
    
    source_id = db.insert_source('PhishTank', 0.9)
    db.link_domain_source(domain_id, source_id)
    
    # Get statistics
    stats = db.get_statistics()
    print("Database Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
