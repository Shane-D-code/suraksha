"""
Script to setup database schema for Person 3
Run: python setup_db.py
"""
import asyncio
import asyncpg
import sys

SCHEMA_SQL = """
-- Graph node table (replaces nodes.csv)
CREATE TABLE IF NOT EXISTS graph_nodes (
    domain              TEXT PRIMARY KEY,
    node_type           TEXT DEFAULT 'domain',
    ip                  TEXT,
    ssl_fingerprint     TEXT,
    registrar           TEXT,
    asn                 TEXT,
    gnn_score           FLOAT DEFAULT 0.0,
    risk_label          TEXT DEFAULT 'UNKNOWN',
    embedding           BYTEA,
    first_seen          TIMESTAMPTZ DEFAULT NOW(),
    last_seen           TIMESTAMPTZ DEFAULT NOW()
);

-- Graph edge table (replaces edges.csv)
CREATE TABLE IF NOT EXISTS graph_edges (
    id              SERIAL PRIMARY KEY,
    source          TEXT NOT NULL,
    target          TEXT NOT NULL,
    relation_type   TEXT NOT NULL,
    weight          FLOAT DEFAULT 1.0,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (source, target, relation_type)
);

-- Domain intelligence table (WHOIS, ASN, DNS, SSL)
CREATE TABLE IF NOT EXISTS domain_intelligence (
    domain              TEXT PRIMARY KEY,
    domain_age_days     INTEGER,
    expiry_days         INTEGER,
    registrar           TEXT,
    registrant_country  TEXT,
    whois_privacy       BOOLEAN DEFAULT FALSE,
    asn                 TEXT,
    asn_org             TEXT,
    ssl_issuer          TEXT,
    ssl_valid           BOOLEAN DEFAULT FALSE,
    ssl_expiry_days     INTEGER,
    dns_ttl             INTEGER,
    has_mx              BOOLEAN DEFAULT FALSE,
    nameservers         JSONB DEFAULT '[]',
    risk_score          FLOAT DEFAULT 0.0,
    risk_reasons        JSONB DEFAULT '[]',
    is_established      BOOLEAN DEFAULT FALSE,
    collected_at        TIMESTAMPTZ DEFAULT NOW()
);

-- Campaigns table
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id         TEXT PRIMARY KEY,
    domain_count        INTEGER DEFAULT 0,
    domains             JSONB DEFAULT '[]',
    shared_ips          JSONB DEFAULT '[]',
    shared_certs         JSONB DEFAULT '[]',
    risk_level          TEXT DEFAULT 'UNKNOWN',
    avg_risk_score      FLOAT DEFAULT 0.0,
    detection_method    TEXT,
    first_seen          TIMESTAMPTZ DEFAULT NOW(),
    last_seen           TIMESTAMPTZ DEFAULT NOW()
);

-- Domain → campaign mapping
CREATE TABLE IF NOT EXISTS domain_campaign_map (
    domain          TEXT PRIMARY KEY,
    campaign_id     TEXT REFERENCES campaigns(campaign_id),
    added_at        TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for fast lookup
CREATE INDEX IF NOT EXISTS idx_graph_nodes_ip ON graph_nodes(ip);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_ssl ON graph_nodes(ssl_fingerprint);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_risk ON graph_nodes(risk_label);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target);
CREATE INDEX IF NOT EXISTS idx_domain_intel_risk ON domain_intelligence(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_domain_campaign_map ON domain_campaign_map(campaign_id);
"""


async def setup_database():
    """Create the database schema."""
    print("Connecting to PostgreSQL...")
    
    try:
        conn = await asyncpg.connect(
            host='localhost',
            port=5432,
            user='postgres',
            password='your-secret-key-change-in-production',
            database='threat_intel'
        )
        print("Connected successfully!")
        
        # Execute schema creation
        print("Creating tables...")
        await conn.execute(SCHEMA_SQL)
        print("Tables created successfully!")
        
        # Check existing tables
        tables = await conn.fetch("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        
        print("\nExisting tables:")
        for t in tables:
            print(f"  - {t['table_name']}")
        
        await conn.close()
        print("\nDatabase setup complete!")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(setup_database())
