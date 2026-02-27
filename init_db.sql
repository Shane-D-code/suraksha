-- Create database schema for Threat Intelligence Platform

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(64) UNIQUE NOT NULL,
    input_hash VARCHAR(64) NOT NULL,
    text TEXT,
    url VARCHAR(2048),
    html TEXT,
    risk VARCHAR(20) NOT NULL CHECK (risk IN ('LOW', 'MEDIUM', 'HIGH')),
    confidence FLOAT NOT NULL,
    graph_score FLOAT NOT NULL,
    model_score FLOAT NOT NULL,
    reasons JSONB DEFAULT '[]'::jsonb,
    meta JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_input_hash ON scans(input_hash);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk);

-- Feedback table
CREATE TABLE IF NOT EXISTS feedback (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(64) NOT NULL REFERENCES scans(scan_id),
    user_flag BOOLEAN NOT NULL,
    corrected_label VARCHAR(32),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feedback_scan_id ON feedback(scan_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback(created_at);

-- Domains table
CREATE TABLE IF NOT EXISTS domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(512) UNIQUE NOT NULL,
    risk_score FLOAT DEFAULT 0.0,
    is_malicious BOOLEAN DEFAULT FALSE,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    registration_date TIMESTAMP,
    tags JSONB DEFAULT '[]'::jsonb,
    meta JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);
CREATE INDEX IF NOT EXISTS idx_domains_risk_score ON domains(risk_score DESC);

-- Relations table
CREATE TABLE IF NOT EXISTS relations (
    id SERIAL PRIMARY KEY,
    source_domain_id INTEGER NOT NULL REFERENCES domains(id),
    target_domain_id INTEGER REFERENCES domains(id),
    target_ip VARCHAR(45),
    relation_type VARCHAR(64) NOT NULL,
    meta JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_relations_source ON relations(source_domain_id);
CREATE INDEX IF NOT EXISTS idx_relations_target ON relations(target_domain_id);
CREATE INDEX IF NOT EXISTS idx_relations_type ON relations(relation_type);
CREATE INDEX IF NOT EXISTS idx_relations_ip ON relations(target_ip);

-- Model metadata table
CREATE TABLE IF NOT EXISTS model_metadata (
    id SERIAL PRIMARY KEY,
    model_name VARCHAR(128) UNIQUE NOT NULL,
    model_version VARCHAR(64) NOT NULL,
    accuracy FLOAT,
    precision FLOAT,
    recall FLOAT,
    f1_score FLOAT,
    training_data_size INTEGER,
    last_training_date TIMESTAMP,
    last_retrain_date TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_model_metadata_name ON model_metadata(model_name);

-- Threat feeds table
CREATE TABLE IF NOT EXISTS threat_feeds (
    id SERIAL PRIMARY KEY,
    feed_name VARCHAR(128) UNIQUE NOT NULL,
    feed_url VARCHAR(2048) NOT NULL,
    feed_type VARCHAR(64) NOT NULL,
    fetch_interval_hours INTEGER DEFAULT 24,
    last_fetch TIMESTAMP,
    next_fetch TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_feeds_name ON threat_feeds(feed_name);
CREATE INDEX IF NOT EXISTS idx_threat_feeds_active ON threat_feeds(is_active);

-- Insert initial model metadata
INSERT INTO model_metadata (model_name, model_version, is_active)
VALUES ('phishing_detector_v1', '1.0.0', TRUE)
ON CONFLICT (model_name) DO NOTHING;

-- Insert sample threat feeds
INSERT INTO threat_feeds (feed_name, feed_url, feed_type, is_active)
VALUES 
    ('PhishTank', 'https://data.phishtank.com/data/online-valid.json', 'PHISHING', TRUE),
    ('OpenPhish', 'https://openphish.com/feed.txt', 'PHISHING', TRUE)
ON CONFLICT (feed_name) DO NOTHING;
