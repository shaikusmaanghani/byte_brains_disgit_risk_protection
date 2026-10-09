-- SentinelShield Enterprise PostgreSQL & SQLite Schema
-- Digital Risk Protection Platform

CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'analyst', -- admin, analyst, viewer
    department VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brands (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    logo_url TEXT,
    official_website TEXT,
    company_description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS brand_aliases (
    id VARCHAR(64) PRIMARY KEY,
    brand_id VARCHAR(64) REFERENCES brands(id) ON DELETE CASCADE,
    alias_name VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS official_domains (
    id VARCHAR(64) PRIMARY KEY,
    brand_id VARCHAR(64) REFERENCES brands(id) ON DELETE CASCADE,
    domain_name VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS official_apps (
    id VARCHAR(64) PRIMARY KEY,
    brand_id VARCHAR(64) REFERENCES brands(id) ON DELETE CASCADE,
    app_name VARCHAR(255) NOT NULL,
    package_id VARCHAR(255) NOT NULL,
    platform VARCHAR(64) NOT NULL, -- google_play, apple_app_store
    developer VARCHAR(255) NOT NULL,
    publisher VARCHAR(255) NOT NULL,
    store_url TEXT,
    version VARCHAR(64),
    category VARCHAR(64),
    icon_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS official_social_accounts (
    id VARCHAR(64) PRIMARY KEY,
    brand_id VARCHAR(64) REFERENCES brands(id) ON DELETE CASCADE,
    platform VARCHAR(64) NOT NULL,
    handle VARCHAR(255) NOT NULL,
    profile_name VARCHAR(255) NOT NULL,
    profile_url TEXT,
    verified BOOLEAN DEFAULT FALSE,
    avatar_url TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(64) PRIMARY KEY,
    brand_id VARCHAR(64) REFERENCES brands(id) ON DELETE CASCADE,
    asset_type VARCHAR(64) NOT NULL, -- mobile_application, social_profile
    platform VARCHAR(64) NOT NULL,
    candidate_name VARCHAR(255) NOT NULL,
    identifier VARCHAR(255) NOT NULL,
    url TEXT,
    publisher_or_developer VARCHAR(255),
    description_snippet TEXT,
    risk_score INTEGER NOT NULL,
    risk_level VARCHAR(32) NOT NULL, -- critical, high, medium, low, informational
    classification VARCHAR(64) NOT NULL,
    confidence NUMERIC(4, 2) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'new', -- new, investigating, confirmed_threat, false_positive, resolved, dismissed
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_analyst VARCHAR(255),
    recommended_action TEXT,
    summary_explanation TEXT,
    candidate_payload JSONB,
    is_simulated BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS detection_signals (
    id VARCHAR(64) PRIMARY KEY,
    finding_id VARCHAR(64) REFERENCES findings(id) ON DELETE CASCADE,
    signal_type VARCHAR(64) NOT NULL,
    score INTEGER NOT NULL,
    weight INTEGER NOT NULL,
    explanation TEXT NOT NULL,
    evidence_snippet TEXT,
    highlight_details JSONB
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id VARCHAR(64) PRIMARY KEY,
    finding_id VARCHAR(64) REFERENCES findings(id) ON DELETE CASCADE,
    author_name VARCHAR(255) NOT NULL,
    author_email VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    action_taken VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS monitoring_sources (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(64) NOT NULL,
    platform VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'connected',
    last_sync TIMESTAMP WITH TIME ZONE,
    records_scanned INTEGER DEFAULT 0,
    threats_detected INTEGER DEFAULT 0,
    sync_interval_hours INTEGER DEFAULT 4
);

CREATE TABLE IF NOT EXISTS watchlists (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    pattern TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'high',
    enabled BOOLEAN DEFAULT TRUE,
    hits_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_platform ON findings(platform);
