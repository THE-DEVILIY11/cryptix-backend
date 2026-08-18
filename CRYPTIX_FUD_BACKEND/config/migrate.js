require('dotenv').config();
const {
  pool
} = require('./db');

const schema = `
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(100) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) DEFAULT '',
  license_key VARCHAR(50) UNIQUE,
  plan VARCHAR(50) DEFAULT 'basic',
  status VARCHAR(20) DEFAULT 'active',
  storage_used BIGINT DEFAULT 0,
  total_crypts INTEGER DEFAULT 0,
  last_login TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Licenses table
CREATE TABLE IF NOT EXISTS licenses (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  license_key VARCHAR(50) UNIQUE NOT NULL,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  plan VARCHAR(50) NOT NULL,
  duration_days INTEGER NOT NULL DEFAULT 90,
  status VARCHAR(20) DEFAULT 'active',
  activated_at TIMESTAMP WITH TIME ZONE,
  expires_at TIMESTAMP WITH TIME ZONE,
  created_by UUID,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Files table
CREATE TABLE IF NOT EXISTS files (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name VARCHAR(500) NOT NULL,
  crypted_name VARCHAR(500),
  file_size BIGINT NOT NULL DEFAULT 0,
  method VARCHAR(50) DEFAULT 'hybrid',
  status VARCHAR(20) DEFAULT 'pending',
  detections INTEGER DEFAULT 0,
  fud_rate DECIMAL(5,2) DEFAULT 0,
  storage_path VARCHAR(1000),
  original_hash VARCHAR(64),
  crypted_hash VARCHAR(64),
  download_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '30 days'),
  processed_at TIMESTAMP WITH TIME ZONE
);

-- Downloads log
CREATE TABLE IF NOT EXISTS downloads (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Activity log
CREATE TABLE IF NOT EXISTS activity (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  message TEXT NOT NULL,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Invoices
CREATE TABLE IF NOT EXISTS invoices (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invoice_number VARCHAR(50) UNIQUE NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  currency VARCHAR(3) DEFAULT 'USD',
  status VARCHAR(20) DEFAULT 'pending',
  stripe_id VARCHAR(255),
  plan VARCHAR(50),
  description TEXT,
  paid_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Sessions / tokens
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token VARCHAR(500) NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  is_active BOOLEAN DEFAULT true,
  expires_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_license ON users(license_key);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);
CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_user ON licenses(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_user ON activity(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity(created_at);
CREATE INDEX IF NOT EXISTS idx_downloads_file ON downloads(file_id);
CREATE INDEX IF NOT EXISTS idx_invoices_user ON invoices(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);

-- Insert demo admin user (password: admin123)
INSERT INTO users (username, email, password_hash, full_name, license_key, plan, status)
VALUES (
  'admin',
  'admin@cryptix.io',
  '$2a$10$8K1p/a0dL1LXMIgoEDFrwOfMQkfAjkMBcGmE0nQqGqF0qGqF0qGqF',
  'CRYPTIX Admin',
  'ADMIN-AAAAA-BBBBB-CCCCC',
  'enterprise',
  'active'
) ON CONFLICT (username) DO NOTHING;

-- Insert demo customer user (password: demo123)
INSERT INTO users (username, email, password_hash, full_name, license_key, plan, status)
VALUES (
  'demo',
  'demo@cryptix.io',
  '$2a$10$8K1p/a0dL1LXMIgoEDFrwOfMQkfAjkMBcGmE0nQqGqF0qGqF0qGqF',
  'Demo Customer',
  'DEMO1-AAAAA-BBBBB-CCCCC',
  'pro',
  'active'
) ON CONFLICT (username) DO NOTHING;

-- Insert demo license
INSERT INTO licenses (license_key, plan, duration_days, status, expires_at)
VALUES ('DEMO1-AAAAA-BBBBB-CCCCC', 'pro', 90, 'active', NOW() + INTERVAL '90 days')
ON CONFLICT (license_key) DO NOTHING;

INSERT INTO licenses (license_key, plan, duration_days, status, expires_at)
VALUES ('ADMIN-AAAAA-BBBBB-CCCCC', 'enterprise', 365, 'active', NOW() + INTERVAL '365 days')
ON CONFLICT (license_key) DO NOTHING;
`;

async function migrate() {
  console.log('[MIGRATE] Starting database migration...');
  try {
    await pool.query(schema);
    console.log('[MIGRATE] Schema created successfully');
    console.log('[MIGRATE] Demo users inserted (admin/admin123, demo/demo123)');
  } catch (err) {
    console.error('[MIGRATE] Error:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
    console.log('[MIGRATE] Done');
  }
}

migrate();
