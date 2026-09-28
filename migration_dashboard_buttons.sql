-- Run this once against your compliance_radar database before restarting index.js
-- Safe to re-run: every statement is IF NOT EXISTS / idempotent.

-- Assessees: fields the Dashboard table + Add Assessee form need
ALTER TABLE assessees ADD COLUMN IF NOT EXISTS incorporation_date DATE;
ALTER TABLE assessees ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE;
ALTER TABLE assessees ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

-- Credentials: status tracking used by the Failed Logins stat card and mock sync
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS status VARCHAR(30) DEFAULT 'Active';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS last_validated_at TIMESTAMP;

-- Sync logs: what the mocked "Sync All" writes on every run
ALTER TABLE sync_logs ADD COLUMN IF NOT EXISTS portal VARCHAR(20);
ALTER TABLE sync_logs ADD COLUMN IF NOT EXISTS run_at TIMESTAMP DEFAULT NOW();
ALTER TABLE sync_logs ADD COLUMN IF NOT EXISTS result VARCHAR(20);
ALTER TABLE sync_logs ADD COLUMN IF NOT EXISTS failure_reason TEXT;

-- Notices: fields the e-Proceeding table/export already reference but the
-- backend never populated until now
ALTER TABLE notices ADD COLUMN IF NOT EXISTS notice_ref_id VARCHAR(50);
ALTER TABLE notices ADD COLUMN IF NOT EXISTS ay VARCHAR(10);
ALTER TABLE notices ADD COLUMN IF NOT EXISTS fy VARCHAR(10);
ALTER TABLE notices ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

-- Optional but recommended: stops duplicate PAN/TAN entries via Add Assessee.
-- Skip this line if you already have duplicate pan_tan rows in your data.
-- ALTER TABLE assessees ADD CONSTRAINT assessees_pan_tan_unique UNIQUE (pan_tan);
