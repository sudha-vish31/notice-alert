-- Run this once against compliance_radar.
-- Safe to re-run.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- One connected mailbox per firm (can extend to per-assessee later).
CREATE TABLE IF NOT EXISTS email_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID REFERENCES companies(id),
  imap_host VARCHAR(255) NOT NULL,
  imap_port INT NOT NULL DEFAULT 993,
  email_address VARCHAR(255) NOT NULL,
  encrypted_app_password TEXT NOT NULL,
  last_uid_seen INT DEFAULT 0,
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

-- FR-4.4: notices that arrived by email but couldn't be matched to a PAN/TAN
-- already in the system — sit here for manual review instead of being dropped.
CREATE TABLE IF NOT EXISTS unmatched_notices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID REFERENCES companies(id),
  email_account_id UUID REFERENCES email_accounts(id),
  sender VARCHAR(255),
  subject TEXT,
  body_snippet TEXT,
  received_at TIMESTAMP,
  extracted_pan VARCHAR(20),
  status VARCHAR(20) DEFAULT 'Pending',
  created_at TIMESTAMP DEFAULT NOW()
);

-- FR-4.5 (dedupe) + FR-4.6 (light audit trail — subject/sender, not full raw MIME)
ALTER TABLE notices ADD COLUMN IF NOT EXISTS source_email_uid INT;
ALTER TABLE notices ADD COLUMN IF NOT EXISTS source_email_account_id UUID;
ALTER TABLE notices ADD COLUMN IF NOT EXISTS source_email_subject TEXT;
ALTER TABLE notices ADD COLUMN IF NOT EXISTS source_email_sender VARCHAR(255);