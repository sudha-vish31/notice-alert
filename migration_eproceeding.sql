-- Run this once against compliance_radar.
-- Safe to re-run.

ALTER TABLE notices ADD COLUMN IF NOT EXISTS priority_status VARCHAR(20) DEFAULT 'Normal';