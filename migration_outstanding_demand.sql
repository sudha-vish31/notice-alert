-- Run this once against compliance_radar.
-- Safe to re-run.

-- Lets notices be split between e-Proceeding and Outstanding Demand views.
-- Existing rows default to 'e_proceeding' so nothing already in e-Proceeding disappears.
ALTER TABLE notices ADD COLUMN IF NOT EXISTS category VARCHAR(30) DEFAULT 'e_proceeding';

-- The demand amount FR-7.2 requires showing.
ALTER TABLE notices ADD COLUMN IF NOT EXISTS demand_amount NUMERIC(12, 2);