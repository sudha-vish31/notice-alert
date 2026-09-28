-- Run this once against compliance_radar, AFTER migration_outstanding_demand.sql.
-- Fixes notices that were created with category='demand' (a bug) instead of
-- 'outstanding_demand', which is what the app actually filters on.

UPDATE notices SET category = 'outstanding_demand' WHERE category = 'demand';