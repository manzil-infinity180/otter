ALTER TABLE vulnerability_indexes
DROP COLUMN IF EXISTS platform;

ALTER TABLE sbom_indexes
DROP COLUMN IF EXISTS platform;
