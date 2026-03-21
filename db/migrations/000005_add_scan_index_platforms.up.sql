ALTER TABLE sbom_indexes
ADD COLUMN IF NOT EXISTS platform TEXT;

ALTER TABLE vulnerability_indexes
ADD COLUMN IF NOT EXISTS platform TEXT;
