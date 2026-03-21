DROP INDEX IF EXISTS idx_sbom_indexes_org_repository_key_updated_at;
DROP INDEX IF EXISTS idx_sbom_indexes_repository_key_updated_at;

ALTER TABLE sbom_indexes
    DROP COLUMN IF EXISTS repository_key;
