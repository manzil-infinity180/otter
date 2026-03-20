ALTER TABLE scan_artifacts
    ADD COLUMN IF NOT EXISTS metadata JSONB;
