CREATE TABLE IF NOT EXISTS scan_artifacts (
    key TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    image_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    content_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_artifacts_org_image
    ON scan_artifacts (org_id, image_id, artifact_type);

CREATE INDEX IF NOT EXISTS idx_scan_artifacts_created_at
    ON scan_artifacts (created_at DESC);
