CREATE TABLE IF NOT EXISTS sbom_indexes (
    org_id TEXT NOT NULL,
    image_id TEXT NOT NULL,
    image_name TEXT NOT NULL DEFAULT '',
    source_format TEXT NOT NULL,
    package_count INTEGER NOT NULL,
    packages JSONB NOT NULL,
    dependency_tree JSONB NOT NULL,
    dependency_roots JSONB NOT NULL DEFAULT '[]'::jsonb,
    license_summary JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, image_id)
);

CREATE INDEX IF NOT EXISTS idx_sbom_indexes_updated_at
    ON sbom_indexes (updated_at DESC);
