ALTER TABLE sbom_indexes
    ADD COLUMN IF NOT EXISTS repository_key TEXT;

UPDATE sbom_indexes
SET repository_key = CASE
    WHEN btrim(image_name) = '' THEN NULL
    ELSE CASE
        WHEN strpos(regexp_replace(image_name, '(@sha256:[A-Fa-f0-9]+|:[^/@]+)$', ''), '/') = 0
            THEN 'index.docker.io/library/' || regexp_replace(image_name, '(@sha256:[A-Fa-f0-9]+|:[^/@]+)$', '')
        WHEN split_part(regexp_replace(image_name, '(@sha256:[A-Fa-f0-9]+|:[^/@]+)$', ''), '/', 1) = 'localhost'
            OR split_part(regexp_replace(image_name, '(@sha256:[A-Fa-f0-9]+|:[^/@]+)$', ''), '/', 1) ~ '[.:]'
            THEN regexp_replace(image_name, '(@sha256:[A-Fa-f0-9]+|:[^/@]+)$', '')
        ELSE 'index.docker.io/' || regexp_replace(image_name, '(@sha256:[A-Fa-f0-9]+|:[^/@]+)$', '')
    END
END
WHERE repository_key IS NULL;

CREATE INDEX IF NOT EXISTS idx_sbom_indexes_repository_key_updated_at
    ON sbom_indexes (repository_key, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_sbom_indexes_org_repository_key_updated_at
    ON sbom_indexes (org_id, repository_key, updated_at DESC);
