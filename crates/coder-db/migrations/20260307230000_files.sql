-- File storage for template versions and other binary uploads.

CREATE TABLE files (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hash        VARCHAR(64)   NOT NULL,
    created_by  UUID          NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    mimetype    VARCHAR(255)  NOT NULL DEFAULT 'application/x-tar',
    data        BYTEA         NOT NULL,
    UNIQUE (hash, created_by)
);

CREATE INDEX idx_files_hash_created_by ON files (hash, created_by);
