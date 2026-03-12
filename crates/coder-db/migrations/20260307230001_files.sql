-- File storage for template versions and other binary uploads.

CREATE TABLE IF NOT EXISTS files (
    id          UUID PRIMARY KEY,
    hash        VARCHAR(64)   NOT NULL,
    created_by  UUID          NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    mimetype    VARCHAR(255)  NOT NULL DEFAULT 'application/x-tar',
    data        BYTEA         NOT NULL,
    UNIQUE (hash, created_by)
);
-- The UNIQUE (hash, created_by) constraint already creates a B-tree index;
-- no additional explicit index is needed.
