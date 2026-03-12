-- Licenses table for enterprise license management.
-- Mirrors the Go schema from coderd/database/dump.sql.

CREATE TABLE IF NOT EXISTS licenses (
    id SERIAL PRIMARY KEY,
    uploaded_at TIMESTAMPTZ NOT NULL,
    jwt TEXT NOT NULL,
    exp TIMESTAMPTZ NOT NULL,
    uuid UUID NOT NULL DEFAULT gen_random_uuid()
);

-- The Go schema enforces uniqueness on the JWT column.
CREATE UNIQUE INDEX IF NOT EXISTS licenses_jwt_key ON licenses (jwt);
