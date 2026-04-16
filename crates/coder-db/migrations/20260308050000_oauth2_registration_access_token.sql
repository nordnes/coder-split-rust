-- Add registration_access_token column (BYTEA) for RFC 7592 client management.
-- Stores the SHA-256 hash of the registration access token generated during
-- dynamic client registration (RFC 7591).
ALTER TABLE oauth2_provider_apps
    ADD COLUMN IF NOT EXISTS registration_access_token BYTEA;
