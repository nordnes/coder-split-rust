-- OAuth2 consent screen (W4.38).
--
-- Adds `first_party` flag to `oauth2_provider_apps` so the authorize flow
-- can distinguish trusted internal clients (auto-approve) from third-party
-- clients that must prompt the user on first use.
--
-- Adds `oauth2_provider_app_user_approvals` to remember approvals per
-- (user_id, app_id) so subsequent authorize requests skip the consent page.
--
-- Also adds `oauth2_provider_app_pending_consents` for the short-lived
-- nonce that ties a consent POST to the authorize parameters the user
-- agreed to.

ALTER TABLE oauth2_provider_apps
    ADD COLUMN IF NOT EXISTS first_party BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS oauth2_provider_app_user_approvals (
    app_id     UUID NOT NULL REFERENCES oauth2_provider_apps(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id)                ON DELETE CASCADE,
    scope      TEXT NOT NULL DEFAULT '',
    approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (app_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth2_provider_app_user_approvals_user
    ON oauth2_provider_app_user_approvals (user_id);

CREATE TABLE IF NOT EXISTS oauth2_provider_app_pending_consents (
    nonce      UUID PRIMARY KEY,
    app_id     UUID NOT NULL REFERENCES oauth2_provider_apps(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id)                ON DELETE CASCADE,
    state      TEXT NOT NULL DEFAULT '',
    resource   TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth2_pending_consents_expires
    ON oauth2_provider_app_pending_consents (expires_at);
