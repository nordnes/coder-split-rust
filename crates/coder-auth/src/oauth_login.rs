//! OAuth2/OIDC login flows: GitHub callback, GitHub device flow, and OIDC callback.
//!
//! These functions implement the server-side of the OAuth authorization code grant
//! and device authorization flows used for user login (as opposed to the external-auth
//! flows which link third-party tokens to existing users).

use coder_core::config::{GithubOAuthConfig, OidcConfig};
use coder_core::{LoginType, StorageError, UserLinkClaims};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Errors that can occur during OAuth/OIDC login flows.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OAuthLoginError {
    /// The backing store returned an error.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The OAuth state parameter did not match the stored state cookie.
    #[error("OAuth state mismatch: {0}")]
    StateMismatch(String),
    /// The authorization code exchange failed.
    #[error("Code exchange failed: {0}")]
    CodeExchangeFailed(String),
    /// The user is not authorized to login (org/team restriction, email domain, etc.).
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    /// The OIDC ID token is invalid.
    #[error("Invalid ID token: {0}")]
    InvalidIdToken(String),
    /// A network or HTTP error occurred.
    #[error("HTTP error: {0}")]
    Http(String),
    /// An internal/unexpected error.
    #[error("Internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// GitHub API response types
// ---------------------------------------------------------------------------

/// GitHub user profile from `/user`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GithubUser {
    pub id: i64,
    pub login: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub avatar_url: String,
}

/// GitHub email from `/user/emails`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GithubEmail {
    pub email: String,
    #[serde(default)]
    pub primary: bool,
    #[serde(default)]
    pub verified: bool,
}

/// GitHub organization from `/user/orgs`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GithubOrganization {
    pub login: String,
}

/// GitHub team from `/user/teams`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GithubTeam {
    pub slug: String,
    pub organization: GithubTeamOrg,
}

/// Nested org inside a team response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GithubTeamOrg {
    pub login: String,
}

/// GitHub OAuth2 token exchange response.
#[derive(Clone, Debug, Deserialize)]
pub struct GithubTokenResponse {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub scope: String,
    /// GitHub may return HTTP 200 with an error field instead of a token.
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// GitHub device authorization response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GithubDeviceResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub expires_in: u64,
    #[serde(default)]
    pub interval: u64,
}

/// OIDC token endpoint response.
#[derive(Clone, Debug, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: String,
    pub id_token: String,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

/// Minimal OIDC discovery document fields we need.
#[derive(Clone, Debug, Deserialize)]
pub struct OidcDiscovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub issuer: String,
}

/// Claims extracted from an OIDC ID token.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OidcClaims {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    /// All raw claims for storage.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// GitHub OAuth2 helper functions
// ---------------------------------------------------------------------------

const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Derives the GitHub OAuth base URL from the configured `api_url`.
///
/// For `https://api.github.com` (the default), OAuth endpoints are on
/// `https://github.com`.  For GitHub Enterprise the API URL is typically
/// `https://<host>/api/v3`, and the OAuth endpoints live on `https://<host>`.
fn github_oauth_url(config: &GithubOAuthConfig, path: &str) -> String {
    let api = config.api_url.as_str().trim_end_matches('/');
    // Standard GitHub API → use github.com for OAuth
    if api == "https://api.github.com" {
        return format!("https://github.com{path}");
    }
    // GHE: strip the /api/v3 suffix (if present) to get the base host.
    // Note: trailing slashes are already stripped above, so "/api/v3/" is unreachable.
    let base = api.strip_suffix("/api/v3").unwrap_or(api);
    format!("{base}{path}")
}

/// Exchanges an authorization code for a GitHub access token.
#[tracing::instrument(skip(config, code))]
pub async fn github_exchange_code(
    client: &reqwest::Client,
    config: &GithubOAuthConfig,
    code: &str,
) -> Result<GithubTokenResponse, OAuthLoginError> {
    let response = client
        .post(github_oauth_url(config, "/login/oauth/access_token"))
        .header("Accept", "application/json")
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code", code),
        ])
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_owned());
        return Err(OAuthLoginError::CodeExchangeFailed(format!(
            "GitHub token endpoint returned {status}: {body}"
        )));
    }

    let token_response = response
        .json::<GithubTokenResponse>()
        .await
        .map_err(|e| OAuthLoginError::CodeExchangeFailed(e.to_string()))?;

    // GitHub may return HTTP 200 with an error field instead of a valid token.
    if let Some(ref err) = token_response.error {
        let detail = token_response
            .error_description
            .as_deref()
            .unwrap_or("unknown");
        return Err(OAuthLoginError::CodeExchangeFailed(format!(
            "GitHub token error: {err} — {detail}"
        )));
    }
    if token_response.access_token.is_empty() {
        return Err(OAuthLoginError::CodeExchangeFailed(
            "GitHub returned an empty access token".to_owned(),
        ));
    }

    Ok(token_response)
}

/// Fetches the authenticated GitHub user profile.
#[tracing::instrument(skip(access_token))]
pub async fn github_fetch_user(
    client: &reqwest::Client,
    api_url: &url::Url,
    access_token: &str,
) -> Result<GithubUser, OAuthLoginError> {
    let url = format!("{}/user", api_url.as_str().trim_end_matches('/'));
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Accept", "application/json")
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_owned());
        return Err(OAuthLoginError::Http(format!(
            "GitHub /user returned {status}: {body}"
        )));
    }
    response
        .json::<GithubUser>()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))
}

/// Fetches the authenticated GitHub user's verified emails.
#[tracing::instrument(skip(access_token))]
pub async fn github_fetch_emails(
    client: &reqwest::Client,
    api_url: &url::Url,
    access_token: &str,
) -> Result<Vec<GithubEmail>, OAuthLoginError> {
    let url = format!("{}/user/emails", api_url.as_str().trim_end_matches('/'));
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Accept", "application/json")
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_owned());
        return Err(OAuthLoginError::Http(format!(
            "GitHub /user/emails returned {status}: {body}"
        )));
    }
    response
        .json::<Vec<GithubEmail>>()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))
}

/// Fetches the authenticated GitHub user's organizations.
#[tracing::instrument(skip(access_token))]
pub async fn github_fetch_orgs(
    client: &reqwest::Client,
    api_url: &url::Url,
    access_token: &str,
) -> Result<Vec<GithubOrganization>, OAuthLoginError> {
    let url = format!("{}/user/orgs", api_url.as_str().trim_end_matches('/'));
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Accept", "application/json")
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_owned());
        return Err(OAuthLoginError::Http(format!(
            "GitHub /user/orgs returned {status}: {body}"
        )));
    }
    response
        .json::<Vec<GithubOrganization>>()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))
}

/// Fetches the authenticated GitHub user's teams.
#[tracing::instrument(skip(access_token))]
pub async fn github_fetch_teams(
    client: &reqwest::Client,
    api_url: &url::Url,
    access_token: &str,
) -> Result<Vec<GithubTeam>, OAuthLoginError> {
    let url = format!("{}/user/teams", api_url.as_str().trim_end_matches('/'));
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Accept", "application/json")
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_owned());
        return Err(OAuthLoginError::Http(format!(
            "GitHub /user/teams returned {status}: {body}"
        )));
    }
    response
        .json::<Vec<GithubTeam>>()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))
}

/// Requests a device code from GitHub's device authorization endpoint.
#[tracing::instrument(skip(config))]
pub async fn github_request_device_code(
    client: &reqwest::Client,
    config: &GithubOAuthConfig,
) -> Result<GithubDeviceResponse, OAuthLoginError> {
    let response = client
        .post(github_oauth_url(config, "/login/device/code"))
        .header("Accept", "application/json")
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("scope", "user:email read:org"),
        ])
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_owned());
        return Err(OAuthLoginError::Http(format!(
            "GitHub device endpoint returned {status}: {body}"
        )));
    }

    response
        .json::<GithubDeviceResponse>()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))
}

/// Checks that the GitHub user belongs to at least one allowed organization.
pub fn github_check_org_membership(
    config: &GithubOAuthConfig,
    orgs: &[GithubOrganization],
) -> bool {
    if config.allow_everyone || config.allowed_orgs.is_empty() {
        return true;
    }
    orgs.iter().any(|org| {
        config
            .allowed_orgs
            .iter()
            .any(|allowed| allowed == &org.login)
    })
}

/// Checks that the GitHub user belongs to at least one allowed team.
pub fn github_check_team_membership(config: &GithubOAuthConfig, teams: &[GithubTeam]) -> bool {
    if config.allow_everyone || config.allowed_teams.is_empty() {
        return true;
    }
    teams.iter().any(|team| {
        let team_slug = format!("{}/{}", team.organization.login, team.slug);
        config
            .allowed_teams
            .iter()
            .any(|allowed| allowed == &team_slug)
    })
}

/// Returns the primary verified email from the GitHub emails list.
pub fn github_primary_email(emails: &[GithubEmail]) -> Option<&GithubEmail> {
    // First try primary + verified
    emails
        .iter()
        .find(|e| e.primary && e.verified)
        // Fall back to any verified email
        .or_else(|| emails.iter().find(|e| e.verified))
}

/// Generates the GitHub linked ID string (matches Go's `githubLinkedID`).
pub fn github_linked_id(github_user_id: i64) -> String {
    format!("gh:{github_user_id}")
}

// ---------------------------------------------------------------------------
// OIDC helper functions
// ---------------------------------------------------------------------------

/// Fetches the OIDC discovery document from the well-known endpoint.
#[tracing::instrument(skip_all)]
pub async fn oidc_discover(
    client: &reqwest::Client,
    issuer_url: &url::Url,
) -> Result<OidcDiscovery, OAuthLoginError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.as_str().trim_end_matches('/')
    );
    client
        .get(&url)
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))?
        .json::<OidcDiscovery>()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))
}

/// Exchanges an authorization code for OIDC tokens.
#[tracing::instrument(skip(config, code, token_endpoint))]
pub async fn oidc_exchange_code(
    client: &reqwest::Client,
    config: &OidcConfig,
    token_endpoint: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<OidcTokenResponse, OAuthLoginError> {
    let response = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ])
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| OAuthLoginError::Http(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_owned());
        return Err(OAuthLoginError::CodeExchangeFailed(format!(
            "OIDC token endpoint returned {status}: {body}"
        )));
    }

    response
        .json::<OidcTokenResponse>()
        .await
        .map_err(|e| OAuthLoginError::CodeExchangeFailed(e.to_string()))
}

/// Decodes an OIDC ID token's payload (WITHOUT cryptographic signature verification).
///
/// // TODO(security): This function base64-decodes the JWT payload WITHOUT verifying
/// // the cryptographic signature against the provider's JWKS. The claims returned
/// // here are NOT authenticated and could have been tampered with. A proper
/// // implementation must:
/// //   1. Fetch the JWKS from `discovery.jwks_uri`
/// //   2. Cache the JWKS (with periodic refresh)
/// //   3. Verify the JWT signature using the `jsonwebtoken` crate
/// //   4. Only then trust the decoded claims
/// // Until this is implemented, the token is partially validated by checking
/// // issuer, audience, and expiry in `validate_oidc_claims`, but a malicious
/// // actor could forge tokens if they control the network path.
pub fn decode_id_token_claims(id_token: &str) -> Result<OidcClaims, OAuthLoginError> {
    tracing::warn!(
        "OIDC ID token signature is NOT cryptographically verified — \
         claims are decoded but not authenticated. \
         See TODO(security) in decode_id_token_claims."
    );
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthLoginError::InvalidIdToken(
            "ID token must have 3 parts".to_owned(),
        ));
    }

    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| OAuthLoginError::InvalidIdToken(format!("base64 decode error: {e}")))?;

    serde_json::from_slice::<OidcClaims>(&payload)
        .map_err(|e| OAuthLoginError::InvalidIdToken(format!("claims parse error: {e}")))
}

/// Validates basic OIDC claims (issuer, audience, expiry).
pub fn validate_oidc_claims(
    claims: &OidcClaims,
    config: &OidcConfig,
) -> Result<(), OAuthLoginError> {
    // Check issuer (required per OIDC Core spec)
    let iss = claims
        .extra
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OAuthLoginError::InvalidIdToken("missing required 'iss' claim".to_owned())
        })?;
    let expected = config.issuer_url.as_str().trim_end_matches('/');
    let actual = iss.trim_end_matches('/');
    if actual != expected {
        return Err(OAuthLoginError::InvalidIdToken(format!(
            "issuer mismatch: expected {expected}, got {actual}"
        )));
    }

    // Check audience (required per OIDC Core spec)
    let aud = claims.extra.get("aud").ok_or_else(|| {
        OAuthLoginError::InvalidIdToken("missing required 'aud' claim".to_owned())
    })?;
    let aud_matches = match aud {
        serde_json::Value::String(s) => s == &config.client_id,
        serde_json::Value::Array(arr) => arr
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s == config.client_id)),
        _ => false,
    };
    if !aud_matches {
        return Err(OAuthLoginError::InvalidIdToken(
            "audience does not match client_id".to_owned(),
        ));
    }

    // Check expiry (required per OIDC Core spec)
    let exp = claims
        .extra
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            OAuthLoginError::InvalidIdToken("missing required 'exp' claim".to_owned())
        })?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if exp < now {
        return Err(OAuthLoginError::InvalidIdToken(
            "ID token has expired".to_owned(),
        ));
    }

    Ok(())
}

/// Extracts a string claim from the OIDC claims by field name.
pub fn extract_claim(claims: &OidcClaims, field: &str) -> Option<String> {
    match field {
        "email" => claims.email.clone(),
        "name" => claims.name.clone(),
        "preferred_username" => claims.preferred_username.clone(),
        "sub" => Some(claims.sub.clone()),
        _ => claims
            .extra
            .get(field)
            .and_then(|v| v.as_str())
            .map(String::from),
    }
}

/// Checks that the email domain is in the allowed list.
pub fn oidc_check_email_domain(config: &OidcConfig, email: &str) -> bool {
    if config.email_domain.is_empty() {
        return true;
    }
    let domain = email.rsplit('@').next().unwrap_or("");
    config.email_domain.iter().any(|allowed| allowed == domain)
}

/// Generates the OIDC linked ID string (matches Go's `oidcLinkedID`).
pub fn oidc_linked_id(subject: &str) -> String {
    format!("oidc:{subject}")
}

/// Derives a username from the OIDC claims, falling back to the email prefix.
pub fn oidc_derive_username(claims: &OidcClaims, config: &OidcConfig) -> String {
    if let Some(username) = extract_claim(claims, &config.username_field) {
        if !username.is_empty() {
            return sanitize_username(&username);
        }
    }
    if let Some(ref email) = claims.email {
        if let Some(prefix) = email.split('@').next() {
            return sanitize_username(prefix);
        }
    }
    sanitize_username(&format!(
        "user-{}",
        claims.sub.chars().take(8).collect::<String>()
    ))
}

/// Sanitizes a string to be a valid username (alphanumeric + hyphens, lowercase).
fn sanitize_username(input: &str) -> String {
    input
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                Some(c.to_ascii_lowercase())
            } else if c == ' ' || c == '.' || c == '@' {
                Some('-')
            } else {
                None
            }
        })
        .collect()
}

/// Builds a `UserLinkClaims` from OIDC claims.
///
/// Because `OidcClaims` uses `#[serde(flatten)]` on the `extra` field, serde
/// deserializes known fields (`sub`, `email`, `email_verified`, `name`,
/// `preferred_username`, `groups`) into their typed struct fields and does NOT
/// place them into `extra`. We must add them back so `id_token_claims` and
/// `merged_claims` contain the complete set of claims.
pub fn build_user_link_claims(claims: &OidcClaims) -> UserLinkClaims {
    let mut all_claims = claims.extra.clone();
    all_claims.insert(
        "sub".to_owned(),
        serde_json::Value::String(claims.sub.clone()),
    );
    if let Some(ref email) = claims.email {
        all_claims.insert("email".to_owned(), serde_json::Value::String(email.clone()));
    }
    if let Some(ref verified) = claims.email_verified {
        all_claims.insert(
            "email_verified".to_owned(),
            serde_json::Value::Bool(*verified),
        );
    }
    if let Some(ref name) = claims.name {
        all_claims.insert("name".to_owned(), serde_json::Value::String(name.clone()));
    }
    if let Some(ref username) = claims.preferred_username {
        all_claims.insert(
            "preferred_username".to_owned(),
            serde_json::Value::String(username.clone()),
        );
    }
    if let Some(ref groups) = claims.groups {
        all_claims.insert("groups".to_owned(), serde_json::json!(groups));
    }

    UserLinkClaims {
        id_token_claims: all_claims.clone(),
        user_info_claims: Default::default(),
        merged_claims: all_claims,
    }
}

// ---------------------------------------------------------------------------
// Shared types for handler use
// ---------------------------------------------------------------------------

/// Query parameters for OAuth2 callback endpoints.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct OAuthCallbackQuery {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_github_linked_id() {
        assert_eq!(github_linked_id(12345), "gh:12345");
        assert_eq!(github_linked_id(0), "gh:0");
    }

    #[test]
    fn test_oidc_linked_id() {
        assert_eq!(oidc_linked_id("abc123"), "oidc:abc123");
    }

    #[test]
    fn test_sanitize_username() {
        assert_eq!(sanitize_username("John.Doe"), "john-doe");
        assert_eq!(sanitize_username("user@example.com"), "user-example-com");
        assert_eq!(sanitize_username("hello world"), "hello-world");
        assert_eq!(sanitize_username("UPPER_case"), "upper_case");
    }

    #[test]
    fn test_github_primary_email() {
        let emails = vec![
            GithubEmail {
                email: "unverified@test.com".to_owned(),
                primary: true,
                verified: false,
            },
            GithubEmail {
                email: "verified@test.com".to_owned(),
                primary: false,
                verified: true,
            },
            GithubEmail {
                email: "primary@test.com".to_owned(),
                primary: true,
                verified: true,
            },
        ];
        let primary = github_primary_email(&emails);
        assert_eq!(primary.map(|e| e.email.as_str()), Some("primary@test.com"));
    }

    #[test]
    fn test_github_primary_email_fallback() {
        let emails = vec![
            GithubEmail {
                email: "unverified@test.com".to_owned(),
                primary: true,
                verified: false,
            },
            GithubEmail {
                email: "verified@test.com".to_owned(),
                primary: false,
                verified: true,
            },
        ];
        let primary = github_primary_email(&emails);
        assert_eq!(primary.map(|e| e.email.as_str()), Some("verified@test.com"));
    }

    #[test]
    fn test_oidc_check_email_domain_empty() {
        let config = OidcConfig {
            issuer_url: url::Url::parse("https://example.com").unwrap(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: Vec::new(),
            allow_signups: true,
            email_domain: Vec::new(),
            username_field: "preferred_username".to_owned(),
            email_field: "email".to_owned(),
            name_field: "name".to_owned(),
            ignore_email_verified: false,
        };
        assert!(oidc_check_email_domain(&config, "user@anything.com"));
    }

    #[test]
    fn test_oidc_check_email_domain_restricted() {
        let config = OidcConfig {
            issuer_url: url::Url::parse("https://example.com").unwrap(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: Vec::new(),
            allow_signups: true,
            email_domain: vec!["example.com".to_owned()],
            username_field: "preferred_username".to_owned(),
            email_field: "email".to_owned(),
            name_field: "name".to_owned(),
            ignore_email_verified: false,
        };
        assert!(oidc_check_email_domain(&config, "user@example.com"));
        assert!(!oidc_check_email_domain(&config, "user@other.com"));
    }

    #[test]
    fn test_github_check_org_membership_allow_everyone() {
        let config = GithubOAuthConfig {
            client_id: String::new(),
            client_secret: String::new(),
            allow_signups: true,
            allow_everyone: true,
            allowed_orgs: vec!["org1".to_owned()],
            allowed_teams: Vec::new(),
            api_url: url::Url::parse("https://api.github.com").unwrap(),
        };
        assert!(github_check_org_membership(&config, &[]));
    }

    #[test]
    fn test_github_check_org_membership_match() {
        let config = GithubOAuthConfig {
            client_id: String::new(),
            client_secret: String::new(),
            allow_signups: false,
            allow_everyone: false,
            allowed_orgs: vec!["my-org".to_owned()],
            allowed_teams: Vec::new(),
            api_url: url::Url::parse("https://api.github.com").unwrap(),
        };
        let orgs = vec![GithubOrganization {
            login: "my-org".to_owned(),
        }];
        assert!(github_check_org_membership(&config, &orgs));
        assert!(!github_check_org_membership(&config, &[]));
    }

    #[test]
    fn test_github_check_team_membership() {
        let config = GithubOAuthConfig {
            client_id: String::new(),
            client_secret: String::new(),
            allow_signups: false,
            allow_everyone: false,
            allowed_orgs: Vec::new(),
            allowed_teams: vec!["my-org/my-team".to_owned()],
            api_url: url::Url::parse("https://api.github.com").unwrap(),
        };
        let teams = vec![GithubTeam {
            slug: "my-team".to_owned(),
            organization: GithubTeamOrg {
                login: "my-org".to_owned(),
            },
        }];
        assert!(github_check_team_membership(&config, &teams));
        assert!(!github_check_team_membership(&config, &[]));
    }

    #[test]
    fn test_decode_id_token_claims() {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"sub":"user123","email":"test@example.com","name":"Test User","iss":"https://example.com","aud":"my-client","exp":9999999999}"#,
        );
        let token = format!("{header}.{payload}.fake-sig");

        let claims = decode_id_token_claims(&token).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.email.as_deref(), Some("test@example.com"));
        assert_eq!(claims.name.as_deref(), Some("Test User"));
    }

    #[test]
    fn test_decode_id_token_claims_invalid() {
        let result = decode_id_token_claims("not.a.valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_oidc_claims_expired() {
        let claims = OidcClaims {
            sub: "user1".to_owned(),
            extra: {
                let mut m = serde_json::Map::new();
                m.insert("exp".to_owned(), serde_json::Value::Number(1.into()));
                m.insert(
                    "iss".to_owned(),
                    serde_json::Value::String("https://example.com".to_owned()),
                );
                m.insert(
                    "aud".to_owned(),
                    serde_json::Value::String("my-client".to_owned()),
                );
                m
            },
            ..Default::default()
        };
        let config = OidcConfig {
            issuer_url: url::Url::parse("https://example.com").unwrap(),
            client_id: "my-client".to_owned(),
            client_secret: String::new(),
            scopes: Vec::new(),
            allow_signups: true,
            email_domain: Vec::new(),
            username_field: "preferred_username".to_owned(),
            email_field: "email".to_owned(),
            name_field: "name".to_owned(),
            ignore_email_verified: false,
        };
        let result = validate_oidc_claims(&claims, &config);
        assert!(matches!(result, Err(OAuthLoginError::InvalidIdToken(_))));
    }

    #[test]
    fn test_validate_oidc_claims_missing_iss() {
        let claims = OidcClaims {
            sub: "user1".to_owned(),
            extra: {
                let mut m = serde_json::Map::new();
                m.insert(
                    "aud".to_owned(),
                    serde_json::Value::String("my-client".to_owned()),
                );
                m.insert(
                    "exp".to_owned(),
                    serde_json::Value::Number(9999999999_i64.into()),
                );
                m
            },
            ..Default::default()
        };
        let config = OidcConfig {
            issuer_url: url::Url::parse("https://example.com").unwrap(),
            client_id: "my-client".to_owned(),
            client_secret: String::new(),
            scopes: Vec::new(),
            allow_signups: true,
            email_domain: Vec::new(),
            username_field: "preferred_username".to_owned(),
            email_field: "email".to_owned(),
            name_field: "name".to_owned(),
            ignore_email_verified: false,
        };
        let result = validate_oidc_claims(&claims, &config);
        assert!(matches!(result, Err(OAuthLoginError::InvalidIdToken(_))));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing required 'iss' claim")
        );
    }

    #[test]
    fn test_validate_oidc_claims_missing_aud() {
        let claims = OidcClaims {
            sub: "user1".to_owned(),
            extra: {
                let mut m = serde_json::Map::new();
                m.insert(
                    "iss".to_owned(),
                    serde_json::Value::String("https://example.com".to_owned()),
                );
                m.insert(
                    "exp".to_owned(),
                    serde_json::Value::Number(9999999999_i64.into()),
                );
                m
            },
            ..Default::default()
        };
        let config = OidcConfig {
            issuer_url: url::Url::parse("https://example.com").unwrap(),
            client_id: "my-client".to_owned(),
            client_secret: String::new(),
            scopes: Vec::new(),
            allow_signups: true,
            email_domain: Vec::new(),
            username_field: "preferred_username".to_owned(),
            email_field: "email".to_owned(),
            name_field: "name".to_owned(),
            ignore_email_verified: false,
        };
        let result = validate_oidc_claims(&claims, &config);
        assert!(matches!(result, Err(OAuthLoginError::InvalidIdToken(_))));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing required 'aud' claim")
        );
    }

    #[test]
    fn test_validate_oidc_claims_missing_exp() {
        let claims = OidcClaims {
            sub: "user1".to_owned(),
            extra: {
                let mut m = serde_json::Map::new();
                m.insert(
                    "iss".to_owned(),
                    serde_json::Value::String("https://example.com".to_owned()),
                );
                m.insert(
                    "aud".to_owned(),
                    serde_json::Value::String("my-client".to_owned()),
                );
                m
            },
            ..Default::default()
        };
        let config = OidcConfig {
            issuer_url: url::Url::parse("https://example.com").unwrap(),
            client_id: "my-client".to_owned(),
            client_secret: String::new(),
            scopes: Vec::new(),
            allow_signups: true,
            email_domain: Vec::new(),
            username_field: "preferred_username".to_owned(),
            email_field: "email".to_owned(),
            name_field: "name".to_owned(),
            ignore_email_verified: false,
        };
        let result = validate_oidc_claims(&claims, &config);
        assert!(matches!(result, Err(OAuthLoginError::InvalidIdToken(_))));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing required 'exp' claim")
        );
    }

    #[test]
    fn test_github_oauth_url_standard() {
        let config = GithubOAuthConfig {
            client_id: String::new(),
            client_secret: String::new(),
            allow_signups: true,
            allow_everyone: true,
            allowed_orgs: Vec::new(),
            allowed_teams: Vec::new(),
            api_url: url::Url::parse("https://api.github.com").unwrap(),
        };
        assert_eq!(
            github_oauth_url(&config, "/login/oauth/access_token"),
            "https://github.com/login/oauth/access_token"
        );
        assert_eq!(
            github_oauth_url(&config, "/login/device/code"),
            "https://github.com/login/device/code"
        );
    }

    #[test]
    fn test_github_oauth_url_enterprise() {
        let config = GithubOAuthConfig {
            client_id: String::new(),
            client_secret: String::new(),
            allow_signups: true,
            allow_everyone: true,
            allowed_orgs: Vec::new(),
            allowed_teams: Vec::new(),
            api_url: url::Url::parse("https://ghe.example.com/api/v3").unwrap(),
        };
        assert_eq!(
            github_oauth_url(&config, "/login/oauth/access_token"),
            "https://ghe.example.com/login/oauth/access_token"
        );
        assert_eq!(
            github_oauth_url(&config, "/login/device/code"),
            "https://ghe.example.com/login/device/code"
        );
    }

    #[test]
    fn test_oidc_derive_username_multibyte_sub() {
        let claims = OidcClaims {
            sub: "αβγδεζηθ-long".to_owned(),
            ..Default::default()
        };
        let config = OidcConfig {
            issuer_url: url::Url::parse("https://example.com").unwrap(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: Vec::new(),
            allow_signups: true,
            email_domain: Vec::new(),
            username_field: "preferred_username".to_owned(),
            email_field: "email".to_owned(),
            name_field: "name".to_owned(),
            ignore_email_verified: false,
        };
        // Should not panic on multi-byte chars, and should produce a valid username
        let username = oidc_derive_username(&claims, &config);
        assert!(username.starts_with("user-"));
        // The sanitized username should only contain valid characters
        assert!(
            username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "username contains invalid characters: {username}"
        );
    }
}
