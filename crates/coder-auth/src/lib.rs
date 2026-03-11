//! Authentication, sessions, and external-auth lifecycle helpers.
#![forbid(unsafe_code)]

pub mod oauth_login;
pub mod session_cache;

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use coder_core::{
    ApiKeyListFilter, ApiKeyResponse, ApiKeyWithOwnerResponse, AuthMethod, AuthMethods, AuthStore,
    AuthenticatedUser, ChangePasswordWithOneTimePasscodeRequest, ConvertLoginRequest,
    CreateApiKeyInput, CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserRequest,
    CreateFirstUserResponse, CreateFirstUserStoreError, CreateTokenRequest,
    DeleteExternalAuthByIdResponse, ExternalAuthAppInstallation, ExternalAuthDevice,
    ExternalAuthDeviceExchangeRequest, ExternalAuthLink, ExternalAuthLinkProvider,
    ExternalAuthLinkRecord, ExternalAuthResponse, ExternalAuthUser, GenerateApiKeyResponse,
    GithubAuthMethod, ListUserExternalAuthResponse, LoginType, StorageError, TokenConfig,
    UpdateUserPasswordRequest, UpsertExternalAuthLinkInput, UserLoginType, UserRecord, UserStatus,
    ValidateUserPasswordRequest, ValidateUserPasswordResponse, ValidationError,
};
use coder_rbac::Actor;
use http::HeaderMap;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tracing::warn;
use url::form_urlencoded;
use uuid::Uuid;

pub use coder_core::{
    LoginWithPasswordRequest, LoginWithPasswordResponse, PasswordError, hash_password,
    hash_session_token, new_session_token, normalize_real_name, validate_email, validate_password,
    validate_real_name, validate_username, verify_password,
};

/// Compatibility header used by the current Rust backend slice.
pub const SESSION_TOKEN_HEADER: &str = "coder-session-token";
/// Compatibility cookie used by browser-originated auth flows.
pub const SESSION_TOKEN_COOKIE: &str = "coder_session_token";
/// OAuth2 state cookie used by callback flows.
pub const OAUTH2_STATE_COOKIE: &str = "oauth_state";
/// OAuth2 redirect cookie used by callback flows.
pub const OAUTH2_REDIRECT_COOKIE: &str = "oauth_redirect";

const EXTERNAL_AUTH_HTTP_TIMEOUT_SECS: u64 = 10;
const EXTERNAL_AUTH_REFRESH_WINDOW_SECS: i64 = 60;
const NON_EXPIRING_TOKEN_SECS: i64 = 60 * 60 * 24 * 365 * 10;
const DEFAULT_SESSION_KEY_LIFETIME_SECS: u64 = 60 * 60 * 24;
const DEFAULT_TOKEN_KEY_LIFETIME_SECS: u64 = 60 * 60 * 24 * 30;
const ONE_TIME_PASSCODE_VALIDITY_SECS: i64 = 60 * 30;

/// Extracts the opaque session token from request headers.
#[must_use]
pub fn session_token_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(SESSION_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
}

/// Extracts a cookie value from the request headers.
#[must_use]
pub fn cookie_from_headers(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(http::header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|entry| {
        let (candidate_name, candidate_value) = entry.trim().split_once('=')?;
        if candidate_name == name {
            Some(candidate_value.to_owned())
        } else {
            None
        }
    })
}

/// Authenticated request actor derived from the current session token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedRequest {
    /// Opaque session token as supplied by the client.
    pub session_token: String,
    /// Authenticated user.
    pub user: AuthenticatedUser,
    /// Derived RBAC actor.
    pub actor: Actor,
}

/// Result payload for successful password login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginOutcome {
    /// Authenticated user used by audit and follow-up logic.
    pub user: AuthenticatedUser,
    /// Public HTTP response payload.
    pub response: LoginWithPasswordResponse,
}

/// Result payload for newly created API keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyGeneration {
    /// Stable key identifier used for audit events.
    pub key_id: String,
    /// Public HTTP response payload containing the secret.
    pub response: GenerateApiKeyResponse,
}

#[derive(Clone, Debug)]
struct ApiKeyCreation<'a> {
    target_user: &'a UserRecord,
    login_type: LoginType,
    lifetime: Duration,
    token_name: String,
    scopes: Vec<String>,
    allow_list: Vec<coder_core::ApiAllowListTarget>,
}

/// Request-scoped failures for auth, sessions, passwords, and API keys.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthServiceError {
    /// The backing store failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The caller is not authenticated.
    #[error("{message}")]
    Unauthorized { message: String },
    /// The caller is authenticated but not allowed to perform the action.
    #[error("{message}")]
    Forbidden { message: String },
    /// The requested resource does not exist.
    #[error("{message}")]
    NotFound { message: String },
    /// The request is invalid but not field-scoped.
    #[error("{message}")]
    BadRequest {
        message: String,
        detail: Option<String>,
    },
    /// The request failed field-scoped validation.
    #[error("{message}")]
    Validation {
        message: String,
        validations: Vec<ValidationError>,
    },
    /// The request conflicted with existing state.
    #[error("{message}")]
    Conflict {
        message: String,
        detail: Option<String>,
        validations: Vec<ValidationError>,
    },
}

impl AuthServiceError {
    #[must_use]
    fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized {
            message: message.into(),
        }
    }

    #[must_use]
    fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden {
            message: message.into(),
        }
    }

    #[must_use]
    fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound {
            message: message.into(),
        }
    }

    #[must_use]
    fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
            detail: None,
        }
    }

    #[must_use]
    fn bad_request_with_detail(message: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
            detail: Some(detail.into()),
        }
    }

    #[must_use]
    fn validation(message: impl Into<String>, validations: Vec<ValidationError>) -> Self {
        Self::Validation {
            message: message.into(),
            validations,
        }
    }

    #[must_use]
    fn conflict(message: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
            detail: Some(detail.into()),
            validations: Vec::new(),
        }
    }
}

/// Returns the advertised auth-method capabilities for the current OSS slice.
#[must_use]
pub fn supported_auth_methods() -> AuthMethods {
    AuthMethods {
        terms_of_service_url: String::new(),
        password: AuthMethod { enabled: true },
        github: GithubAuthMethod {
            enabled: true,
            default_provider_configured: true,
        },
        oidc: coder_core::OidcAuthMethod::default(),
    }
}

/// Authentication and API-key lifecycle service used by the Rust handlers.
#[derive(Clone)]
pub struct AuthService<S> {
    store: S,
    session_cache: Arc<session_cache::SessionCache>,
}

impl<S> AuthService<S>
where
    S: AuthStore + Clone + Send + Sync + 'static,
{
    /// Creates the service for the supplied auth-capable store with a
    /// configurable session cache TTL.
    #[must_use]
    pub fn with_cache_ttl(store: S, cache_ttl: Duration) -> Self {
        Self {
            store,
            session_cache: Arc::new(session_cache::SessionCache::new(cache_ttl)),
        }
    }

    /// Creates the service with the default 30-second session cache TTL.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self::with_cache_ttl(store, Duration::from_secs(30))
    }

    /// Authenticates the incoming request using the session header or cookie.
    ///
    /// Checks the in-memory session cache first (read lock), falling back to
    /// the database on a miss and populating the cache (write lock).
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<AuthenticatedRequest>, StorageError> {
        let session_token = session_token_from_headers(headers)
            .map(str::to_owned)
            .or_else(|| cookie_from_headers(headers, SESSION_TOKEN_COOKIE));
        let Some(session_token) = session_token else {
            return Ok(None);
        };

        let session_token_hash = hash_session_token(&session_token);

        // Fast path: check the in-memory cache.
        if let Some(user) = self.session_cache.get(&session_token_hash).await {
            return Ok(Some(AuthenticatedRequest {
                session_token,
                actor: actor_from_user(&user),
                user,
            }));
        }

        // Slow path: fall back to the database.
        let Some(user) = self
            .store
            .find_user_by_session_token_hash(&session_token_hash)
            .await?
        else {
            metrics::counter!("auth_events_total", "type" => "session_expired").increment(1);
            return Ok(None);
        };

        // Populate cache for subsequent requests.
        self.session_cache
            .insert(session_token_hash, user.clone())
            .await;

        Ok(Some(AuthenticatedRequest {
            session_token,
            actor: actor_from_user(&user),
            user,
        }))
    }

    /// Returns whether the initial deployment user already exists.
    pub async fn first_user_exists(&self) -> Result<bool, StorageError> {
        self.store.first_user_exists().await
    }

    /// Creates the initial password-backed deployment user.
    pub async fn create_first_user(
        &self,
        request: &CreateFirstUserRequest,
    ) -> Result<CreateFirstUserResponse, AuthServiceError> {
        let validations = validate_first_user_request(request);
        if !validations.is_empty() {
            return Err(AuthServiceError::validation(
                "Request body has invalid fields.",
                validations,
            ));
        }

        let password_hash = hash_password(&request.password)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        let created = self
            .store
            .create_first_user(CreateFirstUserInput {
                email: request.email.trim().to_owned(),
                username: request.username.clone(),
                name: normalize_real_name(&request.name),
                password_hash,
            })
            .await
            .map_err(|error| match error {
                CreateFirstUserStoreError::AlreadyExists => AuthServiceError::Conflict {
                    message: "The initial user has already been created!".to_owned(),
                    detail: None,
                    validations: Vec::new(),
                },
                CreateFirstUserStoreError::Storage(error) => AuthServiceError::Storage(error),
            })?;

        Ok(CreateFirstUserResponse {
            user_id: created.user_id,
            organization_id: created.organization_id,
        })
    }

    /// Authenticates a password-backed user and creates a new session.
    pub async fn login_with_password(
        &self,
        request: &LoginWithPasswordRequest,
    ) -> Result<LoginOutcome, AuthServiceError> {
        let Some(user_record) = self
            .store
            .find_password_user_by_email(request.email.trim())
            .await?
        else {
            metrics::counter!("auth_events_total", "type" => "login_failure").increment(1);
            return Err(AuthServiceError::unauthorized(
                "Incorrect email or password.",
            ));
        };

        if user_record.user.deleted
            || user_record.user.is_system
            || user_record.user.login_type != LoginType::Password
            || user_record.user.status != UserStatus::Active
        {
            metrics::counter!("auth_events_total", "type" => "login_failure").increment(1);
            return Err(AuthServiceError::unauthorized(
                "Incorrect email or password.",
            ));
        }

        let password_matches = verify_password(&user_record.password_hash, &request.password)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        if !password_matches {
            metrics::counter!("auth_events_total", "type" => "login_failure").increment(1);
            return Err(AuthServiceError::unauthorized(
                "Incorrect email or password.",
            ));
        }

        let session_token = new_session_token();
        let session_token_hash = hash_session_token(&session_token);
        self.store
            .insert_auth_session(&session_token_hash, user_record.user.id)
            .await?;

        metrics::counter!("auth_events_total", "type" => "login_success").increment(1);
        Ok(LoginOutcome {
            user: AuthenticatedUser::from(user_record.user),
            response: LoginWithPasswordResponse { session_token },
        })
    }

    /// Creates a session for an OAuth/OIDC-authenticated user.
    ///
    /// This is called after the OAuth callback has verified the user's identity
    /// and either found an existing user or created a new one.
    #[tracing::instrument(skip(self))]
    pub async fn create_oauth_session(
        &self,
        user: &UserRecord,
    ) -> Result<String, AuthServiceError> {
        let session_token = new_session_token();
        let session_token_hash = hash_session_token(&session_token);
        self.store
            .insert_auth_session(&session_token_hash, user.id)
            .await?;
        metrics::counter!("auth_events_total", "type" => "oauth_login_success").increment(1);
        Ok(session_token)
    }

    /// Revokes the current session token and evicts it from the cache.
    pub async fn logout(&self, session_token: &str) -> Result<(), StorageError> {
        let token_hash = hash_session_token(session_token);
        self.store.delete_auth_session(&token_hash).await?;
        // Immediately evict from cache so concurrent requests see the logout.
        self.session_cache.evict(&token_hash).await;
        metrics::counter!("auth_events_total", "type" => "logout").increment(1);
        Ok(())
    }

    /// Validates password policy for one candidate password.
    #[must_use]
    pub fn validate_user_password(
        &self,
        request: &ValidateUserPasswordRequest,
    ) -> ValidateUserPasswordResponse {
        let (valid, details) = match validate_password(&request.password) {
            Ok(()) => (true, String::new()),
            Err(error) => (false, error.to_string()),
        };

        ValidateUserPasswordResponse { valid, details }
    }

    /// Stores a password-reset one-time passcode for the supplied email.
    pub async fn request_one_time_passcode(
        &self,
        request: &coder_core::RequestOneTimePasscodeRequest,
    ) -> Result<(), AuthServiceError> {
        let mut validations = Vec::new();
        push_validation(&mut validations, "email", validate_email(&request.email));
        if !validations.is_empty() {
            return Err(AuthServiceError::validation(
                "Request body has invalid fields.",
                validations,
            ));
        }

        let passcode = Uuid::new_v4().to_string();
        let passcode_hash = hash_password(&passcode)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        let expires_at = OffsetDateTime::now_utc()
            .checked_add(time::Duration::seconds(ONE_TIME_PASSCODE_VALIDITY_SECS))
            .ok_or_else(|| StorageError::invalid_data("invalid OTP expiry"))?;

        self.store
            .store_one_time_passcode_by_email(request.email.trim(), &passcode_hash, expires_at)
            .await?;
        Ok(())
    }

    /// Resets a password with a one-time passcode.
    pub async fn change_password_with_one_time_passcode(
        &self,
        request: &ChangePasswordWithOneTimePasscodeRequest,
    ) -> Result<Uuid, AuthServiceError> {
        let mut validations = Vec::new();
        push_validation(&mut validations, "email", validate_email(&request.email));
        push_validation(
            &mut validations,
            "password",
            validate_password(&request.password),
        );
        if request.one_time_passcode.trim().is_empty() {
            validations.push(ValidationError {
                field: "one_time_passcode".to_owned(),
                detail: "must be >= 1 character".to_owned(),
            });
        }
        if !validations.is_empty() {
            return Err(AuthServiceError::validation(
                "Request body has invalid fields.",
                validations,
            ));
        }

        let Some(user) = self
            .store
            .find_password_user_by_email(request.email.trim())
            .await?
        else {
            return Err(AuthServiceError::bad_request(
                "Incorrect email or one-time passcode.",
            ));
        };

        let passcode_matches = user
            .one_time_passcode_hash
            .as_deref()
            .zip(user.one_time_passcode_expires_at)
            .filter(|(_, expires_at)| *expires_at > OffsetDateTime::now_utc())
            .map(|(stored_hash, _)| {
                verify_password(stored_hash, &request.one_time_passcode)
                    .map_err(|error| StorageError::invalid_data(error.to_string()))
            })
            .transpose()?
            .unwrap_or(false);
        if !passcode_matches {
            return Err(AuthServiceError::bad_request(
                "Incorrect email or one-time passcode.",
            ));
        }

        if verify_password(&user.password_hash, &request.password)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?
        {
            return Err(AuthServiceError::bad_request(
                "New password cannot match old password.",
            ));
        }

        let password_hash = hash_password(&request.password)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        if !self
            .store
            .replace_user_password(user.user.id, &password_hash, true)
            .await?
        {
            return Err(AuthServiceError::not_found("User not found."));
        }

        // Evict all cached sessions for this user after password reset.
        self.session_cache.evict_user(user.user.id).await;

        Ok(user.user.id)
    }

    /// Returns the login type for the requested user.
    pub async fn get_user_login_type(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
    ) -> Result<UserLoginType, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if target_user.id != authenticated_user.id || !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to view this user's login type.",
            ));
        }

        Ok(UserLoginType {
            login_type: target_user.login_type,
        })
    }

    /// Changes a password-backed user's password.
    pub async fn update_user_password(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        request: &UpdateUserPasswordRequest,
    ) -> Result<Uuid, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::not_found("User not found."));
        }
        if target_user.login_type != LoginType::Password {
            return Err(AuthServiceError::bad_request(
                "Users without password login type cannot change their password.",
            ));
        }

        let Some(password_user) = self.store.find_password_user_by_id(target_user.id).await? else {
            return Err(AuthServiceError::not_found("User not found."));
        };

        if authenticated_user.id == target_user.id && request.old_password.is_empty() {
            return Err(AuthServiceError::bad_request("Old password is required."));
        }

        if let Err(error) = validate_password(&request.password) {
            return Err(AuthServiceError::validation(
                "Invalid password.",
                vec![ValidationError {
                    field: "password".to_owned(),
                    detail: error.to_string(),
                }],
            ));
        }

        if !request.old_password.is_empty()
            && !verify_password(&password_user.password_hash, &request.old_password)
                .map_err(|error| StorageError::invalid_data(error.to_string()))?
        {
            return Err(AuthServiceError::validation(
                "Old password is incorrect.",
                vec![ValidationError {
                    field: "old_password".to_owned(),
                    detail: "Old password is incorrect.".to_owned(),
                }],
            ));
        }

        if verify_password(&password_user.password_hash, &request.password)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?
        {
            return Err(AuthServiceError::bad_request(
                "New password cannot match old password.",
            ));
        }

        let password_hash = hash_password(&request.password)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?;
        if !self
            .store
            .replace_user_password(target_user.id, &password_hash, false)
            .await?
        {
            return Err(AuthServiceError::not_found("User not found."));
        }

        // Evict all cached sessions for this user after password change.
        self.session_cache.evict_user(target_user.id).await;

        Ok(target_user.id)
    }

    /// Returns the current unsupported login-conversion outcome.
    pub async fn convert_login(
        &self,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        request: &ConvertLoginRequest,
    ) -> Result<String, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if target_user.id != authenticated_user.id {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to convert this user's login type.",
            ));
        }
        if !matches!(request.to_type, LoginType::Github | LoginType::Oidc) {
            return Err(AuthServiceError::bad_request(format!(
                "Cannot convert to login type {}.",
                request.to_type.as_str()
            )));
        }
        if target_user.login_type != LoginType::Password {
            return Err(AuthServiceError::bad_request(
                "User account must have password based authentication.",
            ));
        }

        let Some(password_user) = self.store.find_password_user_by_id(target_user.id).await? else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if !verify_password(&password_user.password_hash, &request.password)
            .map_err(|error| StorageError::invalid_data(error.to_string()))?
        {
            return Err(AuthServiceError::unauthorized(
                "Incorrect email or password.",
            ));
        }

        Ok(match request.to_type {
            LoginType::Github => "GitHub OAuth2 is not enabled.".to_owned(),
            LoginType::Oidc => "OIDC is not enabled.".to_owned(),
            _ => unreachable!(),
        })
    }

    /// Creates a session-scoped API key for the target user.
    pub async fn create_session_api_key(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
    ) -> Result<ApiKeyGeneration, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to create API keys for this user.",
            ));
        }
        if target_user.is_system {
            return Err(AuthServiceError::forbidden(
                "System users cannot receive API keys.",
            ));
        }

        self.create_api_key_for_user(ApiKeyCreation {
            target_user: &target_user,
            login_type: LoginType::Password,
            lifetime: Duration::from_secs(DEFAULT_SESSION_KEY_LIFETIME_SECS),
            token_name: String::new(),
            scopes: vec!["all".to_owned()],
            allow_list: Vec::new(),
        })
        .await
    }

    /// Creates a token-scoped API key for the target user.
    pub async fn create_token_api_key(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        request: CreateTokenRequest,
    ) -> Result<ApiKeyGeneration, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to create API keys for this user.",
            ));
        }
        if target_user.is_system {
            return Err(AuthServiceError::forbidden(
                "System users cannot receive API keys.",
            ));
        }

        let token_config = self.store.token_config(target_user.id).await?;
        let requested_lifetime = if request.lifetime.is_zero() {
            Duration::from_secs(DEFAULT_TOKEN_KEY_LIFETIME_SECS)
        } else {
            request.lifetime
        };
        if requested_lifetime > token_config.max_token_lifetime {
            return Err(AuthServiceError::bad_request_with_detail(
                "Failed to validate create API key request.",
                format!(
                    "lifetime must be less than or equal to {:?}",
                    token_config.max_token_lifetime
                ),
            ));
        }

        let scopes = if !request.scopes.is_empty() {
            request.scopes
        } else if !request.scope.is_empty() {
            vec![request.scope]
        } else {
            vec!["all".to_owned()]
        };
        let token_name = if request.token_name.is_empty() {
            format!("token-{}", Uuid::new_v4().simple())
        } else {
            request.token_name
        };

        self.create_api_key_for_user(ApiKeyCreation {
            target_user: &target_user,
            login_type: LoginType::Token,
            lifetime: requested_lifetime,
            token_name,
            scopes,
            allow_list: request.allow_list,
        })
        .await
    }

    /// Lists token-based API keys for the target user or for all users.
    pub async fn list_token_api_keys(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        include_all: bool,
        include_expired: bool,
    ) -> Result<Vec<ApiKeyWithOwnerResponse>, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };

        if include_all && !actor.is_owner() {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to list API keys for all users.",
            ));
        }
        if !include_all && !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to list API keys for this user.",
            ));
        }

        Ok(self
            .store
            .list_api_keys(ApiKeyListFilter {
                user_id: if include_all {
                    None
                } else {
                    Some(target_user.id)
                },
                login_type: LoginType::Token,
                include_expired,
            })
            .await?
            .into_iter()
            .map(|record| ApiKeyWithOwnerResponse {
                api_key: ApiKeyResponse::from(record.key),
                username: record.username,
            })
            .collect())
    }

    /// Returns one API key by stable identifier.
    pub async fn get_api_key(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        key_id: &str,
    ) -> Result<ApiKeyResponse, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to view API keys for this user.",
            ));
        }

        let Some(key) = self.store.find_api_key_by_id(key_id).await? else {
            return Err(AuthServiceError::not_found("API key not found."));
        };
        if key.user_id != target_user.id {
            return Err(AuthServiceError::not_found("API key not found."));
        }

        Ok(ApiKeyResponse::from(key))
    }

    /// Returns one API key by token name.
    pub async fn get_api_key_by_name(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        key_name: &str,
    ) -> Result<ApiKeyResponse, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to view API keys for this user.",
            ));
        }

        let Some(key) = self
            .store
            .find_api_key_by_name(target_user.id, key_name)
            .await?
        else {
            return Err(AuthServiceError::not_found("API key not found."));
        };

        Ok(ApiKeyResponse::from(key))
    }

    /// Deletes one API key by stable identifier.
    pub async fn delete_api_key(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        key_id: &str,
    ) -> Result<String, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to delete API keys for this user.",
            ));
        }

        let Some(key) = self.store.find_api_key_by_id(key_id).await? else {
            return Err(AuthServiceError::not_found("API key not found."));
        };
        if key.user_id != target_user.id {
            return Err(AuthServiceError::not_found("API key not found."));
        }
        if !self.store.delete_api_key(key_id).await? {
            return Err(AuthServiceError::not_found("API key not found."));
        }

        Ok(key_id.to_owned())
    }

    /// Expires one API key by stable identifier.
    pub async fn expire_api_key(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        key_id: &str,
    ) -> Result<String, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to expire API keys for this user.",
            ));
        }

        let Some(key) = self.store.find_api_key_by_id(key_id).await? else {
            return Err(AuthServiceError::not_found("API key not found."));
        };
        if key.user_id != target_user.id {
            return Err(AuthServiceError::not_found("API key not found."));
        }
        if !self
            .store
            .expire_api_key(key_id, OffsetDateTime::now_utc())
            .await?
        {
            return Err(AuthServiceError::not_found("API key not found."));
        }

        Ok(key_id.to_owned())
    }

    /// Returns token-lifetime configuration for the requested user.
    pub async fn get_token_config(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
    ) -> Result<TokenConfig, AuthServiceError> {
        let Some(target_user) = self
            .resolve_user(requested_user, authenticated_user)
            .await?
        else {
            return Err(AuthServiceError::not_found("User not found."));
        };
        if !actor.can_access_user(target_user.id) {
            return Err(AuthServiceError::forbidden(
                "You are not authorized to view token configuration for this user.",
            ));
        }

        let config = self.store.token_config(target_user.id).await?;
        Ok(TokenConfig {
            max_token_lifetime: config.max_token_lifetime,
        })
    }

    async fn resolve_user(
        &self,
        requested_user: &str,
        authenticated_user: &AuthenticatedUser,
    ) -> Result<Option<UserRecord>, StorageError> {
        if requested_user == "me" {
            return self.store.find_user_by_id(authenticated_user.id).await;
        }
        if let Ok(user_id) = Uuid::parse_str(requested_user) {
            return self.store.find_user_by_id(user_id).await;
        }

        self.store.find_user_by_username(requested_user).await
    }

    async fn create_api_key_for_user(
        &self,
        request: ApiKeyCreation<'_>,
    ) -> Result<ApiKeyGeneration, AuthServiceError> {
        let key_secret = new_session_token();
        let key_id = Uuid::new_v4().to_string();
        let hashed_secret = hash_session_token(&key_secret);
        let now = OffsetDateTime::now_utc();
        let expires_at = now
            .checked_add(time::Duration::seconds(
                i64::try_from(request.lifetime.as_secs())
                    .map_err(|error| StorageError::invalid_data(error.to_string()))?,
            ))
            .ok_or_else(|| StorageError::invalid_data("invalid token lifetime"))?;

        match self
            .store
            .create_api_key(CreateApiKeyInput {
                id: key_id.clone(),
                hashed_secret,
                user_id: request.target_user.id,
                last_used: now,
                expires_at,
                created_at: now,
                updated_at: now,
                login_type: request.login_type,
                scopes: request.scopes,
                token_name: request.token_name,
                lifetime_seconds: i64::try_from(request.lifetime.as_secs())
                    .map_err(|error| StorageError::invalid_data(error.to_string()))?,
                allow_list: request.allow_list,
            })
            .await
        {
            Ok(_) => Ok(ApiKeyGeneration {
                key_id,
                response: GenerateApiKeyResponse { key: key_secret },
            }),
            Err(CreateApiKeyStoreError::DuplicateTokenName) => Err(AuthServiceError::conflict(
                "Failed to create API key.",
                "A token with this name already exists.",
            )),
            Err(CreateApiKeyStoreError::Storage(error)) => Err(AuthServiceError::Storage(error)),
        }
    }
}

pub fn actor_from_user(user: &AuthenticatedUser) -> Actor {
    Actor {
        user_id: user.id,
        username: user.username.clone(),
        organization_ids: user.organization_ids.clone(),
        site_roles: user.roles.iter().map(|role| role.name.clone()).collect(),
        org_roles: user.org_roles.clone(),
        groups: vec![],
        scope: None,
    }
}

fn validate_first_user_request(request: &CreateFirstUserRequest) -> Vec<ValidationError> {
    let mut validations = Vec::new();
    push_validation(&mut validations, "email", validate_email(&request.email));
    push_validation(
        &mut validations,
        "username",
        validate_username(&request.username),
    );
    push_validation(&mut validations, "name", validate_real_name(&request.name));
    push_validation(
        &mut validations,
        "password",
        validate_password(&request.password),
    );
    validations
}

fn push_validation(
    validations: &mut Vec<ValidationError>,
    field: &str,
    result: Result<(), PasswordError>,
) {
    if let Err(error) = result {
        validations.push(ValidationError {
            field: field.to_owned(),
            detail: error.to_string(),
        });
    }
}

/// Request-scoped failures for external-auth flows.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExternalAuthServiceError {
    /// The client supplied a bad request or the provider rejected the flow.
    #[error("{0}")]
    BadRequest(String),
    /// The backing store failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// An upstream provider call or local integration failed.
    #[error("{0}")]
    Internal(String),
}

impl ExternalAuthServiceError {
    /// Returns the user-facing detail string.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::BadRequest(detail) | Self::Internal(detail) => detail.clone(),
            Self::Storage(error) => error.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExternalAuthTokenSet {
    access_token: String,
    refresh_token: String,
    token_type: String,
    scopes: Vec<String>,
    expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ExternalAuthValidation {
    authenticated: bool,
    validate_error: String,
    user: Option<ExternalAuthUser>,
    installations: Vec<ExternalAuthAppInstallation>,
    app_installable: bool,
}

#[async_trait]
trait ExternalAuthProviderAdapter: Send + Sync {
    async fn authorize_device(
        &self,
        provider: &ExternalAuthLinkProvider,
    ) -> Result<ExternalAuthDevice, ExternalAuthServiceError>;

    async fn exchange_callback_code(
        &self,
        provider: &ExternalAuthLinkProvider,
        code: &str,
    ) -> Result<ExternalAuthTokenSet, ExternalAuthServiceError>;

    async fn exchange_device_code(
        &self,
        provider: &ExternalAuthLinkProvider,
        request: &ExternalAuthDeviceExchangeRequest,
    ) -> Result<ExternalAuthTokenSet, ExternalAuthServiceError>;

    async fn refresh_token(
        &self,
        provider: &ExternalAuthLinkProvider,
        link: &ExternalAuthLinkRecord,
    ) -> Result<ExternalAuthTokenSet, ExternalAuthServiceError>;

    async fn validate(
        &self,
        provider: &ExternalAuthLinkProvider,
        access_token: &str,
    ) -> Result<ExternalAuthValidation, ExternalAuthServiceError>;

    async fn revoke(
        &self,
        provider: &ExternalAuthLinkProvider,
        link: &ExternalAuthLinkRecord,
    ) -> Result<bool, ExternalAuthServiceError>;
}

#[derive(Clone, Debug)]
struct HttpExternalAuthProviderAdapter {
    http_client: reqwest::Client,
}

impl HttpExternalAuthProviderAdapter {
    fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(EXTERNAL_AUTH_HTTP_TIMEOUT_SECS))
                .build()?,
        })
    }
}

#[async_trait]
impl ExternalAuthProviderAdapter for HttpExternalAuthProviderAdapter {
    async fn authorize_device(
        &self,
        provider: &ExternalAuthLinkProvider,
    ) -> Result<ExternalAuthDevice, ExternalAuthServiceError> {
        if provider.device_authorization_url.trim().is_empty() {
            return Err(ExternalAuthServiceError::BadRequest(
                "Git auth provider does not support device flow.".to_owned(),
            ));
        }

        let response = post_form(
            &self.http_client,
            &provider.device_authorization_url,
            &[
                ("client_id", provider.client_id.clone()),
                ("scope", provider.scopes.join(" ")),
            ],
            None,
        )
        .await?;

        let device_code = string_field(&response, "device_code").ok_or_else(|| {
            ExternalAuthServiceError::Internal(
                "provider device response is missing device_code".to_owned(),
            )
        })?;
        let user_code = string_field(&response, "user_code").ok_or_else(|| {
            ExternalAuthServiceError::Internal(
                "provider device response is missing user_code".to_owned(),
            )
        })?;
        let verification_uri = string_field(&response, "verification_uri")
            .or_else(|| string_field(&response, "verification_uri_complete"))
            .ok_or_else(|| {
                ExternalAuthServiceError::Internal(
                    "provider device response is missing verification_uri".to_owned(),
                )
            })?;

        Ok(ExternalAuthDevice {
            device_code,
            user_code,
            verification_uri,
            expires_in: integer_field(&response, "expires_in").unwrap_or(900),
            interval: integer_field(&response, "interval").unwrap_or(5),
        })
    }

    async fn exchange_callback_code(
        &self,
        provider: &ExternalAuthLinkProvider,
        code: &str,
    ) -> Result<ExternalAuthTokenSet, ExternalAuthServiceError> {
        if provider.token_url.trim().is_empty() {
            return Err(ExternalAuthServiceError::Internal(
                "provider token endpoint is not configured".to_owned(),
            ));
        }

        let response = post_form(
            &self.http_client,
            &provider.token_url,
            &[
                ("client_id", provider.client_id.clone()),
                ("client_secret", provider.client_secret.clone()),
                ("grant_type", "authorization_code".to_owned()),
                ("code", code.to_owned()),
                ("redirect_uri", provider.callback_url.clone()),
            ],
            None,
        )
        .await?;

        parse_token_set(&response)
    }

    async fn exchange_device_code(
        &self,
        provider: &ExternalAuthLinkProvider,
        request: &ExternalAuthDeviceExchangeRequest,
    ) -> Result<ExternalAuthTokenSet, ExternalAuthServiceError> {
        if provider.token_url.trim().is_empty() {
            return Err(ExternalAuthServiceError::Internal(
                "provider token endpoint is not configured".to_owned(),
            ));
        }

        let response = post_form(
            &self.http_client,
            &provider.token_url,
            &[
                ("client_id", provider.client_id.clone()),
                ("client_secret", provider.client_secret.clone()),
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
                ),
                ("device_code", request.device_code.clone()),
            ],
            None,
        )
        .await?;

        parse_token_set(&response)
    }

    async fn refresh_token(
        &self,
        provider: &ExternalAuthLinkProvider,
        link: &ExternalAuthLinkRecord,
    ) -> Result<ExternalAuthTokenSet, ExternalAuthServiceError> {
        if provider.no_refresh || !provider.allow_refresh {
            return Err(ExternalAuthServiceError::BadRequest(
                "token expired, refreshing is disabled".to_owned(),
            ));
        }
        if provider.token_url.trim().is_empty() {
            return Err(ExternalAuthServiceError::Internal(
                "provider token endpoint is not configured".to_owned(),
            ));
        }
        if link.refresh_token.trim().is_empty() {
            return Err(ExternalAuthServiceError::BadRequest(
                "token expired and refresh token is not set".to_owned(),
            ));
        }

        let response = post_form(
            &self.http_client,
            &provider.token_url,
            &[
                ("client_id", provider.client_id.clone()),
                ("client_secret", provider.client_secret.clone()),
                ("grant_type", "refresh_token".to_owned()),
                ("refresh_token", link.refresh_token.clone()),
            ],
            None,
        )
        .await?;

        parse_token_set(&response)
    }

    async fn validate(
        &self,
        provider: &ExternalAuthLinkProvider,
        access_token: &str,
    ) -> Result<ExternalAuthValidation, ExternalAuthServiceError> {
        let validation_url = if !provider.validate_url.trim().is_empty() {
            Some(provider.validate_url.as_str())
        } else if !provider.user_url.trim().is_empty() {
            Some(provider.user_url.as_str())
        } else {
            None
        };

        let Some(validation_url) = validation_url else {
            return Ok(ExternalAuthValidation {
                authenticated: true,
                validate_error: String::new(),
                user: None,
                installations: Vec::new(),
                app_installable: false,
            });
        };

        let response = bearer_get(&self.http_client, validation_url, access_token).await;
        let (authenticated, validate_error, user) = match response {
            Ok(value) => (true, String::new(), external_auth_user_from_value(&value)),
            Err(ExternalAuthServiceError::BadRequest(detail)) => (false, detail, None),
            Err(error) => return Err(error),
        };

        let (installations, app_installable) =
            fetch_installations(self, provider, access_token).await.unwrap_or_else(|error| {
                warn!(error = %error, provider = provider.id, "failed to refresh app installations");
                (Vec::new(), false)
            });

        Ok(ExternalAuthValidation {
            authenticated,
            validate_error,
            user,
            installations,
            app_installable,
        })
    }

    async fn revoke(
        &self,
        provider: &ExternalAuthLinkProvider,
        link: &ExternalAuthLinkRecord,
    ) -> Result<bool, ExternalAuthServiceError> {
        if !provider.supports_revocation || provider.revoke_url.trim().is_empty() {
            return Ok(false);
        }

        let response = if provider.provider_type.eq_ignore_ascii_case("github") {
            self.http_client
                .delete(&provider.revoke_url)
                .basic_auth(&provider.client_id, Some(&provider.client_secret))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .body(format!("{{\"access_token\":{}}}", json!(link.access_token)))
                .send()
                .await
                .map_err(|error| ExternalAuthServiceError::Internal(error.to_string()))?
        } else {
            let token = if !link.refresh_token.is_empty() {
                link.refresh_token.clone()
            } else {
                link.access_token.clone()
            };
            self.http_client
                .post(&provider.revoke_url)
                .form(&[
                    ("client_id", provider.client_id.clone()),
                    ("client_secret", provider.client_secret.clone()),
                    (
                        "token_type_hint",
                        if !link.refresh_token.is_empty() {
                            "refresh_token".to_owned()
                        } else {
                            "access_token".to_owned()
                        },
                    ),
                    ("token", token),
                ])
                .send()
                .await
                .map_err(|error| ExternalAuthServiceError::Internal(error.to_string()))?
        };

        let status = response.status();
        if provider.provider_type.eq_ignore_ascii_case("github") {
            if status == reqwest::StatusCode::NO_CONTENT {
                return Ok(true);
            }
        } else if status == reqwest::StatusCode::OK {
            return Ok(true);
        }

        let body = response.text().await.unwrap_or_default();
        Err(ExternalAuthServiceError::Internal(format!(
            "failed to revoke token: {} {}",
            status.as_u16(),
            body
        )))
    }
}

async fn fetch_installations(
    adapter: &HttpExternalAuthProviderAdapter,
    provider: &ExternalAuthLinkProvider,
    access_token: &str,
) -> Result<(Vec<ExternalAuthAppInstallation>, bool), ExternalAuthServiceError> {
    if provider.app_installations_url.trim().is_empty() {
        return Ok((Vec::new(), false));
    }

    match bearer_get(
        &adapter.http_client,
        &provider.app_installations_url,
        access_token,
    )
    .await
    {
        Ok(value) => Ok((external_auth_installations_from_value(&value), true)),
        Err(ExternalAuthServiceError::BadRequest(_)) => Ok((Vec::new(), false)),
        Err(error) => Err(error),
    }
}

/// External-auth lifecycle service used by the Rust handlers.
#[derive(Clone)]
pub struct ExternalAuthService<S> {
    store: S,
    adapter: Arc<dyn ExternalAuthProviderAdapter>,
}

impl<S> ExternalAuthService<S>
where
    S: AuthStore + Clone + Send + Sync + 'static,
{
    /// Creates the service with the default HTTP-backed provider adapter.
    pub fn new(store: S) -> Result<Self, reqwest::Error> {
        Ok(Self {
            store,
            adapter: Arc::new(HttpExternalAuthProviderAdapter::new()?),
        })
    }

    /// Lists configured providers and linked accounts for one user.
    pub async fn list(
        &self,
        providers: &[ExternalAuthLinkProvider],
        user_id: Uuid,
    ) -> Result<ListUserExternalAuthResponse, StorageError> {
        let mut links = self.store.list_external_auth_links(user_id).await?;
        for link in &mut links {
            if let Some(provider) = find_provider(providers, &link.provider_id) {
                *link = self
                    .reconcile_link(user_id, provider, link.clone(), false)
                    .await?;
            }
        }

        Ok(ListUserExternalAuthResponse {
            providers: providers.to_vec(),
            links: links.into_iter().map(to_public_link).collect(),
        })
    }

    /// Returns one provider state for one user.
    pub async fn get(
        &self,
        providers: &[ExternalAuthLinkProvider],
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<Option<ExternalAuthResponse>, StorageError> {
        let Some(provider) = find_provider(providers, provider_id) else {
            return Ok(None);
        };
        let link = self
            .store
            .find_external_auth_link(user_id, provider_id)
            .await?;
        let link = match link {
            Some(link) => Some(self.reconcile_link(user_id, provider, link, true).await?),
            None => None,
        };

        Ok(Some(ExternalAuthResponse {
            authenticated: link.as_ref().is_some_and(|value| value.authenticated),
            device: provider.device,
            display_name: provider.display_name.clone(),
            supports_revocation: provider.supports_revocation,
            user: link.as_ref().and_then(|value| value.user.clone()),
            app_installable: link.as_ref().is_some_and(|value| value.app_installable),
            installations: link.map(|value| value.installations).unwrap_or_default(),
            app_install_url: provider.app_install_url.clone(),
        }))
    }

    /// Exchanges an OAuth callback code and persists the resulting link.
    pub async fn exchange_callback(
        &self,
        provider: &ExternalAuthLinkProvider,
        user_id: Uuid,
        code: &str,
    ) -> Result<ExternalAuthLinkRecord, ExternalAuthServiceError> {
        let token = self.adapter.exchange_callback_code(provider, code).await?;
        self.persist_token(provider, user_id, token, None).await
    }

    /// Starts device authorization for one provider.
    pub async fn authorize_device(
        &self,
        provider: &ExternalAuthLinkProvider,
    ) -> Result<ExternalAuthDevice, ExternalAuthServiceError> {
        self.adapter.authorize_device(provider).await
    }

    /// Exchanges a device code and persists the resulting link.
    pub async fn exchange_device(
        &self,
        provider: &ExternalAuthLinkProvider,
        user_id: Uuid,
        request: &ExternalAuthDeviceExchangeRequest,
    ) -> Result<ExternalAuthLinkRecord, ExternalAuthServiceError> {
        let token = self.adapter.exchange_device_code(provider, request).await?;
        self.persist_token(provider, user_id, token, None).await
    }

    /// Deletes one provider link and attempts provider-side revocation.
    pub async fn delete(
        &self,
        providers: &[ExternalAuthLinkProvider],
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<Option<DeleteExternalAuthByIdResponse>, StorageError> {
        let Some(provider) = find_provider(providers, provider_id) else {
            return Ok(None);
        };
        let Some(link) = self
            .store
            .find_external_auth_link(user_id, provider_id)
            .await?
        else {
            return Ok(None);
        };

        let revoke_result = self.adapter.revoke(provider, &link).await;
        self.store
            .delete_external_auth_link(user_id, provider_id)
            .await?;

        Ok(Some(match revoke_result {
            Ok(token_revoked) => DeleteExternalAuthByIdResponse {
                token_revoked,
                token_revocation_error: String::new(),
            },
            Err(error) => DeleteExternalAuthByIdResponse {
                token_revoked: false,
                token_revocation_error: error.detail(),
            },
        }))
    }

    async fn reconcile_link(
        &self,
        user_id: Uuid,
        provider: &ExternalAuthLinkProvider,
        mut link: ExternalAuthLinkRecord,
        detail: bool,
    ) -> Result<ExternalAuthLinkRecord, StorageError> {
        let now = OffsetDateTime::now_utc();
        let mut changed = false;

        if needs_refresh(provider, &link, now) {
            match self.adapter.refresh_token(provider, &link).await {
                Ok(tokens) => {
                    link.access_token = tokens.access_token;
                    link.refresh_token = tokens.refresh_token;
                    link.token_type = tokens.token_type;
                    link.scopes = tokens.scopes;
                    link.expires = tokens.expires_at;
                    link.refresh_error.clear();
                    link.last_refreshed_at = Some(now);
                    changed = true;
                }
                Err(ExternalAuthServiceError::BadRequest(detail)) => {
                    link.authenticated = false;
                    link.refresh_error = detail.clone();
                    link.validate_error = detail;
                    changed = true;
                }
                Err(ExternalAuthServiceError::Storage(error)) => return Err(error),
                Err(ExternalAuthServiceError::Internal(detail)) => {
                    link.authenticated = false;
                    link.validate_error = detail;
                    changed = true;
                }
            }
        }

        if detail || provider.allow_validate {
            match self.adapter.validate(provider, &link.access_token).await {
                Ok(validation) => {
                    link.authenticated = validation.authenticated;
                    link.validate_error = validation.validate_error;
                    link.user = validation.user;
                    link.installations = validation.installations;
                    link.app_installable = validation.app_installable;
                    link.last_validated_at = Some(now);
                    changed = true;
                }
                Err(ExternalAuthServiceError::BadRequest(detail)) => {
                    link.authenticated = false;
                    link.validate_error = detail;
                    link.user = None;
                    link.installations.clear();
                    link.app_installable = false;
                    link.last_validated_at = Some(now);
                    changed = true;
                }
                Err(ExternalAuthServiceError::Storage(error)) => return Err(error),
                Err(ExternalAuthServiceError::Internal(detail)) => {
                    link.authenticated = false;
                    link.validate_error = detail;
                    link.last_validated_at = Some(now);
                    changed = true;
                }
            }
        }

        if changed {
            return self
                .store
                .upsert_external_auth_link(
                    user_id,
                    &UpsertExternalAuthLinkInput {
                        provider_id: link.provider_id.clone(),
                        access_token: link.access_token.clone(),
                        refresh_token: link.refresh_token.clone(),
                        token_type: link.token_type.clone(),
                        scopes: link.scopes.clone(),
                        expires_at: link.expires,
                        authenticated: link.authenticated,
                        validate_error: link.validate_error.clone(),
                        refresh_error: link.refresh_error.clone(),
                        last_validated_at: link.last_validated_at,
                        last_refreshed_at: link.last_refreshed_at,
                        user: link.user.clone(),
                        installations: link.installations.clone(),
                        app_installable: link.app_installable,
                    },
                )
                .await;
        }

        Ok(link)
    }

    async fn persist_token(
        &self,
        provider: &ExternalAuthLinkProvider,
        user_id: Uuid,
        tokens: ExternalAuthTokenSet,
        refresh_timestamp: Option<OffsetDateTime>,
    ) -> Result<ExternalAuthLinkRecord, ExternalAuthServiceError> {
        let now = OffsetDateTime::now_utc();
        let validation = self
            .adapter
            .validate(provider, &tokens.access_token)
            .await?;

        self.store
            .upsert_external_auth_link(
                user_id,
                &UpsertExternalAuthLinkInput {
                    provider_id: provider.id.clone(),
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                    token_type: tokens.token_type,
                    scopes: tokens.scopes,
                    expires_at: tokens.expires_at,
                    authenticated: validation.authenticated,
                    validate_error: validation.validate_error,
                    refresh_error: String::new(),
                    last_validated_at: Some(now),
                    last_refreshed_at: refresh_timestamp,
                    user: validation.user,
                    installations: validation.installations,
                    app_installable: validation.app_installable,
                },
            )
            .await
            .map_err(ExternalAuthServiceError::Storage)
    }
}

fn find_provider<'a>(
    providers: &'a [ExternalAuthLinkProvider],
    provider_id: &str,
) -> Option<&'a ExternalAuthLinkProvider> {
    providers
        .iter()
        .find(|provider| provider.id.eq_ignore_ascii_case(provider_id))
}

fn needs_refresh(
    provider: &ExternalAuthLinkProvider,
    link: &ExternalAuthLinkRecord,
    now: OffsetDateTime,
) -> bool {
    if provider.no_refresh || !provider.allow_refresh || link.refresh_token.trim().is_empty() {
        return false;
    }

    link.expires
        <= now
            .checked_add(time::Duration::seconds(EXTERNAL_AUTH_REFRESH_WINDOW_SECS))
            .unwrap_or(now)
}

fn to_public_link(link: ExternalAuthLinkRecord) -> ExternalAuthLink {
    ExternalAuthLink {
        provider_id: link.provider_id,
        created_at: link.created_at,
        updated_at: link.updated_at,
        has_refresh_token: !link.refresh_token.is_empty(),
        expires: link.expires,
        authenticated: link.authenticated,
        validate_error: link.validate_error,
    }
}

/// Returns `true` when the error represents a transient HTTP failure that
/// should be retried (429, 5xx, or connection-level errors).
///
/// Both `bearer_get_once` and `post_form_once` already classify errors so
/// that only transient failures (5xx, 429, connection/timeout) are wrapped
/// as `Internal`, while client errors (4xx except 429) become `BadRequest`.
/// Therefore every `Internal` variant is safe to retry.
fn is_retryable_external_auth_error(error: &ExternalAuthServiceError) -> bool {
    matches!(error, ExternalAuthServiceError::Internal(_))
}

/// Retry strategy used for external auth provider HTTP calls.
fn external_auth_retry_strategy() -> coder_core::retry::RetryStrategy {
    coder_core::retry::RetryStrategy::ExponentialBackoff {
        initial_delay: Duration::from_secs(1),
        max_attempts: 3,
        max_delay: Duration::from_secs(10),
    }
}

async fn bearer_get(
    http_client: &reqwest::Client,
    url: &str,
    access_token: &str,
) -> Result<Value, ExternalAuthServiceError> {
    let url_owned = url.to_owned();
    let token_owned = access_token.to_owned();

    coder_core::retry::retry_with_strategy(
        external_auth_retry_strategy(),
        is_retryable_external_auth_error,
        || {
            let u = url_owned.clone();
            let t = token_owned.clone();
            let client = http_client.clone();
            async move { bearer_get_once(&client, &u, &t).await }
        },
    )
    .await
}

async fn bearer_get_once(
    http_client: &reqwest::Client,
    url: &str,
    access_token: &str,
) -> Result<Value, ExternalAuthServiceError> {
    let response = http_client
        .get(url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|error| ExternalAuthServiceError::Internal(error.to_string()))?;

    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response
        .text()
        .await
        .map_err(|error| ExternalAuthServiceError::Internal(error.to_string()))?;

    if matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) {
        return Err(ExternalAuthServiceError::BadRequest(
            "token failed to validate".to_owned(),
        ));
    }
    if !status.is_success() {
        let detail = format!("status {}: body: {body}", status.as_u16());
        // Classify 4xx (except 429) as BadRequest (non-retryable), matching
        // the same logic in `post_form_once`.  Only 5xx, 429, and connection
        // errors should be retried.
        if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ExternalAuthServiceError::BadRequest(detail));
        }
        return Err(ExternalAuthServiceError::Internal(detail));
    }

    parse_response_body(content_type.as_deref(), &body)
}

async fn post_form(
    http_client: &reqwest::Client,
    url: &str,
    fields: &[(&str, String)],
    bearer_token: Option<&str>,
) -> Result<Value, ExternalAuthServiceError> {
    let url_owned = url.to_owned();
    let fields_owned: Vec<(String, String)> = fields
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect();
    let token_owned = bearer_token.map(str::to_owned);

    coder_core::retry::retry_with_strategy(
        external_auth_retry_strategy(),
        is_retryable_external_auth_error,
        || {
            let u = url_owned.clone();
            let f = fields_owned.clone();
            let t = token_owned.clone();
            let client = http_client.clone();
            async move { post_form_once(&client, &u, &f, t.as_deref()).await }
        },
    )
    .await
}

async fn post_form_once(
    http_client: &reqwest::Client,
    url: &str,
    form: &[(String, String)],
    bearer_token: Option<&str>,
) -> Result<Value, ExternalAuthServiceError> {
    let mut request = http_client.post(url).header("Accept", "application/json");
    if let Some(token) = bearer_token.filter(|value| !value.is_empty()) {
        request = request.bearer_auth(token);
    }
    let response = request
        .form(form)
        .send()
        .await
        .map_err(|error| ExternalAuthServiceError::Internal(error.to_string()))?;

    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response
        .text()
        .await
        .map_err(|error| ExternalAuthServiceError::Internal(error.to_string()))?;
    let parsed = parse_response_body(content_type.as_deref(), &body)?;

    if !status.is_success() {
        let detail = external_auth_error_detail(&parsed).unwrap_or_else(|| {
            if body.is_empty() {
                format!("status {}", status.as_u16())
            } else {
                format!("status {}: body: {body}", status.as_u16())
            }
        });
        // Classify 4xx (except 429) as BadRequest (non-retryable) and
        // everything else (5xx, 429) as Internal so the retry wrapper can
        // re-attempt the request on transient failures.
        if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ExternalAuthServiceError::BadRequest(detail));
        }
        return Err(ExternalAuthServiceError::Internal(detail));
    }

    Ok(parsed)
}

fn parse_response_body(
    content_type: Option<&str>,
    body: &str,
) -> Result<Value, ExternalAuthServiceError> {
    if body.trim().is_empty() {
        return Ok(json!({}));
    }

    if content_type.is_some_and(|value| value.contains("application/x-www-form-urlencoded")) {
        let object = form_urlencoded::parse(body.as_bytes())
            .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
            .collect::<serde_json::Map<String, Value>>();
        return Ok(Value::Object(object));
    }

    serde_json::from_str(body)
        .map_err(|error| ExternalAuthServiceError::Internal(error.to_string()))
}

fn parse_token_set(response: &Value) -> Result<ExternalAuthTokenSet, ExternalAuthServiceError> {
    if let Some(detail) = external_auth_error_detail(response) {
        return Err(ExternalAuthServiceError::BadRequest(detail));
    }

    let access_token = string_field(response, "access_token").ok_or_else(|| {
        ExternalAuthServiceError::Internal(
            "provider token response is missing access_token".to_owned(),
        )
    })?;
    let expires_in = integer_field(response, "expires_in").unwrap_or_default();
    let expires_at = if expires_in <= 0 {
        OffsetDateTime::now_utc()
            .checked_add(time::Duration::seconds(NON_EXPIRING_TOKEN_SECS))
            .unwrap_or_else(OffsetDateTime::now_utc)
    } else {
        OffsetDateTime::now_utc()
            .checked_add(time::Duration::seconds(i64::from(expires_in)))
            .unwrap_or_else(OffsetDateTime::now_utc)
    };

    Ok(ExternalAuthTokenSet {
        access_token,
        refresh_token: string_field(response, "refresh_token").unwrap_or_default(),
        token_type: string_field(response, "token_type").unwrap_or_default(),
        scopes: response_scopes(response),
        expires_at,
    })
}

fn response_scopes(response: &Value) -> Vec<String> {
    if let Some(values) = response.get("scope").and_then(Value::as_array) {
        return values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
    }

    string_field(response, "scope")
        .map(|value| {
            value
                .split([' ', ','])
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn external_auth_error_detail(response: &Value) -> Option<String> {
    let error = string_field(response, "error")?;
    let description = string_field(response, "error_description").unwrap_or_default();
    if description.is_empty() {
        Some(error)
    } else {
        Some(format!("{error}: {description}"))
    }
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn integer_field(value: &Value, field: &str) -> Option<i32> {
    let field_value = value.get(field)?;
    field_value
        .as_i64()
        .and_then(|raw| i32::try_from(raw).ok())
        .or_else(|| field_value.as_str().and_then(|raw| raw.parse::<i32>().ok()))
}

fn external_auth_user_from_value(value: &Value) -> Option<ExternalAuthUser> {
    let id = value
        .get("id")
        .and_then(Value::as_i64)
        .or_else(|| {
            value
                .get("id")
                .and_then(Value::as_str)
                .and_then(|raw| raw.parse().ok())
        })
        .unwrap_or_default();
    let login = value
        .get("login")
        .and_then(Value::as_str)
        .or_else(|| value.get("username").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned();

    if id == 0 && login.is_empty() {
        return None;
    }

    Some(ExternalAuthUser {
        id,
        login,
        avatar_url: value
            .get("avatar_url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        profile_url: value
            .get("profile_url")
            .and_then(Value::as_str)
            .or_else(|| value.get("html_url").and_then(Value::as_str))
            .unwrap_or_default()
            .to_owned(),
        name: value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

// ---------------------------------------------------------------------------
// OAuth2 Provider Service
// ---------------------------------------------------------------------------

/// Errors specific to OAuth2 provider operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OAuth2ProviderError {
    /// The backing store failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The request is invalid.
    #[error("{message}")]
    BadRequest { message: String },
    /// The resource was not found.
    #[error("{message}")]
    NotFound { message: String },
    /// The caller is not authorized.
    #[error("{message}")]
    Unauthorized { message: String },
}

impl OAuth2ProviderError {
    #[must_use]
    fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
        }
    }

    #[must_use]
    fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound {
            message: message.into(),
        }
    }

    #[must_use]
    fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized {
            message: message.into(),
        }
    }
}

/// OAuth2 provider service for app registration, authorization, and token exchange.
///
/// This implements Coder as an OAuth2 *provider* (not consumer), allowing
/// third-party applications to authenticate against the Coder deployment.
#[derive(Clone)]
pub struct OAuth2ProviderService<S> {
    store: S,
}

impl<S> OAuth2ProviderService<S>
where
    S: coder_core::IdentityStore + AuthStore + Clone + Send + Sync + 'static,
{
    /// Creates the OAuth2 provider service.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Lists all registered OAuth2 provider applications.
    pub async fn list_apps(
        &self,
    ) -> Result<Vec<coder_core::identity::OAuth2ProviderAppRecord>, OAuth2ProviderError> {
        let apps = self.store.list_oauth2_provider_apps().await?;
        Ok(apps)
    }

    /// Creates a new OAuth2 provider application.
    ///
    /// `created_by` is `None` for dynamically registered clients (RFC 7591)
    /// which have no user context, matching Go's `InsertOAuth2ProviderApp`.
    pub async fn create_app(
        &self,
        name: &str,
        icon: &str,
        callback_url: &str,
        created_by: Option<Uuid>,
    ) -> Result<coder_core::identity::OAuth2ProviderAppRecord, OAuth2ProviderError> {
        if name.trim().is_empty() {
            return Err(OAuth2ProviderError::bad_request("App name is required."));
        }
        if callback_url.trim().is_empty() {
            return Err(OAuth2ProviderError::bad_request(
                "Callback URL is required.",
            ));
        }

        let input = coder_core::identity::CreateOAuth2ProviderAppInput {
            name: name.trim().to_owned(),
            icon: icon.to_owned(),
            callback_url: callback_url.trim().to_owned(),
            created_by,
        };
        let app = self.store.create_oauth2_provider_app(&input).await?;
        Ok(app)
    }

    /// Gets an OAuth2 provider application by ID.
    pub async fn get_app(
        &self,
        app_id: Uuid,
    ) -> Result<coder_core::identity::OAuth2ProviderAppRecord, OAuth2ProviderError> {
        self.store
            .find_oauth2_provider_app_by_id(app_id)
            .await?
            .ok_or_else(|| OAuth2ProviderError::not_found("OAuth2 app not found."))
    }

    /// Updates an OAuth2 provider application.
    pub async fn update_app(
        &self,
        app_id: Uuid,
        name: &str,
        icon: &str,
        callback_url: &str,
    ) -> Result<coder_core::identity::OAuth2ProviderAppRecord, OAuth2ProviderError> {
        if name.trim().is_empty() {
            return Err(OAuth2ProviderError::bad_request("App name is required."));
        }
        if callback_url.trim().is_empty() {
            return Err(OAuth2ProviderError::bad_request(
                "Callback URL is required.",
            ));
        }

        // Fetch existing app to preserve redirect_uris when not explicitly provided.
        let existing = self.get_app(app_id).await?;

        let input = coder_core::identity::UpdateOAuth2ProviderAppInput {
            id: app_id,
            name: name.trim().to_owned(),
            icon: icon.to_owned(),
            callback_url: callback_url.trim().to_owned(),
            redirect_uris: existing.redirect_uris,
        };
        self.store
            .update_oauth2_provider_app(&input)
            .await?
            .ok_or_else(|| OAuth2ProviderError::not_found("OAuth2 app not found."))
    }

    /// Deletes an OAuth2 provider application and all its secrets/codes/tokens.
    pub async fn delete_app(&self, app_id: Uuid) -> Result<(), OAuth2ProviderError> {
        if !self.store.delete_oauth2_provider_app(app_id).await? {
            return Err(OAuth2ProviderError::not_found("OAuth2 app not found."));
        }
        Ok(())
    }

    /// Lists all secrets for an OAuth2 provider application.
    pub async fn list_app_secrets(
        &self,
        app_id: Uuid,
    ) -> Result<Vec<coder_core::identity::OAuth2ProviderAppSecretRecord>, OAuth2ProviderError> {
        // Verify the app exists first.
        let _app = self.get_app(app_id).await?;
        let secrets = self.store.list_oauth2_provider_app_secrets(app_id).await?;
        Ok(secrets)
    }

    /// Creates a new secret for an OAuth2 provider application.
    ///
    /// Returns the raw secret (shown once) plus the stored record.
    pub async fn create_app_secret(
        &self,
        app_id: Uuid,
    ) -> Result<(String, coder_core::identity::OAuth2ProviderAppSecretRecord), OAuth2ProviderError>
    {
        use base64::Engine as _;
        use rand::RngCore;
        use sha2::Digest;

        let _app = self.get_app(app_id).await?;

        // Generate a 32-byte random secret and encode as URL-safe base64.
        let mut raw_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_bytes);
        let raw_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_bytes);

        // Hash with SHA-256 for storage.
        let hashed = sha2::Sha256::digest(raw_secret.as_bytes()).to_vec();

        // Display prefix: first 6 chars of the raw secret.
        let display_secret = if raw_secret.len() >= 6 {
            format!("{}******", &raw_secret[..6])
        } else {
            "******".to_owned()
        };

        let record = self
            .store
            .create_oauth2_provider_app_secret(
                app_id,
                raw_secret.as_bytes()[..8].as_ref(),
                &hashed,
                &display_secret,
            )
            .await?;
        Ok((raw_secret, record))
    }

    /// Deletes an OAuth2 provider app secret.
    ///
    /// Verifies that the secret belongs to the specified `app_id` before
    /// deleting, preventing cross-app secret deletion.
    pub async fn delete_app_secret(
        &self,
        app_id: Uuid,
        secret_id: Uuid,
    ) -> Result<(), OAuth2ProviderError> {
        // Verify the secret belongs to the specified app.
        let secrets = self.store.list_oauth2_provider_app_secrets(app_id).await?;
        if !secrets.iter().any(|s| s.id == secret_id) {
            return Err(OAuth2ProviderError::not_found(
                "OAuth2 app secret not found for this app.",
            ));
        }
        if !self
            .store
            .delete_oauth2_provider_app_secret(secret_id)
            .await?
        {
            return Err(OAuth2ProviderError::not_found(
                "OAuth2 app secret not found.",
            ));
        }
        Ok(())
    }

    /// Creates an authorization code for the given user + app.
    ///
    /// This is called when the user consents to granting the app access.
    /// Returns the raw authorization code to be sent to the callback URL.
    pub async fn create_authorization_code(
        &self,
        app_id: Uuid,
        user_id: Uuid,
        resource_uri: &str,
        code_challenge: &str,
        code_challenge_method: &str,
    ) -> Result<String, OAuth2ProviderError> {
        use base64::Engine as _;
        use rand::RngCore;
        use sha2::Digest;

        let _app = self.get_app(app_id).await?;

        // Generate a 32-byte random code and encode as URL-safe base64.
        let mut raw_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_bytes);
        let raw_code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_bytes);

        let hashed = sha2::Sha256::digest(raw_code.as_bytes()).to_vec();
        let prefix = if raw_code.len() >= 8 {
            raw_code.as_bytes()[..8].to_vec()
        } else {
            raw_code.as_bytes().to_vec()
        };

        let expires_at = OffsetDateTime::now_utc()
            .checked_add(time::Duration::minutes(10))
            .ok_or_else(|| {
                OAuth2ProviderError::bad_request("Failed to compute authorization code expiry.")
            })?;

        self.store
            .create_oauth2_provider_app_code(
                app_id,
                user_id,
                &prefix,
                &hashed,
                expires_at,
                resource_uri,
                code_challenge,
                code_challenge_method,
                None,
                None,
            )
            .await?;

        Ok(raw_code)
    }

    /// Exchanges an authorization code for an access token.
    ///
    /// Implements the `authorization_code` grant type from RFC 6749 Section 4.1.3.
    pub async fn exchange_code(
        &self,
        raw_code: &str,
        client_id: Uuid,
        client_secret: &str,
        code_verifier: &str,
    ) -> Result<OAuth2TokenResult, OAuth2ProviderError> {
        use sha2::Digest;

        if raw_code.is_empty() {
            return Err(OAuth2ProviderError::bad_request("Code is required."));
        }

        // Find the code by its prefix.
        let prefix = if raw_code.len() >= 8 {
            raw_code.as_bytes()[..8].to_vec()
        } else {
            raw_code.as_bytes().to_vec()
        };
        let code_record = self
            .store
            .find_oauth2_provider_app_code_by_prefix(&prefix)
            .await?
            .ok_or_else(|| {
                OAuth2ProviderError::unauthorized("Invalid or expired authorization code.")
            })?;

        // Verify the code has not expired.
        if code_record.expires_at < OffsetDateTime::now_utc() {
            let _ = self
                .store
                .delete_oauth2_provider_app_code(code_record.id)
                .await;
            return Err(OAuth2ProviderError::unauthorized(
                "Authorization code has expired.",
            ));
        }

        // Verify the code hash (constant-time comparison to prevent
        // timing side-channel attacks).
        let code_hash = sha2::Sha256::digest(raw_code.as_bytes()).to_vec();
        if !bool::from(
            code_hash
                .as_slice()
                .ct_eq(code_record.hashed_secret.as_slice()),
        ) {
            // Delete the code on hash mismatch to enforce single-use
            // (RFC 6749 §10.5: revoke on any failed exchange attempt).
            let _ = self
                .store
                .delete_oauth2_provider_app_code(code_record.id)
                .await;
            return Err(OAuth2ProviderError::unauthorized(
                "Invalid authorization code.",
            ));
        }

        // Verify app ownership BEFORE leaking any information about
        // client secrets or PKCE verifiers (prevents oracle attacks).
        // If the client_id doesn't match, delete the code to prevent reuse
        // (RFC 6749 §4.1.2: authorization codes MUST be single-use).
        if code_record.app_id != client_id {
            let _ = self
                .store
                .delete_oauth2_provider_app_code(code_record.id)
                .await;
            return Err(OAuth2ProviderError::unauthorized(
                "Authorization code does not belong to this client.",
            ));
        }

        // Verify PKCE if a code challenge was used.
        // On any PKCE failure, delete the code to enforce single-use
        // (RFC 6749 §10.5: revoke on failed exchange attempt).
        if !code_record.code_challenge.is_empty() {
            if code_verifier.is_empty() {
                let _ = self
                    .store
                    .delete_oauth2_provider_app_code(code_record.id)
                    .await;
                return Err(OAuth2ProviderError::bad_request(
                    "Code verifier is required for PKCE.",
                ));
            }
            let valid = verify_pkce(
                code_verifier,
                &code_record.code_challenge,
                &code_record.code_challenge_method,
            );
            if !valid {
                let _ = self
                    .store
                    .delete_oauth2_provider_app_code(code_record.id)
                    .await;
                return Err(OAuth2ProviderError::unauthorized(
                    "PKCE code verifier is invalid.",
                ));
            }
        }

        // Verify the client secret by hashing it and comparing against
        // all registered secrets for this app.
        let secret_hash = sha2::Sha256::digest(client_secret.as_bytes()).to_vec();
        let secrets = self
            .store
            .list_oauth2_provider_app_secrets(code_record.app_id)
            .await?;
        // Iterate ALL secrets without short-circuiting so total elapsed time
        // does not reveal which position matched (prevents timing side-channel).
        // Use fold (like refresh_token) to avoid conditional struct moves that
        // could leak timing via heap allocation differences.
        let secret_valid = secrets.iter().fold(false, |acc, s| {
            acc | bool::from(s.hashed_secret.as_slice().ct_eq(secret_hash.as_slice()))
        });
        // The second pass to find the matched secret is NOT timing-sensitive
        // because the constant-time validity check above already completed.
        let matched_secret = if secret_valid {
            secrets
                .into_iter()
                .find(|s| bool::from(s.hashed_secret.as_slice().ct_eq(secret_hash.as_slice())))
        } else {
            None
        };
        let matched_secret = match matched_secret {
            Some(s) => s,
            None => {
                // Delete the code on client_secret failure to enforce single-use
                // (RFC 6749 §10.5: revoke on failed exchange attempt).
                let _ = self
                    .store
                    .delete_oauth2_provider_app_code(code_record.id)
                    .await;
                return Err(OAuth2ProviderError::unauthorized(
                    "Invalid client credentials.",
                ));
            }
        };

        // Delete the code (single-use).  Propagate errors so that tokens
        // are never issued if the code cannot be invalidated (RFC 6749 §10.5).
        if !self
            .store
            .delete_oauth2_provider_app_code(code_record.id)
            .await?
        {
            return Err(OAuth2ProviderError::unauthorized(
                "Authorization code already consumed.",
            ));
        }

        // Generate tokens.
        let result = self
            .generate_token_pair(
                matched_secret.id,
                code_record.user_id,
                &code_record.resource_uri,
            )
            .await?;

        Ok(result)
    }

    /// Refreshes an access token using a refresh token.
    ///
    /// Implements the `refresh_token` grant type from RFC 6749 Section 6.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        client_id: Uuid,
        client_secret: &str,
    ) -> Result<OAuth2TokenResult, OAuth2ProviderError> {
        use sha2::Digest;

        if refresh_token.is_empty() {
            return Err(OAuth2ProviderError::bad_request(
                "Refresh token is required.",
            ));
        }

        let refresh_hash = sha2::Sha256::digest(refresh_token.as_bytes()).to_vec();
        let token_record = self
            .store
            .find_oauth2_provider_app_token_by_refresh_hash(&refresh_hash)
            .await?
            .ok_or_else(|| OAuth2ProviderError::unauthorized("Invalid refresh token."))?;

        // Verify the token has not expired.
        if token_record.expires_at < OffsetDateTime::now_utc() {
            let _ = self
                .store
                .delete_oauth2_provider_app_token(token_record.id)
                .await;
            return Err(OAuth2ProviderError::unauthorized(
                "Refresh token has expired.",
            ));
        }

        // Verify secret belongs to the right app.
        let secret = self
            .store
            .find_oauth2_provider_app_secret_by_id(token_record.app_secret_id)
            .await?
            .ok_or_else(|| OAuth2ProviderError::unauthorized("App secret not found."))?;
        if secret.app_id != client_id {
            return Err(OAuth2ProviderError::unauthorized(
                "Refresh token does not belong to this client.",
            ));
        }

        // Verify the client secret (RFC 6749 Section 6: confidential clients
        // MUST authenticate when refreshing tokens).
        let client_secret_hash = sha2::Sha256::digest(client_secret.as_bytes()).to_vec();
        let app_secrets = self
            .store
            .list_oauth2_provider_app_secrets(secret.app_id)
            .await?;
        // Iterate ALL secrets without short-circuiting so total elapsed time
        // does not reveal which position matched (prevents timing side-channel).
        let secret_valid = app_secrets.iter().fold(false, |acc, s| {
            acc | bool::from(
                s.hashed_secret
                    .as_slice()
                    .ct_eq(client_secret_hash.as_slice()),
            )
        });
        if !secret_valid {
            return Err(OAuth2ProviderError::unauthorized(
                "Invalid client credentials.",
            ));
        }

        // Delete the old token.  Propagate errors so that token replay
        // is prevented if deletion fails (RFC 6749 §10.4).  Check the
        // bool return to detect concurrent refresh attempts (race).
        if !self
            .store
            .delete_oauth2_provider_app_token(token_record.id)
            .await?
        {
            return Err(OAuth2ProviderError::unauthorized(
                "Refresh token already consumed.",
            ));
        }

        // Also delete the old API key so the previous access token can no
        // longer authenticate.  The access token IS the API key secret, so
        // leaving the key around means the old token remains valid.
        let _ = self.store.delete_api_key(&token_record.api_key_id).await;

        // Generate a new token pair.
        let result = self
            .generate_token_pair(
                token_record.app_secret_id,
                token_record.user_id,
                &token_record.audience,
            )
            .await?;

        Ok(result)
    }

    /// Revokes all tokens for a given app + user combination.
    ///
    /// Also deletes the underlying API keys so that previously issued access
    /// tokens can no longer authenticate.
    pub async fn revoke_tokens(
        &self,
        app_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, OAuth2ProviderError> {
        // Collect API key IDs before deleting the token records, so we can
        // clean up the associated API keys afterwards.
        let tokens = self
            .store
            .list_oauth2_provider_app_tokens_by_app_and_user(app_id, user_id)
            .await?;
        let api_key_ids: Vec<String> = tokens.iter().map(|t| t.api_key_id.clone()).collect();

        let count = self
            .store
            .delete_oauth2_provider_app_tokens_by_app_and_user(app_id, user_id)
            .await?;

        // Best-effort cleanup of associated API keys.
        for key_id in &api_key_ids {
            let _ = self.store.delete_api_key(key_id).await;
        }

        Ok(count)
    }

    /// Internal: generates a new access + refresh token pair.
    async fn generate_token_pair(
        &self,
        app_secret_id: Uuid,
        user_id: Uuid,
        audience: &str,
    ) -> Result<OAuth2TokenResult, OAuth2ProviderError> {
        use base64::Engine as _;
        use rand::RngCore;
        use sha2::Digest;

        // Refresh token: 32 bytes, URL-safe base64.
        let mut refresh_raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut refresh_raw);
        let refresh_token_str =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(refresh_raw);
        let refresh_hash = sha2::Sha256::digest(refresh_token_str.as_bytes()).to_vec();

        // Access token (API key) expires in 1 hour — matching `expires_in`
        // returned to the client.  Refresh token record expires in 30 days.
        let now_utc = OffsetDateTime::now_utc();
        let access_expires_at = now_utc
            .checked_add(time::Duration::hours(1))
            .ok_or_else(|| {
                OAuth2ProviderError::bad_request("Failed to compute access token expiry.")
            })?;
        let refresh_expires_at =
            now_utc
                .checked_add(time::Duration::days(30))
                .ok_or_else(|| {
                    OAuth2ProviderError::bad_request("Failed to compute refresh token expiry.")
                })?;

        // Create a real API key for this token (ties it to the session system).
        // The key_secret IS the access token returned to the OAuth2 client so
        // that the token can be used to authenticate via the standard session
        // token validation path (hash_session_token → lookup).
        let key_secret = new_session_token();
        let api_key_id = Uuid::new_v4().to_string();
        let hashed_secret = hash_session_token(&key_secret);
        let access_prefix = if key_secret.len() >= 8 {
            key_secret.as_bytes()[..8].to_vec()
        } else {
            key_secret.as_bytes().to_vec()
        };
        let api_key_result = self
            .store
            .create_api_key(CreateApiKeyInput {
                id: api_key_id.clone(),
                hashed_secret,
                user_id,
                last_used: now_utc,
                expires_at: access_expires_at,
                created_at: now_utc,
                updated_at: now_utc,
                login_type: LoginType::Oauth2ProviderApp,
                scopes: vec!["all".to_owned()],
                token_name: format!("oauth2_{api_key_id}"),
                lifetime_seconds: 3600, // 1 hour — matches expires_in
                allow_list: Vec::new(),
            })
            .await;
        match api_key_result {
            Ok(_) => {}
            Err(CreateApiKeyStoreError::Storage(e)) => {
                return Err(OAuth2ProviderError::Storage(e));
            }
            Err(CreateApiKeyStoreError::DuplicateTokenName) => {
                // Extremely unlikely with UUID-based names; retry not needed.
                return Err(OAuth2ProviderError::bad_request(
                    "Failed to create API key for token.",
                ));
            }
        }

        let input = coder_core::identity::CreateOAuth2ProviderAppTokenInput {
            expires_at: refresh_expires_at,
            hash_prefix: access_prefix,
            refresh_hash,
            app_secret_id,
            api_key_id: api_key_id.clone(),
            audience: audience.to_owned(),
            user_id,
        };
        // If token-record creation fails, clean up the API key we just
        // created so it doesn't remain as an orphaned, valid credential.
        if let Err(e) = self.store.create_oauth2_provider_app_token(&input).await {
            let _ = self.store.delete_api_key(&api_key_id).await;
            return Err(OAuth2ProviderError::Storage(e));
        }

        Ok(OAuth2TokenResult {
            access_token: key_secret,
            token_type: "Bearer".to_owned(),
            expires_in: 3600,
            refresh_token: refresh_token_str,
        })
    }
}

/// Result of an OAuth2 token exchange or refresh.
#[derive(Clone, Debug, serde::Serialize)]
pub struct OAuth2TokenResult {
    /// The access token string.
    pub access_token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Lifetime of the access token in seconds.
    pub expires_in: i64,
    /// The refresh token string.
    pub refresh_token: String,
}

/// Verifies a PKCE code verifier against a challenge.
fn verify_pkce(code_verifier: &str, code_challenge: &str, method: &str) -> bool {
    use base64::Engine as _;
    use sha2::Digest;

    match method {
        "S256" => {
            let hash = sha2::Sha256::digest(code_verifier.as_bytes());
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
            bool::from(encoded.as_bytes().ct_eq(code_challenge.as_bytes()))
        }
        "plain" | "" => bool::from(code_verifier.as_bytes().ct_eq(code_challenge.as_bytes())),
        _ => false,
    }
}

fn external_auth_installations_from_value(value: &Value) -> Vec<ExternalAuthAppInstallation> {
    let items = value
        .get("installations")
        .and_then(Value::as_array)
        .or_else(|| value.as_array())
        .cloned()
        .unwrap_or_default();

    items
        .into_iter()
        .filter_map(|item| {
            let id = item
                .get("id")
                .and_then(Value::as_i64)
                .and_then(|raw| i32::try_from(raw).ok())
                .unwrap_or_default();
            if id == 0 {
                return None;
            }
            Some(ExternalAuthAppInstallation {
                id,
                account: item
                    .get("account")
                    .and_then(external_auth_user_from_value)
                    .unwrap_or_default(),
                configure_url: item
                    .get("configure_url")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("html_url").and_then(Value::as_str))
                    .unwrap_or_default()
                    .to_owned(),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use coder_core::{
        ApiKeyListFilter, ApiKeyRecord, ApiKeyWithOwnerRecord, AuthStore, AuthenticatedUser,
        CreateApiKeyInput, CreateApiKeyStoreError, CreateFirstUserInput, CreateFirstUserStoreError,
        ExternalAuthLinkRecord, FirstUserRecord, LoginType, PasswordUserRecord, StorageError,
        TokenConfigRecord, UpsertExternalAuthLinkInput, UserRecord, UserStatus,
        ValidateUserPasswordRequest,
    };
    use std::sync::Mutex;
    use time::OffsetDateTime;

    // -----------------------------------------------------------------------
    // Minimal in-memory mock store
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockStoreInner {
        first_user_created: bool,
        users: Vec<UserRecord>,
        password_users: Vec<PasswordUserRecord>,
        sessions: Vec<(Vec<u8>, Uuid)>,
        api_keys: Vec<ApiKeyRecord>,
    }

    #[derive(Default, Clone)]
    struct MockStore {
        inner: Arc<Mutex<MockStoreInner>>,
    }

    fn make_user(id: Uuid, email: &str, username: &str, name: &str) -> UserRecord {
        UserRecord {
            id,
            email: email.to_owned(),
            username: username.to_owned(),
            name: name.to_owned(),
            avatar_url: String::new(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            last_seen_at: None,
            organization_ids: vec![],
            roles: vec![],
            login_type: LoginType::Password,
            status: UserStatus::Active,
            deleted: false,
            is_system: false,
        }
    }

    fn make_authenticated_user(user: &UserRecord) -> AuthenticatedUser {
        AuthenticatedUser {
            id: user.id,
            email: user.email.clone(),
            username: user.username.clone(),
            name: user.name.clone(),
            avatar_url: user.avatar_url.clone(),
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_seen_at: user.last_seen_at,
            organization_ids: user.organization_ids.clone(),
            roles: user.roles.clone(),
            org_roles: vec![],
            login_type: user.login_type,
            status: user.status,
        }
    }

    #[async_trait::async_trait]
    impl AuthStore for MockStore {
        async fn first_user_exists(&self) -> Result<bool, StorageError> {
            let inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            Ok(inner.first_user_created)
        }

        async fn create_first_user(
            &self,
            input: CreateFirstUserInput,
        ) -> Result<FirstUserRecord, CreateFirstUserStoreError> {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            if inner.first_user_created {
                return Err(CreateFirstUserStoreError::AlreadyExists);
            }
            let user_id = Uuid::new_v4();
            let org_id = Uuid::new_v4();
            let user = make_user(user_id, &input.email, &input.username, &input.name);
            inner.users.push(user.clone());
            inner.password_users.push(PasswordUserRecord {
                user,
                password_hash: input.password_hash,
                one_time_passcode_hash: None,
                one_time_passcode_expires_at: None,
            });
            inner.first_user_created = true;
            Ok(FirstUserRecord {
                user_id,
                organization_id: org_id,
            })
        }

        async fn find_password_user_by_email(
            &self,
            email: &str,
        ) -> Result<Option<PasswordUserRecord>, StorageError> {
            let inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            Ok(inner
                .password_users
                .iter()
                .find(|pu| pu.user.email == email)
                .cloned())
        }

        async fn find_password_user_by_id(
            &self,
            user_id: Uuid,
        ) -> Result<Option<PasswordUserRecord>, StorageError> {
            let inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            Ok(inner
                .password_users
                .iter()
                .find(|pu| pu.user.id == user_id)
                .cloned())
        }

        async fn insert_auth_session(
            &self,
            token_hash: &[u8],
            user_id: Uuid,
        ) -> Result<(), StorageError> {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            inner.sessions.push((token_hash.to_vec(), user_id));
            Ok(())
        }

        async fn find_user_by_session_token_hash(
            &self,
            token_hash: &[u8],
        ) -> Result<Option<AuthenticatedUser>, StorageError> {
            let inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            let session = inner.sessions.iter().find(|(h, _)| h == token_hash);
            if let Some((_, user_id)) = session {
                let user = inner.users.iter().find(|u| u.id == *user_id);
                Ok(user.map(make_authenticated_user))
            } else {
                Ok(None)
            }
        }

        async fn delete_auth_session(&self, token_hash: &[u8]) -> Result<bool, StorageError> {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            let before = inner.sessions.len();
            inner.sessions.retain(|(h, _)| h != token_hash);
            Ok(inner.sessions.len() < before)
        }

        async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, StorageError> {
            let inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            Ok(inner.users.iter().find(|u| u.id == user_id).cloned())
        }

        async fn find_user_by_username(
            &self,
            username: &str,
        ) -> Result<Option<UserRecord>, StorageError> {
            let inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            Ok(inner.users.iter().find(|u| u.username == username).cloned())
        }

        async fn store_one_time_passcode_by_email(
            &self,
            _email: &str,
            _passcode_hash: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn replace_user_password(
            &self,
            _user_id: Uuid,
            _password_hash: &str,
            _clear_one_time_passcode: bool,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn create_api_key(
            &self,
            input: CreateApiKeyInput,
        ) -> Result<ApiKeyRecord, CreateApiKeyStoreError> {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            let record = ApiKeyRecord {
                id: input.id,
                hashed_secret: input.hashed_secret,
                user_id: input.user_id,
                last_used: input.last_used,
                expires_at: input.expires_at,
                created_at: input.created_at,
                updated_at: input.updated_at,
                login_type: input.login_type,
                scopes: input.scopes,
                token_name: input.token_name,
                lifetime_seconds: input.lifetime_seconds,
                allow_list: input.allow_list,
            };
            inner.api_keys.push(record.clone());
            Ok(record)
        }

        async fn find_api_key_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, StorageError> {
            let inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            Ok(inner.api_keys.iter().find(|k| k.id == id).cloned())
        }

        async fn find_api_key_by_name(
            &self,
            _user_id: Uuid,
            _token_name: &str,
        ) -> Result<Option<ApiKeyRecord>, StorageError> {
            Ok(None)
        }

        async fn list_api_keys(
            &self,
            _filter: ApiKeyListFilter,
        ) -> Result<Vec<ApiKeyWithOwnerRecord>, StorageError> {
            Ok(vec![])
        }

        async fn delete_api_key(&self, _id: &str) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn expire_api_key(
            &self,
            _id: &str,
            _now: OffsetDateTime,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn token_config(&self, _user_id: Uuid) -> Result<TokenConfigRecord, StorageError> {
            Ok(TokenConfigRecord {
                max_token_lifetime: Duration::from_secs(60 * 60 * 24 * 365),
            })
        }

        async fn list_external_auth_links(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<ExternalAuthLinkRecord>, StorageError> {
            Ok(vec![])
        }

        async fn find_external_auth_link(
            &self,
            _user_id: Uuid,
            _provider_id: &str,
        ) -> Result<Option<ExternalAuthLinkRecord>, StorageError> {
            Ok(None)
        }

        async fn delete_external_auth_link(
            &self,
            _user_id: Uuid,
            _provider_id: &str,
        ) -> Result<bool, StorageError> {
            Ok(false)
        }

        async fn upsert_external_auth_link(
            &self,
            _user_id: Uuid,
            _link: &UpsertExternalAuthLinkInput,
        ) -> Result<ExternalAuthLinkRecord, StorageError> {
            Err(StorageError::unavailable("not implemented"))
        }

        async fn update_api_key_last_used(
            &self,
            id: &str,
            last_used: OffsetDateTime,
            expires_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            if let Some(key) = inner.api_keys.iter_mut().find(|k| k.id == id) {
                key.last_used = last_used;
                key.expires_at = expires_at;
            }
            Ok(())
        }

        async fn update_user_last_seen_at(
            &self,
            user_id: Uuid,
            last_seen_at: OffsetDateTime,
        ) -> Result<(), StorageError> {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| StorageError::unavailable("lock"))?;
            if let Some(user) = inner.users.iter_mut().find(|u| u.id == user_id) {
                user.last_seen_at = Some(last_seen_at);
            }
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_token_from_headers() {
        let mut headers = HeaderMap::new();
        // No header → None.
        assert!(session_token_from_headers(&headers).is_none());

        // With the custom header.
        headers.insert(
            SESSION_TOKEN_HEADER,
            http::HeaderValue::from_static("my-token-123"),
        );
        assert_eq!(session_token_from_headers(&headers), Some("my-token-123"));
    }

    #[test]
    fn test_cookie_from_headers() {
        let mut headers = HeaderMap::new();
        // No cookie header → None.
        assert!(cookie_from_headers(&headers, SESSION_TOKEN_COOKIE).is_none());

        // With cookies set.
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("other=foo; coder_session_token=abc123; extra=bar"),
        );
        assert_eq!(
            cookie_from_headers(&headers, SESSION_TOKEN_COOKIE),
            Some("abc123".to_owned())
        );
        // Non-existent cookie name.
        assert!(cookie_from_headers(&headers, "nonexistent").is_none());
    }

    #[test]
    fn test_validate_password_strong() {
        // Valid passwords (>= 8 characters) pass.
        let service = AuthService::new(MockStore::default());
        let result = service.validate_user_password(&ValidateUserPasswordRequest {
            password: "strongpassword123".to_owned(),
        });
        assert!(result.valid);
        assert!(result.details.is_empty());

        // Exactly 8 characters.
        let result = service.validate_user_password(&ValidateUserPasswordRequest {
            password: "abcdefgh".to_owned(),
        });
        assert!(result.valid);
    }

    #[test]
    fn test_validate_password_weak_rejected() {
        let service = AuthService::new(MockStore::default());
        // Too short (< 8 characters).
        let result = service.validate_user_password(&ValidateUserPasswordRequest {
            password: "short".to_owned(),
        });
        assert!(!result.valid);
        assert!(!result.details.is_empty());

        // Empty password.
        let result = service.validate_user_password(&ValidateUserPasswordRequest {
            password: String::new(),
        });
        assert!(!result.valid);

        // Too long (> 64 characters).
        let result = service.validate_user_password(&ValidateUserPasswordRequest {
            password: "a".repeat(65),
        });
        assert!(!result.valid);
    }

    #[test]
    fn test_supported_auth_methods() {
        let methods = supported_auth_methods();
        assert!(methods.password.enabled);
        assert!(methods.github.enabled);
        assert!(methods.github.default_provider_configured);
        assert!(methods.terms_of_service_url.is_empty());
    }

    #[test]
    fn test_api_key_generation_format() {
        // new_session_token produces base64-encoded 32 random bytes (no padding).
        let token = new_session_token();
        assert!(!token.is_empty());
        // 32 bytes → ceil(32*4/3) = 43 base64 characters (no-pad).
        assert_eq!(token.len(), 43, "session token should be 43 base64 chars");
        // The token must be valid base64 (no-pad).
        assert!(
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(&token)
                .is_ok(),
            "session token must be valid base64"
        );
        // hash_session_token should produce a SHA-256 digest (32 bytes).
        let hash = hash_session_token(&token);
        assert_eq!(hash.len(), 32, "hash should be 32 bytes (SHA-256)");
        // Two different tokens should hash differently.
        let token2 = new_session_token();
        assert_ne!(token, token2, "tokens should be unique");
        let hash2 = hash_session_token(&token2);
        assert_ne!(hash, hash2);
    }

    #[tokio::test]
    async fn test_auth_service_first_user_flow() {
        let store = MockStore::default();
        let service = AuthService::new(store.clone());

        // Initially no first user.
        let exists = service.first_user_exists().await;
        assert!(exists.is_ok());
        assert!(!exists.unwrap_or(true));

        // Create first user.
        let request = CreateFirstUserRequest {
            email: "admin@example.com".to_owned(),
            username: "admin".to_owned(),
            name: "Admin User".to_owned(),
            password: "securepassword123".to_owned(),
        };
        let result = service.create_first_user(&request).await;
        assert!(result.is_ok());
        let response = result.unwrap_or_else(|_| CreateFirstUserResponse {
            user_id: Uuid::nil(),
            organization_id: Uuid::nil(),
        });
        assert_ne!(response.user_id, Uuid::nil());
        assert_ne!(response.organization_id, Uuid::nil());

        // Now first user exists.
        let exists = service.first_user_exists().await;
        assert!(exists.is_ok());
        assert!(exists.unwrap_or(false));

        // Creating a second first user should fail (AlreadyExists).
        let duplicate = service.create_first_user(&request).await;
        assert!(duplicate.is_err(), "duplicate first user must be rejected");
    }

    #[tokio::test]
    async fn test_auth_service_login_logout() {
        let store = MockStore::default();
        let service = AuthService::new(store.clone());

        // Bootstrap user.
        let request = CreateFirstUserRequest {
            email: "testuser@example.com".to_owned(),
            username: "testuser".to_owned(),
            name: "Test User".to_owned(),
            password: "securepassword123".to_owned(),
        };
        let create_result = service.create_first_user(&request).await;
        assert!(create_result.is_ok());

        // Login.
        let login_request = LoginWithPasswordRequest {
            email: "testuser@example.com".to_owned(),
            password: "securepassword123".to_owned(),
        };
        let login_result = service.login_with_password(&login_request).await;
        assert!(login_result.is_ok());
        let outcome = login_result.unwrap_or_else(|_| LoginOutcome {
            user: AuthenticatedUser {
                id: Uuid::nil(),
                email: String::new(),
                username: String::new(),
                name: String::new(),
                avatar_url: String::new(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                last_seen_at: None,
                organization_ids: vec![],
                roles: vec![],
                org_roles: vec![],
                login_type: LoginType::Password,
                status: UserStatus::Active,
            },
            response: LoginWithPasswordResponse {
                session_token: String::new(),
            },
        });
        let session_token = &outcome.response.session_token;
        assert!(!session_token.is_empty());

        // Verify session is valid via authenticate.
        let mut headers = HeaderMap::new();
        headers.insert(
            SESSION_TOKEN_HEADER,
            http::HeaderValue::from_str(session_token)
                .unwrap_or_else(|_| http::HeaderValue::from_static("")),
        );
        let auth_result = service.authenticate(&headers).await;
        assert!(auth_result.is_ok());
        let authenticated = auth_result.unwrap_or(None);
        assert!(authenticated.is_some());

        // Logout.
        let logout_result = service.logout(session_token).await;
        assert!(logout_result.is_ok());

        // Session should now be invalid.
        let auth_result = service.authenticate(&headers).await;
        assert!(auth_result.is_ok());
        let authenticated = auth_result.unwrap_or(None);
        assert!(authenticated.is_none());

        // Login with wrong password must fail.
        let bad_login = LoginWithPasswordRequest {
            email: "testuser@example.com".to_owned(),
            password: "wrongpassword999".to_owned(),
        };
        let bad_result = service.login_with_password(&bad_login).await;
        assert!(bad_result.is_err(), "wrong password must be rejected");
    }

    // ── Authenticate with invalid/empty token ───────────────

    #[tokio::test]
    async fn test_authenticate_empty_headers_returns_none() {
        let store = MockStore::default();
        let service = AuthService::new(store);
        let headers = HeaderMap::new();
        let result = service.authenticate(&headers).await;
        assert!(result.is_ok());
        assert!(
            result.unwrap_or(None).is_none(),
            "empty headers should not authenticate"
        );
    }

    #[tokio::test]
    async fn test_authenticate_invalid_token_returns_none() {
        let store = MockStore::default();
        let service = AuthService::new(store);
        let mut headers = HeaderMap::new();
        headers.insert(
            SESSION_TOKEN_HEADER,
            http::HeaderValue::from_static("totally-invalid-token"),
        );
        let result = service.authenticate(&headers).await;
        assert!(result.is_ok());
        // Token doesn't match any session → None
        assert!(
            result.unwrap_or(None).is_none(),
            "invalid token should not authenticate"
        );
    }

    // ── Login with non-existent email ───────────────────────

    #[tokio::test]
    async fn test_login_nonexistent_email_fails() {
        let store = MockStore::default();
        let service = AuthService::new(store);
        let login_request = LoginWithPasswordRequest {
            email: "nobody@example.com".to_owned(),
            password: "anypassword123".to_owned(),
        };
        let result = service.login_with_password(&login_request).await;
        assert!(result.is_err(), "login with non-existent email must fail");
    }

    // ── Session token hashing consistency ───────────────────

    #[test]
    fn test_session_token_hash_consistency() {
        let token = "test-token-value-for-hashing";
        let hash1 = hash_session_token(token);
        let hash2 = hash_session_token(token);
        assert_eq!(hash1, hash2, "same token must produce same hash");
    }

    #[test]
    fn test_different_tokens_produce_different_hashes() {
        let hash1 = hash_session_token("token-a");
        let hash2 = hash_session_token("token-b");
        assert_ne!(hash1, hash2, "different tokens must hash differently");
    }

    // ── Password validation edge cases ──────────────────────

    #[test]
    fn test_validate_password_exactly_64_chars() {
        let service = AuthService::new(MockStore::default());
        let result = service.validate_user_password(&ValidateUserPasswordRequest {
            password: "a".repeat(64),
        });
        assert!(result.valid, "exactly 64 characters should be valid");
    }

    #[test]
    fn test_validate_password_exactly_7_chars() {
        let service = AuthService::new(MockStore::default());
        let result = service.validate_user_password(&ValidateUserPasswordRequest {
            password: "1234567".to_owned(),
        });
        assert!(!result.valid, "7 characters should be too short");
        assert!(!result.details.is_empty());
    }

    // ── Cookie extraction edge cases ────────────────────────

    #[test]
    fn test_cookie_with_spaces_around_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("coder_session_token=spaced-token"),
        );
        assert_eq!(
            cookie_from_headers(&headers, SESSION_TOKEN_COOKIE),
            Some("spaced-token".to_owned())
        );
    }

    #[test]
    fn test_cookie_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("coder_session_token="),
        );
        // Empty value cookie should still be found
        assert_eq!(
            cookie_from_headers(&headers, SESSION_TOKEN_COOKIE),
            Some(String::new())
        );
    }

    #[test]
    fn test_cookie_multiple_cookies_correct_one_selected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("a=1; coder_session_token=correct; b=2"),
        );
        assert_eq!(
            cookie_from_headers(&headers, SESSION_TOKEN_COOKIE),
            Some("correct".to_owned())
        );
    }

    // ── First user creation validation ──────────────────────

    #[tokio::test]
    async fn test_create_first_user_with_short_password() {
        let store = MockStore::default();
        let service = AuthService::new(store);
        let request = CreateFirstUserRequest {
            email: "admin@example.com".to_owned(),
            username: "admin".to_owned(),
            name: "Admin".to_owned(),
            password: "short".to_owned(),
        };
        let result = service.create_first_user(&request).await;
        assert!(result.is_err(), "short password should be rejected");
    }

    #[tokio::test]
    async fn test_create_first_user_with_empty_fields() {
        let store = MockStore::default();
        let service = AuthService::new(store);
        let request = CreateFirstUserRequest {
            email: String::new(),
            username: String::new(),
            name: String::new(),
            password: "securepassword123".to_owned(),
        };
        let result = service.create_first_user(&request).await;
        assert!(result.is_err(), "empty email/username should be rejected");
    }

    // ── AuthServiceError constructors ───────────────────────

    #[test]
    fn test_auth_service_error_variants() {
        let unauth = AuthServiceError::unauthorized("test");
        assert!(matches!(unauth, AuthServiceError::Unauthorized { .. }));

        let forbidden = AuthServiceError::forbidden("test");
        assert!(matches!(forbidden, AuthServiceError::Forbidden { .. }));

        let not_found = AuthServiceError::not_found("test");
        assert!(matches!(not_found, AuthServiceError::NotFound { .. }));

        let bad_req = AuthServiceError::bad_request("test");
        assert!(matches!(bad_req, AuthServiceError::BadRequest { .. }));
    }

    // ── new_session_token uniqueness ────────────────────────

    #[test]
    fn test_session_tokens_are_unique() {
        let tokens: Vec<String> = (0..100).map(|_| new_session_token()).collect();
        for i in 0..tokens.len() {
            for j in (i + 1)..tokens.len() {
                assert_ne!(tokens[i], tokens[j], "tokens {i} and {j} should differ");
            }
        }
    }

    // ── verify_pkce helper ──────────────────────────────────

    #[test]
    fn test_verify_pkce_plain_method() {
        let verifier = "my-code-verifier-value";
        let challenge = "my-code-verifier-value";
        assert!(verify_pkce(verifier, challenge, "plain"));
        assert!(verify_pkce(verifier, challenge, ""));
        assert!(!verify_pkce("wrong", challenge, "plain"));
    }

    #[test]
    fn test_verify_pkce_s256_method() {
        use base64::Engine as _;
        use sha2::Digest;
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hash = sha2::Sha256::digest(verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
        assert!(verify_pkce(verifier, &challenge, "S256"));
        assert!(!verify_pkce("wrong-verifier", &challenge, "S256"));
    }

    #[test]
    fn test_verify_pkce_unknown_method() {
        assert!(!verify_pkce("v", "c", "unknown_method"));
    }

    // ── parse_response_body helper ──────────────────────────

    #[test]
    fn test_parse_response_body_empty() {
        let result = parse_response_body(None, "");
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or_else(|_| json!(null)), json!({}));
    }

    #[test]
    fn test_parse_response_body_json() {
        let result = parse_response_body(Some("application/json"), r#"{"key":"value"}"#);
        assert!(result.is_ok());
        let parsed = result.unwrap_or_else(|_| json!(null));
        assert_eq!(parsed["key"], "value");
    }

    #[test]
    fn test_parse_response_body_form_urlencoded() {
        let result = parse_response_body(
            Some("application/x-www-form-urlencoded"),
            "access_token=abc123&token_type=bearer",
        );
        assert!(result.is_ok());
        let parsed = result.unwrap_or_else(|_| json!(null));
        assert_eq!(parsed["access_token"], "abc123");
        assert_eq!(parsed["token_type"], "bearer");
    }

    #[test]
    fn test_parse_response_body_invalid_json() {
        let result = parse_response_body(Some("application/json"), "not json at all");
        assert!(result.is_err());
    }
}
