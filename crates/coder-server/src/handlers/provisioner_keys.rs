//! Provisioner key management handlers (enterprise).
//!
//! These routes allow organizations to manage provisioner keys used for
//! authenticating external provisioner daemons without a full user API key.

use std::collections::HashMap;

use super::*;
use coder_core::api::{
    CreateProvisionerKeyRequest, CreateProvisionerKeyResponse, PROVISIONER_KEY_ID_BUILT_IN,
    PROVISIONER_KEY_ID_PSK, PROVISIONER_KEY_ID_USER_AUTH, ProvisionerDaemonResponse,
    ProvisionerKeyDaemonsResponse, ProvisionerKeyResponse, RESERVED_PROVISIONER_KEY_NAMES,
};
use coder_core::provisioner::{InsertProvisionerKeyInput, ProvisionerKeyRecord};
use coder_license::FeatureName;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::handlers::licenses::{is_feature_entitled, require_enterprise_feature};

/// Header name for provisioner daemon key authentication.
const PROVISIONER_DAEMON_KEY_HEADER: &str = "coder-provisioner-daemon-key";

/// Length of the random secret token (matches Go's `secretLength = 43`).
const SECRET_LENGTH: usize = 43;

/// Stale daemon threshold: 3× the default heartbeat interval of 30 s = 90 s.
/// Matches the Go reference `provisionerdserver.DefaultHeartbeatInterval * 3`.
const STALE_DAEMON_THRESHOLD_SECS: i64 = 90;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Converts a [`ProvisionerKeyRecord`] to a [`ProvisionerKeyResponse`],
/// stripping the hashed secret.
fn key_to_response(record: &ProvisionerKeyRecord) -> ProvisionerKeyResponse {
    let tags: HashMap<String, String> = record
        .tags
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default();

    ProvisionerKeyResponse {
        id: record.id,
        created_at: record.created_at,
        organization_id: record.organization_id,
        name: record.name.clone(),
        tags,
    }
}

/// Converts a [`coder_core::provisioner::ProvisionerDaemonRecord`] to API response.
fn daemon_to_response(
    d: &coder_core::provisioner::ProvisionerDaemonRecord,
) -> ProvisionerDaemonResponse {
    ProvisionerDaemonResponse {
        id: d.id,
        organization_id: d.organization_id,
        created_at: d.created_at,
        last_seen_at: d.last_seen_at,
        name: d.name.clone(),
        version: d.version.clone(),
        api_version: d.api_version.clone(),
        provisioners: d.provisioners.clone(),
        tags: d.tags.clone(),
    }
}

/// Generates a cryptographically random ASCII string of the given length.
fn generate_random_secret(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hashes a secret string with SHA-256 (matches Go's `apikey.HashSecret`).
fn hash_secret(secret: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/v2/organizations/{organization}/provisionerkeys
///
/// Creates a new provisioner key for the organization. Returns the raw token
/// which cannot be retrieved later.
pub(crate) async fn post_provisioner_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(organization): Path<Uuid>,
    payload: Result<Json<CreateProvisionerKeyRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    // Auth
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::ExternalProvisionerDaemons) {
        return Ok(require_enterprise_feature(
            &FeatureName::ExternalProvisionerDaemons,
        ));
    }

    // RBAC
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::ProvisionerDaemon).in_org(organization),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create provisioner keys for this organization.",
        ));
    }

    // Parse body
    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Validate name: required
    if request.name.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: "Name is required".to_owned(),
                detail: Some(String::new()),
                validations: vec![ValidationError {
                    field: "name".to_owned(),
                    detail: "Name is required".to_owned(),
                }],
            }),
        )
            .into_response());
    }

    // Validate name: max length
    if request.name.len() > 64 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: "Name must be at most 64 characters".to_owned(),
                detail: Some(String::new()),
                validations: vec![ValidationError {
                    field: "name".to_owned(),
                    detail: "Name must be at most 64 characters".to_owned(),
                }],
            }),
        )
            .into_response());
    }

    // Validate name: not reserved
    if RESERVED_PROVISIONER_KEY_NAMES
        .iter()
        .any(|r| r.eq_ignore_ascii_case(&request.name))
    {
        let msg = format!("Name cannot be reserved name '{}'", request.name);
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                message: msg.clone(),
                detail: Some(String::new()),
                validations: vec![ValidationError {
                    field: "name".to_owned(),
                    detail: msg,
                }],
            }),
        )
            .into_response());
    }

    // Generate token + hash
    let secret = generate_random_secret(SECRET_LENGTH);
    let hashed = hash_secret(&secret);

    let tags = serde_json::to_value(&request.tags).map_err(|e| AppError::BadRequest {
        message: format!("Failed to serialize tags: {e}"),
        detail: None,
        validations: Vec::new(),
    })?;

    let input = InsertProvisionerKeyInput {
        id: Uuid::new_v4(),
        created_at: OffsetDateTime::now_utc(),
        organization_id: organization,
        name: request.name.clone(),
        hashed_secret: hashed,
        tags,
    };

    // Check uniqueness first (fast-path), then handle the race condition
    // at insert time by re-checking on failure.
    let existing = state
        .store
        .get_provisioner_key_by_name(organization, &request.name)
        .await?;
    if existing.is_some() {
        return Ok((
            StatusCode::CONFLICT,
            Json(ApiResponse::error(
                format!(
                    "Provisioner key with name '{}' already exists in organization",
                    request.name
                ),
                "",
            )),
        )
            .into_response());
    }

    match state.store.insert_provisioner_key(input).await {
        Ok(_) => {}
        Err(storage_err) => {
            // Concurrent insert may have won the race — re-check before
            // propagating as a generic storage error.
            if let Ok(Some(_)) = state
                .store
                .get_provisioner_key_by_name(organization, &request.name)
                .await
            {
                return Ok((
                    StatusCode::CONFLICT,
                    Json(ApiResponse::error(
                        format!(
                            "Provisioner key with name '{}' already exists in organization",
                            request.name
                        ),
                        "",
                    )),
                )
                    .into_response());
            }
            return Err(AppError::from(storage_err));
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(CreateProvisionerKeyResponse { key: secret }),
    )
        .into_response())
}

/// GET /api/v2/organizations/{organization}/provisionerkeys
///
/// Lists all non-reserved provisioner keys for an organization.
pub(crate) async fn list_provisioner_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(organization): Path<Uuid>,
) -> Result<Response, AppError> {
    // Auth
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::ExternalProvisionerDaemons) {
        return Ok(require_enterprise_feature(
            &FeatureName::ExternalProvisionerDaemons,
        ));
    }

    // RBAC
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::ProvisionerDaemon).in_org(organization),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view provisioner keys for this organization.",
        ));
    }

    let keys = state
        .store
        .list_provisioner_keys_by_organization_exclude_reserved(organization)
        .await?;

    let mut response: Vec<ProvisionerKeyResponse> = keys.iter().map(key_to_response).collect();
    response.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /api/v2/organizations/{organization}/provisionerkeys/daemons
///
/// Lists provisioner keys with their associated daemons for an organization.
pub(crate) async fn list_provisioner_key_daemons(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(organization): Path<Uuid>,
) -> Result<Response, AppError> {
    // Auth
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::ExternalProvisionerDaemons) {
        return Ok(require_enterprise_feature(
            &FeatureName::ExternalProvisionerDaemons,
        ));
    }

    // RBAC
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::ProvisionerDaemon).in_org(organization),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view provisioner keys for this organization.",
        ));
    }

    // Fetch all keys (including reserved) for this org
    let keys = state
        .store
        .list_provisioner_keys_by_organization(organization)
        .await?;
    let mut sdk_keys: Vec<ProvisionerKeyResponse> = keys.iter().map(key_to_response).collect();

    // Ensure user-auth key is present (for non-default orgs it may not exist
    // in the database, but we still need it in the list).
    let user_auth_uuid =
        Uuid::parse_str(PROVISIONER_KEY_ID_USER_AUTH).map_err(|e| AppError::InternalError {
            message: format!("Invalid user-auth UUID constant: {e}"),
            detail: String::new(),
        })?;
    if !sdk_keys.iter().any(|k| k.id == user_auth_uuid) {
        sdk_keys.push(ProvisionerKeyResponse {
            id: user_auth_uuid,
            created_at: OffsetDateTime::UNIX_EPOCH,
            organization_id: organization,
            name: "user-auth".to_owned(),
            tags: HashMap::new(),
        });
    }

    // Fetch daemons and filter to recent ones
    let all_daemons = state
        .store
        .get_provisioner_daemons_by_organization(organization)
        .await?;
    let now = OffsetDateTime::now_utc();
    let stale_cutoff = now - time::Duration::seconds(STALE_DAEMON_THRESHOLD_SECS);
    let recent_daemons: Vec<_> = all_daemons
        .iter()
        .filter(|d| d.last_seen_at.is_some_and(|t| t >= stale_cutoff))
        .collect();

    // Build response: each key with its associated daemons
    let mut result: Vec<ProvisionerKeyDaemonsResponse> = Vec::with_capacity(sdk_keys.len());
    for mut key in sdk_keys {
        // Overwrite user-auth org ID to match the queried org
        if key.id == user_auth_uuid {
            key.organization_id = organization;
        }

        let daemons: Vec<ProvisionerDaemonResponse> = recent_daemons
            .iter()
            .filter(|d| d.key_id == Some(key.id))
            .map(|d| daemon_to_response(d))
            .collect();

        result.push(ProvisionerKeyDaemonsResponse { key, daemons });
    }

    Ok((StatusCode::OK, Json(result)).into_response())
}

/// DELETE /api/v2/organizations/{organization}/provisionerkeys/{provisionerkey}
///
/// Deletes a provisioner key by name. Cannot delete reserved keys.
pub(crate) async fn delete_provisioner_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((organization, key_name)): Path<(Uuid, String)>,
) -> Result<Response, AppError> {
    // Auth
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::ExternalProvisionerDaemons) {
        return Ok(require_enterprise_feature(
            &FeatureName::ExternalProvisionerDaemons,
        ));
    }

    // RBAC
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::ProvisionerDaemon).in_org(organization),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete provisioner keys for this organization.",
        ));
    }

    // Resolve key by name
    let key = state
        .store
        .get_provisioner_key_by_name(organization, &key_name)
        .await?;
    let Some(key) = key else {
        return Ok(resource_not_found_response());
    };

    // Prevent deleting reserved keys
    let id_str = key.id.to_string();
    if id_str == PROVISIONER_KEY_ID_BUILT_IN
        || id_str == PROVISIONER_KEY_ID_USER_AUTH
        || id_str == PROVISIONER_KEY_ID_PSK
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                format!("Cannot delete reserved '{}' provisioner key", key.name),
                "",
            )),
        )
            .into_response());
    }

    state.store.delete_provisioner_key(key.id).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /api/v2/provisionerkeys/{provisionerkey}
///
/// Fetches provisioner key details. This is a deployment-level route used
/// by provisioner daemons to validate their key. The key token itself serves
/// as authentication (via the `Coder-Provisioner-Daemon-Key` header).
pub(crate) async fn get_provisioner_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key_id): Path<Uuid>,
) -> Result<Response, AppError> {
    // Enterprise gate
    let entitlements = state.entitlements.clone();
    if !is_feature_entitled(&entitlements, FeatureName::ExternalProvisionerDaemons) {
        return Ok(require_enterprise_feature(
            &FeatureName::ExternalProvisionerDaemons,
        ));
    }

    // Authenticate via the provisioner daemon key header
    let raw_token = headers
        .get(PROVISIONER_DAEMON_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if raw_token.is_empty() {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error(
                format!(
                    "unable to auth: please provide the {} header",
                    PROVISIONER_DAEMON_KEY_HEADER
                ),
                "",
            )),
        )
            .into_response());
    }

    // Look up the key by its hashed token
    let hashed = hash_secret(raw_token);
    let key = state
        .store
        .get_provisioner_key_by_hashed_secret(&hashed)
        .await?;

    let Some(key) = key else {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error(
                format!(
                    "unable to auth: please provide the {} header",
                    PROVISIONER_DAEMON_KEY_HEADER
                ),
                "",
            )),
        )
            .into_response());
    };

    // Verify the path param matches the authenticated key
    if key.id != key_id {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error(
                "Key ID in path does not match authenticated key.",
                "",
            )),
        )
            .into_response());
    }

    Ok((StatusCode::OK, Json(key_to_response(&key))).into_response())
}
