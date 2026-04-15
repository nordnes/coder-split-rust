//! IDP Sync settings handlers (enterprise — gated on `MultipleExternalAuth`).

use super::*;
use crate::handlers::templates::resolve_organization;

/// `GET /api/v2/organizations/{organization}/settings/idpsync/available-fields`
pub(crate) async fn get_org_idpsync_available_fields(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view IDP sync settings.",
        ));
    }

    let fields = state.store.oidc_claim_fields(org.id).await?;
    Ok((StatusCode::OK, Json(fields)).into_response())
}

/// Query parameters for the field-values endpoint.
#[derive(Debug, Deserialize)]
pub(crate) struct FieldValuesQuery {
    #[serde(rename = "claimField", default)]
    pub claim_field: String,
}

/// `GET /api/v2/organizations/{organization}/settings/idpsync/field-values`
pub(crate) async fn get_org_idpsync_field_values(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    Query(query): Query<FieldValuesQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view IDP sync settings.",
        ));
    }

    if query.claim_field.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok(
                "claimField query parameter is required".to_string(),
            )),
        )
            .into_response());
    }

    let values = state
        .store
        .oidc_claim_field_values(org.id, &query.claim_field)
        .await?;
    Ok((StatusCode::OK, Json(values)).into_response())
}

// ── Group sync ──────────────────────────────────────────────────────────

/// `GET /api/v2/organizations/{organization}/settings/idpsync/groups`
pub(crate) async fn get_group_idpsync_settings(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view IDP sync settings.",
        ));
    }

    let settings = state.store.group_sync_settings(org.id).await?;
    Ok((StatusCode::OK, Json(settings)).into_response())
}

/// `PATCH /api/v2/organizations/{organization}/settings/idpsync/groups`
pub(crate) async fn patch_group_idpsync_settings(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::api::GroupSyncSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update IDP sync settings.",
        ));
    }

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    // Reject legacy_group_name_mapping if it is provided.
    if let Some(ref legacy) = request.legacy_group_name_mapping {
        if !legacy.is_empty() {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    message: "Unexpected field 'legacy_group_name_mapping'. Field not allowed, set to null or remove it.".to_string(),
                    detail: Some("legacy_group_name_mapping is deprecated, use mapping instead".to_string()),
                    validations: vec![ValidationError {
                        field: "legacy_group_name_mapping".to_string(),
                        detail: "field is not allowed".to_string(),
                    }],
                }),
            )
                .into_response());
        }
    }

    state
        .store
        .upsert_group_sync_settings(org.id, &request)
        .await?;

    let settings = state.store.group_sync_settings(org.id).await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsGroup,
        Some(&context.user),
        Some(org.id.to_string()),
        format!("updated group IDP sync settings for org {}", org.name),
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

/// `PATCH /api/v2/organizations/{organization}/settings/idpsync/groups/config`
pub(crate) async fn patch_group_idpsync_config(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::api::PatchGroupIDPSyncConfigRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update IDP sync settings.",
        ));
    }

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let mut settings = state.store.group_sync_settings(org.id).await?;
    settings.field = request.field;
    settings.regex_filter = request.regex_filter;
    settings.auto_create_missing_groups = request.auto_create_missing_groups;

    state
        .store
        .upsert_group_sync_settings(org.id, &settings)
        .await?;

    let settings = state.store.group_sync_settings(org.id).await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsGroup,
        Some(&context.user),
        Some(org.id.to_string()),
        format!("updated group IDP sync config for org {}", org.name),
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

/// `PATCH /api/v2/organizations/{organization}/settings/idpsync/groups/mapping`
pub(crate) async fn patch_group_idpsync_mapping(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::api::PatchGroupIDPSyncMappingRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update IDP sync settings.",
        ));
    }

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let mut settings = state.store.group_sync_settings(org.id).await?;
    apply_group_mapping_diff(&mut settings.mapping, &request.add, &request.remove);

    state
        .store
        .upsert_group_sync_settings(org.id, &settings)
        .await?;

    let settings = state.store.group_sync_settings(org.id).await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsGroup,
        Some(&context.user),
        Some(org.id.to_string()),
        format!("updated group IDP sync mapping for org {}", org.name),
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

// ── Role sync ───────────────────────────────────────────────────────────

/// `GET /api/v2/organizations/{organization}/settings/idpsync/roles`
pub(crate) async fn get_role_idpsync_settings(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view IDP sync settings.",
        ));
    }

    let settings = state.store.role_sync_settings(org.id).await?;
    Ok((StatusCode::OK, Json(settings)).into_response())
}

/// `PATCH /api/v2/organizations/{organization}/settings/idpsync/roles`
pub(crate) async fn patch_role_idpsync_settings(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::api::RoleSyncSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update IDP sync settings.",
        ));
    }

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    state
        .store
        .upsert_role_sync_settings(org.id, &request)
        .await?;

    let settings = state.store.role_sync_settings(org.id).await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsRole,
        Some(&context.user),
        Some(org.id.to_string()),
        format!("updated role IDP sync settings for org {}", org.name),
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

/// `PATCH /api/v2/organizations/{organization}/settings/idpsync/roles/config`
pub(crate) async fn patch_role_idpsync_config(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::api::PatchRoleIDPSyncConfigRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update IDP sync settings.",
        ));
    }

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let mut settings = state.store.role_sync_settings(org.id).await?;
    settings.field = request.field;

    state
        .store
        .upsert_role_sync_settings(org.id, &settings)
        .await?;

    let settings = state.store.role_sync_settings(org.id).await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsRole,
        Some(&context.user),
        Some(org.id.to_string()),
        format!("updated role IDP sync config for org {}", org.name),
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

/// `PATCH /api/v2/organizations/{organization}/settings/idpsync/roles/mapping`
pub(crate) async fn patch_role_idpsync_mapping(
    State(state): State<AppState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<coder_core::api::PatchRoleIDPSyncMappingRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(org) = resolve_organization(&state, &organization).await? else {
        return Ok(not_found_response("Organization not found."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::IdpsyncSettings).in_org(org.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update IDP sync settings.",
        ));
    }

    let Json(request) = match payload {
        Ok(r) => r,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    let mut settings = state.store.role_sync_settings(org.id).await?;
    apply_role_mapping_diff(&mut settings.mapping, &request.add, &request.remove);

    state
        .store
        .upsert_role_sync_settings(org.id, &settings)
        .await?;

    let settings = state.store.role_sync_settings(org.id).await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsRole,
        Some(&context.user),
        Some(org.id.to_string()),
        format!("updated role IDP sync mapping for org {}", org.name),
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Applies add/remove diff to a group sync mapping (mirroring Go's
/// `applyIDPSyncMappingDiff`).
fn apply_group_mapping_diff(
    mapping: &mut HashMap<String, Vec<Uuid>>,
    add: &[coder_core::api::IDPSyncMappingGroup],
    remove: &[coder_core::api::IDPSyncMappingGroup],
) {
    for entry in add {
        let ids = mapping.entry(entry.given.clone()).or_default();
        if !ids.contains(&entry.gets) {
            ids.push(entry.gets);
        }
    }
    for entry in remove {
        if let Some(ids) = mapping.get_mut(&entry.given) {
            ids.retain(|id| *id != entry.gets);
        }
    }
}

/// Applies add/remove diff to a role sync mapping.
fn apply_role_mapping_diff(
    mapping: &mut HashMap<String, Vec<String>>,
    add: &[coder_core::api::IDPSyncMappingRole],
    remove: &[coder_core::api::IDPSyncMappingRole],
) {
    for entry in add {
        let roles = mapping.entry(entry.given.clone()).or_default();
        if !roles.contains(&entry.gets) {
            roles.push(entry.gets.clone());
        }
    }
    for entry in remove {
        if let Some(roles) = mapping.get_mut(&entry.given) {
            roles.retain(|role| *role != entry.gets);
        }
    }
}
