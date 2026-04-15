//! IDP Sync settings handlers (enterprise — gated on `MultipleExternalAuth`).

use super::*;
use crate::handlers::templates::resolve_organization;
use coder_core::api::{
    IDPSyncMappingUUID, OrganizationSyncSettings, PatchOrganizationIDPSyncConfigRequest,
    PatchOrganizationIDPSyncMappingRequest,
};

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

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsGroup,
        Some(&context.user),
        Some(org.id.to_string()),
        format!("updated group IDP sync settings for org {}", org.name),
    )
    .await;

    Ok((StatusCode::OK, Json(request)).into_response())
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

    let settings = state
        .store
        .update_group_sync_config(
            org.id,
            request.field,
            request.regex_filter,
            request.auto_create_missing_groups,
        )
        .await?;

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

    let settings = state
        .store
        .apply_group_sync_mapping_diff(org.id, &request.add, &request.remove)
        .await?;

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

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsRole,
        Some(&context.user),
        Some(org.id.to_string()),
        format!("updated role IDP sync settings for org {}", org.name),
    )
    .await;

    Ok((StatusCode::OK, Json(request)).into_response())
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

    let settings = state
        .store
        .update_role_sync_config(org.id, request.field)
        .await?;

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

    let settings = state
        .store
        .apply_role_sync_mapping_diff(org.id, &request.add, &request.remove)
        .await?;

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

// ── Deployment-level IDP sync handlers ──────────────────────────────────
//
// These routes manage how identity provider claims are mapped to Coder
// organizations at the deployment level (not org-scoped).

/// `GET /api/v2/settings/idpsync/available-fields`
///
/// Returns all distinct OIDC claim field names seen across every user link in
/// the deployment (nil org ID ⇒ all organisations).
pub(crate) async fn get_deployment_idpsync_available_fields(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::IdpsyncSettings),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You do not have permission to view the available IDP fields.",
        ));
    }

    let fields = state.store.oidc_claim_fields(Uuid::nil()).await?;
    Ok((StatusCode::OK, Json(fields)).into_response())
}

/// `GET /api/v2/settings/idpsync/field-values`
///
/// Returns distinct values for a given OIDC claim field across all users.
/// Requires the `claimField` query parameter.
pub(crate) async fn get_deployment_idpsync_field_values(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<FieldValuesQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::IdpsyncSettings),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You do not have permission to view the IDP claim field values.",
        ));
    }

    if params.claim_field.is_empty() {
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
        .oidc_claim_field_values(Uuid::nil(), &params.claim_field)
        .await?;
    Ok((StatusCode::OK, Json(values)).into_response())
}

/// `GET /api/v2/settings/idpsync/organization`
///
/// Returns the deployment-level organization IDP sync settings.
pub(crate) async fn get_org_idpsync_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::IdpsyncSettings),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to read IDP sync settings.",
        ));
    }

    let settings = state.store.get_organization_idp_sync_settings().await?;
    Ok((StatusCode::OK, Json(settings)).into_response())
}

/// `PATCH /api/v2/settings/idpsync/organization`
///
/// Full replacement of the organization IDP sync settings. Audit logged.
pub(crate) async fn patch_org_idpsync_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<OrganizationSyncSettings>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::IdpsyncSettings),
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
        .upsert_organization_idp_sync_settings(&request)
        .await?;

    let settings = state.store.get_organization_idp_sync_settings().await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsOrganization,
        Some(&context.user),
        None,
        "updated organization IDP sync settings",
    )
    .await;

    Ok((StatusCode::OK, Json(settings)).into_response())
}

/// `PATCH /api/v2/settings/idpsync/organization/config`
///
/// Partial update: changes `field` and `assign_default` while preserving the
/// existing mapping.
pub(crate) async fn patch_org_idpsync_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PatchOrganizationIDPSyncConfigRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::IdpsyncSettings),
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

    let existing = state.store.get_organization_idp_sync_settings().await?;

    let updated = OrganizationSyncSettings {
        field: request.field,
        assign_default: request.assign_default,
        mapping: existing.mapping,
    };

    state
        .store
        .upsert_organization_idp_sync_settings(&updated)
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsOrganization,
        Some(&context.user),
        None,
        "updated organization IDP sync config",
    )
    .await;

    Ok((StatusCode::OK, Json(updated)).into_response())
}

/// `PATCH /api/v2/settings/idpsync/organization/mapping`
///
/// Adds and/or removes individual mapping entries without replacing the full
/// settings.  If a mapping appears in both `add` and `remove`, the removal
/// takes precedence (matching Go behaviour).
pub(crate) async fn patch_org_idpsync_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PatchOrganizationIDPSyncMappingRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::IdpsyncSettings),
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

    let existing = state.store.get_organization_idp_sync_settings().await?;

    let new_mapping = apply_idp_sync_mapping_diff(existing.mapping, &request.add, &request.remove);

    let updated = OrganizationSyncSettings {
        field: existing.field,
        assign_default: existing.assign_default,
        mapping: new_mapping,
    };

    state
        .store
        .upsert_organization_idp_sync_settings(&updated)
        .await?;

    record_audit(
        &state,
        AuditAction::Write,
        ResourceKind::IdpSyncSettingsOrganization,
        Some(&context.user),
        None,
        "updated organization IDP sync mapping",
    )
    .await;

    Ok((StatusCode::OK, Json(updated)).into_response())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Applies add/remove diffs to a mapping, matching Go's `applyIDPSyncMappingDiff`.
fn apply_idp_sync_mapping_diff(
    previous: HashMap<String, Vec<Uuid>>,
    add: &[IDPSyncMappingUUID],
    remove: &[IDPSyncMappingUUID],
) -> HashMap<String, Vec<Uuid>> {
    let mut next: HashMap<String, Vec<Uuid>> = HashMap::new();

    // Copy existing mapping.
    for (key, ids) in &previous {
        next.entry(key.clone()).or_default().extend(ids);
    }

    // Add unique entries.
    for mapping in add {
        let ids = next.entry(mapping.given.clone()).or_default();
        if !ids.contains(&mapping.gets) {
            ids.push(mapping.gets);
        }
    }

    // Remove entries.
    for mapping in remove {
        if let Some(ids) = next.get_mut(&mapping.given) {
            ids.retain(|id| *id != mapping.gets);
        }
    }

    next
}
