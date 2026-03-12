//! Audit log listing and test generation handlers.

use super::users::clamp_pagination_limit;
use super::*;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AuditQuery {
    #[serde(default)]
    q: String,
    limit: Option<u32>,
    offset: Option<u32>,
}

/// GET /api/v2/audit — list audit log entries with optional filtering.
pub(crate) async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    // RBAC: verify the actor can read audit logs.
    // This replaces the previous can_view_operational_data() check, which was
    // redundant — role_auditor() and role_owner() both grant AuditLog::Read at
    // site level, and the RBAC check is strictly more correct and extensible.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Read,
            &Object::new(ResourceType::AuditLog),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to view audit logs.",
        ));
    }

    let response = state
        .store
        .list_audit_logs(AuditLogListFilter {
            search: query.q,
            limit: clamp_pagination_limit(query.limit.unwrap_or(50)),
            offset: query.offset.unwrap_or_default(),
        })
        .await?;

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// POST /api/v2/audit/testgenerate — create a synthetic audit log entry for testing.
pub(crate) async fn post_generate_test_audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateTestAuditLogRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // RBAC: verify the actor can create audit log entries.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::AuditLog),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to generate audit logs.",
        ));
    }

    let Json(mut request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };

    if request.time.is_none() {
        request.time = Some(OffsetDateTime::now_utc());
    }

    let mut additional_fields = match request.additional_fields {
        Value::Null => json!({}),
        value => value,
    };
    if let Some(build_reason) = request.build_reason {
        if !additional_fields.is_object() {
            additional_fields = json!({});
        }
        if let Some(fields) = additional_fields.as_object_mut() {
            fields.insert("build_reason".to_owned(), Value::String(build_reason));
        }
    }

    state
        .store
        .insert_audit_log(PersistAuditLogInput {
            id: Uuid::new_v4(),
            request_id: request.request_id.or_else(|| Some(Uuid::new_v4())),
            time: request.time.unwrap_or_else(OffsetDateTime::now_utc),
            ip: String::new(),
            user_agent: String::new(),
            resource_type: request.resource_type.as_str().to_owned(),
            resource_id: request.resource_id.or_else(|| Some(Uuid::new_v4())),
            resource_target: context.user.username.clone(),
            resource_icon: String::new(),
            action: request.action.as_str().to_owned(),
            diff: json!({
                "foo": {
                    "old": "bar",
                    "new": "baz",
                    "secret": false
                }
            }),
            status_code: i32::from(StatusCode::OK.as_u16()),
            additional_fields,
            description: "generated test audit log".to_owned(),
            resource_link: String::new(),
            is_deleted: false,
            organization_id: request.organization_id,
            user_id: Some(context.user.id),
        })
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
