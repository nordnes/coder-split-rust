//! Tasks handlers.

use std::{collections::HashMap, str::FromStr, sync::Arc};

use async_trait::async_trait;
use axum::{
    Form, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, OriginalUri, Path, Query, State,
        rejection::JsonRejection,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{
            ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
            ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, LOCATION,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
};
use coder_audit::{AuditAction, AuditEvent, AuditSink};
use coder_auth::{
    AuthService, AuthServiceError, AuthenticatedRequest, ExternalAuthService,
    ExternalAuthServiceError, OAUTH2_REDIRECT_COOKIE, OAUTH2_STATE_COOKIE, OAuth2ProviderError,
    OAuth2ProviderService, cookie_from_headers, supported_auth_methods,
};
use coder_connectivity::{
    HealthService,
    agents::{AgentConnection, AgentError, AgentProvider},
    generate_git_ssh_key,
    tailnet::{DerpTrafficTracker, TailnetCoordinator},
};
use coder_core::StorageError;
use coder_core::api::{
    ArchiveTemplateVersionsRequest, ArchiveTemplateVersionsResponse, CreateTemplateRequest,
    CreateTemplateVersionDryRunRequest, CreateTemplateVersionRequest, DAUEntry, DAUsResponse,
    DynamicParametersRequest, DynamicParametersResponse, MatchedProvisioners, MinimalUser,
    PatchTemplateVersionRequest, ProvisionerJobLog, ProvisionerJobResponse, ProvisionerJobStatus,
    TemplateExample, TemplateFilter, TemplateResponse, TemplateVersionExternalAuth,
    TemplateVersionParameter, TemplateVersionPreset, TemplateVersionPresetParameter,
    TemplateVersionResponse, TemplateVersionVariable, UpdateActiveTemplateVersionRequest,
    UpdateTemplateMeta, WorkspaceBuildParameter, WorkspaceResource, WorkspaceResourceMetadata,
    WorkspaceResourceResponse,
};
use coder_core::api::{InsightsReportInterval, TemplateInsightsSection};
use coder_core::api::{
    UpdateWorkspaceACLRequest, WorkspaceACLGroup, WorkspaceACLResponse, WorkspaceACLUser,
};
use coder_core::ports::UpdateWorkspaceACLInput;
use coder_core::pubsub::PubSub;
use coder_core::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord as TemplateProvisionerJobRecord,
    TemplateListFilter, TemplateRecord, TemplateVersionListFilter, TemplateVersionRecord,
    UpdateTemplateMetaInput,
};
use coder_core::{
    AWSInstanceIdentityToken, ApiResponse, AppHostResponse, AppStore, AuditLogListFilter,
    AuthMethods, AuthenticatedUser, AuthorizationRequest, AvailableExperiments,
    AzureInstanceIdentityToken, BuildMetadata, ChangePasswordWithOneTimePasscodeRequest,
    ChatMessagePart, ChatMessageRecord, ChatMessageResponse, ChatMessageUsage,
    ChatMessageVisibility, ChatQueuedMessageRecord, ChatQueuedMessageResponse, ChatRecord,
    ChatResponse, ChatWithMessagesResponse, ConvertLoginRequest, CreateChatMessageApiResponse,
    CreateChatMessageRequest, CreateChatRequest, CreateFirstUserRequest, CreateFirstUserResponse,
    CreateLogSourceRequest, CreateTaskRequest, CreateTestAuditLogRequest, CreateTokenRequest,
    CreateUserRequestWithOrgs, CreateWorkspaceBuildInput, CreateWorkspaceInput, DERPMap,
    DERPMapRegion, DERPNode, DeploymentConfigResponse, ExternalApiKeyScopes,
    ExternalAuthDeviceExchangeRequest, GCPInstanceIdentityToken, GetUsersResponse, HealthSettings,
    HealthcheckReport, InsertChatInput, InsertChatMessageInput, InsertFileInput, InsertTaskInput,
    LoginType, LoginWithPasswordRequest, OAuth2AuthorizeRequest, OAuth2ProviderAppEndpoints,
    OAuth2ProviderAppResponse, OAuth2ProviderAppSecretFullResponse,
    OAuth2ProviderAppSecretResponse, OAuth2TokenRequest, OAuth2TokenResponse, OrganizationMember,
    OrganizationMemberWithUserData, OrganizationRecord, OrganizationResponse,
    PaginatedMembersResponse, PatchAgentLogsRequest, PatchAppStatusRequest, PersistAuditLogInput,
    PostOAuth2ProviderAppRequest, PutOAuth2ProviderAppRequest, RequestOneTimePasscodeRequest,
    ServerConfig, SshConfigResponse, TaskListFilter, TaskLogSnapshotEnvelope, TaskLogsResponse,
    TaskRecord, TaskResponse, TaskSendRequest, TasksListResponse, UpdateCheckResponse,
    UpdateInboxNotificationReadStatusRequest, UpdateNotificationTemplateMethod, UpdateRolesRequest,
    UpdateUserAppearanceSettingsRequest, UpdateUserNotificationPreferences,
    UpdateUserPasswordRequest, UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest,
    UploadFileResponse, UpsertPortShareInput, UserAppearanceSettings, UserListFilter,
    UserParameter, UserPreferenceSettings, UserRecord, UserResponse, UserRolesResponse, UserStatus,
    ValidateUserPasswordRequest, ValidationError, WebpushSubscription,
    WorkspaceAgentAuthenticateResponse, WorkspaceAgentConnectionInfo,
    WorkspaceAgentListContainersResponse, WorkspaceAgentListeningPortsResponse,
    WorkspaceListFilter,
};
use coder_identity::{IdentityService, IdentityServiceError};
use coder_provisioner::{InitScriptError, render_init_script};
use coder_rbac::{Action, Actor, Authorizer, Object, ROLE_AUDITOR, ResourceKind, ResourceType};
use coder_workspaces::DeploymentStatsService;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use time::OffsetDateTime;
use tracing::debug;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;
use crate::helpers::*;

/// GET /tasks — list tasks for the authenticated user.
pub(crate) async fn list_tasks(
    State(state): State<AppState>,
    Query(query): Query<TasksQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Always scope to the authenticated user — no cross-user enumeration.
    let filter = TaskListFilter {
        owner_id: Some(context.user.id),
        organization_id: query.organization_id,
        ..Default::default()
    };
    let tasks = state.store.list_tasks(filter).await?;
    let count = tasks.len();
    let task_responses: Vec<TaskResponse> =
        tasks.into_iter().map(task_response_from_record).collect();

    Ok(Json(TasksListResponse {
        tasks: task_responses,
        count,
    })
    .into_response())
}

/// POST /tasks/{user} — create a new task.
pub(crate) async fn create_task(
    State(state): State<AppState>,
    Path(user_param): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CreateTaskRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    // Resolve the user from the path parameter.
    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok(not_found_response("Task not found."));
    };

    // Only allow creating tasks for oneself.
    if target_user.id != context.user.id {
        return Ok(not_found_response("Task not found."));
    }

    // RBAC: verify the actor can create a task.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Create,
            &Object::new(ResourceType::Task).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to create tasks.",
        ));
    }

    let now = OffsetDateTime::now_utc();
    let task_id = Uuid::new_v4();
    let name = request.name.unwrap_or_else(|| format!("task-{task_id}"));
    let display_name = request.display_name.unwrap_or_default();

    let Some(&organization_id) = context.user.organization_ids.first() else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error(
                "User has no organization memberships.",
                "A task cannot be created without an organization.",
            )),
        )
            .into_response());
    };

    let input = InsertTaskInput {
        id: task_id,
        organization_id,
        owner_id: context.user.id,
        name,
        display_name,
        template_version_id: request.template_version_id,
        template_parameters: Value::Object(serde_json::Map::new()),
        prompt: request.input,
        created_at: now,
    };

    let record = state.store.insert_task(input).await?;
    Ok((StatusCode::CREATED, Json(task_response_from_record(record))).into_response())
}

/// Helper: resolve a task from the `{task}` path segment — accepts UUID or
/// task name (scoped to owner).
pub(crate) async fn resolve_task(
    state: &AppState,
    task_param: &str,
    owner_id: Uuid,
) -> Result<Option<TaskRecord>, AppError> {
    // Try parsing as UUID first.
    if let Ok(task_id) = Uuid::parse_str(task_param) {
        let record = state.store.find_task_by_id(task_id).await?;
        // Ensure the task belongs to the expected owner.
        return Ok(record.filter(|r| r.owner_id == owner_id));
    }

    // Fall back to name-based lookup.
    state
        .store
        .find_task_by_owner_and_name(owner_id, task_param)
        .await
        .map_err(AppError::from)
}

/// GET /tasks/{user}/{task} — get a single task by ID or name.
pub(crate) async fn get_task(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok(not_found_response("Task not found."));
    };

    // Only allow viewing own tasks.
    if target_user.id != context.user.id {
        return Ok(not_found_response("Task not found."));
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok(not_found_response("Task not found."));
    };

    Ok(Json(task_response_from_record(record)).into_response())
}

/// PATCH /tasks/{user}/{task}/input — update a task's input (prompt).
pub(crate) async fn patch_task_input(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<coder_core::UpdateTaskInputRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok(not_found_response("Task not found."));
    };

    if target_user.id != context.user.id {
        return Ok(not_found_response("Task not found."));
    }

    // RBAC: verify the actor can update a task.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Task).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to update this task.",
        ));
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok(not_found_response("Task not found."));
    };

    // Validate non-empty input.
    if request.input.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Task input is required.", "")),
        )
            .into_response());
    }

    // In the Go implementation, the task must be paused to update input.
    if record.status != coder_core::TaskStatus::Paused {
        return Ok((
            StatusCode::CONFLICT,
            Json(ApiResponse::error(
                "Unable to update task input, task must be paused.",
                "Please stop the task's workspace before updating the input.",
            )),
        )
            .into_response());
    }

    let _updated = state
        .store
        .update_task_prompt(record.id, &request.input)
        .await?;

    // Go returns 204 No Content on success.
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// DELETE /tasks/{user}/{task} — soft-delete a task.
pub(crate) async fn delete_task(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok(not_found_response("Task not found."));
    };

    if target_user.id != context.user.id {
        return Ok(not_found_response("Task not found."));
    }

    // RBAC: verify the actor can delete a task.
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Delete,
            &Object::new(ResourceType::Task).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to delete this task.",
        ));
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok(not_found_response("Task not found."));
    };

    let now = OffsetDateTime::now_utc();
    let deleted = state.store.delete_task(record.id, now).await?;
    if !deleted {
        return Ok(not_found_response("Task not found."));
    }

    // Go returns 202 Accepted (workspace deletion is async).
    Ok(StatusCode::ACCEPTED.into_response())
}

/// GET /tasks/{user}/{task}/logs — get task logs (snapshot-based).
pub(crate) async fn get_task_logs(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok(not_found_response("Task not found."));
    };

    if target_user.id != context.user.id {
        return Ok(not_found_response("Task not found."));
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok(not_found_response("Task not found."));
    };

    // In the Go implementation, error/unknown status tasks cannot fetch logs.
    match record.status {
        coder_core::TaskStatus::Error | coder_core::TaskStatus::Unknown => {
            return Ok((
                StatusCode::CONFLICT,
                Json(ApiResponse::error(
                    "Cannot fetch logs for task in current state.",
                    format!("Task status is {}.", record.status),
                )),
            )
                .into_response());
        }
        // Active tasks would normally fetch live logs from the agent; for the
        // Rust port we fall through to the snapshot path since we don't yet
        // have the agent-dial infrastructure.
        _ => {}
    }

    // Check for a stored snapshot.
    let snapshot = state.store.find_task_snapshot(record.id).await?;
    let response = match snapshot {
        Some(snap) => TaskLogsResponse {
            logs: Vec::new(),
            snapshot: true,
            snapshot_at: Some(snap.log_snapshot_created_at),
        },
        None => TaskLogsResponse {
            logs: Vec::new(),
            snapshot: false,
            snapshot_at: None,
        },
    };

    Ok(Json(response).into_response())
}

/// POST /tasks/{user}/{task}/send — send input to a task.
pub(crate) async fn post_task_send(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<TaskSendRequest>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok(not_found_response("Task not found."));
    };

    if target_user.id != context.user.id {
        return Ok(not_found_response("Task not found."));
    }

    // RBAC: verify the actor can update a task (send is a form of update).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Task).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to send input to this task.",
        ));
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok(not_found_response("Task not found."));
    };

    // Validate non-empty input.
    if request.input.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Task input is required.", "")),
        )
            .into_response());
    }

    // Task must be active to accept input (matches Go status check).
    match record.status {
        coder_core::TaskStatus::Active => { /* ok */ }
        coder_core::TaskStatus::Pending | coder_core::TaskStatus::Initializing => {
            return Ok((
                StatusCode::CONFLICT,
                Json(ApiResponse::error(
                    format!("Task is {}.", record.status),
                    "The task is resuming. Wait for the task to become active before sending messages.",
                )),
            )
                .into_response());
        }
        coder_core::TaskStatus::Paused => {
            return Ok((
                StatusCode::CONFLICT,
                Json(ApiResponse::error(
                    "Task is paused.",
                    "Resume the task to send messages.",
                )),
            )
                .into_response());
        }
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(
                    "Task must be active.",
                    format!(
                        "Task status is {}, it must be \"active\" to interact with the task.",
                        record.status
                    ),
                )),
            )
                .into_response());
        }
    }

    // In the full implementation this dials the agent and sends input to the
    // workspace sidebar app via AgentAPI. For now we acknowledge the request.
    // Go returns 204 No Content.
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// POST /tasks/{user}/{task}/pause — pause a task.
pub(crate) async fn post_task_pause(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok(not_found_response("Task not found."));
    };

    if target_user.id != context.user.id {
        return Ok(not_found_response("Task not found."));
    }

    // RBAC: verify the actor can update a task (pause is a form of update).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Task).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to pause this task.",
        ));
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok(not_found_response("Task not found."));
    };

    // Task must have a workspace to pause.
    if record.workspace_id.is_none() {
        return Ok(internal_server_error_response(
            "Task does not have a workspace.",
        ));
    }

    // In the full implementation this would stop the workspace (transition =
    // stop) and enqueue a notification. Go returns 202 Accepted.
    Ok((
        StatusCode::ACCEPTED,
        Json(coder_core::PauseTaskResponse {
            workspace_build: None,
        }),
    )
        .into_response())
}

/// POST /tasks/{user}/{task}/resume — resume a task.
pub(crate) async fn post_task_resume(
    State(state): State<AppState>,
    Path((user_param, task_param)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    let Some(target_user) = resolve_user(&state, &user_param, &context.user).await? else {
        return Ok(not_found_response("Task not found."));
    };

    if target_user.id != context.user.id {
        return Ok(not_found_response("Task not found."));
    }

    // RBAC: verify the actor can update a task (resume is a form of update).
    let authorizer = Authorizer::new();
    if authorizer
        .authorize(
            &context.actor,
            Action::Update,
            &Object::new(ResourceType::Task).with_owner(context.user.id),
        )
        .is_err()
    {
        return Ok(forbidden_response(
            "You are not authorized to resume this task.",
        ));
    }

    let Some(record) = resolve_task(&state, &task_param, target_user.id).await? else {
        return Ok(not_found_response("Task not found."));
    };

    // Task must have a workspace to resume.
    if record.workspace_id.is_none() {
        return Ok(internal_server_error_response(
            "Task does not have a workspace.",
        ));
    }

    // In the full implementation this would start the workspace (transition =
    // start) and enqueue a notification. Go returns 202 Accepted.
    Ok((
        StatusCode::ACCEPTED,
        Json(coder_core::ResumeTaskResponse {
            workspace_build: None,
        }),
    )
        .into_response())
}

pub(crate) async fn post_task_log_snapshot(
    State(state): State<AppState>,
    Path(task_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<TaskLogSnapshotEnvelope>,
) -> Result<Response, AppError> {
    // This endpoint supports both agent auth and user auth.
    // Agents post log snapshots for tasks running in their workspace.
    let agent = authenticate_agent_request(&state, &headers).await?;
    let owner_id = if let Some(ref agent_row) = agent {
        // Agent auth: look up the workspace owner.
        let workspace = state.store.find_workspace_by_agent_id(agent_row.id).await?;
        match workspace {
            Some(ws) => ws.owner_id,
            None => {
                return Ok(internal_server_error_response(
                    "Failed to resolve workspace for agent.",
                ));
            }
        }
    } else {
        // Fall back to user auth.
        let Some(context) = authenticate_request(&state, &headers).await? else {
            return Ok(unauthorized_response("Missing or invalid session token."));
        };
        context.user.id
    };

    let Some(record) = state.store.find_task_by_id(task_id).await? else {
        return Ok(not_found_response("Task not found."));
    };

    if record.owner_id != owner_id {
        return Ok(not_found_response("Task not found."));
    }

    let now = OffsetDateTime::now_utc();
    state
        .store
        .upsert_task_snapshot(task_id, &request.log_snapshot, now)
        .await?;

    Ok((StatusCode::OK, Json(ApiResponse::ok("Snapshot saved."))).into_response())
}

pub(crate) fn task_response_from_record(record: TaskRecord) -> TaskResponse {
    TaskResponse {
        id: record.id,
        organization_id: record.organization_id,
        owner_id: record.owner_id,
        owner_name: String::new(),
        owner_avatar_url: String::new(),
        name: record.name,
        display_name: record.display_name,
        template_version_id: record.template_version_id,
        workspace_id: record.workspace_id,
        initial_prompt: record.prompt,
        status: record.status,
        current_state: None,
        created_at: record.created_at,
    }
}

#[derive(Deserialize)]
pub(crate) struct TasksQuery {
    #[serde(default)]
    organization_id: Option<Uuid>,
}
