//! External Auth handlers.

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

pub(crate) async fn list_external_auths(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };

    Ok(Json(
        state
            .external_auth
            .list(&state.config.external_auth_providers, context.user.id)
            .await?,
    )
    .into_response())
}

pub(crate) async fn get_external_auth_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    let response = state
        .external_auth
        .get(
            &state.config.external_auth_providers,
            context.user.id,
            &provider,
        )
        .await?;
    let Some(response) = response else {
        debug_assert!(config.id.eq_ignore_ascii_case(&provider));
        return Ok(resource_not_found_response());
    };

    Ok(Json(response).into_response())
}

pub(crate) async fn delete_external_auth_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(response) = state
        .external_auth
        .delete(
            &state.config.external_auth_providers,
            context.user.id,
            &provider,
        )
        .await?
    else {
        return Ok(resource_not_found_response());
    };

    record_audit(
        &state,
        AuditAction::Delete,
        ResourceKind::ExternalAuth,
        Some(&context.user),
        Some(provider.clone()),
        "deleted external auth link",
    )
    .await;

    Ok((StatusCode::OK, Json(response)).into_response())
}

pub(crate) async fn get_external_auth_device_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let Some(_context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    if !config.device {
        return Ok(external_auth_device_flow_unsupported_response());
    }

    state
        .external_auth
        .authorize_device(config)
        .await
        .map(|device| (StatusCode::OK, Json(device)).into_response())
        .or_else(|error| handle_external_auth_error("Failed to authorize device.", error))
}

pub(crate) async fn post_external_auth_device_exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    payload: Result<Json<ExternalAuthDeviceExchangeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(unauthorized_response("Missing or invalid session token."));
    };
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    if !config.device {
        return Ok(external_auth_device_flow_unsupported_response());
    }
    let Json(request) = match payload {
        Ok(request) => request,
        Err(error) => return Ok(invalid_json_response(error)),
    };
    if request.device_code.trim().is_empty() {
        return Ok(validation_message_response(
            "Request body has invalid fields.",
            vec![ValidationError {
                field: "device_code".to_owned(),
                detail: "Missing value, this cannot be empty".to_owned(),
            }],
        ));
    }

    if let Err(error) = state
        .external_auth
        .exchange_device(config, context.user.id, &request)
        .await
    {
        return handle_external_auth_error("Failed to exchange device code.", error);
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_external_auth_callback_by_id(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(query): Query<ExternalAuthCallbackQuery>,
) -> Result<Response, AppError> {
    let Some(config) = find_external_auth_provider(&state, &provider) else {
        return Ok(resource_not_found_response());
    };
    let Some(context) = authenticate_request(&state, &headers).await? else {
        return Ok(redirect_to_login_response(
            &uri,
            "Missing or invalid session token.",
        ));
    };
    let Some(state_value) = query.state.filter(|value| !value.trim().is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("State must be provided.")),
        )
            .into_response());
    };
    let Some(state_cookie) = cookie_from_headers(&headers, OAUTH2_STATE_COOKIE) else {
        return Ok(unauthorized_response(format!(
            "Cookie {OAUTH2_STATE_COOKIE:?} must be provided."
        )));
    };
    if state_cookie != state_value {
        return Ok(unauthorized_response("State mismatched."));
    }
    let Some(code) = query.code.filter(|value| !value.trim().is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::ok("Code must be provided.")),
        )
            .into_response());
    };

    if let Err(error) = state
        .external_auth
        .exchange_callback(config, context.user.id, &code)
        .await
    {
        return handle_external_auth_error("Failed exchanging OAuth code.", error);
    }

    let redirect = cookie_from_headers(&headers, OAUTH2_REDIRECT_COOKIE)
        .map(|value| sanitize_redirect_uri(&value))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("/external-auth/{provider}?redirected=true"));

    let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&redirect).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    Ok(response)
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ExternalAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}
