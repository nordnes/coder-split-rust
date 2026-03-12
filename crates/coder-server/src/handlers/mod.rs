//! Domain-specific handler modules.
//!
//! Each sub-module implements the Axum handler functions for one API domain
//! (users, workspaces, templates, etc.).  Shared imports and re-exports are
//! centralised here so individual handler files stay focused on request logic.

pub(crate) use crate::app::*;
pub(crate) use crate::error::AppError;
pub(crate) use crate::helpers::*;

use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
    Form, Json,
    body::Bytes,
    extract::{
        OriginalUri, Path, Query, State,
        rejection::JsonRejection,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    },
    response::{IntoResponse, Response},
};
use coder_audit::AuditAction;
use coder_auth::{
    OAUTH2_REDIRECT_COOKIE, OAUTH2_STATE_COOKIE, OAuth2ProviderError, cookie_from_headers,
    supported_auth_methods,
};
use coder_connectivity::agents::{AgentConnection, AgentError, AgentProvider};
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
use coder_core::template::{
    CreateProvisionerJobInput, CreateTemplateInput, CreateTemplateStoreError,
    CreateTemplateVersionInput, ProvisionerJobRecord as TemplateProvisionerJobRecord,
    TemplateListFilter, TemplateRecord, TemplateVersionListFilter, TemplateVersionRecord,
    UpdateTemplateMetaInput,
};
use coder_core::{
    AWSInstanceIdentityToken, ApiResponse, AppHostResponse, AppStore, AuditLogListFilter,
    AuthMethods, AuthorizationRequest, AvailableExperiments, AzureInstanceIdentityToken,
    ChangePasswordWithOneTimePasscodeRequest, ChatMessagePart, ChatMessageRecord,
    ChatMessageResponse, ChatMessageUsage, ChatMessageVisibility, ChatModelCallConfig,
    ChatModelConfigRecord, ChatModelConfigResponse, ChatProviderConfigResponse,
    ChatProviderConfigSource, ChatProviderRecord, ChatQueuedMessageRecord,
    ChatQueuedMessageResponse, ChatRecord, ChatResponse, ChatWithMessagesResponse,
    ConvertLoginRequest, CreateChatMessageApiResponse, CreateChatMessageRequest,
    CreateChatModelConfigRequest, CreateChatProviderConfigRequest, CreateChatRequest,
    CreateFirstUserRequest, CreateFirstUserResponse, CreateLogSourceRequest, CreateTaskRequest,
    CreateTestAuditLogRequest, CreateTokenRequest, CreateUserRequestWithOrgs,
    CreateWorkspaceBuildInput, CreateWorkspaceInput, DERPMap, DERPMapRegion, DERPNode,
    DeploymentConfigResponse, EditChatMessageRequest, ExternalApiKeyScopes,
    ExternalAuthDeviceExchangeRequest, GCPInstanceIdentityToken, GetUsersResponse, HealthSettings,
    InsertChatInput, InsertChatMessageInput, InsertChatModelConfigInput, InsertChatProviderInput,
    InsertFileInput, InsertTaskInput, LoginType, LoginWithPasswordRequest,
    OAuth2AuthorizationServerMetadata, OAuth2AuthorizeRequest, OAuth2ClientConfiguration,
    OAuth2ClientRegistrationRequest, OAuth2ClientRegistrationResponse, OAuth2ErrorResponse,
    OAuth2ProtectedResourceMetadata, OAuth2ProviderAppEndpoints, OAuth2ProviderAppResponse,
    OAuth2ProviderAppSecretFullResponse, OAuth2ProviderAppSecretResponse, OAuth2TokenRequest,
    OAuth2TokenResponse, OAuth2TokenRevocationRequest, OrganizationMember,
    OrganizationMemberWithUserData, OrganizationRecord, OrganizationResponse,
    PaginatedMembersResponse, PatchAgentLogsRequest, PatchAppStatusRequest, PersistAuditLogInput,
    PostOAuth2ProviderAppRequest, PutOAuth2ProviderAppRequest, RequestOneTimePasscodeRequest,
    ServerConfig, SshConfigResponse, TaskListFilter, TaskLogSnapshotEnvelope, TaskLogsResponse,
    TaskRecord, TaskResponse, TaskSendRequest, TasksListResponse, UpdateChatMessageContentInput,
    UpdateChatModelConfigInput, UpdateChatModelConfigRequest, UpdateChatProviderConfigRequest,
    UpdateChatProviderInput, UpdateCheckResponse, UpdateInboxNotificationReadStatusRequest,
    UpdateNotificationTemplateMethod, UpdateRolesRequest, UpdateUserAppearanceSettingsRequest,
    UpdateUserNotificationPreferences, UpdateUserPasswordRequest,
    UpdateUserPreferenceSettingsRequest, UpdateUserProfileRequest, UploadFileResponse,
    UpsertPortShareInput, UserAppearanceSettings, UserListFilter, UserParameter,
    UserPreferenceSettings, UserResponse, UserRolesResponse, UserStatus,
    ValidateUserPasswordRequest, ValidationError, WebpushSubscription,
    WorkspaceAgentAuthenticateResponse, WorkspaceAgentConnectionInfo,
    WorkspaceAgentListContainersResponse, WorkspaceAgentListeningPortsResponse,
    WorkspaceListFilter,
};
use coder_provisioner::{InitScriptError, render_init_script};
use coder_rbac::{Action, Authorizer, Object, ResourceKind, ResourceType};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use time::OffsetDateTime;
use tracing::debug;
use uuid::Uuid;

/// Strips Markdown formatting from a string, returning plain text.
///
/// This is a lightweight implementation that handles the most common Markdown
/// constructs (headings, bold/italic, links, images, inline code, fenced code
/// blocks, blockquotes, list markers, horizontal rules, and HTML tags).
/// It matches the Go reference behaviour of `coderd/richparameters.go:stripMarkdown`.
pub(crate) fn strip_markdown(md: &str) -> String {
    let mut out = String::with_capacity(md.len());
    let mut in_fenced_block = false;

    for line in md.lines() {
        let trimmed = line.trim();

        // Toggle fenced code blocks (``` or ~~~).
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fenced_block = !in_fenced_block;
            continue;
        }
        if in_fenced_block {
            // Keep code block content as-is.
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(line);
            continue;
        }

        // Skip horizontal rules (---, ***, ___).
        if trimmed.len() >= 3
            && (trimmed.chars().all(|c| c == '-' || c == ' ')
                || trimmed.chars().all(|c| c == '*' || c == ' ')
                || trimmed.chars().all(|c| c == '_' || c == ' '))
            && trimmed.chars().filter(|c| !c.is_whitespace()).count() >= 3
        {
            continue;
        }

        let mut s = line.to_string();

        // Strip heading markers (# … ######).
        if let Some(rest) = s.strip_prefix("######") {
            s = rest.trim().to_string();
        } else if let Some(rest) = s.strip_prefix("#####") {
            s = rest.trim().to_string();
        } else if let Some(rest) = s.strip_prefix("####") {
            s = rest.trim().to_string();
        } else if let Some(rest) = s.strip_prefix("###") {
            s = rest.trim().to_string();
        } else if let Some(rest) = s.strip_prefix("##") {
            s = rest.trim().to_string();
        } else if let Some(rest) = s.strip_prefix('#') {
            s = rest.trim().to_string();
        }

        // Strip blockquote markers.
        while s.starts_with("> ") || s.starts_with('>') {
            s = s.trim_start_matches('>').trim_start().to_string();
        }

        // Strip unordered list markers (- , * , + ).
        if let Some(rest) = s.strip_prefix("- ") {
            s = rest.to_string();
        } else if let Some(rest) = s.strip_prefix("* ") {
            s = rest.to_string();
        } else if let Some(rest) = s.strip_prefix("+ ") {
            s = rest.to_string();
        }

        // Strip images: ![alt](url) -> alt
        while let Some(start) = s.find("![") {
            if let Some(alt_end) = s[start + 2..].find("](") {
                let alt_end = start + 2 + alt_end;
                if let Some(url_end) = s[alt_end + 2..].find(')') {
                    let url_end = alt_end + 2 + url_end;
                    let alt = s[start + 2..alt_end].to_string();
                    s = format!("{}{}{}", &s[..start], alt, &s[url_end + 1..]);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Strip links: [text](url) -> text
        while let Some(start) = s.find('[') {
            if let Some(text_end) = s[start + 1..].find("](") {
                let text_end = start + 1 + text_end;
                if let Some(url_end) = s[text_end + 2..].find(')') {
                    let url_end = text_end + 2 + url_end;
                    let text = s[start + 1..text_end].to_string();
                    s = format!("{}{}{}", &s[..start], text, &s[url_end + 1..]);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Strip inline code (`code`).
        s = s.replace('`', "");

        // Strip bold and italic markers (**, __, *, _).
        // Order matters: strip double before single.
        s = s.replace("**", "");
        s = s.replace("__", "");
        s = s.replace('*', "");
        s = s.replace('_', "");

        // Strip simple HTML tags (<tag> and </tag>).
        while let Some(start) = s.find('<') {
            if let Some(end) = s[start..].find('>') {
                s = format!("{}{}", &s[..start], &s[start + end + 1..]);
            } else {
                break;
            }
        }

        let trimmed_s = s.trim();
        if trimmed_s.is_empty() {
            continue;
        }

        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(trimmed_s);
    }

    out
}

pub(crate) mod agents;
pub(crate) mod audit;
pub(crate) mod auth;
pub(crate) mod chats;
pub(crate) mod deployment;
pub(crate) mod derp;
pub(crate) mod external_auth;
pub(crate) mod files;
pub(crate) mod health;
pub(crate) mod insights;
pub(crate) mod licenses;
pub(crate) mod mcp;
pub(crate) mod notifications;
pub(crate) mod oauth2;
pub(crate) mod organizations;
pub(crate) mod tasks;
pub(crate) mod telemetry;
pub(crate) mod templates;
pub(crate) mod users;
// Many items are defined for incremental integration (database-backed app
// resolution, subdomain middleware wiring, etc.) and are only exercised in
// tests for now.
#[allow(dead_code)]
pub(crate) mod workspace_apps;
pub(crate) mod workspaces;
