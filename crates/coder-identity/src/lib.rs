//! Identity and organization boundary for the Rust `coderd` rewrite.
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use coder_core::{
    AssignableRoleResponse, CreateGroupInput, CreateUserInput, CreateUserRequestWithOrgs,
    CreateUserStoreError, CustomRoleRecord, GroupMemberRecord, GroupRecord, IdentityStore,
    InsertOrganizationMemberError, LoginType, OrganizationMemberListFilter,
    OrganizationMemberRecord, PasswordError, RoleResponse, StorageError, UpdateRolesRequest,
    UpdateUserAppearanceSettingsRequest, UpdateUserPreferenceSettingsRequest,
    UpdateUserProfileRequest, UpsertCustomRoleInput, UpsertUserLinkInput, UserAppearanceRecord,
    UserConfigRecord, UserLinkRecord, UserPreferenceRecord, UserRecord, UserStatus,
    UserStatusChangeRecord, ValidationError, hash_password, normalize_real_name, validate_email,
    validate_password, validate_real_name, validate_username,
};
use coder_rbac::{Actor, BuiltinRole, organization_builtin_roles, site_builtin_roles};
use thiserror::Error;
use uuid::Uuid;

pub use coder_core::{
    AuthenticatedUser, CreateApiKeyInput, CreateApiKeyStoreError, CreateFirstUserInput,
    CreateFirstUserRequest, CreateFirstUserResponse, CreateFirstUserStoreError, FirstUserRecord,
    InsertOrganizationMemberError as InsertOrganizationMemberStoreError, OrganizationResponse,
    PasswordUserRecord, SlimRole, UserResponse,
};

const SUPPORTED_TERMINAL_FONTS: &[&str] = &[
    "",
    "geist-mono",
    "ibm-plex-mono",
    "fira-code",
    "source-code-pro",
    "jetbrains-mono",
];

/// Identity-domain failures mapped by the HTTP layer.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum IdentityServiceError {
    /// Backing store failure.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Resource not found.
    #[error("{message}")]
    NotFound { message: String },
    /// Action is forbidden.
    #[error("{message}")]
    Forbidden { message: String },
    /// Request is syntactically valid but rejected by domain rules.
    #[error("{message}")]
    BadRequest {
        message: String,
        detail: Option<String>,
    },
    /// Request failed field validation.
    #[error("{message}")]
    Validation {
        message: String,
        validations: Vec<ValidationError>,
    },
    /// Request conflicts with existing state.
    #[error("{message}")]
    Conflict {
        message: String,
        detail: Option<String>,
        validations: Vec<ValidationError>,
    },
}

impl IdentityServiceError {
    fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound {
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden {
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
            detail: None,
        }
    }

    fn bad_request_with_detail(message: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
            detail: Some(detail.into()),
        }
    }

    fn validation(message: impl Into<String>, validations: Vec<ValidationError>) -> Self {
        Self::Validation {
            message: message.into(),
            validations,
        }
    }

    fn conflict(message: impl Into<String>, validations: Vec<ValidationError>) -> Self {
        Self::Conflict {
            message: message.into(),
            detail: None,
            validations,
        }
    }
}

/// Domain service for users, organizations, memberships, roles, and preferences.
#[derive(Clone, Debug)]
pub struct IdentityService<S> {
    store: S,
}

impl<S> IdentityService<S> {
    /// Creates a new identity service.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S> IdentityService<S>
where
    S: IdentityStore,
{
    /// Lists users visible to the actor.
    pub async fn list_users(
        &self,
        actor: &Actor,
        filter: coder_core::UserListFilter,
    ) -> Result<(Vec<UserRecord>, usize), IdentityServiceError> {
        if !actor.can_list_users() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to list users.",
            ));
        }

        self.store.list_users(filter).await.map_err(Into::into)
    }

    /// Creates a new site user.
    pub async fn create_user(
        &self,
        actor: &Actor,
        request: &CreateUserRequestWithOrgs,
    ) -> Result<UserRecord, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to create users.",
            ));
        }

        let login_type = request.login_type.unwrap_or(LoginType::Password);
        let status = request.user_status.unwrap_or(UserStatus::Dormant);
        let validations = validate_create_user_request(request, login_type);
        if !validations.is_empty() {
            return Err(IdentityServiceError::validation(
                "Request body has invalid fields.",
                validations,
            ));
        }

        let organizations = self.store.list_organizations(Vec::new()).await?;
        let default_organization_id = organizations
            .iter()
            .find(|organization| organization.is_default)
            .map(|organization| organization.id)
            .ok_or_else(|| {
                IdentityServiceError::Storage(StorageError::invalid_data(
                    "default organization is missing",
                ))
            })?;
        let known_organization_ids = organizations
            .iter()
            .map(|organization| organization.id)
            .collect::<HashSet<_>>();
        let mut seen_organization_ids = HashSet::new();
        let mut organization_ids = Vec::new();
        for requested_id in &request.organization_ids {
            let organization_id = if requested_id.is_nil() {
                default_organization_id
            } else {
                *requested_id
            };
            if !known_organization_ids.contains(&organization_id) {
                return Err(IdentityServiceError::not_found("Organization not found."));
            }
            if seen_organization_ids.insert(organization_id) {
                organization_ids.push(organization_id);
            }
        }

        let password_hash = if login_type == LoginType::Password {
            Some(hash_password(&request.password).map_err(|error| {
                IdentityServiceError::Storage(StorageError::invalid_data(error.to_string()))
            })?)
        } else {
            None
        };

        self.store
            .create_user(CreateUserInput {
                email: request.email.trim().to_owned(),
                username: request.username.to_owned(),
                name: normalize_real_name(&request.name),
                password_hash,
                login_type,
                status,
                organization_ids,
            })
            .await
            .map_err(|error| match error {
                CreateUserStoreError::AlreadyExists => IdentityServiceError::Conflict {
                    message: "User already exists.".to_owned(),
                    detail: None,
                    validations: Vec::new(),
                },
                CreateUserStoreError::Storage(error) => IdentityServiceError::Storage(error),
            })
    }

    /// Returns a user visible to the actor.
    pub async fn get_user(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
    ) -> Result<UserRecord, IdentityServiceError> {
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;

        if !actor.can_access_user(target_user.id) {
            return Err(IdentityServiceError::not_found("User not found."));
        }

        Ok(target_user)
    }

    /// Lists assignable site roles.
    pub fn list_site_roles(
        &self,
        actor: &Actor,
    ) -> Result<Vec<AssignableRoleResponse>, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to list assignable site roles.",
            ));
        }

        Ok(site_builtin_roles()
            .iter()
            .map(|role| assignable_role_response(role, None, true))
            .collect())
    }

    /// Returns a user's site and organization roles.
    pub async fn get_user_roles(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
    ) -> Result<(UserRecord, HashMap<Uuid, Vec<String>>), IdentityServiceError> {
        let target_user = self
            .get_user(actor, authenticated_user, requested_user)
            .await?;
        let memberships = self.store.list_user_memberships(target_user.id).await?;
        let organization_roles = memberships
            .into_iter()
            .map(|membership| {
                (
                    membership.organization_id,
                    membership
                        .roles
                        .into_iter()
                        .map(|role| role.name)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        Ok((target_user, organization_roles))
    }

    /// Updates site roles for a user.
    pub async fn update_user_roles(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        request: &UpdateRolesRequest,
    ) -> Result<UserRecord, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to modify user roles.",
            ));
        }

        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if target_user.id == authenticated_user.id {
            return Err(IdentityServiceError::bad_request(
                "You cannot change your own roles.",
            ));
        }

        let roles = validate_role_update_request(&request.roles, site_builtin_roles(), "roles")
            .map_err(|validations| {
                IdentityServiceError::validation("Request body has invalid fields.", validations)
            })?;

        self.store
            .update_user_roles(target_user.id, roles)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))
    }

    /// Lists organizations visible to the actor.
    pub async fn list_organizations(
        &self,
        actor: &Actor,
    ) -> Result<Vec<coder_core::OrganizationRecord>, IdentityServiceError> {
        self.store
            .list_organizations(if actor.is_owner() {
                Vec::new()
            } else {
                actor.organization_ids.clone()
            })
            .await
            .map_err(Into::into)
    }

    /// Returns one visible organization.
    pub async fn get_organization(
        &self,
        actor: &Actor,
        requested_organization: &str,
    ) -> Result<coder_core::OrganizationRecord, IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_access_organization(target_organization.id) {
            return Err(IdentityServiceError::not_found("Organization not found."));
        }

        Ok(target_organization)
    }

    /// Lists assignable roles for an organization.
    pub async fn list_organization_roles(
        &self,
        actor: &Actor,
        requested_organization: &str,
    ) -> Result<Vec<AssignableRoleResponse>, IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_manage_organization(target_organization.id) {
            return Err(IdentityServiceError::not_found("Organization not found."));
        }

        Ok(organization_builtin_roles()
            .iter()
            .map(|role| assignable_role_response(role, Some(target_organization.id), true))
            .collect())
    }

    /// Lists members for an organization.
    pub async fn list_organization_members(
        &self,
        actor: &Actor,
        requested_organization: &str,
        search: String,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<OrganizationMemberRecord>, IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_access_organization(target_organization.id) {
            return Err(IdentityServiceError::not_found("Organization not found."));
        }

        self.store
            .list_organization_members(OrganizationMemberListFilter {
                organization_id: target_organization.id,
                search,
                limit,
                offset,
            })
            .await
            .map_err(Into::into)
    }

    /// Lists paginated members for an organization.
    pub async fn list_organization_members_page(
        &self,
        actor: &Actor,
        requested_organization: &str,
        search: String,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<OrganizationMemberRecord>, usize), IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_access_organization(target_organization.id) {
            return Err(IdentityServiceError::not_found("Organization not found."));
        }

        self.store
            .list_organization_members_page(OrganizationMemberListFilter {
                organization_id: target_organization.id,
                search,
                limit,
                offset,
            })
            .await
            .map_err(Into::into)
    }

    /// Returns one organization member record.
    pub async fn get_organization_member(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_organization: &str,
        requested_user: &str,
    ) -> Result<OrganizationMemberRecord, IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_access_organization(target_organization.id) {
            return Err(IdentityServiceError::not_found("Organization not found."));
        }
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;

        self.store
            .find_organization_member(target_organization.id, target_user.id)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization member not found."))
    }

    /// Adds an organization member.
    pub async fn create_organization_member(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_organization: &str,
        requested_user: &str,
    ) -> Result<OrganizationMemberRecord, IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_manage_organization(target_organization.id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to manage organization members.",
            ));
        }
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;

        self.store
            .insert_organization_member(target_organization.id, target_user.id)
            .await
            .map_err(|error| match error {
                InsertOrganizationMemberError::AlreadyExists => {
                    IdentityServiceError::bad_request_with_detail(
                        "User is already an organization member",
                        format!(
                            "{} is already a member of {}",
                            target_user.username, target_organization.display_name
                        ),
                    )
                }
                InsertOrganizationMemberError::Storage(error) => {
                    IdentityServiceError::Storage(error)
                }
            })
    }

    /// Removes an organization member.
    pub async fn delete_organization_member(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_organization: &str,
        requested_user: &str,
    ) -> Result<(Uuid, Uuid), IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_manage_organization(target_organization.id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to manage organization members.",
            ));
        }
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if target_user.id == authenticated_user.id {
            return Err(IdentityServiceError::bad_request(
                "cannot remove self from an organization",
            ));
        }

        if !self
            .store
            .delete_organization_member(target_organization.id, target_user.id)
            .await?
        {
            return Err(IdentityServiceError::not_found(
                "Organization member not found.",
            ));
        }

        Ok((target_organization.id, target_user.id))
    }

    /// Updates organization-scoped member roles.
    pub async fn update_organization_member_roles(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_organization: &str,
        requested_user: &str,
        request: &UpdateRolesRequest,
    ) -> Result<OrganizationMemberRecord, IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_manage_organization(target_organization.id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to manage organization members.",
            ));
        }
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if target_user.id == authenticated_user.id {
            return Err(IdentityServiceError::BadRequest {
                message: "You cannot change your own organization roles.".to_owned(),
                detail: Some(
                    "Another user with the appropriate permissions must change your roles."
                        .to_owned(),
                ),
            });
        }

        let roles =
            validate_role_update_request(&request.roles, organization_builtin_roles(), "roles")
                .map_err(|validations| {
                    IdentityServiceError::validation(
                        "Request body has invalid fields.",
                        validations,
                    )
                })?;

        self.store
            .update_organization_member_roles(target_organization.id, target_user.id, roles)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization member not found."))
    }

    /// Lists the organizations attached to one user.
    pub async fn list_user_organizations(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
    ) -> Result<Vec<coder_core::OrganizationRecord>, IdentityServiceError> {
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if !actor.can_access_user(target_user.id) {
            return Err(IdentityServiceError::not_found("User not found."));
        }

        self.store
            .list_organizations(target_user.organization_ids)
            .await
            .map_err(Into::into)
    }

    /// Looks up one user organization by name or identifier.
    pub async fn get_user_organization_by_name(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        requested_organization: &str,
    ) -> Result<coder_core::OrganizationRecord, IdentityServiceError> {
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if !actor.can_access_user(target_user.id) {
            return Err(IdentityServiceError::not_found("User not found."));
        }

        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !target_user
            .organization_ids
            .contains(&target_organization.id)
        {
            return Err(IdentityServiceError::not_found("Organization not found."));
        }

        Ok(target_organization)
    }

    /// Soft-deletes a user.
    pub async fn delete_user(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
    ) -> Result<UserRecord, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to delete users.",
            ));
        }
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if target_user.id == authenticated_user.id {
            return Err(IdentityServiceError::forbidden(
                "You cannot delete yourself!",
            ));
        }
        if target_user.is_system {
            return Err(IdentityServiceError::forbidden(
                "System users cannot be deleted.",
            ));
        }

        if !self.store.soft_delete_user(target_user.id).await? {
            return Err(IdentityServiceError::not_found("User not found."));
        }

        Ok(target_user)
    }

    /// Updates user profile fields.
    pub async fn update_user_profile(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        request: &UpdateUserProfileRequest,
    ) -> Result<UserRecord, IdentityServiceError> {
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if !actor.can_access_user(target_user.id) {
            return Err(IdentityServiceError::not_found("User not found."));
        }

        let validations = validate_update_user_profile_request(request);
        if !validations.is_empty() {
            return Err(IdentityServiceError::validation(
                "Request body has invalid fields.",
                validations,
            ));
        }

        if request.username != target_user.username && !actor.is_owner() {
            return Err(IdentityServiceError::not_found("User not found."));
        }

        if let Some(existing_user) = self.store.find_user_by_username(&request.username).await?
            && existing_user.id != target_user.id
        {
            return Err(IdentityServiceError::conflict(
                "A user with this username already exists.",
                vec![ValidationError {
                    field: "username".to_owned(),
                    detail: "This username is already in use.".to_owned(),
                }],
            ));
        }

        self.store
            .update_user_profile(
                target_user.id,
                &request.username,
                &normalize_real_name(&request.name),
            )
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))
    }

    /// Updates a user's status.
    pub async fn update_user_status(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        status: UserStatus,
    ) -> Result<UserRecord, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to update user status.",
            ));
        }
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;

        if status == UserStatus::Suspended {
            if target_user.id == authenticated_user.id {
                return Err(IdentityServiceError::bad_request(
                    "You cannot suspend yourself.",
                ));
            }
            if target_user.roles.iter().any(|role| role.name == "owner") {
                return Err(IdentityServiceError::bad_request(
                    "You cannot suspend a user with the \"owner\" role. You must remove the role first.",
                ));
            }
        }

        self.store
            .update_user_status(target_user.id, status)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))
    }

    /// Returns appearance settings for a visible user.
    pub async fn get_user_appearance(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
    ) -> Result<UserAppearanceRecord, IdentityServiceError> {
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if !actor.can_access_user(target_user.id) {
            return Err(IdentityServiceError::not_found("User not found."));
        }

        self.store
            .user_appearance(target_user.id)
            .await
            .map_err(Into::into)
    }

    /// Updates appearance settings for a visible user.
    pub async fn update_user_appearance(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        request: &UpdateUserAppearanceSettingsRequest,
    ) -> Result<(Uuid, UserAppearanceRecord), IdentityServiceError> {
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if !actor.can_access_user(target_user.id) {
            return Err(IdentityServiceError::not_found("User not found."));
        }
        if !SUPPORTED_TERMINAL_FONTS.contains(&request.terminal_font.as_str()) {
            return Err(IdentityServiceError::bad_request(
                "Unsupported font family.",
            ));
        }

        let settings = self
            .store
            .update_user_appearance(
                target_user.id,
                &request.theme_preference,
                &request.terminal_font,
            )
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;

        Ok((target_user.id, settings))
    }

    /// Returns preference settings for a visible user.
    pub async fn get_user_preferences(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
    ) -> Result<UserPreferenceRecord, IdentityServiceError> {
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if !actor.can_access_user(target_user.id) {
            return Err(IdentityServiceError::not_found("User not found."));
        }

        self.store
            .user_preferences(target_user.id)
            .await
            .map_err(Into::into)
    }

    /// Updates preference settings for a visible user.
    pub async fn update_user_preferences(
        &self,
        actor: &Actor,
        authenticated_user: &AuthenticatedUser,
        requested_user: &str,
        request: &UpdateUserPreferenceSettingsRequest,
    ) -> Result<(Uuid, UserPreferenceRecord), IdentityServiceError> {
        let target_user = self
            .resolve_user(requested_user, authenticated_user)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;
        if !actor.can_access_user(target_user.id) {
            return Err(IdentityServiceError::not_found("User not found."));
        }

        let settings = self
            .store
            .update_user_preferences(target_user.id, request.task_notification_alert_dismissed)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("User not found."))?;

        Ok((target_user.id, settings))
    }

    async fn resolve_user(
        &self,
        requested_user: &str,
        authenticated_user: &AuthenticatedUser,
    ) -> Result<Option<UserRecord>, IdentityServiceError> {
        if requested_user == "me" {
            return self
                .store
                .find_user_by_id(authenticated_user.id)
                .await
                .map_err(Into::into);
        }

        if let Ok(user_id) = Uuid::parse_str(requested_user) {
            return self
                .store
                .find_user_by_id(user_id)
                .await
                .map_err(Into::into);
        }

        self.store
            .find_user_by_username(requested_user)
            .await
            .map_err(Into::into)
    }

    async fn resolve_organization(
        &self,
        requested_organization: &str,
    ) -> Result<Option<coder_core::OrganizationRecord>, IdentityServiceError> {
        if let Ok(organization_id) = Uuid::parse_str(requested_organization) {
            return self
                .store
                .find_organization_by_id(organization_id)
                .await
                .map_err(Into::into);
        }

        self.store
            .find_organization_by_name(requested_organization)
            .await
            .map_err(Into::into)
    }

    // -----------------------------------------------------------------
    // User Links
    // -----------------------------------------------------------------

    /// Lists user links for a given user.
    pub async fn list_user_links(
        &self,
        actor: &Actor,
        user_id: Uuid,
    ) -> Result<Vec<UserLinkRecord>, IdentityServiceError> {
        if !actor.can_access_user(user_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to view user links.",
            ));
        }
        self.store
            .list_user_links(user_id)
            .await
            .map_err(Into::into)
    }

    /// Links a user with an external identity provider.
    pub async fn upsert_user_link(
        &self,
        actor: &Actor,
        user_id: Uuid,
        input: &UpsertUserLinkInput,
    ) -> Result<UserLinkRecord, IdentityServiceError> {
        if !actor.can_access_user(user_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to modify user links.",
            ));
        }
        self.store
            .upsert_user_link(user_id, input)
            .await
            .map_err(Into::into)
    }

    /// Removes a user's link with an external identity provider.
    pub async fn delete_user_link(
        &self,
        actor: &Actor,
        user_id: Uuid,
        login_type: LoginType,
    ) -> Result<bool, IdentityServiceError> {
        if !actor.can_access_user(user_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to modify user links.",
            ));
        }
        self.store
            .delete_user_link(user_id, login_type)
            .await
            .map_err(Into::into)
    }

    // -----------------------------------------------------------------
    // User Configs
    // -----------------------------------------------------------------

    /// Gets a user configuration value.
    pub async fn get_user_config(
        &self,
        actor: &Actor,
        user_id: Uuid,
        key: &str,
    ) -> Result<Option<UserConfigRecord>, IdentityServiceError> {
        if !actor.can_access_user(user_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to view user config.",
            ));
        }
        self.store
            .get_user_config(user_id, key)
            .await
            .map_err(Into::into)
    }

    /// Sets a user configuration value.
    pub async fn upsert_user_config(
        &self,
        actor: &Actor,
        user_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<UserConfigRecord, IdentityServiceError> {
        if !actor.can_access_user(user_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to modify user config.",
            ));
        }
        if key.trim().is_empty() {
            return Err(IdentityServiceError::bad_request(
                "Config key must not be empty.",
            ));
        }
        self.store
            .upsert_user_config(user_id, key, value)
            .await
            .map_err(Into::into)
    }

    /// Deletes a user configuration value.
    pub async fn delete_user_config(
        &self,
        actor: &Actor,
        user_id: Uuid,
        key: &str,
    ) -> Result<bool, IdentityServiceError> {
        if !actor.can_access_user(user_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to modify user config.",
            ));
        }
        self.store
            .delete_user_config(user_id, key)
            .await
            .map_err(Into::into)
    }

    // -----------------------------------------------------------------
    // Status Changes
    // -----------------------------------------------------------------

    /// Records a user status change for audit.
    pub async fn record_user_status_change(
        &self,
        actor: &Actor,
        user_id: Uuid,
        old_status: UserStatus,
        new_status: UserStatus,
        reason: &str,
    ) -> Result<UserStatusChangeRecord, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to record status changes.",
            ));
        }
        self.store
            .insert_user_status_change(user_id, old_status, new_status, Some(actor.user_id), reason)
            .await
            .map_err(Into::into)
    }

    /// Lists status changes for a given user.
    pub async fn list_user_status_changes(
        &self,
        actor: &Actor,
        user_id: Uuid,
    ) -> Result<Vec<UserStatusChangeRecord>, IdentityServiceError> {
        if !actor.can_access_user(user_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to view status changes.",
            ));
        }
        self.store
            .list_user_status_changes(user_id)
            .await
            .map_err(Into::into)
    }

    // -----------------------------------------------------------------
    // Custom Roles
    // -----------------------------------------------------------------

    /// Lists custom roles, optionally filtered by organization.
    pub async fn list_custom_roles(
        &self,
        actor: &Actor,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<CustomRoleRecord>, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to list custom roles.",
            ));
        }
        self.store
            .list_custom_roles(organization_id)
            .await
            .map_err(Into::into)
    }

    /// Creates or updates a custom role.
    pub async fn upsert_custom_role(
        &self,
        actor: &Actor,
        input: &UpsertCustomRoleInput,
    ) -> Result<CustomRoleRecord, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to manage custom roles.",
            ));
        }
        if input.name.trim().is_empty() {
            return Err(IdentityServiceError::bad_request(
                "Role name must not be empty.",
            ));
        }
        self.store
            .upsert_custom_role(input)
            .await
            .map_err(Into::into)
    }

    /// Deletes a custom role.
    pub async fn delete_custom_role(
        &self,
        actor: &Actor,
        name: &str,
        organization_id: Option<Uuid>,
    ) -> Result<bool, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to manage custom roles.",
            ));
        }
        self.store
            .delete_custom_role(name, organization_id)
            .await
            .map_err(Into::into)
    }

    // -----------------------------------------------------------------
    // Groups
    // -----------------------------------------------------------------

    /// Lists groups for an organization.
    pub async fn list_groups(
        &self,
        actor: &Actor,
        organization_id: Uuid,
    ) -> Result<Vec<GroupRecord>, IdentityServiceError> {
        if !actor.can_access_organization(organization_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to view groups in this organization.",
            ));
        }
        self.store
            .list_groups(organization_id)
            .await
            .map_err(Into::into)
    }

    /// Creates a new group.
    pub async fn create_group(
        &self,
        actor: &Actor,
        organization_id: Uuid,
        name: &str,
        display_name: &str,
        avatar_url: &str,
        quota_allowance: i32,
    ) -> Result<GroupRecord, IdentityServiceError> {
        if !actor.can_manage_organization(organization_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to create groups in this organization.",
            ));
        }
        if name.trim().is_empty() {
            return Err(IdentityServiceError::bad_request(
                "Group name must not be empty.",
            ));
        }
        let input = CreateGroupInput {
            organization_id,
            name: name.trim().to_owned(),
            display_name: display_name.to_owned(),
            avatar_url: avatar_url.to_owned(),
            quota_allowance,
        };
        self.store.create_group(&input).await.map_err(Into::into)
    }

    /// Gets a group by identifier.
    pub async fn get_group(
        &self,
        actor: &Actor,
        group_id: Uuid,
    ) -> Result<GroupRecord, IdentityServiceError> {
        let group = self
            .store
            .find_group_by_id(group_id)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Group not found."))?;
        if !actor.can_access_organization(group.organization_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to view this group.",
            ));
        }
        Ok(group)
    }

    /// Deletes a group.
    pub async fn delete_group(
        &self,
        actor: &Actor,
        group_id: Uuid,
    ) -> Result<(), IdentityServiceError> {
        let group = self
            .store
            .find_group_by_id(group_id)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Group not found."))?;
        if !actor.can_manage_organization(group.organization_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to delete this group.",
            ));
        }
        if !self.store.delete_group(group_id).await? {
            return Err(IdentityServiceError::not_found("Group not found."));
        }
        Ok(())
    }

    /// Lists members of a group.
    pub async fn list_group_members(
        &self,
        actor: &Actor,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberRecord>, IdentityServiceError> {
        let group = self
            .store
            .find_group_by_id(group_id)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Group not found."))?;
        if !actor.can_access_organization(group.organization_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to view group members.",
            ));
        }
        self.store
            .list_group_members(group_id)
            .await
            .map_err(Into::into)
    }

    /// Adds a user to a group.
    pub async fn add_group_member(
        &self,
        actor: &Actor,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), IdentityServiceError> {
        let group = self
            .store
            .find_group_by_id(group_id)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Group not found."))?;
        if !actor.can_manage_organization(group.organization_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to modify group membership.",
            ));
        }
        self.store
            .insert_group_member(group_id, user_id)
            .await
            .map_err(Into::into)
    }

    /// Removes a user from a group.
    pub async fn remove_group_member(
        &self,
        actor: &Actor,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, IdentityServiceError> {
        let group = self
            .store
            .find_group_by_id(group_id)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Group not found."))?;
        if !actor.can_manage_organization(group.organization_id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to modify group membership.",
            ));
        }
        self.store
            .delete_group_member(group_id, user_id)
            .await
            .map_err(Into::into)
    }
}

fn validate_create_user_request(
    request: &CreateUserRequestWithOrgs,
    login_type: LoginType,
) -> Vec<ValidationError> {
    let mut validations = Vec::new();
    push_validation(&mut validations, "email", validate_email(&request.email));
    push_validation(
        &mut validations,
        "username",
        validate_username(&request.username),
    );
    push_validation(&mut validations, "name", validate_real_name(&request.name));

    if request.organization_ids.is_empty() {
        validations.push(ValidationError {
            field: "organization_ids".to_owned(),
            detail: "Missing values, this cannot be empty".to_owned(),
        });
    }

    match login_type {
        LoginType::Password => {
            push_validation(
                &mut validations,
                "password",
                validate_password(&request.password),
            );
        }
        LoginType::None | LoginType::Github | LoginType::Oidc => {
            if !request.password.is_empty() {
                validations.push(ValidationError {
                    field: "password".to_owned(),
                    detail: "password cannot be set for non-password authentication".to_owned(),
                });
            }
        }
        LoginType::Token | LoginType::Oauth2ProviderApp => validations.push(ValidationError {
            field: "login_type".to_owned(),
            detail: "unsupported login type for manual user creation".to_owned(),
        }),
    }

    validations
}

fn validate_update_user_profile_request(
    request: &UpdateUserProfileRequest,
) -> Vec<ValidationError> {
    let mut validations = Vec::new();
    push_validation(
        &mut validations,
        "username",
        validate_username(&request.username),
    );
    push_validation(&mut validations, "name", validate_real_name(&request.name));
    validations
}

fn validate_role_update_request(
    requested_roles: &[String],
    allowed_roles: &[BuiltinRole],
    field: &str,
) -> Result<Vec<String>, Vec<ValidationError>> {
    let allowed = allowed_roles
        .iter()
        .map(|role| role.name)
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for role in requested_roles {
        if !allowed.contains(role.as_str()) {
            return Err(vec![ValidationError {
                field: field.to_owned(),
                detail: format!("unsupported role: {role}"),
            }]);
        }
        if seen.insert(role.clone()) {
            normalized.push(role.clone());
        }
    }

    Ok(normalized)
}

fn assignable_role_response(
    role: &BuiltinRole,
    organization_id: Option<Uuid>,
    assignable: bool,
) -> AssignableRoleResponse {
    AssignableRoleResponse {
        role: RoleResponse {
            name: role.name.to_owned(),
            organization_id: organization_id.map_or_else(String::new, |id| id.to_string()),
            display_name: role.display_name.to_owned(),
            site_permissions: Vec::new(),
            user_permissions: Vec::new(),
            organization_permissions: Vec::new(),
            organization_member_permissions: Vec::new(),
        },
        assignable,
        built_in: true,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_user_validation_rejects_empty_organizations() {
        let validations = validate_create_user_request(
            &CreateUserRequestWithOrgs {
                email: "alice@example.com".to_owned(),
                username: "alice".to_owned(),
                name: "Alice".to_owned(),
                password: "password1234".to_owned(),
                login_type: Some(LoginType::Password),
                organization_ids: Vec::new(),
                user_status: Some(UserStatus::Active),
            },
            LoginType::Password,
        );

        assert!(validations.iter().any(|validation| {
            validation.field == "organization_ids"
                && validation.detail == "Missing values, this cannot be empty"
        }));
    }

    #[test]
    fn role_update_validation_rejects_unknown_roles() {
        let result =
            validate_role_update_request(&[String::from("bogus")], site_builtin_roles(), "roles");

        assert!(
            matches!(result, Err(validations) if validations[0].detail == "unsupported role: bogus")
        );
    }

    // ── LoginType tests ─────────────────────────────────────────

    #[test]
    fn test_login_type_variants() {
        let variants = [
            (LoginType::Password, "password"),
            (LoginType::Github, "github"),
            (LoginType::Oidc, "oidc"),
            (LoginType::Token, "token"),
            (LoginType::None, "none"),
            (LoginType::Oauth2ProviderApp, "oauth2_provider_app"),
        ];

        for (variant, expected_str) in &variants {
            assert_eq!(variant.as_str(), *expected_str);
        }

        // Round-trip through FromStr
        for (variant, wire_str) in &variants {
            let parsed: Result<LoginType, _> = wire_str.parse();
            assert!(
                parsed.is_ok(),
                "should parse '{wire_str}' back to LoginType"
            );
            assert_eq!(parsed.ok(), Some(*variant));
        }

        // Unknown string should fail
        let bad: Result<LoginType, _> = "bogus_login".parse();
        assert!(bad.is_err(), "unknown login type should fail to parse");
    }

    // ── External auth / OIDC config validation ──────────────────

    #[test]
    fn test_external_auth_provider_config() {
        // Validate that create-user validation rejects passwords for
        // non-password login types (Github, Oidc, None).
        for login_type in [LoginType::Github, LoginType::Oidc, LoginType::None] {
            let validations = validate_create_user_request(
                &CreateUserRequestWithOrgs {
                    email: "ext@example.com".to_owned(),
                    username: "extuser".to_owned(),
                    name: "External User".to_owned(),
                    password: "should-not-be-set".to_owned(),
                    login_type: Some(login_type),
                    organization_ids: vec![Uuid::new_v4()],
                    user_status: Some(UserStatus::Active),
                },
                login_type,
            );

            assert!(
                validations.iter().any(|v| v.field == "password"
                    && v.detail
                        .contains("password cannot be set for non-password authentication")),
                "login type {:?} should reject password",
                login_type
            );
        }
    }

    #[test]
    fn test_oidc_config_validation() {
        // Token and Oauth2ProviderApp are unsupported for manual user creation.
        for login_type in [LoginType::Token, LoginType::Oauth2ProviderApp] {
            let validations = validate_create_user_request(
                &CreateUserRequestWithOrgs {
                    email: "token@example.com".to_owned(),
                    username: "tokenuser".to_owned(),
                    name: "Token User".to_owned(),
                    password: String::new(),
                    login_type: Some(login_type),
                    organization_ids: vec![Uuid::new_v4()],
                    user_status: Some(UserStatus::Active),
                },
                login_type,
            );

            assert!(
                validations.iter().any(|v| v.field == "login_type"
                    && v.detail
                        .contains("unsupported login type for manual user creation")),
                "login type {:?} should be rejected for manual creation",
                login_type
            );
        }

        // A valid password-type user should produce no validation errors
        // (except the missing organizations, which we supply here).
        let validations = validate_create_user_request(
            &CreateUserRequestWithOrgs {
                email: "valid@example.com".to_owned(),
                username: "validuser".to_owned(),
                name: "Valid User".to_owned(),
                password: "StrongP@ss1234".to_owned(),
                login_type: Some(LoginType::Password),
                organization_ids: vec![Uuid::new_v4()],
                user_status: Some(UserStatus::Active),
            },
            LoginType::Password,
        );
        assert!(
            validations.is_empty(),
            "valid password user should have no validation errors, got: {validations:?}"
        );
    }

    // ── UserLinkRecord tests ────────────────────────────────────

    #[test]
    fn test_user_link_record_creation() {
        let user_id = Uuid::new_v4();
        let now = time::OffsetDateTime::now_utc();
        let link = UserLinkRecord {
            user_id,
            login_type: LoginType::Github,
            linked_id: "gh-12345".to_owned(),
            oauth_access_token: "access-token-abc".to_owned(),
            oauth_refresh_token: "refresh-token-xyz".to_owned(),
            oauth_expiry: now,
        };

        assert_eq!(link.user_id, user_id);
        assert_eq!(link.login_type, LoginType::Github);
        assert_eq!(link.linked_id, "gh-12345");
        assert!(!link.oauth_access_token.is_empty());
        assert!(!link.oauth_refresh_token.is_empty());

        // Verify a different login type
        let oidc_link = UserLinkRecord {
            user_id,
            login_type: LoginType::Oidc,
            linked_id: "oidc-sub-001".to_owned(),
            oauth_access_token: String::new(),
            oauth_refresh_token: String::new(),
            oauth_expiry: now,
        };

        assert_eq!(oidc_link.login_type, LoginType::Oidc);
        assert_eq!(oidc_link.linked_id, "oidc-sub-001");
    }

    // ── Identity provider display names ─────────────────────────

    #[test]
    fn test_identity_provider_display_names() {
        // Site-level roles must have human-readable display names
        let site_roles = site_builtin_roles();
        assert!(!site_roles.is_empty(), "should have site roles");

        let expected_site = [
            ("owner", "Owner"),
            ("member", "Member"),
            ("template-admin", "Template Admin"),
            ("user-admin", "User Admin"),
            ("auditor", "Auditor"),
        ];
        for (name, display) in &expected_site {
            let role = site_roles.iter().find(|r| r.name == *name);
            assert!(role.is_some(), "site role '{name}' should exist");
            assert_eq!(
                role.map(|r| r.display_name),
                Some(*display),
                "display name mismatch for role '{name}'"
            );
        }

        // Organization roles
        let org_roles = organization_builtin_roles();
        assert!(!org_roles.is_empty(), "should have organization roles");

        for role in org_roles {
            assert!(
                !role.display_name.is_empty(),
                "org role '{}' must have a display name",
                role.name
            );
        }

        // assignable_role_response must produce correct display names
        let first_site = &site_roles[0];
        let response = assignable_role_response(first_site, None, true);
        assert_eq!(response.role.display_name, first_site.display_name);
        assert!(response.assignable);
        assert!(response.built_in);

        // With an org id, the organization_id field should be set
        let org_id = Uuid::new_v4();
        let response_with_org = assignable_role_response(first_site, Some(org_id), false);
        assert_eq!(response_with_org.role.organization_id, org_id.to_string());
        assert!(!response_with_org.assignable);
    }
}
