//! Identity and organization boundary for the Rust `coderd` rewrite.
//!
//! `coder-identity` provides [`IdentityService`], the domain service for:
//!
//! * **Users** — CRUD, profile updates, status transitions, soft-delete
//! * **Organizations** — listing, membership management
//! * **Roles** — site and org-scoped role assignment via [`coder_rbac`]
//! * **Groups** — group CRUD and membership
//! * **Preferences** — appearance settings, terminal font, notification prefs
//! * **User links** — external IdP link management (OIDC / GitHub)
//! * **Custom roles** — upsert / delete of custom RBAC roles
//!
//! Every public method on [`IdentityService`] enforces RBAC checks via the
//! [`coder_rbac::Actor`] before touching the store.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{HashMap, HashSet};

use coder_core::{
    AssignableRoleResponse, CreateGroupInput, CreateOrganizationInput, CreateUserInput,
    CreateUserRequestWithOrgs, CreateUserStoreError, CustomRoleRecord, GroupMemberRecord,
    GroupRecord, IdentityStore, InsertOrganizationMemberError, LoginType, OrgResourceCounts,
    OrganizationMemberListFilter, OrganizationMemberRecord, OrganizationRecord, PasswordError,
    RoleResponse, StorageError, UpdateOrganizationInput, UpdateRolesRequest,
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
    NotFound {
        /// Human-readable error description.
        message: String,
    },
    /// Action is forbidden.
    #[error("{message}")]
    Forbidden {
        /// Human-readable error description.
        message: String,
    },
    /// Request is syntactically valid but rejected by domain rules.
    #[error("{message}")]
    BadRequest {
        /// Message.
        message: String,
        /// Detail.
        detail: Option<String>,
    },
    /// Request failed field validation.
    #[error("{message}")]
    Validation {
        /// Message.
        message: String,
        /// Validations.
        validations: Vec<ValidationError>,
    },
    /// Request conflicts with existing state.
    #[error("{message}")]
    Conflict {
        /// Message.
        message: String,
        /// Detail.
        detail: Option<String>,
        /// Validations.
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
        // For org-scoped operations, allow org admins; otherwise require owner.
        match organization_id {
            Some(org_id) if actor.can_manage_organization(org_id) => {}
            None if actor.is_owner() => {}
            _ => {
                return Err(IdentityServiceError::forbidden(
                    "You are not authorized to list custom roles.",
                ));
            }
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
        // For org-scoped operations, allow org admins; otherwise require owner.
        match input.organization_id {
            Some(org_id) if actor.can_manage_organization(org_id) => {}
            None if actor.is_owner() => {}
            _ => {
                return Err(IdentityServiceError::forbidden(
                    "You are not authorized to manage custom roles.",
                ));
            }
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
        // For org-scoped operations, allow org admins; otherwise require owner.
        match organization_id {
            Some(org_id) if actor.can_manage_organization(org_id) => {}
            None if actor.is_owner() => {}
            _ => {
                return Err(IdentityServiceError::forbidden(
                    "You are not authorized to manage custom roles.",
                ));
            }
        }
        self.store
            .delete_custom_role(name, organization_id)
            .await
            .map_err(Into::into)
    }

    /// Looks up a custom role by name and optional organization.
    pub async fn find_custom_role(
        &self,
        actor: &Actor,
        name: &str,
        organization_id: Option<Uuid>,
    ) -> Result<Option<CustomRoleRecord>, IdentityServiceError> {
        // For org-scoped operations, allow org admins; otherwise require owner.
        match organization_id {
            Some(org_id) if actor.can_manage_organization(org_id) => {}
            None if actor.is_owner() => {}
            _ => {
                return Err(IdentityServiceError::forbidden(
                    "You are not authorized to view custom roles.",
                ));
            }
        }
        self.store
            .find_custom_role(name, organization_id)
            .await
            .map_err(Into::into)
    }

    // -----------------------------------------------------------------
    // Organization CRUD
    // -----------------------------------------------------------------

    /// Creates a new organization.
    pub async fn create_organization(
        &self,
        actor: &Actor,
        input: &CreateOrganizationInput,
    ) -> Result<OrganizationRecord, IdentityServiceError> {
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to create organizations.",
            ));
        }
        if input.name.eq_ignore_ascii_case("default") {
            return Err(IdentityServiceError::bad_request(
                "Organization name 'default' is reserved.",
            ));
        }
        if input.name.trim().is_empty() {
            return Err(IdentityServiceError::bad_request(
                "Organization name must not be empty.",
            ));
        }
        let org = self
            .store
            .insert_organization(input)
            .await
            .map_err(|error| match error {
                coder_core::CreateOrganizationStoreError::AlreadyExists => {
                    IdentityServiceError::Conflict {
                        message: "Organization already exists.".to_owned(),
                        detail: None,
                        validations: vec![],
                    }
                }
                coder_core::CreateOrganizationStoreError::Storage(e) => {
                    IdentityServiceError::Storage(e)
                }
            })?;

        // Create the "Everyone" group for the new organization.
        self.store
            .create_group(&CreateGroupInput {
                organization_id: org.id,
                name: "Everyone".to_owned(),
                display_name: "Everyone".to_owned(),
                avatar_url: String::new(),
                quota_allowance: 0,
                source: None,
            })
            .await
            .map_err(IdentityServiceError::Storage)?;

        // Add the creator as an organization member.
        self.store
            .insert_organization_member(org.id, input.actor_user_id)
            .await
            .map_err(|e| match e {
                InsertOrganizationMemberError::AlreadyExists => IdentityServiceError::bad_request(
                    "Creator is already a member of this organization.",
                ),
                InsertOrganizationMemberError::Storage(se) => IdentityServiceError::Storage(se),
            })?;

        Ok(org)
    }

    /// Updates an existing organization.
    pub async fn update_organization(
        &self,
        actor: &Actor,
        requested_organization: &str,
        input: &coder_core::UpdateOrganizationInput,
    ) -> Result<OrganizationRecord, IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_manage_organization(target_organization.id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to update this organization.",
            ));
        }
        if input.id != target_organization.id {
            return Err(IdentityServiceError::bad_request(
                "Organization ID in request body does not match the resolved organization.",
            ));
        }
        if input.name.eq_ignore_ascii_case("default") && !target_organization.is_default {
            return Err(IdentityServiceError::bad_request(
                "Organization name 'default' is reserved.",
            ));
        }
        if input.name.trim().is_empty() {
            return Err(IdentityServiceError::bad_request(
                "Organization name must not be empty.",
            ));
        }
        self.store
            .update_organization(input)
            .await
            .map_err(|error| match error {
                coder_core::UpdateOrganizationStoreError::AlreadyExists => {
                    IdentityServiceError::Conflict {
                        message: "An organization with that name already exists.".to_owned(),
                        detail: None,
                        validations: vec![],
                    }
                }
                coder_core::UpdateOrganizationStoreError::Storage(e) => {
                    IdentityServiceError::Storage(e)
                }
            })
    }

    /// Soft-deletes an organization.
    pub async fn delete_organization(
        &self,
        actor: &Actor,
        requested_organization: &str,
    ) -> Result<Uuid, IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.is_owner() {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to delete organizations.",
            ));
        }
        if target_organization.is_default {
            return Err(IdentityServiceError::bad_request(
                "Cannot delete the default organization.",
            ));
        }

        // Check resource counts BEFORE deleting to prevent deleting non-empty orgs.
        let counts = self
            .store
            .get_organization_resource_counts(target_organization.id)
            .await?;
        // Only block on workspaces, templates, and provisioner keys.
        // Members and groups are expected (creator + "Everyone" group) and will
        // be cleaned up as part of the soft-delete cascade.
        if counts.workspace_count > 0
            || counts.template_count > 0
            || counts.provisioner_key_count > 0
        {
            let detail = format!(
                "Organization has {} workspace(s), {} template(s), and {} provisioner key(s).",
                counts.workspace_count, counts.template_count, counts.provisioner_key_count,
            );
            return Err(IdentityServiceError::bad_request_with_detail(
                "Organization is not empty and cannot be deleted.",
                detail,
            ));
        }

        let deleted = self
            .store
            .soft_delete_organization(target_organization.id)
            .await?;

        if !deleted {
            return Err(IdentityServiceError::not_found(
                "Organization not found or already deleted.",
            ));
        }

        Ok(target_organization.id)
    }

    /// Returns resource counts for an organization.
    pub async fn get_organization_resource_counts(
        &self,
        actor: &Actor,
        requested_organization: &str,
    ) -> Result<OrgResourceCounts, IdentityServiceError> {
        let target_organization = self
            .resolve_organization(requested_organization)
            .await?
            .ok_or_else(|| IdentityServiceError::not_found("Organization not found."))?;
        if !actor.can_access_organization(target_organization.id) {
            return Err(IdentityServiceError::forbidden(
                "You are not authorized to view this organization.",
            ));
        }
        self.store
            .get_organization_resource_counts(target_organization.id)
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
            source: None,
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

/// Ensures the built-in system roles (currently the per-organization
/// `organization-member` role) exist in the `custom_roles` table and carry
/// up-to-date permission definitions.
///
/// Called once from `apps/coderd/src/main.rs` at startup, before the HTTP
/// server binds. Idempotent — safe to run on every boot. Mirrors Go's
/// `rolestore.ReconcileSystemRoles` call at
/// [coder/coderd/coderd.go:584](coder/coderd/coderd.go) and the implementation at
/// [coder/coderd/rbac/rolestore/rolestore.go:171](coder/coderd/rbac/rolestore/rolestore.go).
///
/// Multi-replica safety: acquires the shared
/// `advisory_lock_ids::RECONCILE_SYSTEM_ROLES` advisory lock via the
/// supplied `AppStore`. If another replica is mid-reconcile, we skip this
/// boot rather than block — the system role state converges on the next
/// boot regardless.
///
/// # Errors
///
/// Returns [`StorageError`] if listing organizations or upserting the
/// role fails. Advisory lock contention is treated as success because the
/// peer replica is performing the work.
pub async fn reconcile_system_roles(store: &dyn coder_core::AppStore) -> Result<(), StorageError> {
    use coder_core::ports::advisory_lock_ids;

    let Some(guard) = store
        .try_acquire_advisory_lock(advisory_lock_ids::RECONCILE_SYSTEM_ROLES)
        .await?
    else {
        // Another replica is reconciling; that's fine — the outcome is
        // identical regardless of which replica performs the writes.
        return Ok(());
    };

    let result = reconcile_system_roles_locked(store).await;
    // Always release the lock, even on error, so a subsequent boot can
    // proceed.
    let release_result = guard.release().await;
    match (result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), _) => Err(e),
        (Ok(()), Err(e)) => Err(e),
    }
}

async fn reconcile_system_roles_locked(
    store: &dyn coder_core::AppStore,
) -> Result<(), StorageError> {
    let orgs = store.list_organizations(Vec::new()).await?;
    for org in orgs {
        let role = coder_rbac::role_org_member(org.id);
        let site_perms = permissions_to_json(&role.site);
        let (org_perms, member_perms) = role
            .by_org_id
            .get(&org.id.to_string())
            .map(|p| (permissions_to_json(&p.org), permissions_to_json(&p.member)))
            .unwrap_or_else(|| ("[]".to_owned(), "[]".to_owned()));

        store
            .upsert_custom_role(&UpsertCustomRoleInput {
                name: role.name.clone(),
                display_name: role.display_name.clone(),
                organization_id: Some(org.id),
                site_permissions: site_perms,
                org_permissions: org_perms,
                user_permissions: member_perms,
            })
            .await?;
    }
    Ok(())
}

/// Serialises a slice of RBAC permissions into the JSON shape the
/// `custom_roles` table expects. The wire format matches the
/// `CustomRolePermissions` array used by the Go backend so the two
/// remain interoperable.
fn permissions_to_json(perms: &[coder_rbac::Permission]) -> String {
    let api_perms: Vec<coder_core::Permission> = perms
        .iter()
        .map(|p| coder_core::Permission {
            resource_type: p.resource_type.as_str().to_owned(),
            action: p
                .action
                .map(|a| a.as_str().to_owned())
                .unwrap_or_else(|| "*".to_owned()),
            negate: p.negate,
        })
        .collect();
    serde_json::to_string(&api_perms).unwrap_or_else(|_| "[]".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coder_core::UserLinkClaims;

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

    // ── Create-user validation tests ─────────────────────────────

    #[test]
    fn test_non_password_login_type_rejects_password() {
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
    fn test_unsupported_and_password_login_type_validation() {
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
        // NOTE: Intentional construction-validation smoke test for UserLinkRecord.
        // This struct has no behavior methods, so we verify all fields survive round-trip
        // construction to guard against accidental field reordering or type changes.
        let user_id = Uuid::new_v4();
        let now = time::OffsetDateTime::now_utc();
        let link = UserLinkRecord {
            user_id,
            login_type: LoginType::Github,
            linked_id: "gh-12345".to_owned(),
            oauth_access_token: "access-token-abc".to_owned(),
            oauth_refresh_token: "refresh-token-xyz".to_owned(),
            oauth_expiry: now,
            claims: UserLinkClaims::default(),
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
            claims: UserLinkClaims::default(),
        };

        assert_eq!(oidc_link.login_type, LoginType::Oidc);
        assert_eq!(oidc_link.linked_id, "oidc-sub-001");
    }

    // ── Identity provider display names ─────────────────────────

    #[test]
    fn test_identity_provider_display_names() {
        // Site-level roles must have human-readable display names.
        // These must match coder_rbac::site_builtin_roles() — update if roles change.
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
