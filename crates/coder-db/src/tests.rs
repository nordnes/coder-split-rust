//! Integration tests for `PostgresStore` SQL paths.
//!
//! These tests run against a real Postgres database and verify SQL correctness,
//! parameterization, JOINs, and row-to-record conversions that are not exercised
//! by `FakeStore`-based unit tests.
//!
//! # Running
//!
//! Set `DATABASE_URL` to a Postgres connection string and run:
//!
//! ```sh
//! DATABASE_URL="postgres://user:pass@localhost/coder_test" cargo test -p coder-db -- --ignored
//! ```
//!
//! Without `DATABASE_URL` these tests are skipped (`#[ignore]`).

use std::error::Error;

use coder_core::template::{
    CreateTemplateInput, CreateTemplateVersionInput, TemplateVersionListFilter,
};
use coder_core::{
    AppStore, CreateGroupInput, CreateOAuth2ProviderAppInput, CreateOAuth2ProviderAppTokenInput,
    CreateUserInput, CreateWorkspaceBuildInput, CreateWorkspaceInput, DatabaseConfig, LoginType,
    UserStatus, WorkspaceListFilter,
};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::PostgresStore;

type TestResult = Result<(), Box<dyn Error>>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Connect to a test database using `DATABASE_URL`. Returns `None` when the
/// env var is missing so callers can bail out early (the `#[ignore]` attribute
/// already gates these tests, but this is a safety net).
async fn setup_store() -> Result<Option<PostgresStore>, Box<dyn Error>> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(u) => u,
        Err(_) => return Ok(None),
    };

    let config = DatabaseConfig {
        postgres_url: url,
        max_connections: 5,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };

    let store = PostgresStore::connect(&config).await?;
    store.migrate().await?;
    Ok(Some(store))
}

/// Create a test organization and return its id.
async fn ensure_default_org(pool: &PgPool) -> Result<Uuid, Box<dyn Error>> {
    let org_id = Uuid::new_v4();
    let org_name = format!("test-org-{}", &org_id.to_string()[..8]);
    sqlx::query(
        "INSERT INTO organizations (id, name, display_name, description, icon, created_at, updated_at, is_default)
         VALUES ($1, $2, $3, '', '', NOW(), NOW(), false)
         ON CONFLICT DO NOTHING",
    )
    .bind(org_id)
    .bind(&org_name)
    .bind("Test Org")
    .execute(pool)
    .await?;
    Ok(org_id)
}

/// Create a test user and return its id.
async fn create_test_user(
    store: &PostgresStore,
    org_id: Uuid,
    suffix: &str,
) -> Result<Uuid, Box<dyn Error>> {
    let input = CreateUserInput {
        email: format!("test-{suffix}@example.com"),
        username: format!("testuser-{suffix}"),
        name: format!("Test User {suffix}"),
        password_hash: Some("hashed".to_string()),
        login_type: LoginType::Password,
        status: UserStatus::Active,
        organization_ids: vec![org_id],
    };
    let user = store.create_user(input).await?;
    Ok(user.id)
}

/// Create a minimal provisioner job via raw SQL and return its id.
/// We use raw SQL to avoid needing all the provisioner enum dependencies;
/// the job only serves as a FK target for template versions and workspace builds.
async fn create_provisioner_job(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Uuid, Box<dyn Error>> {
    let job_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO provisioner_jobs (
            id, created_at, updated_at, organization_id, initiator_id,
            provisioner, file_id, "type", input, tags
         ) VALUES (
            $1, NOW(), NOW(), $2, $3,
            'echo'::provisioner_type, NULL,
            'template_version_import'::provisioner_job_type,
            '{}'::jsonb, '{}'::jsonb
         )"#,
    )
    .bind(job_id)
    .bind(org_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(job_id)
}

/// Create a template with an initial version and return the template id.
async fn create_test_template(
    store: &PostgresStore,
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    name: &str,
) -> Result<Uuid, Box<dyn Error>> {
    let template_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let job_id = create_provisioner_job(pool, org_id, user_id).await?;

    let input = CreateTemplateInput {
        id: template_id,
        created_at: now,
        updated_at: now,
        organization_id: org_id,
        name: name.to_string(),
        display_name: name.to_string(),
        provisioner: "echo".to_string(),
        active_version_id: version_id,
        description: "test template".to_string(),
        default_ttl: 0,
        created_by: user_id,
        icon: "".to_string(),
        allow_user_cancel_workspace_jobs: true,
        allow_user_autostart: true,
        allow_user_autostop: true,
        failure_ttl: 0,
        time_til_dormant: 0,
        time_til_dormant_autodelete: 0,
        require_active_version: false,
        activity_bump: 0,
        max_port_share_level: "owner".to_string(),
    };

    store.insert_template(input).await?;

    let tv_input = CreateTemplateVersionInput {
        id: version_id,
        template_id: Some(template_id),
        organization_id: org_id,
        created_at: now,
        updated_at: now,
        name: format!("{name}-v1"),
        message: "initial".to_string(),
        readme: "".to_string(),
        job_id,
        created_by: user_id,
        source_example_id: None,
    };
    store.insert_template_version(tv_input).await?;

    Ok(template_id)
}

/// Unique suffix for test isolation.
fn uniq() -> String {
    Uuid::new_v4().to_string()[..8].to_string()
}

// =========================================================================
// 1. OAuth2 Provider App Lifecycle
// =========================================================================

#[tokio::test]
#[ignore]
async fn test_oauth2_secret_lifecycle() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    // Create app
    let app = store
        .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
            name: format!("test-app-{}", uniq()),
            icon: "https://example.com/icon.png".to_string(),
            callback_url: "https://example.com/callback".to_string(),
            created_by: user_id,
        })
        .await?;

    // Create secret
    let prefix = b"prefix1234";
    let hashed = b"hashedsecretbytes";
    let secret = store
        .create_oauth2_provider_app_secret(app.id, prefix, hashed, "disp****")
        .await?;
    assert_eq!(secret.app_id, app.id);
    assert!(secret.last_used_at.is_none());

    // Find by prefix
    let found = store
        .find_oauth2_provider_app_secret_by_prefix(prefix)
        .await?;
    assert!(found.is_some());
    assert_eq!(found.as_ref().map(|s| s.id), Some(secret.id));

    // Update last_used
    let updated = store
        .update_oauth2_provider_app_secret_last_used(secret.id)
        .await?;
    assert!(updated.is_some());
    assert!(updated.as_ref().and_then(|s| s.last_used_at).is_some());

    // Delete secret
    let deleted = store.delete_oauth2_provider_app_secret(secret.id).await?;
    assert!(deleted);

    // Verify gone
    let gone = store
        .find_oauth2_provider_app_secret_by_prefix(prefix)
        .await?;
    assert!(gone.is_none());
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_oauth2_code_lifecycle() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    let app = store
        .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
            name: format!("code-app-{}", uniq()),
            icon: "".to_string(),
            callback_url: "https://example.com/cb".to_string(),
            created_by: user_id,
        })
        .await?;

    let code_prefix = b"codeprefix";
    let code_hash = b"codehashval";
    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);

    let code = store
        .create_oauth2_provider_app_code(
            app.id,
            user_id,
            code_prefix,
            code_hash,
            expires,
            "urn:example:resource",
            "S256challenge",
            "S256",
            None,
            None,
        )
        .await?;
    assert_eq!(code.app_id, app.id);
    assert_eq!(code.user_id, user_id);

    // Find by prefix
    let found = store
        .find_oauth2_provider_app_code_by_prefix(code_prefix)
        .await?;
    assert!(found.is_some());
    assert_eq!(found.as_ref().map(|c| c.id), Some(code.id));

    // Delete code
    let deleted = store.delete_oauth2_provider_app_code(code.id).await?;
    assert!(deleted);

    let gone = store
        .find_oauth2_provider_app_code_by_prefix(code_prefix)
        .await?;
    assert!(gone.is_none());
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_oauth2_token_lifecycle() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    let app = store
        .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
            name: format!("token-app-{}", uniq()),
            icon: "".to_string(),
            callback_url: "https://example.com/cb".to_string(),
            created_by: user_id,
        })
        .await?;

    let secret = store
        .create_oauth2_provider_app_secret(app.id, b"tkprefix", b"tkhashed", "tk****")
        .await?;

    // Insert a minimal api_keys row so the FK is satisfied
    let api_key_id = format!("ak-{}", &uniq());
    sqlx::query(
        "INSERT INTO api_keys (id, hashed_secret, user_id, last_used, expires_at, created_at,
         updated_at, login_type, lifetime_seconds, ip_address, scope, token_name)
         VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '1 hour', NOW(), NOW(),
         'password'::login_type, 3600, '127.0.0.1'::inet, 'all'::api_key_scope, '')",
    )
    .bind(&api_key_id)
    .bind(b"fakehashedsecret".to_vec())
    .bind(user_id)
    .execute(&pool)
    .await?;

    let token_prefix = b"tokenprefix";
    let refresh_hash = b"refreshhash1";
    let token = store
        .create_oauth2_provider_app_token(&CreateOAuth2ProviderAppTokenInput {
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            hash_prefix: token_prefix.to_vec(),
            refresh_hash: refresh_hash.to_vec(),
            app_secret_id: secret.id,
            api_key_id: api_key_id.clone(),
            audience: "https://example.com".to_string(),
            user_id,
        })
        .await?;

    // Find by prefix
    let by_prefix = store
        .find_oauth2_provider_app_token_by_prefix(token_prefix)
        .await?;
    assert!(by_prefix.is_some());
    assert_eq!(by_prefix.as_ref().map(|t| t.id), Some(token.id));

    // Find by API key id
    let by_api = store
        .find_oauth2_provider_app_token_by_api_key_id(&api_key_id)
        .await?;
    assert!(by_api.is_some());
    assert_eq!(by_api.as_ref().map(|t| t.id), Some(token.id));

    // Find by refresh hash
    let by_refresh = store
        .find_oauth2_provider_app_token_by_refresh_hash(refresh_hash)
        .await?;
    assert!(by_refresh.is_some());
    assert_eq!(by_refresh.as_ref().map(|t| t.id), Some(token.id));

    // Delete token
    let deleted = store.delete_oauth2_provider_app_token(token.id).await?;
    assert!(deleted);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_oauth2_delete_app_cascades() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    let app = store
        .create_oauth2_provider_app(&CreateOAuth2ProviderAppInput {
            name: format!("cascade-app-{}", uniq()),
            icon: "".to_string(),
            callback_url: "https://example.com/cb".to_string(),
            created_by: user_id,
        })
        .await?;

    // Create a secret
    let secret_prefix = b"cascpfx1";
    let _secret = store
        .create_oauth2_provider_app_secret(app.id, secret_prefix, b"caschashe", "cs****")
        .await?;

    // Create a code
    let code_prefix = b"casccpfx";
    let _code = store
        .create_oauth2_provider_app_code(
            app.id,
            user_id,
            code_prefix,
            b"casccodehs",
            OffsetDateTime::now_utc() + time::Duration::hours(1),
            "",
            "",
            "plain",
            None,
            None,
        )
        .await?;

    // Delete the app -- should cascade
    let deleted = store.delete_oauth2_provider_app(app.id).await?;
    assert!(deleted);

    // Verify secret is gone
    let secret_gone = store
        .find_oauth2_provider_app_secret_by_prefix(secret_prefix)
        .await?;
    assert!(secret_gone.is_none(), "secret should be cascade deleted");

    // Verify code is gone
    let code_gone = store
        .find_oauth2_provider_app_code_by_prefix(code_prefix)
        .await?;
    assert!(code_gone.is_none(), "code should be cascade deleted");

    // Verify app is gone
    let app_gone = store.find_oauth2_provider_app_by_id(app.id).await?;
    assert!(app_gone.is_none(), "app should be deleted");
    Ok(())
}

// =========================================================================
// 2. Group Membership
// =========================================================================

#[tokio::test]
#[ignore]
async fn test_group_create_insert_list_members() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    let group = store
        .create_group(&CreateGroupInput {
            name: format!("grp-{}", uniq()),
            display_name: "Test Group".to_string(),
            organization_id: org_id,
            avatar_url: "".to_string(),
            quota_allowance: 0,
        })
        .await?;

    // Insert member
    store.insert_group_member(group.id, user_id).await?;

    // List members -- should contain our user
    let members = store.list_group_members(group.id).await?;
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].user_id, user_id);
    assert_eq!(members[0].group_id, group.id);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_group_delete_member() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    let group = store
        .create_group(&CreateGroupInput {
            name: format!("grp-del-{}", uniq()),
            display_name: "Delete Group".to_string(),
            organization_id: org_id,
            avatar_url: "".to_string(),
            quota_allowance: 0,
        })
        .await?;

    store.insert_group_member(group.id, user_id).await?;

    // Delete member
    let removed = store.delete_group_member(group.id, user_id).await?;
    assert!(removed);

    // Verify gone
    let members = store.list_group_members(group.id).await?;
    assert!(members.is_empty());
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_group_soft_deleted_user_excluded() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    let group = store
        .create_group(&CreateGroupInput {
            name: format!("grp-soft-{}", uniq()),
            display_name: "Soft Delete Group".to_string(),
            organization_id: org_id,
            avatar_url: "".to_string(),
            quota_allowance: 0,
        })
        .await?;

    store.insert_group_member(group.id, user_id).await?;

    // Verify member is there
    let members = store.list_group_members(group.id).await?;
    assert_eq!(members.len(), 1);

    // Soft-delete the user
    store.soft_delete_user(user_id).await?;

    // List members again -- deleted user should be excluded
    let members_after = store.list_group_members(group.id).await?;
    assert!(
        members_after.is_empty(),
        "soft-deleted user should be excluded from group members"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_group_delete_cleans_up_members() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    let group = store
        .create_group(&CreateGroupInput {
            name: format!("grp-cleanup-{}", uniq()),
            display_name: "Cleanup Group".to_string(),
            organization_id: org_id,
            avatar_url: "".to_string(),
            quota_allowance: 0,
        })
        .await?;

    store.insert_group_member(group.id, user_id).await?;

    // Delete the group
    let deleted = store.delete_group(group.id).await?;
    assert!(deleted);

    // The group is gone
    let found = store.find_group_by_id(group.id).await?;
    assert!(found.is_none(), "group should be deleted");

    // Members should be cleaned up (FK cascade).
    // Verify by attempting to delete the member -- should return false.
    let was_member = store.delete_group_member(group.id, user_id).await?;
    assert!(
        !was_member,
        "member should have been cascade-deleted with group"
    );
    Ok(())
}

// =========================================================================
// 3. Workspace Listings with Filters
// =========================================================================

fn default_ws_filter() -> WorkspaceListFilter {
    WorkspaceListFilter {
        owner_id: None,
        owner_username: None,
        template_name: None,
        template_ids: vec![],
        name: None,
        status: None,
        has_agent: None,
        dormant: None,
        last_used_before: None,
        last_used_after: None,
        organization_id: None,
        limit: 100,
        offset: 0,
        viewer_id: None,
    }
}

#[tokio::test]
#[ignore]
async fn test_workspace_list_filters() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let owner1 = create_test_user(&store, org_id, &uniq()).await?;
    let owner2 = create_test_user(&store, org_id, &uniq()).await?;

    let tmpl1 =
        create_test_template(&store, &pool, org_id, owner1, &format!("tmpl-a-{}", uniq())).await?;
    let tmpl2 =
        create_test_template(&store, &pool, org_id, owner1, &format!("tmpl-b-{}", uniq())).await?;

    // Insert workspaces
    let ws1_id = Uuid::new_v4();
    store
        .insert_workspace(CreateWorkspaceInput {
            id: ws1_id,
            owner_id: owner1,
            organization_id: org_id,
            template_id: tmpl1,
            name: format!("ws-alpha-{}", uniq()),
            autostart_schedule: None,
            ttl_ns: None,
            automatic_updates: "never".to_string(),
        })
        .await?;

    let ws2_id = Uuid::new_v4();
    store
        .insert_workspace(CreateWorkspaceInput {
            id: ws2_id,
            owner_id: owner2,
            organization_id: org_id,
            template_id: tmpl2,
            name: format!("ws-beta-{}", uniq()),
            autostart_schedule: None,
            ttl_ns: None,
            automatic_updates: "never".to_string(),
        })
        .await?;

    // Filter by owner
    let (by_owner, count) = store
        .list_workspaces(WorkspaceListFilter {
            owner_id: Some(owner1),
            ..default_ws_filter()
        })
        .await?;
    assert_eq!(count, 1);
    assert_eq!(by_owner.len(), 1);
    assert_eq!(by_owner[0].owner_id, owner1);

    // Filter by template_ids
    let (by_tmpl, count) = store
        .list_workspaces(WorkspaceListFilter {
            template_ids: vec![tmpl2],
            ..default_ws_filter()
        })
        .await?;
    assert_eq!(count, 1);
    assert_eq!(by_tmpl.len(), 1);
    assert_eq!(by_tmpl[0].template_id, tmpl2);

    // Filter by organization_id -- should get both
    let (by_org, count) = store
        .list_workspaces(WorkspaceListFilter {
            organization_id: Some(org_id),
            ..default_ws_filter()
        })
        .await?;
    assert!(count >= 2);
    assert!(by_org.len() >= 2);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_workspace_soft_deleted_excluded() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;
    let tmpl = create_test_template(
        &store,
        &pool,
        org_id,
        user_id,
        &format!("tmpl-del-{}", uniq()),
    )
    .await?;

    let ws_id = Uuid::new_v4();
    store
        .insert_workspace(CreateWorkspaceInput {
            id: ws_id,
            owner_id: user_id,
            organization_id: org_id,
            template_id: tmpl,
            name: format!("ws-del-{}", uniq()),
            autostart_schedule: None,
            ttl_ns: None,
            automatic_updates: "never".to_string(),
        })
        .await?;

    // Verify it shows up
    let found = store.find_workspace_by_id(ws_id, None).await?;
    assert!(found.is_some());

    // Soft-delete
    store.soft_delete_workspace(ws_id).await?;

    // Should not be found
    let gone = store.find_workspace_by_id(ws_id, None).await?;
    assert!(gone.is_none(), "soft-deleted workspace should not be found");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_workspace_dormant_filter() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;
    let tmpl = create_test_template(
        &store,
        &pool,
        org_id,
        user_id,
        &format!("tmpl-dorm-{}", uniq()),
    )
    .await?;

    let ws_id = Uuid::new_v4();
    store
        .insert_workspace(CreateWorkspaceInput {
            id: ws_id,
            owner_id: user_id,
            organization_id: org_id,
            template_id: tmpl,
            name: format!("ws-dormant-{}", uniq()),
            autostart_schedule: None,
            ttl_ns: None,
            automatic_updates: "never".to_string(),
        })
        .await?;

    // Mark workspace as dormant via raw SQL
    sqlx::query("UPDATE workspaces SET dormant_at = NOW() WHERE id = $1")
        .bind(ws_id)
        .execute(&pool)
        .await?;

    // Filter dormant=true -- should include it
    let (dormant_list, dormant_count) = store
        .list_workspaces(WorkspaceListFilter {
            owner_id: Some(user_id),
            dormant: Some(true),
            ..default_ws_filter()
        })
        .await?;
    assert_eq!(dormant_count, 1);
    assert_eq!(dormant_list.len(), 1);

    // Filter dormant=false -- should exclude it
    let (active_list, active_count) = store
        .list_workspaces(WorkspaceListFilter {
            owner_id: Some(user_id),
            dormant: Some(false),
            ..default_ws_filter()
        })
        .await?;
    assert_eq!(active_count, 0);
    assert!(active_list.is_empty());
    Ok(())
}

// =========================================================================
// 4. Notification Inbox Filters
// =========================================================================

#[tokio::test]
#[ignore]
async fn test_notification_inbox_count_and_filter() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    // Seed a notification template
    let template_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO notification_templates (id, name, title_template, body_template, "group", actions, kind)
           VALUES ($1, $2, 'Title', 'Body', NULL, '[]', 'system')
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(template_id)
    .bind(format!("test-notif-{}", uniq()))
    .execute(&pool)
    .await?;

    // Insert inbox notifications directly (no store method for insertion)
    let notif1_id = Uuid::new_v4();
    let notif2_id = Uuid::new_v4();
    for (id, read) in [(notif1_id, false), (notif2_id, true)] {
        let read_at: Option<OffsetDateTime> = if read {
            Some(OffsetDateTime::now_utc())
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO inbox_notifications (id, user_id, template_id, targets, title, content, icon, actions, read_at, created_at)
             VALUES ($1, $2, $3, ARRAY[]::uuid[], 'Test Title', 'Test Content', '', '[]', $4, NOW())",
        )
        .bind(id)
        .bind(user_id)
        .bind(template_id)
        .bind(read_at)
        .execute(&pool)
        .await?;
    }

    // Count unread -- should be at least 1
    let unread_count = store.count_unread_inbox_notifications(user_id).await?;
    assert!(unread_count >= 1, "expected at least 1 unread notification");

    // Filter: unread only
    let unread = store
        .get_filtered_inbox_notifications(user_id, None, None, "unread", None)
        .await?;
    assert!(
        unread.iter().all(|n| n.read_at.is_none()),
        "all returned notifications should be unread"
    );

    // Filter: read only
    let read_notifs = store
        .get_filtered_inbox_notifications(user_id, None, None, "read", None)
        .await?;
    assert!(
        read_notifs.iter().all(|n| n.read_at.is_some()),
        "all returned notifications should be read"
    );

    // Filter: all
    let all = store
        .get_filtered_inbox_notifications(user_id, None, None, "all", None)
        .await?;
    assert!(all.len() >= 2, "expected at least 2 total notifications");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_notification_message_fetch_pending_respects_max_attempts() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;

    // Seed a notification template
    let template_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO notification_templates (id, name, title_template, body_template, "group", actions, kind)
           VALUES ($1, $2, 'Title', 'Body', NULL, '[]', 'system')
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(template_id)
    .bind(format!("msg-tmpl-{}", uniq()))
    .execute(&pool)
    .await?;

    // Insert notification messages with different attempt counts
    let msg1_id = Uuid::new_v4(); // attempt_count = 0 (should be fetched)
    let msg2_id = Uuid::new_v4(); // attempt_count = 5 (should be filtered out with max=3)
    for (id, attempts) in [(msg1_id, 0), (msg2_id, 5)] {
        sqlx::query(
            "INSERT INTO notification_messages (id, user_id, notification_template_id, method, status, attempt_count, payload, created_at, updated_at)
             VALUES ($1, $2, $3, 'smtp'::notification_method, 'pending'::notification_message_status, $4, '{}'::jsonb, NOW(), NOW())",
        )
        .bind(id)
        .bind(user_id)
        .bind(template_id)
        .bind(attempts)
        .execute(&pool)
        .await?;
    }

    // Fetch with max_attempt_count = 3 -- should only get msg1
    let pending = store.fetch_pending_notification_messages(10, 3).await?;

    let fetched_ids: Vec<_> = pending.iter().map(|m| m.id).collect();
    assert!(
        fetched_ids.contains(&msg1_id),
        "msg1 (attempt_count=0) should be fetched"
    );
    assert!(
        !fetched_ids.contains(&msg2_id),
        "msg2 (attempt_count=5) should be filtered out with max_attempt_count=3"
    );
    Ok(())
}

// =========================================================================
// 5. Template Version Archiving
// =========================================================================

#[tokio::test]
#[ignore]
async fn test_template_version_archive_unused() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;
    let template_name = format!("tmpl-archive-{}", uniq());

    // Create a template with an initial version (the active one)
    let template_id = create_test_template(&store, &pool, org_id, user_id, &template_name).await?;

    // Get the active version id from the template
    let tmpl = store
        .find_template_by_id(template_id)
        .await?
        .ok_or("template not found")?;
    let active_version_id = tmpl.active_version_id;

    // Create a second (unused) version
    let job_id2 = create_provisioner_job(&pool, org_id, user_id).await?;
    let v2_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    store
        .insert_template_version(CreateTemplateVersionInput {
            id: v2_id,
            template_id: Some(template_id),
            organization_id: org_id,
            created_at: now,
            updated_at: now,
            name: format!("{template_name}-v2"),
            message: "unused version".to_string(),
            readme: "".to_string(),
            job_id: job_id2,
            created_by: user_id,
            source_example_id: None,
        })
        .await?;

    // Create a third (unused) version
    let job_id3 = create_provisioner_job(&pool, org_id, user_id).await?;
    let v3_id = Uuid::new_v4();
    store
        .insert_template_version(CreateTemplateVersionInput {
            id: v3_id,
            template_id: Some(template_id),
            organization_id: org_id,
            created_at: now + time::Duration::seconds(1),
            updated_at: now + time::Duration::seconds(1),
            name: format!("{template_name}-v3"),
            message: "another unused".to_string(),
            readme: "".to_string(),
            job_id: job_id3,
            created_by: user_id,
            source_example_id: None,
        })
        .await?;

    // Archive unused (all=true)
    let archived = store
        .archive_unused_template_versions(template_id, true)
        .await?;

    // The active version should NOT be archived
    assert!(
        !archived.contains(&active_version_id),
        "active version should not be archived"
    );

    // v2 and v3 should be archived
    assert!(archived.contains(&v2_id), "v2 should be archived");
    assert!(archived.contains(&v3_id), "v3 should be archived");

    // Verify via list with include_archived=false
    let versions = store
        .list_template_versions(TemplateVersionListFilter {
            template_id,
            include_archived: false,
            limit: 100,
            offset: 0,
        })
        .await?;

    let version_ids: Vec<_> = versions.iter().map(|v| v.id).collect();
    assert!(
        version_ids.contains(&active_version_id),
        "active version should still be listed"
    );
    assert!(
        !version_ids.contains(&v2_id),
        "v2 should not appear when archived excluded"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_template_version_unarchive() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;
    let template_name = format!("tmpl-unarch-{}", uniq());

    let template_id = create_test_template(&store, &pool, org_id, user_id, &template_name).await?;

    // Create an unused version
    let job_id = create_provisioner_job(&pool, org_id, user_id).await?;
    let v2_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    store
        .insert_template_version(CreateTemplateVersionInput {
            id: v2_id,
            template_id: Some(template_id),
            organization_id: org_id,
            created_at: now,
            updated_at: now,
            name: format!("{template_name}-v2"),
            message: "to archive".to_string(),
            readme: "".to_string(),
            job_id,
            created_by: user_id,
            source_example_id: None,
        })
        .await?;

    // Archive it
    let archived = store.archive_template_version(v2_id).await?;
    assert!(archived);

    // Verify it's archived (not in non-archived list)
    let versions = store
        .list_template_versions(TemplateVersionListFilter {
            template_id,
            include_archived: false,
            limit: 100,
            offset: 0,
        })
        .await?;
    assert!(
        !versions.iter().any(|v| v.id == v2_id),
        "archived version should not appear"
    );

    // Unarchive it
    let unarchived = store.unarchive_template_version(v2_id).await?;
    assert!(unarchived);

    // Verify it's back
    let versions_after = store
        .list_template_versions(TemplateVersionListFilter {
            template_id,
            include_archived: false,
            limit: 100,
            offset: 0,
        })
        .await?;
    assert!(
        versions_after.iter().any(|v| v.id == v2_id),
        "unarchived version should appear again"
    );
    Ok(())
}

// =========================================================================
// 6. Workspace Build Number Sequencing
// =========================================================================

#[tokio::test]
#[ignore]
async fn test_workspace_build_number_sequencing() -> TestResult {
    let store = match setup_store().await? {
        Some(s) => s,
        None => return Ok(()),
    };
    let pool = store.pool();
    let org_id = ensure_default_org(&pool).await?;
    let user_id = create_test_user(&store, org_id, &uniq()).await?;
    let tmpl_name = format!("tmpl-build-{}", uniq());
    let template_id = create_test_template(&store, &pool, org_id, user_id, &tmpl_name).await?;

    // Get the template version id for build references
    let tmpl = store
        .find_template_by_id(template_id)
        .await?
        .ok_or("template not found")?;
    let tv_id = tmpl.active_version_id;

    // Create a workspace
    let ws_id = Uuid::new_v4();
    store
        .insert_workspace(CreateWorkspaceInput {
            id: ws_id,
            owner_id: user_id,
            organization_id: org_id,
            template_id,
            name: format!("ws-build-{}", uniq()),
            autostart_schedule: None,
            ttl_ns: None,
            automatic_updates: "never".to_string(),
        })
        .await?;

    // next_workspace_build_number on empty workspace should be 1
    let next = store.next_workspace_build_number(ws_id).await?;
    assert_eq!(next, 1, "first build number should be 1");

    // Insert first build -- should get build_number = 1
    let job1 = create_provisioner_job(&pool, org_id, user_id).await?;
    let build1 = store
        .insert_workspace_build(CreateWorkspaceBuildInput {
            id: Uuid::new_v4(),
            workspace_id: ws_id,
            template_version_id: tv_id,
            build_number: 0, // ignored -- computed by inline subquery
            transition: "start".to_string(),
            initiator_id: user_id,
            job_id: job1,
            reason: "initiator".to_string(),
            deadline: None,
            max_deadline: None,
        })
        .await?;
    assert_eq!(build1.build_number, 1, "first build should be number 1");

    // Insert second build -- should get build_number = 2
    let job2 = create_provisioner_job(&pool, org_id, user_id).await?;
    let build2 = store
        .insert_workspace_build(CreateWorkspaceBuildInput {
            id: Uuid::new_v4(),
            workspace_id: ws_id,
            template_version_id: tv_id,
            build_number: 0,
            transition: "stop".to_string(),
            initiator_id: user_id,
            job_id: job2,
            reason: "initiator".to_string(),
            deadline: None,
            max_deadline: None,
        })
        .await?;
    assert_eq!(build2.build_number, 2, "second build should be number 2");

    // Insert third build
    let job3 = create_provisioner_job(&pool, org_id, user_id).await?;
    let build3 = store
        .insert_workspace_build(CreateWorkspaceBuildInput {
            id: Uuid::new_v4(),
            workspace_id: ws_id,
            template_version_id: tv_id,
            build_number: 0,
            transition: "start".to_string(),
            initiator_id: user_id,
            job_id: job3,
            reason: "initiator".to_string(),
            deadline: None,
            max_deadline: None,
        })
        .await?;
    assert_eq!(build3.build_number, 3, "third build should be number 3");

    // next_workspace_build_number should now be 4
    let next_after = store.next_workspace_build_number(ws_id).await?;
    assert_eq!(
        next_after, 4,
        "next build number after 3 builds should be 4"
    );

    // Verify find_workspace_build_by_number works
    let found = store.find_workspace_build_by_number(ws_id, 2).await?;
    assert!(found.is_some());
    assert_eq!(found.as_ref().map(|b| b.id), Some(build2.id));
    Ok(())
}
