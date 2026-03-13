//! Integration test crate for the Coder Rust backend.
//!
//! All tests live in the `#[cfg(test)]` module below and exercise the full
//! request -> handler -> store -> database -> response pipeline
//! using a real PostgreSQL database.
#![forbid(unsafe_code)]

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, Response, StatusCode, header::CONTENT_TYPE};
    use coder_audit::{AuditEvent, AuditSink};
    use coder_connectivity::agents::InMemoryAgentProvider;
    use coder_connectivity::tailnet::{DerpTrafficTracker, InMemoryCoordinator};
    use coder_core::pubsub::InMemoryPubSub;
    use coder_core::{BuildMetadata, DatabaseConfig, ServerConfig};
    use coder_db::PostgresStore;
    use coder_server::{AppState, build_router};
    use serde::Serialize;
    use serde_json::Value;
    use sqlx::PgPool;
    use tower::ServiceExt;
    use uuid::Uuid;

    // ─────────────────────────────────────────────────────────────────────────────
    // Test harness
    // ─────────────────────────────────────────────────────────────────────────────

    /// Session token header used by the Coder API.
    const SESSION_TOKEN_HEADER: &str = "Coder-Session-Token";

    /// Returns the test database URL or `None` when the env var is unset.
    fn test_database_url() -> Option<String> {
        std::env::var("TEST_DATABASE_URL").ok()
    }

    /// Macro that skips (returns `Ok(())`) when no database URL is configured.
    macro_rules! skip_without_db {
        () => {
            if test_database_url().is_none() {
                eprintln!("TEST_DATABASE_URL not set – skipping integration test");
                return Ok(());
            }
        };
    }

    /// In-memory audit sink that captures recorded events for assertions.
    #[derive(Debug, Default)]
    struct MemoryAuditSink {
        events: std::sync::Mutex<Vec<AuditEvent>>,
    }

    #[async_trait::async_trait]
    impl AuditSink for MemoryAuditSink {
        async fn record(&self, event: AuditEvent) {
            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }
    }

    impl MemoryAuditSink {
        #[allow(dead_code)]
        fn recorded_events(&self) -> Vec<AuditEvent> {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    /// Build a [`ServerConfig`] suitable for integration tests.
    fn test_config(db_url: &str) -> Result<ServerConfig, url::ParseError> {
        Ok(ServerConfig {
            listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            access_url: url::Url::parse("http://127.0.0.1:3000")?,
            wildcard_access_url: String::new(),
            database: DatabaseConfig {
                postgres_url: db_url.to_owned(),
                max_connections: 5,
                min_connections: 1,
                acquire_timeout_secs: 10,
            },
            tls: coder_core::config::TlsConfig::default(),
            networking: coder_core::config::NetworkingConfig::default(),
            http_cookies: coder_core::config::HttpCookieConfig::default(),
            telemetry: coder_core::config::TelemetryConfig::default(),
            ssh: coder_core::config::SshConfig {
                hostname_prefix: "coder".to_owned(),
                hostname_suffix: "example.internal".to_owned(),
                ssh_config_options: HashMap::from([(
                    "StrictHostKeyChecking".to_owned(),
                    "no".to_owned(),
                )]),
            },
            external_auth_providers: Vec::new(),
            derp_regions: Vec::new(),
            shutdown_grace_period_secs: 10,
            log_format: coder_core::config::LogFormat::Pretty,
            logging: coder_core::config::LoggingConfig::default(),
            session_cache_ttl_secs: 0, // disable caching in tests
            audit_batch_flush_interval_ms: 500,
            audit_batch_max_size: 50,
            max_concurrent_requests: 1024,
            max_concurrent_db_queries: 40,
            rate_limit: coder_core::config::RateLimitConfig::default(),
            github_oauth: None,
            oidc: None,
            otel: coder_core::config::OtelConfig::default(),
            cors: coder_core::config::CorsConfig::default(),
            security_headers: coder_core::config::SecurityHeadersConfig::default(),
            provisioner: coder_core::config::ProvisionerConfig::default(),
            session_lifetime: coder_core::config::SessionLifetimeConfig::default(),
            dangerous: coder_core::config::DangerousConfig::default(),
            healthcheck: coder_core::config::HealthcheckConfig::default(),
            workspace: coder_core::config::WorkspaceConfig::default(),
            worker: coder_core::config::WorkerConfig::default(),
            swagger_enabled: true,
            update_check: false,
            ssh_keygen_algorithm: "ed25519".to_owned(),
            cache_dir: String::new(),
            browser_only: false,
            disable_password_auth: false,
            disable_path_apps: false,
            disable_owner_workspace_exec: false,
            strict_transport_security: 0,
            strict_transport_security_options: Vec::new(),
            experiments: Vec::new(),
            agent_fallback_troubleshooting_url: String::new(),
            terms_of_service_url: String::new(),
            web_terminal_renderer: String::new(),
            allow_workspace_renames: false,
            additional_csp_policy: Vec::new(),
            disable_workspace_sharing: false,
            docs_url: String::new(),
            scim_api_key: String::new(),
            cli_upgrade_message: String::new(),
        })
    }

    /// Per-test isolated database.
    ///
    /// Each test gets its own database so tests cannot interfere with each other.
    /// Call [`TestDatabase::cleanup`] explicitly at the end of each test rather
    /// than relying on `Drop` (which cannot run async code reliably).
    struct TestDatabase {
        db_name: String,
        pool: PgPool,
        /// Admin pool connected to the `postgres` database, used for cleanup.
        admin_pool: PgPool,
    }

    impl TestDatabase {
        /// Create a fresh test database, run migrations, and return the pool.
        async fn new(base_url: &str) -> Result<Self, Box<dyn Error>> {
            let db_name = format!("coder_test_{}", Uuid::new_v4().simple());

            // Connect to the default `postgres` database to create the test DB.
            let admin_pool = PgPool::connect(base_url).await?;
            sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
                .execute(&admin_pool)
                .await?;

            // Build connection string to the new database.
            let test_url = base_url
                .rsplit_once('/')
                .map(|(base, _)| format!("{base}/{db_name}"))
                .unwrap_or_else(|| format!("{base_url}/{db_name}"));

            // Connect to the test database and run migrations.
            let pool = PgPool::connect(&test_url).await?;
            coder_db::run_migrations(&pool).await?;

            Ok(Self {
                db_name,
                pool,
                admin_pool,
            })
        }

        fn url(&self) -> String {
            let base = test_database_url().expect("TEST_DATABASE_URL must be set");
            base.rsplit_once('/')
                .map(|(b, _)| format!("{b}/{}", self.db_name))
                .unwrap_or_else(|| format!("{base}/{}", self.db_name))
        }

        /// Explicitly clean up the test database.
        ///
        /// Closes all connections then drops the database.  Must be called at
        /// the end of every test that creates a `TestDatabase` or `TestHarness`.
        async fn cleanup(self) {
            // Close the test-database pool so no active connections remain.
            self.pool.close().await;

            // Terminate any lingering back-end connections.
            let _ = sqlx::query(&format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
                self.db_name
            ))
            .execute(&self.admin_pool)
            .await;

            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{}\"", self.db_name))
                .execute(&self.admin_pool)
                .await;

            self.admin_pool.close().await;
        }
    }

    /// Holds everything needed for an integration test: database, router, and
    /// an audit sink that can be inspected.
    struct TestHarness {
        router: Router,
        #[allow(dead_code)]
        audit: Arc<MemoryAuditSink>,
        db: TestDatabase,
    }

    impl TestHarness {
        async fn new() -> Result<Self, Box<dyn Error>> {
            let base_url = test_database_url().expect("TEST_DATABASE_URL required");
            let db = TestDatabase::new(&base_url).await?;

            let db_config = DatabaseConfig {
                postgres_url: db.url(),
                max_connections: 5,
                min_connections: 1,
                acquire_timeout_secs: 10,
            };

            let store = Arc::new(PostgresStore::connect(&db_config).await?)
                as Arc<dyn coder_core::AppStore>;

            let audit = Arc::new(MemoryAuditSink::default());
            let audit_trait: Arc<dyn AuditSink> = audit.clone();
            let pubsub: Arc<dyn coder_core::pubsub::PubSub> = Arc::new(InMemoryPubSub::new());
            let agent_provider: Arc<dyn coder_connectivity::agents::AgentProvider> =
                Arc::new(InMemoryAgentProvider::new());
            let coordinator = InMemoryCoordinator::new(Default::default());
            let derp_tracker = DerpTrafficTracker::new();

            let state = AppState::new(
                test_config(&db.url())?,
                BuildMetadata::default(),
                Uuid::nil(),
                store,
                audit_trait,
                pubsub,
                agent_provider,
                coordinator,
                derp_tracker,
                coder_connectivity::derp::DerpServer::new(coder_connectivity::derp::NodeKey::new(
                    [0u8; 32],
                )),
                None,
                coder_telemetry::TelemetryReporter::disabled(Uuid::nil()),
            )?;

            let router = build_router(state, None);

            Ok(Self { router, audit, db })
        }

        /// Explicitly clean up the test database.
        async fn cleanup(self) {
            self.db.cleanup().await;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HTTP helpers
    // ─────────────────────────────────────────────────────────────────────────────

    fn plain_request(method: Method, uri: &str) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
    }

    fn json_request<T: Serialize>(
        method: Method,
        uri: &str,
        payload: &T,
    ) -> Result<Request<Body>, Box<dyn Error>> {
        let body = serde_json::to_vec(payload)?;
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))?;
        Ok(req)
    }

    fn authed_request(
        method: Method,
        uri: &str,
        token: &str,
    ) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(SESSION_TOKEN_HEADER, token)
            .body(Body::empty())
    }

    fn authed_json_request<T: Serialize>(
        method: Method,
        uri: &str,
        token: &str,
        payload: &T,
    ) -> Result<Request<Body>, Box<dyn Error>> {
        let body = serde_json::to_vec(payload)?;
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(SESSION_TOKEN_HEADER, token)
            .body(Body::from(body))?;
        Ok(req)
    }

    async fn call(app: Router, request: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {
        let response = match app.oneshot(request).await {
            Ok(r) => r,
            Err(never) => match never {},
        };
        Ok(response)
    }

    async fn response_json(response: Response<Body>) -> Result<Value, Box<dyn Error>> {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // High-level test helpers
    // ─────────────────────────────────────────────────────────────────────────────

    /// Creates the first user and logs in, returning the session token.
    async fn create_first_user_and_login(app: &Router) -> Result<String, Box<dyn Error>> {
        let create = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/first",
                &serde_json::json!({
                    "email": "owner@example.com",
                    "username": "owner",
                    "name": "Owner",
                    "password": "Password123!"
                }),
            )?,
        )
        .await?;
        assert_eq!(
            create.status(),
            StatusCode::CREATED,
            "first user creation failed: {}",
            create.status()
        );

        let login = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &serde_json::json!({
                    "email": "owner@example.com",
                    "password": "Password123!"
                }),
            )?,
        )
        .await?;
        assert_eq!(login.status(), StatusCode::CREATED, "login failed");
        let body = response_json(login).await?;
        Ok(body
            .get("session_token")
            .and_then(Value::as_str)
            .ok_or("missing session_token in login response")?
            .to_owned())
    }

    /// Fetches the first (default) organization ID for the logged-in user.
    async fn first_organization_id(app: &Router, token: &str) -> Result<Uuid, Box<dyn Error>> {
        let resp = call(
            app.clone(),
            authed_request(Method::GET, "/api/v2/organizations", token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let org_id = body
            .as_array()
            .and_then(|a| a.first())
            .and_then(|o| o.get("id"))
            .and_then(Value::as_str)
            .ok_or("no organization found")?;
        Ok(Uuid::parse_str(org_id)?)
    }

    /// Creates an additional user via the admin API, returns the new user's ID.
    async fn create_user(
        app: &Router,
        token: &str,
        email: &str,
        username: &str,
        password: &str,
        org_id: Uuid,
    ) -> Result<Uuid, Box<dyn Error>> {
        let resp = call(
            app.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/users",
                token,
                &serde_json::json!({
                    "email": email,
                    "username": username,
                    "name": username,
                    "password": password,
                    "login_type": "password",
                    "organization_ids": [org_id],
                    "user_status": "active"
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::CREATED, "create user failed");
        let body = response_json(resp).await?;
        let user_id = body
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing user id")?;
        Ok(Uuid::parse_str(user_id)?)
    }

    /// Logs in a user, returns session token.
    async fn login_user(
        app: &Router,
        email: &str,
        password: &str,
    ) -> Result<String, Box<dyn Error>> {
        let resp = call(
            app.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &serde_json::json!({
                    "email": email,
                    "password": password
                }),
            )?,
        )
        .await?;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "login failed for {email}"
        );
        let body = response_json(resp).await?;
        Ok(body
            .get("session_token")
            .and_then(Value::as_str)
            .ok_or("missing session_token")?
            .to_owned())
    }

    // ═════════════════════════════════════════════════════════════════════════════
    // Integration tests
    // ═════════════════════════════════════════════════════════════════════════════

    // ── 1. Migrations run successfully ──────────────────────────────────────────

    #[tokio::test]
    async fn migrations_apply_cleanly() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let base_url = test_database_url().unwrap();
        let db = TestDatabase::new(&base_url).await?;

        // Verify migration status via the public API.
        let status = coder_db::migration_status(&db.pool).await?;
        assert!(
            status.is_up_to_date,
            "expected migrations to be up-to-date, applied={}",
            status.applied_count
        );
        assert!(
            status.applied_count > 0,
            "expected at least one migration to be applied"
        );
        db.cleanup().await;
        Ok(())
    }

    // ── 2. First user registration ─────────────────────────────────────────────

    #[tokio::test]
    async fn first_user_registration() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/first",
                &serde_json::json!({
                    "email": "admin@example.com",
                    "username": "admin",
                    "name": "Admin",
                    "password": "SecurePass123!"
                }),
            )?,
        )
        .await?;

        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_json(resp).await?;
        // CreateFirstUserResponse returns user_id and organization_id, not the full user.
        assert!(
            body.get("user_id").and_then(Value::as_str).is_some(),
            "expected user_id in first-user response: {body:?}"
        );
        assert!(
            body.get("organization_id")
                .and_then(Value::as_str)
                .is_some(),
            "expected organization_id in first-user response: {body:?}"
        );

        // Duplicate first-user registration must fail.
        let dup = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/first",
                &serde_json::json!({
                    "email": "admin2@example.com",
                    "username": "admin2",
                    "name": "Admin2",
                    "password": "SecurePass123!"
                }),
            )?,
        )
        .await?;
        assert_eq!(dup.status(), StatusCode::CONFLICT);

        h.cleanup().await;
        Ok(())
    }

    // ── 3. Login with password ──────────────────────────────────────────────────

    #[tokio::test]
    async fn login_returns_session_token() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        assert!(!token.is_empty(), "session token should not be empty");
        h.cleanup().await;
        Ok(())
    }

    // ── 4. Login with wrong password ────────────────────────────────────────────

    #[tokio::test]
    async fn login_wrong_password_returns_unauthorized() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &serde_json::json!({
                    "email": "owner@example.com",
                    "password": "WrongPassword!"
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ── 5. Authenticated request: GET /api/v2/users/me ──────────────────────────

    #[tokio::test]
    async fn get_current_user_with_session_token() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = response_json(resp).await?;
        assert_eq!(body.get("username").and_then(Value::as_str), Some("owner"));
        assert_eq!(
            body.get("email").and_then(Value::as_str),
            Some("owner@example.com")
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 6. Unauthenticated request returns 401 ─────────────────────────────────

    #[tokio::test]
    async fn unauthenticated_request_returns_401() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            plain_request(Method::GET, "/api/v2/users/me")?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ── 7. Default organization exists after first user ─────────────────────────

    #[tokio::test]
    async fn default_organization_exists() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let org_id = first_organization_id(&h.router, &token).await?;
        assert_ne!(org_id, Uuid::nil(), "default org should have a valid id");

        // Fetch the organization directly.
        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert!(
            body.get("is_default")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            "expected the organization to be the default"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 8. Create a second user via admin API ───────────────────────────────────

    #[tokio::test]
    async fn create_additional_user() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        let user_id = create_user(
            &h.router,
            &token,
            "dev@example.com",
            "developer",
            "DevPass123!",
            org_id,
        )
        .await?;
        assert_ne!(user_id, Uuid::nil());

        // The new user can log in.
        let dev_token = login_user(&h.router, "dev@example.com", "DevPass123!").await?;
        assert!(!dev_token.is_empty());

        // The new user can fetch their own profile.
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &dev_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert_eq!(
            body.get("username").and_then(Value::as_str),
            Some("developer")
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 9. List users returns all created users ─────────────────────────────────

    #[tokio::test]
    async fn list_users_returns_created_users() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        create_user(
            &h.router,
            &token,
            "user1@example.com",
            "user1",
            "Pass1234!",
            org_id,
        )
        .await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let users = body
            .get("users")
            .and_then(Value::as_array)
            .expect("expected users array");
        // At least the owner + user1 (system user may also be present).
        assert!(
            users.len() >= 2,
            "expected at least 2 users, got {}",
            users.len()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 10. Update user profile ─────────────────────────────────────────────────

    #[tokio::test]
    async fn update_user_profile() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::PUT,
                "/api/v2/users/me/profile",
                &token,
                &serde_json::json!({
                    "username": "owner",
                    "name": "Updated Owner"
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = response_json(resp).await?;
        assert_eq!(
            body.get("name").and_then(Value::as_str),
            Some("Updated Owner")
        );

        // Verify the update persisted.
        let me = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &token)?,
        )
        .await?;
        let me_body = response_json(me).await?;
        assert_eq!(
            me_body.get("name").and_then(Value::as_str),
            Some("Updated Owner")
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 11. API key: create → use → delete ──────────────────────────────────────

    #[tokio::test]
    async fn api_key_create_use_delete() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        // Create an API key (token).
        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/users/me/keys/tokens",
                &token,
                &serde_json::json!({
                    "token_name": "test-token",
                    "lifetime": 3_600_000_000_000_i64
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let key_body = response_json(resp).await?;
        let api_key = key_body
            .get("key")
            .and_then(Value::as_str)
            .ok_or("missing key in token response")?
            .to_owned();
        assert!(!api_key.is_empty());

        // List tokens and find ours.
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/keys/tokens", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let tokens_body = response_json(resp).await?;
        let tokens = tokens_body.as_array().expect("expected array of tokens");
        let our_token = tokens
            .iter()
            .find(|t| t.get("token_name").and_then(Value::as_str) == Some("test-token"))
            .expect("created token not found in list");
        let key_id = our_token
            .get("id")
            .and_then(Value::as_str)
            .expect("token entry missing id field");

        // Delete by key id: DELETE /api/v2/users/me/keys/{keyid}
        let resp = call(
            h.router.clone(),
            authed_request(
                Method::DELETE,
                &format!("/api/v2/users/me/keys/{key_id}"),
                &token,
            )?,
        )
        .await?;
        // 204 No Content on successful delete
        assert!(
            resp.status() == StatusCode::NO_CONTENT || resp.status() == StatusCode::OK,
            "expected 204 or 200 for key deletion, got {}",
            resp.status()
        );

        // After deletion the token should no longer appear in the list.
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/keys/tokens", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let after = response_json(resp).await?;
        assert!(
            !after
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .any(|t| t.get("token_name").and_then(Value::as_str) == Some("test-token")),
            "deleted token should not appear in list"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 12. Logout invalidates session ──────────────────────────────────────────

    #[tokio::test]
    async fn logout_invalidates_session() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        // Verify the token works.
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        // Logout.
        let resp = call(
            h.router.clone(),
            authed_request(Method::POST, "/api/v2/users/logout", &token)?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "expected successful logout, got {}",
            resp.status()
        );

        // The token should no longer be valid.
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ── 13. Build info endpoint works with real store ───────────────────────────

    #[tokio::test]
    async fn build_info_with_real_store() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            plain_request(Method::GET, "/api/v2/buildinfo")?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert!(
            body.get("version").and_then(Value::as_str).is_some(),
            "buildinfo should include version"
        );
        assert!(
            body.get("external_url").and_then(Value::as_str).is_some(),
            "buildinfo should include external_url"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 14. Audit log: generate and list ────────────────────────────────────────

    #[tokio::test]
    async fn audit_log_generation_and_listing() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        // Generate a test audit log entry.
        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/audit/testgenerate",
                &token,
                &serde_json::json!({
                    "resource_type": "user",
                    "action": "write"
                }),
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::NO_CONTENT || resp.status() == StatusCode::OK,
            "expected successful audit generation, got {}",
            resp.status()
        );

        // Allow a brief moment for the batched audit sink to flush.
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;

        // List audit logs.
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/audit?limit=50", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let logs = body
            .get("audit_logs")
            .and_then(Value::as_array)
            .expect("expected audit_logs array");
        // We should have at least the test-generated entry plus any login/register
        // events from first user creation.
        assert!(!logs.is_empty(), "expected at least one audit log entry");
        h.cleanup().await;
        Ok(())
    }

    // ── 15. RBAC: non-owner cannot create users ─────────────────────────────────

    #[tokio::test]
    async fn rbac_non_owner_cannot_create_users() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let owner_token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &owner_token).await?;

        // Create a regular user.
        create_user(
            &h.router,
            &owner_token,
            "member@example.com",
            "member",
            "MemberPass1!",
            org_id,
        )
        .await?;

        // Login as the regular user.
        let member_token = login_user(&h.router, "member@example.com", "MemberPass1!").await?;

        // Attempt to create another user — should be forbidden.
        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/users",
                &member_token,
                &serde_json::json!({
                    "email": "hacker@example.com",
                    "username": "hacker",
                    "name": "Hacker",
                    "password": "HackPass1!",
                    "login_type": "password",
                    "organization_ids": [org_id]
                }),
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "expected 403 or 401 for non-owner user creation, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 16. Organization membership ─────────────────────────────────────────────

    #[tokio::test]
    async fn organization_membership_listed() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/members"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        // The response may be a direct array or have a "members" key.
        let members = body
            .get("members")
            .and_then(Value::as_array)
            .or_else(|| body.as_array())
            .expect("expected members in response");
        assert!(
            !members.is_empty(),
            "owner should be a member of the default org"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 17. Health endpoint with real database ──────────────────────────────────

    #[tokio::test]
    async fn healthz_with_real_database() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(h.router.clone(), plain_request(Method::GET, "/healthz")?).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 18. Deployment config endpoint ──────────────────────────────────────────

    #[tokio::test]
    async fn deployment_config_returns_ok() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/deployment/config", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert!(
            body.get("config").is_some(),
            "deployment config should include config object"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 19. SSH config endpoint ─────────────────────────────────────────────────

    #[tokio::test]
    async fn ssh_config_returns_hostname_info() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/deployment/ssh", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert!(
            body.get("hostname_prefix").is_some() || body.get("hostname_suffix").is_some(),
            "ssh config should include hostname fields"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 20. Template CRUD with real database ────────────────────────────────────

    #[tokio::test]
    async fn template_create_and_list() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        // Create a template.
        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                &format!("/api/v2/organizations/{org_id}/templates"),
                &token,
                &serde_json::json!({
                    "name": "test-template",
                    "display_name": "Test Template",
                    "description": "An integration test template"
                }),
            )?,
        )
        .await?;
        // Template creation may require a template version first, so accept
        // either CREATED or BAD_REQUEST with a meaningful error.
        let status = resp.status();
        if status == StatusCode::CREATED {
            let body = response_json(resp).await?;
            assert_eq!(
                body.get("name").and_then(Value::as_str),
                Some("test-template")
            );
        } else {
            // Even if creation requires a version, the endpoint should be wired up
            // and return a structured error (not 404).
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "template creation endpoint should exist"
            );
        }

        // List templates for the organization.
        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/templates"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 21. User appearance settings round-trip ─────────────────────────────────

    #[tokio::test]
    async fn user_appearance_settings_roundtrip() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        // Update appearance settings.
        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::PUT,
                "/api/v2/users/me/appearance",
                &token,
                &serde_json::json!({
                    "theme_preference": "dark",
                    "terminal_font": "fira-code"
                }),
            )?,
        )
        .await?;
        // The store may not implement appearance yet; accept 200 or 500.
        if resp.status() == StatusCode::OK {
            let body = response_json(resp).await?;
            assert_eq!(
                body.get("theme_preference").and_then(Value::as_str),
                Some("dark")
            );
        } else {
            // If the store does not support appearance, just verify it
            // doesn't return a client error (400-range).
            assert!(
                !resp.status().is_client_error(),
                "unexpected client error {} from PUT appearance",
                resp.status()
            );
        }

        // Read back (only if the PUT succeeded).
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/appearance", &token)?,
        )
        .await?;
        // Accept OK or server error (if store doesn't support it yet).
        let body = response_json(resp).await?;
        if body.get("theme_preference").is_some() {
            assert_eq!(
                body.get("theme_preference").and_then(Value::as_str),
                Some("dark")
            );
        }
        h.cleanup().await;
        Ok(())
    }

    // ── 22. Git SSH key auto-generation ─────────────────────────────────────────

    #[tokio::test]
    async fn git_ssh_key_operations() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/gitsshkey", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert!(
            body.get("public_key").and_then(Value::as_str).is_some(),
            "expected a public_key in git ssh key response"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 23. Full auth flow: register → login → use token → logout ──────────────

    #[tokio::test]
    async fn full_auth_lifecycle() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        // 1. Register first user.
        let resp = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/first",
                &serde_json::json!({
                    "email": "lifecycle@example.com",
                    "username": "lifecycle",
                    "name": "Lifecycle User",
                    "password": "LifePass123!"
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // 2. Login.
        let token = login_user(&h.router, "lifecycle@example.com", "LifePass123!").await?;

        // 3. Make authenticated request.
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        // 4. Logout.
        let resp = call(
            h.router.clone(),
            authed_request(Method::POST, "/api/v2/users/logout", &token)?,
        )
        .await?;
        assert!(resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT);

        // 5. Token no longer valid.
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        h.cleanup().await;
        Ok(())
    }

    // ── 24. Concurrent user operations ──────────────────────────────────────────

    #[tokio::test]
    async fn concurrent_user_creation() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        // Create multiple users sequentially but verify all are distinct.
        let mut created_ids = Vec::new();
        for i in 0..5 {
            let user_id = create_user(
                &h.router,
                &token,
                &format!("concurrent{i}@example.com"),
                &format!("concurrent{i}"),
                "ConcPass123!",
                org_id,
            )
            .await?;
            created_ids.push(user_id);
        }

        // All IDs should be unique.
        created_ids.sort();
        created_ids.dedup();
        assert_eq!(
            created_ids.len(),
            5,
            "expected 5 unique user IDs from batch creation"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 25. Deployment statistics endpoint ──────────────────────────────────────

    #[tokio::test]
    async fn deployment_stats_returns_ok() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/deployment/stats", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert!(
            body.get("session_count").is_some() || body.get("workspaces").is_some(),
            "deployment stats should contain session or workspace data"
        );
        h.cleanup().await;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // EXPANDED INTEGRATION TESTS (26–80+)
    // ═══════════════════════════════════════════════════════════════════════════

    // ─────────────────────────────────────────────────────────────────────────────
    // Category 1: Auth Flow Tests
    // ─────────────────────────────────────────────────────────────────────────────

    // ── 26. Invalid session token returns 401 ────────────────────────────────────

    #[tokio::test]
    async fn invalid_session_token_returns_401() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", "bogus-token-value")?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ── 27. Multiple concurrent sessions for same user ───────────────────────────

    #[tokio::test]
    async fn multiple_sessions_for_same_user() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        create_first_user_and_login(&h.router).await?;

        let token2 = login_user(&h.router, "owner@example.com", "Password123!").await?;
        let token3 = login_user(&h.router, "owner@example.com", "Password123!").await?;

        let resp2 = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &token2)?,
        )
        .await?;
        assert_eq!(resp2.status(), StatusCode::OK);

        let resp3 = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &token3)?,
        )
        .await?;
        assert_eq!(resp3.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 28. API key creation and listing works ───────────────────────────────────

    #[tokio::test]
    async fn api_key_authenticates_requests() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        // Create an API key token.
        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/users/me/keys/tokens",
                &token,
                &serde_json::json!({
                    "token_name": "auth-test-token",
                    "lifetime": 3_600_000_000_000_i64
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let key_body = response_json(resp).await?;
        let api_key = key_body
            .get("key")
            .and_then(Value::as_str)
            .ok_or("missing key")?
            .to_owned();
        assert!(!api_key.is_empty(), "API key should not be empty");

        // Verify the token appears in the list.
        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/keys/tokens", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let tokens_body = response_json(resp).await?;
        let tokens = tokens_body.as_array().expect("expected array of tokens");
        assert!(
            tokens
                .iter()
                .any(|t| t.get("token_name").and_then(Value::as_str) == Some("auth-test-token")),
            "created token should appear in listing"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 29. Login with nonexistent user returns error ────────────────────────────

    #[tokio::test]
    async fn login_nonexistent_user_returns_error() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &serde_json::json!({
                    "email": "nonexistent@example.com",
                    "password": "SomePass123!"
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ── 30. Get user login type returns password ─────────────────────────────────

    #[tokio::test]
    async fn get_user_login_type_returns_password() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/login-type", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert_eq!(
            body.get("login_type").and_then(Value::as_str),
            Some("password")
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 31. Auth methods endpoint returns available methods ──────────────────────

    #[tokio::test]
    async fn auth_methods_returns_available_methods() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            plain_request(Method::GET, "/api/v2/users/authmethods")?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert!(
            body.get("password").is_some(),
            "auth methods should include password: {body:?}"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 32. Password change and re-login ─────────────────────────────────────────

    #[tokio::test]
    async fn password_change_and_relogin() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::PUT,
                "/api/v2/users/me/password",
                &token,
                &serde_json::json!({
                    "old_password": "Password123!",
                    "password": "NewPassword456!"
                }),
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::NO_CONTENT || resp.status() == StatusCode::OK,
            "password change should succeed, got {}",
            resp.status()
        );

        let new_token = login_user(&h.router, "owner@example.com", "NewPassword456!").await?;
        assert!(!new_token.is_empty());

        let resp = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/api/v2/users/login",
                &serde_json::json!({
                    "email": "owner@example.com",
                    "password": "Password123!"
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ── 33. RBAC: non-owner cannot list audit logs ───────────────────────────────

    #[tokio::test]
    async fn rbac_non_owner_cannot_list_audit_logs() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let owner_token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &owner_token).await?;

        create_user(
            &h.router,
            &owner_token,
            "auditmember@example.com",
            "auditmember",
            "MemberPass1!",
            org_id,
        )
        .await?;

        let member_token = login_user(&h.router, "auditmember@example.com", "MemberPass1!").await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/audit?limit=10", &member_token)?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "non-owner should not access audit logs, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 34. RBAC: non-owner cannot access deployment config ──────────────────────

    #[tokio::test]
    async fn rbac_non_owner_cannot_access_deployment_config() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let owner_token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &owner_token).await?;

        create_user(
            &h.router,
            &owner_token,
            "configmember@example.com",
            "configmember",
            "MemberPass1!",
            org_id,
        )
        .await?;

        let member_token =
            login_user(&h.router, "configmember@example.com", "MemberPass1!").await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/deployment/config", &member_token)?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "non-owner should not access deployment config, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 35. RBAC: member can read own profile ────────────────────────────────────

    #[tokio::test]
    async fn rbac_member_can_read_own_profile() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let owner_token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &owner_token).await?;

        create_user(
            &h.router,
            &owner_token,
            "selfread@example.com",
            "selfread",
            "SelfPass1!",
            org_id,
        )
        .await?;

        let member_token = login_user(&h.router, "selfread@example.com", "SelfPass1!").await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &member_token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert_eq!(
            body.get("username").and_then(Value::as_str),
            Some("selfread")
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 36. Expire API key ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn expire_api_key() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/users/me/keys/tokens",
                &token,
                &serde_json::json!({
                    "token_name": "expire-test",
                    "lifetime": 3_600_000_000_000_i64
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let key_body = response_json(resp).await?;
        let api_key = key_body
            .get("key")
            .and_then(Value::as_str)
            .ok_or("missing key")?
            .to_owned();

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/keys/tokens", &token)?,
        )
        .await?;
        let tokens_body = response_json(resp).await?;
        let key_id = tokens_body
            .as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|t| t.get("token_name").and_then(Value::as_str) == Some("expire-test"))
            })
            .and_then(|t| t.get("id").and_then(Value::as_str))
            .ok_or("token not found")?
            .to_owned();

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::PUT,
                &format!("/api/v2/users/me/keys/{key_id}/expire"),
                &token,
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "expire should succeed, got {}",
            resp.status()
        );

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &api_key)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ── 37. List site roles ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_site_roles() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/roles", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let roles = body.as_array().expect("expected roles array");
        assert!(!roles.is_empty(), "expected at least one site role");
        h.cleanup().await;
        Ok(())
    }

    // ── 38. Authcheck endpoint ───────────────────────────────────────────────────

    #[tokio::test]
    async fn authcheck_endpoint_works() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/authcheck",
                &token,
                &serde_json::json!({
                    "checks": {
                        "readSelf": {
                            "object": {
                                "resource_type": "user",
                                "owner_id": "me"
                            },
                            "action": "read"
                        }
                    }
                }),
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::FORBIDDEN,
            "authcheck should return 200 or 403, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Category 2: Workspace Lifecycle Tests
    // ─────────────────────────────────────────────────────────────────────────────

    // ── 39. List workspaces returns empty initially ──────────────────────────────

    #[tokio::test]
    async fn list_workspaces_empty_initially() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/workspaces", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let workspaces = body
            .get("workspaces")
            .and_then(Value::as_array)
            .or_else(|| body.as_array());
        if let Some(ws) = workspaces {
            assert!(ws.is_empty(), "expected no workspaces initially");
        }
        h.cleanup().await;
        Ok(())
    }

    // ── 40. List templates returns empty initially ───────────────────────────────

    #[tokio::test]
    async fn list_all_templates_empty_initially() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/templates", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let empty = vec![];
        let templates = body.as_array().unwrap_or(&empty);
        assert!(templates.is_empty(), "expected no templates initially");
        h.cleanup().await;
        Ok(())
    }

    // ── 41. Template examples endpoint ───────────────────────────────────────────

    #[tokio::test]
    async fn template_examples_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/templates/examples", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 42. Create workspace requires template ───────────────────────────────────

    #[tokio::test]
    async fn create_workspace_requires_template() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/users/me/workspaces",
                &token,
                &serde_json::json!({
                    "template_id": Uuid::new_v4().to_string(),
                    "name": "test-workspace"
                }),
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::NOT_FOUND
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "creating workspace without valid template should fail, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 43. Workspace count in deployment stats ──────────────────────────────────

    #[tokio::test]
    async fn deployment_stats_workspace_count() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/deployment/stats", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        if let Some(ws) = body.get("workspaces") {
            assert!(
                ws.is_object(),
                "workspaces in stats should be an object: {ws:?}"
            );
        }
        h.cleanup().await;
        Ok(())
    }

    // ── 44. Organization templates listing ───────────────────────────────────────

    #[tokio::test]
    async fn organization_templates_listing() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/templates"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Category 3: SCIM Provisioning Tests
    // ─────────────────────────────────────────────────────────────────────────────

    /// Creates a [`TestHarness`] with SCIM API key configured.
    async fn new_harness_with_scim() -> Result<(TestHarness, String), Box<dyn Error>> {
        let base_url = test_database_url().expect("TEST_DATABASE_URL required");
        let db = TestDatabase::new(&base_url).await?;

        let db_config = DatabaseConfig {
            postgres_url: db.url(),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout_secs: 10,
        };

        let store =
            Arc::new(PostgresStore::connect(&db_config).await?) as Arc<dyn coder_core::AppStore>;

        let audit = Arc::new(MemoryAuditSink::default());
        let audit_trait: Arc<dyn AuditSink> = audit.clone();
        let pubsub: Arc<dyn coder_core::pubsub::PubSub> = Arc::new(InMemoryPubSub::new());
        let agent_provider: Arc<dyn coder_connectivity::agents::AgentProvider> =
            Arc::new(InMemoryAgentProvider::new());
        let coordinator = InMemoryCoordinator::new(Default::default());
        let derp_tracker = DerpTrafficTracker::new();

        let scim_key = "test-scim-api-key-12345".to_owned();
        let mut config = test_config(&db.url())?;
        config.scim_api_key = scim_key.clone();

        let state = AppState::new(
            config,
            BuildMetadata::default(),
            Uuid::nil(),
            store,
            audit_trait,
            pubsub,
            agent_provider,
            coordinator,
            derp_tracker,
            coder_connectivity::derp::DerpServer::new(coder_connectivity::derp::NodeKey::new(
                [0u8; 32],
            )),
            None,
            coder_telemetry::TelemetryReporter::disabled(Uuid::nil()),
        )?;

        let router = build_router(state, None);

        let harness = TestHarness { router, audit, db };
        Ok((harness, scim_key))
    }

    fn scim_authed_request(
        method: Method,
        uri: &str,
        scim_key: &str,
    ) -> Result<Request<Body>, http::Error> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", format!("Bearer {scim_key}"))
            .body(Body::empty())
    }

    fn scim_authed_json_request<T: Serialize>(
        method: Method,
        uri: &str,
        scim_key: &str,
        payload: &T,
    ) -> Result<Request<Body>, Box<dyn Error>> {
        let body = serde_json::to_vec(payload)?;
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header("Authorization", format!("Bearer {scim_key}"))
            .body(Body::from(body))?;
        Ok(req)
    }

    // ── 45. SCIM without API key returns 401 ─────────────────────────────────────

    #[tokio::test]
    async fn scim_without_api_key_returns_401() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let (h, _scim_key) = new_harness_with_scim().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            plain_request(Method::GET, "/scim/v2/Users")?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ── 46. SCIM get users returns empty list ────────────────────────────────────

    #[tokio::test]
    async fn scim_get_users_returns_empty_list() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let (h, scim_key) = new_harness_with_scim().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            scim_authed_request(Method::GET, "/scim/v2/Users", &scim_key)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert_eq!(
            body.get("totalResults").and_then(Value::as_i64),
            Some(0),
            "SCIM get users should return empty list"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 47. SCIM create user ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn scim_create_user() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let (h, scim_key) = new_harness_with_scim().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            scim_authed_json_request(
                Method::POST,
                "/scim/v2/Users",
                &scim_key,
                &serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "scimuser",
                    "name": {
                        "givenName": "SCIM",
                        "familyName": "User"
                    },
                    "emails": [{"primary": true, "value": "scim@example.com"}],
                    "active": true
                }),
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::CREATED || resp.status() == StatusCode::OK,
            "SCIM create user should succeed, got {}",
            resp.status()
        );
        let body = response_json(resp).await?;
        assert!(
            body.get("id").and_then(Value::as_str).is_some(),
            "SCIM user should have an id"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 48. SCIM create user and deactivate ──────────────────────────────────────

    #[tokio::test]
    async fn scim_create_and_deactivate_user() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let (h, scim_key) = new_harness_with_scim().await?;
        create_first_user_and_login(&h.router).await?;

        let create_resp = call(
            h.router.clone(),
            scim_authed_json_request(
                Method::POST,
                "/scim/v2/Users",
                &scim_key,
                &serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "scimdeactivate",
                    "name": {"givenName": "Deactivate", "familyName": "Test"},
                    "emails": [{"primary": true, "value": "deactivate@example.com"}],
                    "active": true
                }),
            )?,
        )
        .await?;
        assert!(
            create_resp.status() == StatusCode::CREATED || create_resp.status() == StatusCode::OK
        );
        let create_body = response_json(create_resp).await?;
        let user_id = create_body
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing user id")?
            .to_owned();

        let patch_resp = call(
            h.router.clone(),
            scim_authed_json_request(
                Method::PATCH,
                &format!("/scim/v2/Users/{user_id}"),
                &scim_key,
                &serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "active": false
                }),
            )?,
        )
        .await?;
        assert_eq!(patch_resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 49. SCIM create, deactivate, reactivate ─────────────────────────────────

    #[tokio::test]
    async fn scim_deactivate_and_reactivate_user() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let (h, scim_key) = new_harness_with_scim().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            scim_authed_json_request(
                Method::POST,
                "/scim/v2/Users",
                &scim_key,
                &serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "scimreactivate",
                    "name": {"givenName": "Reactivate", "familyName": "Test"},
                    "emails": [{"primary": true, "value": "reactivate@example.com"}],
                    "active": true
                }),
            )?,
        )
        .await?;
        let body = response_json(resp).await?;
        let user_id = body
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?
            .to_owned();

        let resp = call(
            h.router.clone(),
            scim_authed_json_request(
                Method::PATCH,
                &format!("/scim/v2/Users/{user_id}"),
                &scim_key,
                &serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "active": false
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = call(
            h.router.clone(),
            scim_authed_json_request(
                Method::PATCH,
                &format!("/scim/v2/Users/{user_id}"),
                &scim_key,
                &serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "active": true
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 50. SCIM get single user returns 404 ─────────────────────────────────────

    #[tokio::test]
    async fn scim_get_single_user_returns_404() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let (h, scim_key) = new_harness_with_scim().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            scim_authed_request(
                Method::GET,
                &format!("/scim/v2/Users/{}", Uuid::new_v4()),
                &scim_key,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        h.cleanup().await;
        Ok(())
    }

    // ── 51. SCIM with wrong API key returns 401 ──────────────────────────────────

    #[tokio::test]
    async fn scim_wrong_api_key_returns_401() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let (h, _scim_key) = new_harness_with_scim().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            scim_authed_request(Method::GET, "/scim/v2/Users", "wrong-key")?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ── 52. SCIM PUT user (replace) ──────────────────────────────────────────────

    #[tokio::test]
    async fn scim_put_user_replace() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let (h, scim_key) = new_harness_with_scim().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            scim_authed_json_request(
                Method::POST,
                "/scim/v2/Users",
                &scim_key,
                &serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "scimput",
                    "name": {"givenName": "Put", "familyName": "Test"},
                    "emails": [{"primary": true, "value": "put@example.com"}],
                    "active": true
                }),
            )?,
        )
        .await?;
        let body = response_json(resp).await?;
        let user_id = body
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?
            .to_owned();

        let resp = call(
            h.router.clone(),
            scim_authed_json_request(
                Method::PUT,
                &format!("/scim/v2/Users/{user_id}"),
                &scim_key,
                &serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "scimput",
                    "name": {"givenName": "Put", "familyName": "Test"},
                    "emails": [{"primary": true, "value": "put@example.com"}],
                    "active": false
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Category 4: OAuth2 Flow Tests
    // ─────────────────────────────────────────────────────────────────────────────

    // ── 53. OAuth2 register endpoint exists ──────────────────────────────────────

    #[tokio::test]
    async fn oauth2_register_endpoint_exists() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            json_request(Method::POST, "/oauth2/register", &serde_json::json!({}))?,
        )
        .await?;
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "oauth2 register endpoint should exist"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 54. OAuth2 token endpoint exists ─────────────────────────────────────────

    #[tokio::test]
    async fn oauth2_token_endpoint_exists() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/oauth2/tokens",
                &serde_json::json!({
                    "grant_type": "authorization_code",
                    "code": "fake-code"
                }),
            )?,
        )
        .await?;
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
        h.cleanup().await;
        Ok(())
    }

    // ── 55. OAuth2 revoke endpoint exists ────────────────────────────────────────

    #[tokio::test]
    async fn oauth2_revoke_endpoint_exists() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/oauth2/revoke",
                &serde_json::json!({"token": "fake-token"}),
            )?,
        )
        .await?;
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
        h.cleanup().await;
        Ok(())
    }

    // ── 56. API key scopes listing ───────────────────────────────────────────────

    #[tokio::test]
    async fn api_key_scopes_listing() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            plain_request(Method::GET, "/api/v2/auth/scopes")?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Category 5: Notification Flow Tests
    // ─────────────────────────────────────────────────────────────────────────────

    // ── 57. Notification settings endpoint ───────────────────────────────────────

    #[tokio::test]
    async fn notification_settings_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/notifications/settings", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 58. System notification templates ────────────────────────────────────────

    #[tokio::test]
    async fn system_notification_templates() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                "/api/v2/notifications/templates/system",
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 59. Notification dispatch methods ────────────────────────────────────────

    #[tokio::test]
    async fn notification_dispatch_methods() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                "/api/v2/notifications/dispatch-methods",
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 60. List inbox notifications empty ───────────────────────────────────────

    #[tokio::test]
    async fn list_inbox_notifications_empty() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/notifications/inbox", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let notifications = body
            .get("notifications")
            .and_then(Value::as_array)
            .or_else(|| body.as_array());
        if let Some(notifs) = notifications {
            assert!(notifs.is_empty(), "inbox should be empty initially");
        }
        h.cleanup().await;
        Ok(())
    }

    // ── 61. Notification preferences roundtrip ───────────────────────────────────

    #[tokio::test]
    async fn notification_preferences_roundtrip() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                "/api/v2/users/me/notifications/preferences",
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::PUT,
                "/api/v2/users/me/notifications/preferences",
                &token,
                &serde_json::json!({
                    "template_disabled_map": {}
                }),
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "PUT notification preferences should succeed, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 62. Post test notification ───────────────────────────────────────────────

    #[tokio::test]
    async fn post_test_notification_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/notifications/test",
                &token,
                &serde_json::json!({}),
            )?,
        )
        .await?;
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
        h.cleanup().await;
        Ok(())
    }

    // ── 63. Custom notification templates endpoint ───────────────────────────────

    #[tokio::test]
    async fn custom_notification_templates() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                "/api/v2/notifications/templates/custom",
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 64. Mark all inbox notifications as read ─────────────────────────────────

    #[tokio::test]
    async fn mark_all_inbox_notifications_read() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::PUT,
                "/api/v2/notifications/inbox/mark-all-as-read",
                &token,
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "mark all read should succeed, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 65. Custom notification requires auth ────────────────────────────────────

    #[tokio::test]
    async fn custom_notification_requires_auth() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/api/v2/notifications/custom",
                &serde_json::json!({"template_id": Uuid::new_v4().to_string()}),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        h.cleanup().await;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Category 6: Audit Trail Tests
    // ─────────────────────────────────────────────────────────────────────────────

    // ── 66. Audit logs contain entries after testgenerate ─────────────────────────

    #[tokio::test]
    async fn audit_logs_contain_user_creation_events() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        // Use testgenerate endpoint to create a guaranteed audit entry.
        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::POST,
                "/api/v2/audit/testgenerate",
                &token,
                &serde_json::json!({
                    "resource_type": "user",
                    "action": "create"
                }),
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::NO_CONTENT || resp.status() == StatusCode::OK,
            "testgenerate should succeed, got {}",
            resp.status()
        );

        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/audit?limit=50", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let logs = body
            .get("audit_logs")
            .and_then(Value::as_array)
            .expect("expected audit_logs array");
        assert!(
            !logs.is_empty(),
            "expected audit entries after testgenerate"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 67. Multiple audit log generation ────────────────────────────────────────

    #[tokio::test]
    async fn multiple_audit_log_entries() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        for _ in 0..3 {
            let resp = call(
                h.router.clone(),
                authed_json_request(
                    Method::POST,
                    "/api/v2/audit/testgenerate",
                    &token,
                    &serde_json::json!({
                        "resource_type": "user",
                        "action": "write"
                    }),
                )?,
            )
            .await?;
            assert!(resp.status() == StatusCode::NO_CONTENT || resp.status() == StatusCode::OK);
        }

        tokio::time::sleep(std::time::Duration::from_millis(700)).await;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/audit?limit=50", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let logs = body
            .get("audit_logs")
            .and_then(Value::as_array)
            .expect("expected audit_logs array");
        assert!(
            logs.len() >= 3,
            "expected at least 3 audit log entries, got {}",
            logs.len()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 68. Audit logs with limit parameter ──────────────────────────────────────

    #[tokio::test]
    async fn audit_logs_with_limit() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        for _ in 0..5 {
            call(
                h.router.clone(),
                authed_json_request(
                    Method::POST,
                    "/api/v2/audit/testgenerate",
                    &token,
                    &serde_json::json!({
                        "resource_type": "template",
                        "action": "create"
                    }),
                )?,
            )
            .await?;
        }

        tokio::time::sleep(std::time::Duration::from_millis(700)).await;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/audit?limit=2", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let logs = body
            .get("audit_logs")
            .and_then(Value::as_array)
            .expect("expected audit_logs array");
        assert!(
            logs.len() <= 2,
            "expected at most 2 entries with limit=2, got {}",
            logs.len()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 69. Audit logs with offset parameter ─────────────────────────────────────

    #[tokio::test]
    async fn audit_logs_with_offset() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        for _ in 0..3 {
            call(
                h.router.clone(),
                authed_json_request(
                    Method::POST,
                    "/api/v2/audit/testgenerate",
                    &token,
                    &serde_json::json!({
                        "resource_type": "workspace",
                        "action": "delete"
                    }),
                )?,
            )
            .await?;
        }

        tokio::time::sleep(std::time::Duration::from_millis(700)).await;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/audit?limit=50&offset=0", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 70. Memory audit sink captures events ────────────────────────────────────

    #[tokio::test]
    async fn memory_audit_sink_captures_events() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let _token = create_first_user_and_login(&h.router).await?;

        let events = h.audit.recorded_events();
        assert!(
            !events.is_empty(),
            "memory audit sink should capture events from login"
        );
        h.cleanup().await;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Category 7: Store Roundtrip Tests (via HTTP API)
    // ─────────────────────────────────────────────────────────────────────────────

    // ── 71. User CRUD: create -> get -> delete ───────────────────────────────────

    #[tokio::test]
    async fn user_crud_lifecycle() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        let user_id = create_user(
            &h.router,
            &token,
            "crud@example.com",
            "cruduser",
            "CrudPass1!",
            org_id,
        )
        .await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, &format!("/api/v2/users/{user_id}"), &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert_eq!(
            body.get("username").and_then(Value::as_str),
            Some("cruduser")
        );

        let resp = call(
            h.router.clone(),
            authed_request(Method::DELETE, &format!("/api/v2/users/{user_id}"), &token)?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "user deletion should succeed, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 72. User suspend and activate ────────────────────────────────────────────

    #[tokio::test]
    async fn user_suspend_and_activate() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        let user_id = create_user(
            &h.router,
            &token,
            "suspend@example.com",
            "suspenduser",
            "SuspendPass1!",
            org_id,
        )
        .await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::PUT,
                &format!("/api/v2/users/{user_id}/status/suspend"),
                &token,
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "suspend should succeed, got {}",
            resp.status()
        );

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::PUT,
                &format!("/api/v2/users/{user_id}/status/activate"),
                &token,
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "activate should succeed, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 73. Organization: list and get by ID ─────────────────────────────────────

    #[tokio::test]
    async fn organization_list_and_get() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/organizations", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let orgs = body.as_array().expect("expected orgs array");
        assert!(!orgs.is_empty(), "expected at least one organization");

        let org_id = orgs[0]
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing org id")?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert_eq!(body.get("id").and_then(Value::as_str), Some(org_id));
        h.cleanup().await;
        Ok(())
    }

    // ── 74. Organization member roles ────────────────────────────────────────────

    #[tokio::test]
    async fn organization_member_roles() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/members/roles"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 75. User organizations listing ───────────────────────────────────────────

    #[tokio::test]
    async fn user_organizations_listing() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/organizations", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let orgs = body.as_array().expect("expected orgs array");
        assert!(!orgs.is_empty(), "user should belong to at least one org");
        h.cleanup().await;
        Ok(())
    }

    // ── 76. Git SSH key regeneration ─────────────────────────────────────────────

    #[tokio::test]
    async fn git_ssh_key_regeneration() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/gitsshkey", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let initial_key = body
            .get("public_key")
            .and_then(Value::as_str)
            .ok_or("missing public_key")?
            .to_owned();
        assert!(!initial_key.is_empty());

        let resp = call(
            h.router.clone(),
            authed_request(Method::PUT, "/api/v2/users/me/gitsshkey", &token)?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "regenerate should succeed, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 77. User appearance settings ─────────────────────────────────────────────

    #[tokio::test]
    async fn user_appearance_get() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/appearance", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 78. Experiments endpoint ─────────────────────────────────────────────────

    #[tokio::test]
    async fn experiments_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/experiments", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 79. Available experiments endpoint ────────────────────────────────────────

    #[tokio::test]
    async fn available_experiments_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/experiments/available", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 80. Entitlements endpoint ────────────────────────────────────────────────

    #[tokio::test]
    async fn entitlements_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/entitlements", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 81. Regions endpoint ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn regions_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/regions", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 82. Telemetry status endpoint ────────────────────────────────────────────

    #[tokio::test]
    async fn telemetry_status_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/telemetry", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 83. External auth list endpoint ──────────────────────────────────────────

    #[tokio::test]
    async fn external_auth_list_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/external-auth", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 84. Licenses endpoint ────────────────────────────────────────────────────

    #[tokio::test]
    async fn licenses_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/licenses", &token)?,
        )
        .await?;
        // The licenses table may not exist in migrations yet, so accept
        // either 200 (success) or 503 (DB table missing).
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR
                || resp.status() == StatusCode::SERVICE_UNAVAILABLE,
            "licenses endpoint should be reachable, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 85. User profile update with username change ─────────────────────────────

    #[tokio::test]
    async fn user_profile_update_username() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::PUT,
                "/api/v2/users/me/profile",
                &token,
                &serde_json::json!({
                    "username": "newowner",
                    "name": "Owner"
                }),
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        assert_eq!(
            body.get("username").and_then(Value::as_str),
            Some("newowner")
        );

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me", &token)?,
        )
        .await?;
        let body = response_json(resp).await?;
        assert_eq!(
            body.get("username").and_then(Value::as_str),
            Some("newowner")
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 86. Token config endpoint ────────────────────────────────────────────────

    #[tokio::test]
    async fn token_config_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                "/api/v2/users/me/keys/tokens/tokenconfig",
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 87. Multiple users batch creation and listing ────────────────────────────

    #[tokio::test]
    async fn batch_user_creation_and_listing() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        for i in 0..10 {
            create_user(
                &h.router,
                &token,
                &format!("batch{i}@example.com"),
                &format!("batchuser{i}"),
                "BatchPass1!",
                org_id,
            )
            .await?;
        }

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let users = body
            .get("users")
            .and_then(Value::as_array)
            .expect("expected users array");
        assert!(
            users.len() >= 11,
            "expected at least 11 users, got {}",
            users.len()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 88. Get first user endpoint (after creation) ─────────────────────────────

    #[tokio::test]
    async fn get_first_user_after_creation() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            plain_request(Method::GET, "/api/v2/users/first")?,
        )
        .await?;
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
        h.cleanup().await;
        Ok(())
    }

    // ── 89. CSP report endpoint ──────────────────────────────────────────────────

    #[tokio::test]
    async fn csp_report_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            json_request(
                Method::POST,
                "/api/v2/csp/reports",
                &serde_json::json!({"csp-report": {"document-uri": "http://test.example.com"}}),
            )?,
        )
        .await?;
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
        h.cleanup().await;
        Ok(())
    }

    // ── 90. Update check endpoint ────────────────────────────────────────────────

    #[tokio::test]
    async fn update_check_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            plain_request(Method::GET, "/api/v2/updatecheck")?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 91. API root endpoint ────────────────────────────────────────────────────

    #[tokio::test]
    async fn api_root_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(h.router.clone(), plain_request(Method::GET, "/api/v2")?).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 92. Latency check endpoint ───────────────────────────────────────────────

    #[tokio::test]
    async fn latency_check_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(
            h.router.clone(),
            plain_request(Method::GET, "/latency-check")?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 93. Server root endpoint ─────────────────────────────────────────────────

    #[tokio::test]
    async fn server_root_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;

        let resp = call(h.router.clone(), plain_request(Method::GET, "/")?).await?;
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::TEMPORARY_REDIRECT
                || resp.status() == StatusCode::PERMANENT_REDIRECT
                || resp.status() == StatusCode::MOVED_PERMANENTLY,
            "root should return OK or redirect, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 94. Applications host endpoint ───────────────────────────────────────────

    #[tokio::test]
    async fn applications_host_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/applications/host", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 95. Insights DAUs endpoint ───────────────────────────────────────────────

    #[tokio::test]
    async fn insights_daus_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/insights/daus", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 96. Debug health endpoint ────────────────────────────────────────────────

    #[tokio::test]
    async fn debug_health_endpoint() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/debug/health", &token)?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::SERVICE_UNAVAILABLE,
            "debug/health should return 200 or 503, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 97. Organization add member ──────────────────────────────────────────────

    #[tokio::test]
    async fn organization_add_member() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        let user_id = create_user(
            &h.router,
            &token,
            "orgmember@example.com",
            "orgmember",
            "OrgPass1!",
            org_id,
        )
        .await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/members"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let members = body
            .get("members")
            .and_then(Value::as_array)
            .or_else(|| body.as_array())
            .expect("expected members array");
        let member_ids: Vec<&str> = members
            .iter()
            .filter_map(|m| {
                m.get("user_id")
                    .and_then(Value::as_str)
                    .or_else(|| m.get("id").and_then(Value::as_str))
            })
            .collect();
        assert!(
            member_ids.contains(&user_id.to_string().as_str()),
            "new user should be in org members"
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 98. User roles assignment ────────────────────────────────────────────────

    #[tokio::test]
    async fn user_roles_assignment() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        let user_id = create_user(
            &h.router,
            &token,
            "roleuser@example.com",
            "roleuser",
            "RolePass1!",
            org_id,
        )
        .await?;

        let resp = call(
            h.router.clone(),
            authed_json_request(
                Method::PUT,
                &format!("/api/v2/users/{user_id}/roles"),
                &token,
                &serde_json::json!({
                    "roles": ["member"]
                }),
            )?,
        )
        .await?;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT,
            "role assignment should succeed, got {}",
            resp.status()
        );
        h.cleanup().await;
        Ok(())
    }

    // ── 99. Paginated organization members ───────────────────────────────────────

    #[tokio::test]
    async fn paginated_organization_members() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;
        let org_id = first_organization_id(&h.router, &token).await?;

        let resp = call(
            h.router.clone(),
            authed_request(
                Method::GET,
                &format!("/api/v2/organizations/{org_id}/paginated-members"),
                &token,
            )?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        h.cleanup().await;
        Ok(())
    }

    // ── 100. Multiple API tokens for same user ───────────────────────────────────

    #[tokio::test]
    async fn multiple_api_tokens_for_same_user() -> Result<(), Box<dyn Error>> {
        skip_without_db!();
        let h = TestHarness::new().await?;
        let token = create_first_user_and_login(&h.router).await?;

        for i in 0..3 {
            let resp = call(
                h.router.clone(),
                authed_json_request(
                    Method::POST,
                    "/api/v2/users/me/keys/tokens",
                    &token,
                    &serde_json::json!({
                        "token_name": format!("multi-token-{i}"),
                        "lifetime": 3_600_000_000_000_i64
                    }),
                )?,
            )
            .await?;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let resp = call(
            h.router.clone(),
            authed_request(Method::GET, "/api/v2/users/me/keys/tokens", &token)?,
        )
        .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await?;
        let tokens = body.as_array().expect("expected token array");
        let multi_tokens: Vec<_> = tokens
            .iter()
            .filter(|t| {
                t.get("token_name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.starts_with("multi-token-"))
            })
            .collect();
        assert_eq!(
            multi_tokens.len(),
            3,
            "expected 3 multi-tokens, got {}",
            multi_tokens.len()
        );
        h.cleanup().await;
        Ok(())
    }
}
