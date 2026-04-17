//! Periodic GitHub release update checker.
//!
//! Ports `coder/coderd/updatecheck/updatecheck.go` and the `/updatecheck`
//! response path from `coder/coderd/updatecheck.go`. The checker queries the
//! GitHub "latest release" endpoint on a fixed interval and caches the last
//! known-good result in memory. The HTTP handler reads from that cache so
//! every request is an O(1) lookup instead of a network hit.
//!
//! Failure modes (network, non-2xx, parse error) are absorbed: callers
//! receive the last successful result, or `None` until the first refresh
//! succeeds. In that "no cache yet" state the `/updatecheck` handler falls
//! back to reporting the current running version as up to date, matching
//! the Go behavior when the updater is disabled or has not yet run.

use std::{sync::Arc, time::Duration};

use semver::Version;
use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Default URL used to fetch the latest Coder release from GitHub.
///
/// Matches `defaultURL` in `coder/coderd/updatecheck/updatecheck.go`.
pub const DEFAULT_UPDATE_CHECK_URL: &str =
    "https://api.github.com/repos/coder/coder/releases/latest";

/// Default poll interval (24h), mirroring the Go reference.
pub const DEFAULT_UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default upstream timeout, mirroring the Go reference (30s).
pub const DEFAULT_UPDATE_CHECK_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors surfaced while fetching a release.
///
/// All variants are treated as "keep last known good" by the checker's
/// background loop; they are only surfaced directly for tests that want to
/// assert on specific failure shapes.
#[derive(Debug, Error)]
pub enum UpdateCheckError {
    /// The upstream HTTP call failed (network, TLS, DNS, …).
    #[error("update check request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// The upstream responded with a non-2xx status code.
    #[error("update check returned status {status}")]
    UpstreamStatus {
        /// HTTP status code returned by the upstream.
        status: u16,
    },
    /// Upstream responded successfully but the body could not be decoded.
    #[error("update check response decode failed: {0}")]
    Decode(String),
}

/// A cached latest-release record.
///
/// Mirrors the Go `updatecheck.Result` struct but uses `OffsetDateTime` for
/// timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateCheckerResult {
    /// Timestamp at which this record was produced.
    pub checked_at: OffsetDateTime,
    /// Semantic version string from the GitHub release (e.g. `v2.32.0`).
    pub version: String,
    /// HTML URL to the release page on GitHub.
    pub url: String,
}

/// Options controlling the update checker.
#[derive(Clone, Debug)]
pub struct UpdateCheckerOptions {
    /// URL to query for the latest release. Defaults to
    /// [`DEFAULT_UPDATE_CHECK_URL`].
    pub url: String,
    /// Interval between background refreshes.
    pub interval: Duration,
    /// Timeout applied to each upstream request.
    pub timeout: Duration,
}

impl Default for UpdateCheckerOptions {
    fn default() -> Self {
        Self {
            url: DEFAULT_UPDATE_CHECK_URL.to_owned(),
            interval: DEFAULT_UPDATE_CHECK_INTERVAL,
            timeout: DEFAULT_UPDATE_CHECK_TIMEOUT,
        }
    }
}

/// The subset of the GitHub release payload we care about.
#[derive(Debug, Deserialize)]
struct GithubRelease {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
}

/// Background-refreshed cache of the latest Coder release.
///
/// Construct via [`UpdateChecker::new`] (does not start polling) and kick off
/// the background loop with [`UpdateChecker::spawn`]. Tests and other
/// callers that do not want to poll can call [`UpdateChecker::refresh_now`]
/// directly or pre-populate the cache with [`UpdateChecker::set_cached`].
///
/// The background loop respects a [`CancellationToken`] so graceful
/// shutdown can stop polling before the tokio runtime is dropped. This
/// matches the pattern used by the notification dispatcher, autobuild
/// executor, and the other worker services in `apps/coderd/src/main.rs`.
pub struct UpdateChecker {
    client: reqwest::Client,
    options: UpdateCheckerOptions,
    cached: RwLock<Option<UpdateCheckerResult>>,
    cancel: CancellationToken,
}

/// Handle returned by [`UpdateChecker::spawn`] so the graceful-shutdown
/// coordinator can cancel the background loop and await its completion.
pub struct UpdateCheckerHandle {
    checker: Arc<UpdateChecker>,
    join: tokio::task::JoinHandle<()>,
}

impl UpdateCheckerHandle {
    /// Returns a cloneable handle to the underlying checker for wiring
    /// into [`AppState`](crate::AppState).
    #[must_use]
    pub fn checker(&self) -> Arc<UpdateChecker> {
        Arc::clone(&self.checker)
    }

    /// Cancels the background loop and awaits the task.
    ///
    /// Idempotent: cancelling an already-cancelled checker is a no-op.
    pub async fn shutdown(self) {
        self.checker.cancel.cancel();
        if let Err(error) = self.join.await {
            warn!(error = %error, "update check task panicked during shutdown");
        }
    }
}

impl UpdateChecker {
    /// Builds a new checker with the supplied HTTP client and options.
    #[must_use]
    pub fn new(client: reqwest::Client, options: UpdateCheckerOptions) -> Self {
        Self::with_cancel(client, options, CancellationToken::new())
    }

    /// Builds a new checker using a caller-provided cancellation token.
    ///
    /// Prefer this when the caller already owns a token registered with
    /// the shutdown coordinator. Calling [`Self::spawn`] on the resulting
    /// checker will exit the loop as soon as the token is cancelled.
    #[must_use]
    pub fn with_cancel(
        client: reqwest::Client,
        options: UpdateCheckerOptions,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            client,
            options,
            cached: RwLock::new(None),
            cancel,
        }
    }

    /// Returns a clone of the cancellation token that stops the background
    /// loop.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Spawns the background refresh loop and returns a handle that can
    /// cancel it and await completion.
    ///
    /// The first refresh is triggered immediately so the cache warms up
    /// without waiting a full interval. Subsequent refreshes honour
    /// `options.interval`. Failures keep the last known good value; only
    /// the background task ever mutates the cache.
    #[must_use]
    pub fn spawn(self: Arc<Self>) -> UpdateCheckerHandle {
        let checker = Arc::clone(&self);
        let join = tokio::spawn(async move {
            checker.run_loop().await;
        });
        UpdateCheckerHandle {
            checker: self,
            join,
        }
    }

    /// Returns the last known good release, if any.
    pub async fn latest(&self) -> Option<UpdateCheckerResult> {
        self.cached.read().await.clone()
    }

    /// Replaces the cached result, primarily for tests.
    pub async fn set_cached(&self, result: UpdateCheckerResult) {
        *self.cached.write().await = Some(result);
    }

    /// Refreshes the cache immediately.
    ///
    /// On success, the cache is updated and the new result returned. On
    /// failure, the cache is left unchanged and the error is returned to
    /// the caller.
    pub async fn refresh_now(&self) -> Result<UpdateCheckerResult, UpdateCheckError> {
        let result = self.fetch().await?;
        *self.cached.write().await = Some(result.clone());
        Ok(result)
    }

    async fn fetch(&self) -> Result<UpdateCheckerResult, UpdateCheckError> {
        debug!(url = %self.options.url, "performing update check");
        let response = self
            .client
            .get(&self.options.url)
            .timeout(self.options.timeout)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::USER_AGENT, "coder-updatecheck/rust")
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(UpdateCheckError::UpstreamStatus {
                status: status.as_u16(),
            });
        }

        let body = response.text().await?;
        let release: GithubRelease =
            serde_json::from_str(&body).map_err(|err| UpdateCheckError::Decode(err.to_string()))?;

        Ok(UpdateCheckerResult {
            checked_at: OffsetDateTime::now_utc(),
            version: release.tag_name,
            url: release.html_url,
        })
    }

    async fn run_loop(self: Arc<Self>) {
        let cancel = self.cancel.clone();
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    debug!("update check loop cancelled; exiting");
                    return;
                }
                refresh = self.refresh_now() => {
                    match refresh {
                        Ok(result) => {
                            debug!(latest = %result.version, "update check refreshed cache");
                        }
                        Err(err) => {
                            warn!(error = %err, "update check refresh failed; keeping last known good");
                        }
                    }
                }
            }

            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    debug!("update check loop cancelled during sleep; exiting");
                    return;
                }
                () = tokio::time::sleep(self.options.interval) => {}
            }
        }
    }
}

/// Compares the running version against the latest advertised version and
/// returns `true` when the runtime is at or ahead of the upstream release.
///
/// Mirrors the Go update-check handler in `coder/coderd/updatecheck.go`,
/// which strips the `-devel+commit` suffix from the running version with
/// `strings.SplitN(v, "-", 2)[0]` before calling `semver.Compare`. We do
/// the same in [`normalize_version`] but extend the stripping to all
/// pre-release tags (`-rc.1`, `-beta.2`, …) so that RC / beta dev builds
/// are treated as current against the matching stable release. Note that
/// Go's `golang.org/x/mod/semver.Compare` itself still honours SemVer
/// pre-release precedence — it is the Coder handler's explicit pre-split
/// that flattens dev tags, not `semver.Compare`. If either side cannot
/// be parsed as SemVer after normalization, the comparison falls back to
/// a string equality check between the normalized forms so we never
/// wrongly flag a build as stale.
#[must_use]
pub fn is_current(running: &str, upstream: &str) -> bool {
    let running_norm = normalize_version(running);
    let upstream_norm = normalize_version(upstream);

    match (Version::parse(running_norm), Version::parse(upstream_norm)) {
        (Ok(running_v), Ok(upstream_v)) => running_v >= upstream_v,
        _ => running_norm == upstream_norm,
    }
}

/// Normalizes a raw version string into a candidate SemVer form.
///
/// Strips the leading `v` prefix and drops anything after the first `-`
/// (all pre-release suffixes — `-devel+commit`, `-rc.1`, `-beta.2`, …).
/// This mirrors Go's `semver.Compare` which ignores pre-release tags
/// when comparing, so a dev or RC build of `v2.50.0` is treated as
/// `2.50.0` for update-check purposes.
fn normalize_version(raw: &str) -> &str {
    let stripped = raw.split('-').next().unwrap_or(raw);
    stripped.strip_prefix('v').unwrap_or(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{error::Error, net::SocketAddr};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn sample_release_json() -> &'static str {
        r#"{"tag_name":"v2.50.0","html_url":"https://github.com/coder/coder/releases/tag/v2.50.0"}"#
    }

    fn checker_with(url: String) -> UpdateChecker {
        UpdateChecker::new(
            reqwest::Client::new(),
            UpdateCheckerOptions {
                url,
                interval: Duration::from_secs(3600),
                timeout: Duration::from_secs(5),
            },
        )
    }

    /// Minimal HTTP responder: accepts a single connection and replies with
    /// the supplied raw body + status. Avoids adding a mock-server crate
    /// just for a handful of tests.
    async fn serve_once(
        body: &'static str,
        status_line: &'static str,
    ) -> Result<SocketAddr, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        Ok(addr)
    }

    #[test]
    fn is_current_handles_equal_newer_and_older() {
        assert!(is_current("v2.50.0", "v2.50.0"));
        assert!(is_current("v2.50.1", "v2.50.0"));
        assert!(!is_current("v2.49.0", "v2.50.0"));
    }

    #[test]
    fn is_current_strips_devel_suffix_like_go() {
        // Go's example: v0.12.9-devel+f7246386 vs v0.12.8 should be "current".
        assert!(is_current("v0.12.9-devel+f7246386", "v0.12.8"));
        // Dev build of the same minor is still current against stable.
        assert!(is_current("v2.50.0-devel+abcdef", "v2.50.0"));
    }

    #[test]
    fn is_current_falls_back_to_string_compare_on_unparseable() {
        assert!(is_current("nightly", "nightly"));
        assert!(!is_current("nightly", "v2.50.0"));
    }

    #[tokio::test]
    async fn latest_hits_cache_without_network() {
        // Bind to a guaranteed-unused URL — if the checker tried to reach it
        // the test would hang. `latest()` must not touch it.
        let checker = checker_with("http://127.0.0.1:1/unreachable".to_owned());
        let seeded = UpdateCheckerResult {
            checked_at: OffsetDateTime::now_utc(),
            version: "v1.2.3".to_owned(),
            url: "https://example.com/v1.2.3".to_owned(),
        };
        checker.set_cached(seeded.clone()).await;

        let observed = checker.latest().await;
        assert_eq!(observed, Some(seeded));
    }

    #[tokio::test]
    async fn refresh_now_populates_cache_on_success() -> Result<(), Box<dyn Error>> {
        let addr = serve_once(sample_release_json(), "200 OK").await?;
        let checker = checker_with(format!("http://{addr}"));

        let result = checker.refresh_now().await?;
        assert_eq!(result.version, "v2.50.0");
        assert_eq!(
            result.url,
            "https://github.com/coder/coder/releases/tag/v2.50.0"
        );

        let cached = checker.latest().await;
        assert_eq!(cached.as_ref().map(|r| r.version.as_str()), Some("v2.50.0"));
        Ok(())
    }

    #[tokio::test]
    async fn refresh_fallback_preserves_last_known_good_on_5xx() -> Result<(), Box<dyn Error>> {
        let addr = serve_once("internal error", "500 Internal Server Error").await?;
        let checker = checker_with(format!("http://{addr}"));

        // Seed a last known good value.
        let seeded = UpdateCheckerResult {
            checked_at: OffsetDateTime::now_utc(),
            version: "v2.49.0".to_owned(),
            url: "https://github.com/coder/coder/releases/tag/v2.49.0".to_owned(),
        };
        checker.set_cached(seeded.clone()).await;

        match checker.refresh_now().await {
            Err(UpdateCheckError::UpstreamStatus { status }) => assert_eq!(status, 500),
            Err(other) => return Err(format!("unexpected error variant: {other:?}").into()),
            Ok(_) => return Err("refresh should have failed on 500".into()),
        }

        // Cache is unchanged.
        let cached = checker.latest().await;
        assert_eq!(cached, Some(seeded));
        Ok(())
    }

    #[tokio::test]
    async fn refresh_surfaces_decode_error_on_malformed_body() -> Result<(), Box<dyn Error>> {
        let addr = serve_once("not-json", "200 OK").await?;
        let checker = checker_with(format!("http://{addr}"));
        match checker.refresh_now().await {
            Err(UpdateCheckError::Decode(_)) => Ok(()),
            Err(other) => Err(format!("unexpected error: {other:?}").into()),
            Ok(_) => Err("refresh should have failed on malformed JSON".into()),
        }
    }

    #[tokio::test]
    async fn run_loop_exits_on_cancellation() -> Result<(), Box<dyn Error>> {
        // Use an unreachable URL with a long interval so the task would
        // otherwise block forever — proving the cancellation token is the
        // only thing that lets it exit.
        let cancel = CancellationToken::new();
        let checker = Arc::new(UpdateChecker::with_cancel(
            reqwest::Client::new(),
            UpdateCheckerOptions {
                url: "http://127.0.0.1:1/unreachable".to_owned(),
                interval: Duration::from_secs(3600),
                timeout: Duration::from_millis(50),
            },
            cancel.clone(),
        ));
        let handle = checker.spawn();

        // Give the loop a moment to enter its first refresh/sleep cycle
        // before cancelling, so we cover both select! arms.
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();

        tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
            .await
            .map_err(|_| "update checker shutdown did not complete within 5s")?;
        Ok(())
    }

    #[test]
    fn is_current_fallback_uses_normalized_strings() {
        // Non-SemVer tags still fall back to string equality, but only
        // after stripping the leading `v`. `vnightly` and `nightly` now
        // compare equal because both normalize to `nightly`; previously
        // the verbatim string compare would have returned `false` here
        // and wrongly flagged the build as stale.
        assert!(is_current("vnightly", "nightly"));
        // The `v` prefix still matters when the remainder differs.
        assert!(!is_current("vnightly", "stable"));
    }
}
