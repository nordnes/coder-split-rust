//! Reconnecting-PTY session store.
//!
//! Keeps a per-`reconnect_id` ring buffer of PTY output so that a user whose
//! WebSocket drops can reconnect with the same `reconnect_id` and resume
//! their shell from where they left off.
//!
//! Go reference: `coder/coderd/workspaceagents.go`
//! (`workspaceAgentReconnectingPTY` + the in-server session map). The Rust
//! handler is `crates/coder-server/src/handlers/agents.rs`
//! (`get_workspace_agent_pty`), which previously treated every WebSocket as a
//! fresh stateless pubsub relay. See `docs/backend-gap-analysis-2026-04.md`
//! §B.4 / W2.4.
//!
//! # Design
//!
//! * Sessions are keyed on `reconnect_id` (a client-supplied UUID).
//! * Each session owns a bounded ring buffer of the last N bytes of output
//!   (default 256 KiB) plus a `tokio::sync::broadcast` fan-out that delivers
//!   live output to every attached client.
//! * When an agent disconnects, the session enters a short "grace window"
//!   (default 60s). During the grace window, reconnecting clients can still
//!   read scrollback, but no new output will arrive. After the grace window
//!   expires the session is removed.
//! * An idle session (no reader and no writer) is pruned after
//!   `idle_timeout` (default 1h).
//!
//! Only the client side of the WebSocket is affected. The agent side (PTY
//! output and stdin via pub/sub) is unchanged: output still arrives via
//! `workspace_agent_pty_output_channel` and stdin still publishes to
//! `workspace_agent_pty_input_channel`.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::{Mutex, RwLock, broadcast};
use uuid::Uuid;

/// Default size of a session's output ring buffer, in bytes.
pub const DEFAULT_BUFFER_BYTES: usize = 256 * 1024;

/// Default grace window kept open after the agent side drops.
pub const DEFAULT_AGENT_GRACE: Duration = Duration::from_secs(60);

/// Default idle timeout after which a fully detached session is pruned.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

/// Default capacity of the live broadcast fan-out channel.
const BROADCAST_CAPACITY: usize = 256;

/// Configurable lifetimes and sizes for [`ReconnectingPtyStore`].
#[derive(Clone, Copy, Debug)]
pub struct ReconnectingPtyOptions {
    /// Maximum number of bytes retained in the per-session scrollback ring.
    pub buffer_bytes: usize,
    /// Grace window kept open after the agent side drops, during which
    /// reconnecting clients can still read scrollback.
    pub agent_grace: Duration,
    /// Idle timeout after which a session with no reader and no writer is
    /// pruned.
    pub idle_timeout: Duration,
}

impl Default for ReconnectingPtyOptions {
    fn default() -> Self {
        Self {
            buffer_bytes: DEFAULT_BUFFER_BYTES,
            agent_grace: DEFAULT_AGENT_GRACE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

/// Errors returned by [`ReconnectingPtyStore`] operations.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReconnectingPtyError {
    /// The caller's requested agent ID does not match the agent that
    /// originally owned this reconnect session. The client must not be
    /// able to hop sessions across agents.
    #[error("reconnect_id already bound to a different agent")]
    AgentMismatch,
    /// The session exists but is closed and no longer usable (for example,
    /// the agent disconnected and the grace window expired).
    #[error("reconnect session closed")]
    Closed,
}

/// Bounded byte ring that discards the oldest bytes when full.
struct RingBuffer {
    capacity: usize,
    data: VecDeque<u8>,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            data: VecDeque::with_capacity(capacity.clamp(1, 64 * 1024)),
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        // If the input is larger than capacity, only the last `capacity`
        // bytes are relevant.
        let (start, overflow) = if bytes.len() >= self.capacity {
            let start = bytes.len() - self.capacity;
            self.data.clear();
            (start, 0)
        } else {
            let needed = (self.data.len() + bytes.len()).saturating_sub(self.capacity);
            (0, needed)
        };
        for _ in 0..overflow {
            self.data.pop_front();
        }
        self.data.extend(bytes[start..].iter().copied());
    }

    fn snapshot(&self) -> Vec<u8> {
        let (a, b) = self.data.as_slices();
        let mut out = Vec::with_capacity(a.len() + b.len());
        out.extend_from_slice(a);
        out.extend_from_slice(b);
        out
    }
}

/// Per-session state kept inside [`ReconnectingPtyStore`].
pub struct Session {
    /// Agent that owns this session. Used to reject cross-agent re-use of
    /// a `reconnect_id`.
    agent_id: Uuid,
    /// Scrollback ring buffer of recent output bytes.
    buffer: Mutex<RingBuffer>,
    /// Fan-out of live output to all attached clients.
    fanout: broadcast::Sender<Vec<u8>>,
    /// Timestamp of the last observed reader/writer activity; used for idle
    /// timeout pruning.
    last_activity: Mutex<Instant>,
    /// Live reader count. Clients increment on attach and decrement on
    /// drop.
    readers: Mutex<usize>,
    /// Live writer (agent-side) count. Set to 1 while the agent-side
    /// producer is attached, 0 once it drops.
    writers: Mutex<usize>,
    /// If set, the session is in the agent-drop grace window. After this
    /// instant the session is removed and further attach calls fail.
    grace_deadline: Mutex<Option<Instant>>,
    /// Guards `start_agent_pump_once` so only one pump task runs per
    /// session regardless of how many concurrent clients attach.
    pump_started: Mutex<bool>,
}

impl Session {
    fn new(agent_id: Uuid, buffer_bytes: usize) -> Self {
        let (fanout, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            agent_id,
            buffer: Mutex::new(RingBuffer::new(buffer_bytes)),
            fanout,
            last_activity: Mutex::new(Instant::now()),
            readers: Mutex::new(0),
            writers: Mutex::new(0),
            grace_deadline: Mutex::new(None),
            pump_started: Mutex::new(false),
        }
    }

    /// Atomically starts a single agent-pump task for this session. Returns
    /// `true` on the first call (caller should spawn the pump) and `false`
    /// on subsequent calls.
    pub async fn start_pump_once(&self) -> bool {
        let mut started = self.pump_started.lock().await;
        if *started {
            false
        } else {
            *started = true;
            true
        }
    }

    /// Marks the agent-pump as stopped so a future reconnect can start a
    /// fresh pump. Does not affect live clients or the scrollback.
    pub async fn mark_pump_stopped(&self) {
        *self.pump_started.lock().await = false;
    }

    /// Returns the agent that owns this session.
    #[must_use]
    pub fn agent_id(&self) -> Uuid {
        self.agent_id
    }

    async fn touch(&self) {
        *self.last_activity.lock().await = Instant::now();
    }

    /// Appends output bytes to the ring buffer and fans them out to live
    /// subscribers.
    pub async fn push_output(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.buffer.lock().await.push(bytes);
        // `send` returns `Err` when there are no live subscribers — that's
        // fine and expected while the client is detached.
        let _ = self.fanout.send(bytes.to_vec());
        self.touch().await;
    }

    /// Returns the current scrollback snapshot.
    pub async fn scrollback(&self) -> Vec<u8> {
        self.buffer.lock().await.snapshot()
    }

    /// Subscribes to the live output fan-out. Drop the returned receiver
    /// to unsubscribe.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.fanout.subscribe()
    }
}

/// Store of active reconnecting-PTY sessions.
///
/// See the module-level docs for a description of the session lifecycle.
pub struct ReconnectingPtyStore {
    sessions: RwLock<HashMap<Uuid, Arc<Session>>>,
    options: ReconnectingPtyOptions,
}

impl ReconnectingPtyStore {
    /// Constructs a new store with default options.
    #[must_use]
    pub fn new() -> Self {
        Self::with_options(ReconnectingPtyOptions::default())
    }

    /// Constructs a new store with the supplied options.
    #[must_use]
    pub fn with_options(options: ReconnectingPtyOptions) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            options,
        }
    }

    /// Returns the configured options.
    #[must_use]
    pub fn options(&self) -> ReconnectingPtyOptions {
        self.options
    }

    /// Guard held by a client WebSocket. When dropped, decrements the
    /// reader count on the underlying session.
    pub async fn attach_client(
        self: &Arc<Self>,
        reconnect_id: Uuid,
        agent_id: Uuid,
    ) -> Result<ClientAttach, ReconnectingPtyError> {
        let session = self.get_or_create(reconnect_id, agent_id).await?;
        *session.readers.lock().await += 1;
        session.touch().await;
        Ok(ClientAttach {
            store: Arc::clone(self),
            reconnect_id,
            session,
        })
    }

    /// Guard held by the agent-side writer. When dropped, decrements the
    /// writer count and starts the grace window if that was the last
    /// writer.
    pub async fn attach_agent(
        self: &Arc<Self>,
        reconnect_id: Uuid,
        agent_id: Uuid,
    ) -> Result<AgentAttach, ReconnectingPtyError> {
        let session = self.get_or_create(reconnect_id, agent_id).await?;
        // An agent re-attaching clears any prior grace window.
        *session.grace_deadline.lock().await = None;
        *session.writers.lock().await += 1;
        session.touch().await;
        Ok(AgentAttach {
            store: Arc::clone(self),
            reconnect_id,
            session,
        })
    }

    async fn get_or_create(
        &self,
        reconnect_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Arc<Session>, ReconnectingPtyError> {
        // Fast path: session exists. Bind the clone into a local so the
        // read guard is dropped before we may need a write lock below.
        let existing_opt = {
            let guard = self.sessions.read().await;
            guard.get(&reconnect_id).cloned()
        };
        if let Some(existing) = existing_opt {
            if existing.agent_id != agent_id {
                return Err(ReconnectingPtyError::AgentMismatch);
            }
            // Grace-window check: if agent dropped AND the deadline passed,
            // treat the session as closed. Otherwise resume.
            let now = Instant::now();
            let deadline = *existing.grace_deadline.lock().await;
            if let Some(deadline) = deadline {
                if now >= deadline {
                    // Expire it lazily and refuse the attach.
                    let mut write = self.sessions.write().await;
                    write.remove(&reconnect_id);
                    return Err(ReconnectingPtyError::Closed);
                }
            }
            return Ok(existing);
        }
        // Slow path: create.
        let mut write = self.sessions.write().await;
        if let Some(existing) = write.get(&reconnect_id).cloned() {
            if existing.agent_id != agent_id {
                return Err(ReconnectingPtyError::AgentMismatch);
            }
            return Ok(existing);
        }
        let session = Arc::new(Session::new(agent_id, self.options.buffer_bytes));
        write.insert(reconnect_id, Arc::clone(&session));
        Ok(session)
    }

    /// Removes idle sessions and sessions whose grace window has expired.
    ///
    /// Intended to be called periodically by a background task.
    pub async fn prune(&self) {
        let now = Instant::now();
        let idle = self.options.idle_timeout;
        let mut to_remove: Vec<Uuid> = Vec::new();
        let sessions = self.sessions.read().await;
        for (id, session) in sessions.iter() {
            // Expired grace window → remove.
            if let Some(deadline) = *session.grace_deadline.lock().await {
                if now >= deadline {
                    to_remove.push(*id);
                    continue;
                }
            }
            let readers = *session.readers.lock().await;
            let writers = *session.writers.lock().await;
            let last = *session.last_activity.lock().await;
            if readers == 0 && writers == 0 && now.duration_since(last) >= idle {
                to_remove.push(*id);
            }
        }
        drop(sessions);
        if to_remove.is_empty() {
            return;
        }
        let mut write = self.sessions.write().await;
        for id in to_remove {
            write.remove(&id);
        }
    }

    /// Returns the current number of live sessions. Primarily for tests
    /// and metrics.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Returns the session for a `reconnect_id`, if any. Intended for
    /// tests and metrics.
    pub async fn get(&self, reconnect_id: Uuid) -> Option<Arc<Session>> {
        self.sessions.read().await.get(&reconnect_id).cloned()
    }
}

impl Default for ReconnectingPtyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard held by a client-side WebSocket attachment.
pub struct ClientAttach {
    store: Arc<ReconnectingPtyStore>,
    reconnect_id: Uuid,
    /// The underlying shared session.
    pub session: Arc<Session>,
}

impl ClientAttach {
    /// Returns the reconnect id owned by this guard.
    #[must_use]
    pub fn reconnect_id(&self) -> Uuid {
        self.reconnect_id
    }
}

impl Drop for ClientAttach {
    fn drop(&mut self) {
        // Spawn a small async cleanup: decrement reader count and touch
        // `last_activity`. Spawning is fine because the store is reference
        // counted and lives as long as the server. Keeping `_store` alive
        // until the task returns prevents the session from being freed
        // mid-cleanup if it was the last reference.
        let _store = Arc::clone(&self.store);
        let session = Arc::clone(&self.session);
        tokio::spawn(async move {
            let mut readers = session.readers.lock().await;
            *readers = readers.saturating_sub(1);
            drop(readers);
            session.touch().await;
            drop(_store);
        });
    }
}

/// RAII guard held by the agent-side writer.
pub struct AgentAttach {
    store: Arc<ReconnectingPtyStore>,
    reconnect_id: Uuid,
    /// The underlying shared session.
    pub session: Arc<Session>,
}

impl AgentAttach {
    /// Returns the reconnect id owned by this guard.
    #[must_use]
    pub fn reconnect_id(&self) -> Uuid {
        self.reconnect_id
    }
}

impl Drop for AgentAttach {
    fn drop(&mut self) {
        let store = Arc::clone(&self.store);
        let session = Arc::clone(&self.session);
        let grace = store.options.agent_grace;
        tokio::spawn(async move {
            let mut writers = session.writers.lock().await;
            *writers = writers.saturating_sub(1);
            let remaining = *writers;
            drop(writers);
            session.touch().await;
            if remaining == 0 {
                // Start the grace window. After it expires the next attach
                // (or the pruner) will remove the session.
                *session.grace_deadline.lock().await = Some(Instant::now() + grace);
            }
            drop(store);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    fn tiny_options(
        buffer_bytes: usize,
        grace: Duration,
        idle: Duration,
    ) -> ReconnectingPtyOptions {
        ReconnectingPtyOptions {
            buffer_bytes,
            agent_grace: grace,
            idle_timeout: idle,
        }
    }

    fn must_ok<T, E>(r: Result<T, E>) -> T {
        match r {
            Ok(v) => v,
            Err(_) => unreachable!("expected Ok"),
        }
    }

    fn must_err<T, E>(r: Result<T, E>) -> E {
        match r {
            Ok(_) => unreachable!("expected Err"),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn replay_includes_prior_output_after_reconnect() {
        let store = Arc::new(ReconnectingPtyStore::new());
        let reconnect = Uuid::new_v4();
        let agent = Uuid::new_v4();

        // Agent attaches and pushes output.
        let agent_attach = must_ok(store.attach_agent(reconnect, agent).await);
        agent_attach.session.push_output(b"hello ").await;
        agent_attach.session.push_output(b"world").await;

        // Client attaches then detaches without consuming fanout.
        {
            let client1 = must_ok(store.attach_client(reconnect, agent).await);
            let replay = client1.session.scrollback().await;
            assert_eq!(replay, b"hello world".to_vec());
        }

        // Client reconnects with the same id and sees the same scrollback.
        let client2 = must_ok(store.attach_client(reconnect, agent).await);
        assert_eq!(client2.session.scrollback().await, b"hello world".to_vec());
    }

    #[tokio::test]
    async fn ring_buffer_evicts_oldest_bytes() {
        let store = Arc::new(ReconnectingPtyStore::with_options(tiny_options(
            8,
            DEFAULT_AGENT_GRACE,
            DEFAULT_IDLE_TIMEOUT,
        )));
        let reconnect = Uuid::new_v4();
        let agent = Uuid::new_v4();

        let a = must_ok(store.attach_agent(reconnect, agent).await);
        a.session.push_output(b"0123456789ABCDEF").await;

        // Buffer holds only the most-recent 8 bytes.
        let replay = a.session.scrollback().await;
        assert_eq!(replay.len(), 8);
        assert_eq!(replay, b"89ABCDEF".to_vec());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_drop_starts_grace_window_and_expires() {
        // 100ms grace window so the test is fast but robust against
        // scheduler jitter.
        let store = Arc::new(ReconnectingPtyStore::with_options(tiny_options(
            256,
            Duration::from_millis(100),
            DEFAULT_IDLE_TIMEOUT,
        )));
        let reconnect = Uuid::new_v4();
        let agent = Uuid::new_v4();

        {
            let a = must_ok(store.attach_agent(reconnect, agent).await);
            a.session.push_output(b"hi").await;
        }
        // Drop spawns the grace-window task; yield generously so it runs.
        sleep(Duration::from_millis(30)).await;

        // Within the grace window, reconnection still sees scrollback.
        {
            let c = must_ok(store.attach_client(reconnect, agent).await);
            assert_eq!(c.session.scrollback().await, b"hi".to_vec());
        }

        // After the grace window expires, attach fails with Closed.
        sleep(Duration::from_millis(200)).await;
        let err = must_err(store.attach_client(reconnect, agent).await);
        assert_eq!(err, ReconnectingPtyError::Closed);
        assert_eq!(store.session_count().await, 0);
    }

    #[tokio::test]
    async fn agent_mismatch_is_rejected() {
        let store = Arc::new(ReconnectingPtyStore::new());
        let reconnect = Uuid::new_v4();
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();

        let _attach = must_ok(store.attach_agent(reconnect, agent_a).await);
        let err = must_err(store.attach_client(reconnect, agent_b).await);
        assert_eq!(err, ReconnectingPtyError::AgentMismatch);
    }

    #[tokio::test]
    async fn two_clients_both_receive_live_output() {
        let store = Arc::new(ReconnectingPtyStore::new());
        let reconnect = Uuid::new_v4();
        let agent = Uuid::new_v4();

        let agent_attach = must_ok(store.attach_agent(reconnect, agent).await);

        let c1 = must_ok(store.attach_client(reconnect, agent).await);
        let c2 = must_ok(store.attach_client(reconnect, agent).await);
        let mut rx1 = c1.session.subscribe();
        let mut rx2 = c2.session.subscribe();

        agent_attach.session.push_output(b"burst").await;

        let got1 = must_ok(rx1.recv().await);
        let got2 = must_ok(rx2.recv().await);
        assert_eq!(got1, b"burst".to_vec());
        assert_eq!(got2, b"burst".to_vec());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prune_removes_fully_idle_sessions() {
        let store = Arc::new(ReconnectingPtyStore::with_options(tiny_options(
            64,
            Duration::from_millis(20),
            Duration::from_millis(20),
        )));
        let reconnect = Uuid::new_v4();
        let agent = Uuid::new_v4();

        {
            let _a = must_ok(store.attach_agent(reconnect, agent).await);
        }
        // The agent dropped → grace deadline set. Wait past grace + idle.
        sleep(Duration::from_millis(100)).await;
        store.prune().await;
        assert_eq!(store.session_count().await, 0);
    }
}
