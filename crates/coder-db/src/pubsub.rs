//! PostgreSQL-backed pub/sub using `LISTEN`/`NOTIFY`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use coder_core::pubsub::{PubSub, PubSubError, Subscription};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{debug, warn};

/// Buffer size for internal broadcast channels (matches Go `BufferSize`).
const BROADCAST_CAPACITY: usize = 2048;

/// Commands sent to the background listener task.
enum ListenerCommand {
    /// Start listening on a new channel.
    Listen(String),
    /// Remove a channel that has no remaining subscribers.
    Unlisten(String),
    /// Shut down the listener.
    Close,
}

/// PostgreSQL-backed [`PubSub`] implementation.
///
/// Uses a dedicated [`PgListener`] connection (separate from the pool) for
/// `LISTEN`, and the connection pool for `NOTIFY` via `pg_notify()`.
/// Internally fans out received notifications to per-channel
/// `tokio::sync::broadcast` senders.
pub struct PostgresPubSub {
    /// Connection pool used for `SELECT pg_notify(...)` on publish.
    pool: PgPool,
    /// Per-channel broadcast senders shared with the background listener task.
    channels: Arc<Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>>,
    /// Sender half of the command channel to the background listener task.
    command_tx: mpsc::UnboundedSender<ListenerCommand>,
    /// Handle to the background listener task.
    listener_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Whether the pubsub has been closed.
    closed: Arc<Mutex<bool>>,
}

impl PostgresPubSub {
    /// Creates a new PostgreSQL pub/sub instance.
    ///
    /// Opens a dedicated `PgListener` connection (separate from the pool) and
    /// spawns a background task that listens for `NOTIFY` messages and
    /// dispatches them to the appropriate broadcast channel.
    ///
    /// Returns an error immediately if the initial `PgListener` connection
    /// cannot be established.
    pub async fn new(pool: PgPool) -> Result<Self, PubSubError> {
        // Create the PgListener eagerly so connection failures are surfaced
        // immediately rather than silently killing the background task.
        let listener = PgListener::connect_with(&pool)
            .await
            .map_err(|err| PubSubError::unavailable(format!("create PgListener: {err}")))?;

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let channels: Arc<Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(Mutex::new(false));

        let listener_channels = channels.clone();

        let handle = tokio::spawn(async move {
            Self::listener_loop(listener, listener_channels, command_rx).await;
        });

        Ok(Self {
            pool,
            channels,
            command_tx,
            listener_handle: Mutex::new(Some(handle)),
            closed,
        })
    }

    /// Background loop that processes listener commands and incoming PG
    /// notifications.
    async fn listener_loop(
        mut listener: PgListener,
        channels: Arc<Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>>,
        mut command_rx: mpsc::UnboundedReceiver<ListenerCommand>,
    ) {
        debug!("pubsub listener loop started");

        loop {
            tokio::select! {
                // Process commands from the main PubSub handle.
                cmd = command_rx.recv() => {
                    match cmd {
                        Some(ListenerCommand::Listen(channel)) => {
                            if let Err(err) = listener.listen(&channel).await {
                                warn!(
                                    channel = %channel,
                                    error = %err,
                                    "failed to LISTEN on channel"
                                );
                            } else {
                                debug!(channel = %channel, "started listening on channel");
                            }
                        }
                        Some(ListenerCommand::Unlisten(channel)) => {
                            if let Err(err) = listener.unlisten(&channel).await {
                                warn!(
                                    channel = %channel,
                                    error = %err,
                                    "failed to UNLISTEN on channel"
                                );
                            } else {
                                debug!(channel = %channel, "stopped listening on channel");
                            }
                        }
                        Some(ListenerCommand::Close) | None => {
                            debug!("pubsub listener loop shutting down");
                            break;
                        }
                    }
                }
                // Receive notifications from PostgreSQL.
                notification = listener.recv() => {
                    match notification {
                        Ok(notif) => {
                            let channel_map = channels.lock().await;
                            if let Some(sender) = channel_map.get(notif.channel()) {
                                // It is fine if there are currently no receivers.
                                let _ = sender.send(notif.payload().as_bytes().to_vec());
                            }
                        }
                        Err(err) => {
                            // PgListener automatically reconnects on transient
                            // errors, so we log and continue.
                            warn!(error = %err, "pubsub listener received error, will reconnect");
                        }
                    }
                }
            }
        }
    }

    /// Removes the channel from the map and issues an UNLISTEN command if the
    /// broadcast sender has no remaining receivers.
    async fn maybe_cleanup_channel(&self, channel: &str) {
        let mut channels = self.channels.lock().await;
        let should_remove = channels
            .get(channel)
            .is_some_and(|sender| sender.receiver_count() == 0);

        if should_remove {
            channels.remove(channel);
            drop(channels);
            // Best-effort: if the background task is gone the send will fail
            // silently, which is fine.
            let _ = self
                .command_tx
                .send(ListenerCommand::Unlisten(channel.to_owned()));
        }
    }
}

#[async_trait]
impl PubSub for PostgresPubSub {
    async fn subscribe(&self, channel: &str) -> Result<Subscription, PubSubError> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(PubSubError::Closed);
        }
        drop(closed);

        let mut channels = self.channels.lock().await;
        let need_listen = !channels.contains_key(channel);
        let sender = channels
            .entry(channel.to_owned())
            .or_insert_with(|| broadcast::channel(BROADCAST_CAPACITY).0)
            .clone();
        let receiver = sender.subscribe();
        drop(channels);

        // Tell the background task to LISTEN on this channel if it is new.
        if need_listen {
            if let Err(err) = self
                .command_tx
                .send(ListenerCommand::Listen(channel.to_owned()))
            {
                // Clean up the channel entry we just inserted so future
                // subscribe calls don't skip the LISTEN command.
                let mut channels = self.channels.lock().await;
                channels.remove(channel);
                return Err(PubSubError::unavailable(err.to_string()));
            }
        }

        Ok(Subscription::new(receiver))
    }

    async fn publish(&self, channel: &str, message: &[u8]) -> Result<(), PubSubError> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(PubSubError::Closed);
        }
        drop(closed);

        // pg_notify() requires a text payload. Validate that the message is
        // valid UTF-8 rather than silently replacing invalid bytes (which would
        // corrupt the data). All expected payloads are JSON so this should
        // always succeed.
        let payload = std::str::from_utf8(message).map_err(|err| {
            PubSubError::unavailable(format!("payload is not valid UTF-8: {err}"))
        })?;

        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(channel)
            .bind(payload)
            .execute(&self.pool)
            .await
            .map_err(|err| PubSubError::unavailable(err.to_string()))?;

        // Best-effort cleanup: if the channel has no remaining subscribers,
        // remove it from the map and UNLISTEN.
        self.maybe_cleanup_channel(channel).await;

        Ok(())
    }

    async fn close(&self) -> Result<(), PubSubError> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Ok(());
        }
        *closed = true;
        drop(closed);

        // Signal the background listener task to shut down.
        let _ = self.command_tx.send(ListenerCommand::Close);

        // Wait for the listener task to finish.
        let mut handle = self.listener_handle.lock().await;
        if let Some(h) = handle.take() {
            let _ = h.await;
        }

        // Clear all channels so receivers get a Closed error.
        let mut channels = self.channels.lock().await;
        channels.clear();

        debug!("pubsub closed");
        Ok(())
    }
}
