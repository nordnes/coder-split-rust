//! PostgreSQL-backed pub/sub using `LISTEN`/`NOTIFY`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use coder_core::pubsub::{PubSub, PubSubError, Subscription};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{debug, error, warn};

/// Buffer size for internal broadcast channels (matches Go `BufferSize`).
const BROADCAST_CAPACITY: usize = 2048;

/// Commands sent to the background listener task.
enum ListenerCommand {
    /// Start listening on a new channel.
    Listen(String),
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
    /// Spawns a background task that listens for `NOTIFY` messages and
    /// dispatches them to the appropriate broadcast channel.
    pub async fn new(pool: PgPool) -> Result<Self, PubSubError> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let channels: Arc<Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(Mutex::new(false));

        let listener_channels = channels.clone();
        let listener_pool = pool.clone();

        let handle = tokio::spawn(async move {
            Self::listener_loop(listener_pool, listener_channels, command_rx).await;
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
        pool: PgPool,
        channels: Arc<Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>>,
        mut command_rx: mpsc::UnboundedReceiver<ListenerCommand>,
    ) {
        let mut listener = match PgListener::connect_with(&pool).await {
            Ok(listener) => listener,
            Err(err) => {
                error!(error = %err, "failed to create PgListener for pubsub");
                return;
            }
        };

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
            self.command_tx
                .send(ListenerCommand::Listen(channel.to_owned()))
                .map_err(|err| PubSubError::unavailable(err.to_string()))?;
        }

        Ok(Subscription::new(receiver))
    }

    async fn publish(&self, channel: &str, message: &[u8]) -> Result<(), PubSubError> {
        let closed = self.closed.lock().await;
        if *closed {
            return Err(PubSubError::Closed);
        }
        drop(closed);

        // Use pg_notify() which takes the channel name and a text payload.
        // The payload is transmitted as a string, so we encode the bytes.
        let payload = String::from_utf8_lossy(message);
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(channel)
            .bind(payload.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|err| PubSubError::unavailable(err.to_string()))?;

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
