//! Durable, bounded storage for Cyrene's opaque relay protocol.

#![forbid(unsafe_code)]

use std::{path::Path, sync::Arc};

use cyrene_net::{
    RelayDelivery, RelayEnvelope, RelayOperation, RelayProtocolError, RelayRejection, RelayRequest,
    RelayResponse,
};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;

const SCHEMA: &str = "
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS relay_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL
) STRICT;
INSERT OR IGNORE INTO relay_meta (singleton, version) VALUES (1, 1);
CREATE TABLE IF NOT EXISTS relay_objects (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    route BLOB NOT NULL,
    object_id BLOB NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
    ciphertext BLOB NOT NULL,
    UNIQUE (route, object_id)
) STRICT;
CREATE INDEX IF NOT EXISTS relay_objects_route_sequence
ON relay_objects (route, sequence);
CREATE INDEX IF NOT EXISTS relay_objects_expiry
ON relay_objects (expires_at);
CREATE TABLE IF NOT EXISTS relay_replays (
    route BLOB NOT NULL,
    nonce BLOB NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
    PRIMARY KEY (route, nonce)
) STRICT;
CREATE INDEX IF NOT EXISTS relay_replays_expiry
ON relay_replays (expires_at);";

/// Resource ceilings enforced independently of public protocol limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLimits {
    /// Maximum retained ciphertext bytes for one pseudonymous mailbox.
    pub mailbox_bytes: u64,
    /// Maximum retained objects for one pseudonymous mailbox.
    pub mailbox_objects: u64,
    /// Maximum retained ciphertext bytes across the service.
    pub total_bytes: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            mailbox_bytes: 64 * 1024 * 1024,
            mailbox_objects: 10_000,
            total_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// A durable relay storage failure.
#[derive(Debug, Error)]
pub enum RelayStoreError {
    /// `SQLite` could not complete a durable operation.
    #[error("relay storage failed: {0}")]
    Storage(#[from] rusqlite::Error),
    /// A persisted row violated the relay's own invariants.
    #[error("relay storage contains malformed data")]
    CorruptStorage,
}

/// A single bounded relay connection failure.
#[derive(Debug, Error)]
pub enum RelayServeError {
    /// Reading or writing the TCP frame failed.
    #[error("relay connection failed: {0}")]
    Io(#[from] std::io::Error),
    /// A response could not be encoded.
    #[error("relay response encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
}

/// SQLite-backed opaque mailbox storage.
pub struct RelayStore {
    connection: Connection,
    limits: RelayLimits,
}

impl RelayStore {
    /// Opens or creates a durable relay database.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot configure or initialize the database.
    pub fn open(path: impl AsRef<Path>, limits: RelayLimits) -> Result<Self, RelayStoreError> {
        let connection = Connection::open(path)?;
        let store = Self { connection, limits };
        store.connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;",
        )?;
        store.connection.execute_batch(SCHEMA)?;
        Ok(store)
    }

    /// Opens an isolated in-memory relay store.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot initialize the schema.
    pub fn in_memory(limits: RelayLimits) -> Result<Self, RelayStoreError> {
        let connection = Connection::open_in_memory()?;
        let store = Self { connection, limits };
        store.connection.execute_batch(SCHEMA)?;
        Ok(store)
    }

    /// Authenticates, replay-checks, and atomically applies one request.
    ///
    /// Protocol and quota failures become stable public rejection responses;
    /// only local durable storage failures are returned as Rust errors.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot complete the operation or a retained
    /// row cannot satisfy protocol invariants.
    pub fn handle(
        &mut self,
        request: &RelayRequest,
        now: u64,
    ) -> Result<RelayResponse, RelayStoreError> {
        if let Err(error) = request.verify(now) {
            return Ok(RelayResponse::Rejected {
                code: rejection_for(&error),
            });
        }
        let route = request.route().to_bytes();
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM relay_objects WHERE expires_at <= ?1",
            [to_i64(now)?],
        )?;
        transaction.execute(
            "DELETE FROM relay_replays WHERE expires_at <= ?1",
            [to_i64(now)?],
        )?;
        let replay_expiry = now.saturating_add(cyrene_net::MAX_RELAY_CLOCK_SKEW + 1);
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO relay_replays (route, nonce, expires_at)
             VALUES (?1, ?2, ?3)",
            params![
                route.as_slice(),
                request.nonce().as_slice(),
                to_i64(replay_expiry)?
            ],
        )?;
        if inserted != 1 {
            transaction.rollback()?;
            return Ok(RelayResponse::Rejected {
                code: RelayRejection::Unauthorized,
            });
        }
        let response = match request.operation() {
            RelayOperation::Push { envelopes } => {
                apply_push(&transaction, &self.limits, &route, envelopes)?
            }
            RelayOperation::Pull { after, limit } => {
                apply_pull(&transaction, &route, *after, *limit, now)?
            }
            RelayOperation::Acknowledge { ids } => apply_ack(&transaction, &route, ids)?,
        };
        transaction.commit()?;
        Ok(response)
    }

    /// Returns current retained object and ciphertext-byte totals.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot inspect the store.
    pub fn usage(&self) -> Result<(u64, u64), RelayStoreError> {
        let (objects, bytes) = self.connection.query_row(
            "SELECT count(*), coalesce(sum(length(ciphertext)), 0) FROM relay_objects",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        Ok((from_i64(objects)?, from_i64(bytes)?))
    }
}

/// Serves one bounded request/response exchange and closes the stream.
///
/// Malformed input and durable failures are reduced to stable public rejection
/// categories rather than exposing service internals.
///
/// # Errors
///
/// Returns an error only when framing or response encoding fails.
pub async fn serve_connection(
    stream: TcpStream,
    store: &Arc<Mutex<RelayStore>>,
) -> Result<(), RelayServeError> {
    let (mut reader, mut writer) = stream.into_split();
    let length = usize::try_from(reader.read_u32().await?).unwrap_or(usize::MAX);
    if length == 0 || length > MAX_FRAME_BYTES {
        return write_response(
            &mut writer,
            &RelayResponse::Rejected {
                code: RelayRejection::LimitExceeded,
            },
        )
        .await;
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes).await?;
    let Ok(request) = serde_json::from_slice::<RelayRequest>(&bytes) else {
        return write_response(
            &mut writer,
            &RelayResponse::Rejected {
                code: RelayRejection::Unauthorized,
            },
        )
        .await;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let response = store
        .lock()
        .await
        .handle(&request, now)
        .unwrap_or(RelayResponse::Rejected {
            code: RelayRejection::Unavailable,
        });
    write_response(&mut writer, &response).await
}

async fn write_response(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    response: &RelayResponse,
) -> Result<(), RelayServeError> {
    let bytes = serde_json::to_vec(response)?;
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.shutdown().await?;
    Ok(())
}

fn apply_push(
    transaction: &rusqlite::Transaction<'_>,
    limits: &RelayLimits,
    route: &[u8; 32],
    envelopes: &[RelayEnvelope],
) -> Result<RelayResponse, RelayStoreError> {
    let (mailbox_objects, mailbox_bytes) = transaction.query_row(
        "SELECT count(*), coalesce(sum(length(ciphertext)), 0)
         FROM relay_objects WHERE route = ?1",
        [route.as_slice()],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let total_bytes: i64 = transaction.query_row(
        "SELECT coalesce(sum(length(ciphertext)), 0) FROM relay_objects",
        [],
        |row| row.get(0),
    )?;
    let mut added_objects = 0_u64;
    let mut added_bytes = 0_u64;
    for envelope in envelopes {
        let exists = transaction
            .query_row(
                "SELECT 1 FROM relay_objects WHERE route = ?1 AND object_id = ?2",
                params![route.as_slice(), envelope.id().as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            added_objects += 1;
            added_bytes = added_bytes
                .checked_add(
                    u64::try_from(envelope.ciphertext().len())
                        .map_err(|_| RelayStoreError::CorruptStorage)?,
                )
                .ok_or(RelayStoreError::CorruptStorage)?;
        }
    }
    let fits = from_i64(mailbox_objects)?
        .checked_add(added_objects)
        .is_some_and(|value| value <= limits.mailbox_objects)
        && from_i64(mailbox_bytes)?
            .checked_add(added_bytes)
            .is_some_and(|value| value <= limits.mailbox_bytes)
        && from_i64(total_bytes)?
            .checked_add(added_bytes)
            .is_some_and(|value| value <= limits.total_bytes);
    if !fits {
        return Ok(RelayResponse::Rejected {
            code: RelayRejection::LimitExceeded,
        });
    }
    for envelope in envelopes {
        transaction.execute(
            "INSERT OR IGNORE INTO relay_objects
             (route, object_id, expires_at, ciphertext) VALUES (?1, ?2, ?3, ?4)",
            params![
                route.as_slice(),
                envelope.id().as_slice(),
                to_i64(envelope.expires_at())?,
                envelope.ciphertext(),
            ],
        )?;
    }
    Ok(RelayResponse::Applied {
        changed: u16::try_from(added_objects).map_err(|_| RelayStoreError::CorruptStorage)?,
    })
}

fn apply_pull(
    transaction: &rusqlite::Transaction<'_>,
    route: &[u8; 32],
    after: u64,
    limit: u16,
    now: u64,
) -> Result<RelayResponse, RelayStoreError> {
    let mut statement = transaction.prepare(
        "SELECT sequence, object_id, expires_at, ciphertext FROM relay_objects
         WHERE route = ?1 AND sequence > ?2 AND expires_at > ?3
         ORDER BY sequence LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            route.as_slice(),
            to_i64(after)?,
            to_i64(now)?,
            i64::from(limit),
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        },
    )?;
    let mut items = Vec::new();
    for row in rows {
        let (cursor, object_id, expires_at, ciphertext) = row?;
        let object_id: [u8; 32] = object_id
            .try_into()
            .map_err(|_| RelayStoreError::CorruptStorage)?;
        let envelope =
            RelayEnvelope::with_opaque_id(object_id, ciphertext, from_i64(expires_at)?, now)
                .map_err(|_| RelayStoreError::CorruptStorage)?;
        items.push(RelayDelivery {
            cursor: from_i64(cursor)?,
            envelope,
        });
    }
    Ok(RelayResponse::Deliveries { items })
}

fn apply_ack(
    transaction: &rusqlite::Transaction<'_>,
    route: &[u8; 32],
    ids: &[[u8; 32]],
) -> Result<RelayResponse, RelayStoreError> {
    let mut changed = 0_u16;
    for id in ids {
        let deleted = transaction.execute(
            "DELETE FROM relay_objects WHERE route = ?1 AND object_id = ?2",
            params![route.as_slice(), id.as_slice()],
        )?;
        changed = changed
            .checked_add(u16::try_from(deleted).map_err(|_| RelayStoreError::CorruptStorage)?)
            .ok_or(RelayStoreError::CorruptStorage)?;
    }
    Ok(RelayResponse::Applied { changed })
}

fn rejection_for(error: &RelayProtocolError) -> RelayRejection {
    match error {
        RelayProtocolError::LimitExceeded => RelayRejection::LimitExceeded,
        _ => RelayRejection::Unauthorized,
    }
}

fn to_i64(value: u64) -> Result<i64, RelayStoreError> {
    i64::try_from(value).map_err(|_| RelayStoreError::CorruptStorage)
}

fn from_i64(value: i64) -> Result<u64, RelayStoreError> {
    u64::try_from(value).map_err(|_| RelayStoreError::CorruptStorage)
}

#[cfg(test)]
mod tests {
    use cyrene_net::{RelayMailbox, RelayRejection};

    use super::*;

    #[test]
    fn push_pull_deduplicate_acknowledge_and_replay_are_atomic() {
        let mut store = RelayStore::in_memory(RelayLimits::default()).unwrap();
        let mailbox = RelayMailbox::derive(&[1; 32], &[2; 32]);
        let envelope = RelayEnvelope::new(vec![3; 64], 2_000, 1_000).unwrap();
        let push = mailbox.push(vec![envelope.clone()], 1_000).unwrap();
        assert!(matches!(
            store.handle(&push, 1_000).unwrap(),
            RelayResponse::Applied { changed: 1 }
        ));
        assert!(matches!(
            store.handle(&push, 1_000).unwrap(),
            RelayResponse::Rejected {
                code: RelayRejection::Unauthorized
            }
        ));
        let duplicate = mailbox.push(vec![envelope.clone()], 1_001).unwrap();
        assert!(matches!(
            store.handle(&duplicate, 1_001).unwrap(),
            RelayResponse::Applied { changed: 0 }
        ));
        let pull = mailbox.pull(0, 10, 1_002).unwrap();
        let RelayResponse::Deliveries { items } = store.handle(&pull, 1_002).unwrap() else {
            panic!("expected deliveries");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].envelope, envelope);
        let ack = mailbox.acknowledge(vec![envelope.id()], 1_003).unwrap();
        assert!(matches!(
            store.handle(&ack, 1_003).unwrap(),
            RelayResponse::Applied { changed: 1 }
        ));
        assert_eq!(store.usage().unwrap(), (0, 0));
    }

    #[test]
    fn quotas_and_expiry_are_enforced_without_partial_inserts() {
        let limits = RelayLimits {
            mailbox_bytes: 100,
            mailbox_objects: 2,
            total_bytes: 100,
        };
        let mut store = RelayStore::in_memory(limits).unwrap();
        let mailbox = RelayMailbox::derive(&[4; 32], &[5; 32]);
        let first = RelayEnvelope::new(vec![1; 60], 1_010, 1_000).unwrap();
        let second = RelayEnvelope::new(vec![2; 60], 1_010, 1_000).unwrap();
        let request = mailbox.push(vec![first, second], 1_000).unwrap();
        assert!(matches!(
            store.handle(&request, 1_000).unwrap(),
            RelayResponse::Rejected {
                code: RelayRejection::LimitExceeded
            }
        ));
        assert_eq!(store.usage().unwrap(), (0, 0));

        let expiring = RelayEnvelope::new(vec![3; 60], 1_001, 1_000).unwrap();
        let request = mailbox.push(vec![expiring], 1_000).unwrap();
        assert!(matches!(
            store.handle(&request, 1_000).unwrap(),
            RelayResponse::Applied { changed: 1 }
        ));
        let pull = mailbox.pull(0, 10, 1_002).unwrap();
        assert!(matches!(
            store.handle(&pull, 1_002).unwrap(),
            RelayResponse::Deliveries { ref items } if items.is_empty()
        ));
        assert_eq!(store.usage().unwrap(), (0, 0));
    }
}
