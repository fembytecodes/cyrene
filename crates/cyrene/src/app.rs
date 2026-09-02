use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

use cyrene_core::{Error, ErrorCode, ReplicaId, Result, SpaceId};
use cyrene_store::{BackupReport, CompactionReport, SqliteStore, StoredSchema};
use cyrene_sync::Replica;
use tokio::sync::broadcast;

use crate::{Actor, Collection, Document, LocalTransaction, collection::RawChange};

const CRDT_COUNTER_RESERVATION: u64 = 65_536;

pub(crate) type MergePayloads = fn(&[u8], &[&[u8]]) -> Result<Vec<u8>>;

#[derive(Clone, Copy, Debug)]
pub(crate) struct MergeStrategy {
    pub(crate) enabled: bool,
    pub(crate) merge: MergePayloads,
}

/// A point-in-time view of an application's local durable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalStatus {
    /// Stable identity of the inspected space.
    pub space: SpaceId,
    /// Greatest committed local change sequence.
    pub frontier: u64,
    /// Number of live materialized documents.
    pub documents: u64,
    /// Number of retained durable changes.
    pub changes: u64,
    /// Stable identity of the local replica author.
    pub replica: ReplicaId,
    /// Greatest contiguous local-author change retained by this replica.
    pub replica_frontier: u64,
    /// Number of globally identified changes retained for reconciliation.
    pub replicated_changes: u64,
    /// Result of the storage integrity check.
    pub integrity: String,
}

impl LocalStatus {
    /// Returns whether local durable storage passed its integrity check.
    pub fn is_healthy(&self) -> bool {
        self.integrity == "ok"
    }
}

/// An open local Cyrene application.
#[derive(Clone, Debug)]
pub struct App {
    pub(crate) store: Arc<Mutex<SqliteStore>>,
    pub(crate) space: SpaceId,
    pub(crate) changes: broadcast::Sender<RawChange>,
    pub(crate) replica: Arc<Mutex<Replica>>,
    pub(crate) schemas: Arc<Mutex<BTreeMap<String, StoredSchema>>>,
    pub(crate) mergers: Arc<Mutex<BTreeMap<String, MergeStrategy>>>,
}

impl App {
    /// Opens or creates an application database at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage worker fails or the database cannot be
    /// opened, migrated, or read.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_owned();
        let mut store = tokio::task::spawn_blocking(move || SqliteStore::open(path))
            .await
            .map_err(task_error)??;
        let space = store.default_space()?;
        Self::from_store(store, space)
    }

    /// Opens an isolated in-memory application.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory database cannot be initialized.
    pub async fn in_memory() -> Result<Self> {
        let mut store = tokio::task::spawn_blocking(SqliteStore::open_in_memory)
            .await
            .map_err(task_error)??;
        let space = store.default_space()?;
        Self::from_store(store, space)
    }

    /// Opens or creates a database bound to an existing shared `space`.
    ///
    /// This low-level constructor is used by pairing and tests. A store already
    /// bound to another space is rejected rather than silently reassigned.
    ///
    /// # Errors
    ///
    /// Returns an error if storage cannot be opened, the existing space differs,
    /// or replica history cannot be reconstructed.
    pub async fn open_space(path: impl AsRef<Path>, space: SpaceId) -> Result<Self> {
        let path = path.as_ref().to_owned();
        let mut store = tokio::task::spawn_blocking(move || SqliteStore::open(path))
            .await
            .map_err(task_error)??;
        store.bind_default_space(space)?;
        Self::from_store(store, space)
    }

    /// Opens an isolated in-memory replica of an existing shared `space`.
    ///
    /// # Errors
    ///
    /// Returns an error if in-memory storage cannot be initialized.
    pub async fn in_memory_space(space: SpaceId) -> Result<Self> {
        let mut store = tokio::task::spawn_blocking(SqliteStore::open_in_memory)
            .await
            .map_err(task_error)??;
        store.bind_default_space(space)?;
        Self::from_store(store, space)
    }

    fn from_store(mut store: SqliteStore, space: SpaceId) -> Result<Self> {
        let replica_id = store.replica_id()?;
        let mut replica = Replica::new(replica_id, space);
        let schemas = store
            .collection_schemas(space)?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        for (collection, schema) in &schemas {
            replica.register_schema(collection.clone(), schema.fingerprint)?;
        }
        let replicated = store.replicated_changes(space)?;
        for change in &replicated {
            replica.register_schema(
                change.operation.collection().to_owned(),
                change.operation.schema(),
            )?;
        }
        for change in replicated {
            replica.apply(change, unix_time_ms()?)?;
        }
        let (changes, _) = broadcast::channel(256);
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            space,
            changes,
            replica: Arc::new(Mutex::new(replica)),
            schemas: Arc::new(Mutex::new(schemas)),
            mergers: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Opens a typed collection in the application's default space.
    pub fn collection<T: Document>(&self, name: impl Into<String>) -> Collection<T> {
        let name = name.into();
        let schema = StoredSchema::from(T::SCHEMA);
        let accepted = self.schemas.lock().is_ok_and(|mut schemas| {
            if let Some(existing) = schemas.get(&name) {
                existing == &schema
            } else {
                schemas.insert(name.clone(), schema.clone());
                true
            }
        });
        if accepted && let Ok(mut replica) = self.replica.lock() {
            let _ = replica.register_schema(name.clone(), schema.fingerprint);
        }
        if accepted && let Ok(mut mergers) = self.mergers.lock() {
            mergers.insert(
                name.clone(),
                MergeStrategy {
                    enabled: T::HAS_MERGE_FIELDS,
                    merge: T::merge_payloads,
                },
            );
        }
        Collection::new(self.clone(), name)
    }

    /// Begins an in-memory builder for one atomic local transaction.
    ///
    /// Nothing is made visible or durable until
    /// [`LocalTransaction::commit`] succeeds.
    pub fn transaction(&self) -> LocalTransaction {
        LocalTransaction::new(self.clone())
    }

    /// Reserves a durable range and returns an operation author for merge-aware
    /// [`crate::Text`] and [`crate::List`] edits.
    ///
    /// Reserving ahead keeps individual edits synchronous and cheap. Unused
    /// counters after a crash become harmless gaps and are never reused.
    ///
    /// # Errors
    ///
    /// Returns an error if replica identity cannot be read or storage cannot
    /// durably reserve the counter range.
    pub async fn actor(&self) -> Result<Actor> {
        let replica = self.replica_id()?;
        let store = Arc::clone(&self.store);
        let (previous, limit) = tokio::task::spawn_blocking(move || {
            store
                .lock()
                .map_err(|error| {
                    Error::new(
                        ErrorCode::Storage,
                        format!("the local storage lock was poisoned: {error}"),
                    )
                })?
                .reserve_crdt_counters(CRDT_COUNTER_RESERVATION)
        })
        .await
        .map_err(task_error)??;
        Actor::reserved(replica, previous, limit)
    }

    /// Returns the stable identity of the application's default space.
    pub const fn space_id(&self) -> SpaceId {
        self.space
    }

    /// Returns the durable identity of this local replica.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-process replica lock was poisoned.
    pub fn replica_id(&self) -> Result<ReplicaId> {
        self.replica
            .lock()
            .map(|replica| replica.id())
            .map_err(|error| {
                Error::new(
                    ErrorCode::Storage,
                    format!("the local replica lock was poisoned: {error}"),
                )
            })
    }

    /// Inspects local durability and storage health.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage worker fails or the database cannot be
    /// inspected.
    pub async fn status(&self) -> Result<LocalStatus> {
        let store = Arc::clone(&self.store);
        let status = tokio::task::spawn_blocking(move || {
            store
                .lock()
                .map_err(|error| {
                    Error::new(
                        ErrorCode::Storage,
                        format!("the local storage lock was poisoned: {error}"),
                    )
                })?
                .status()
        })
        .await
        .map_err(task_error)??;
        let replica = self.replica.lock().map_err(|error| {
            Error::new(
                ErrorCode::Storage,
                format!("the local replica lock was poisoned: {error}"),
            )
        })?;
        Ok(LocalStatus {
            space: self.space,
            frontier: status.frontier,
            documents: status.documents,
            changes: status.changes,
            replica: replica.id(),
            replica_frontier: replica.frontier().get(replica.id()),
            replicated_changes: status.replicated_changes,
            integrity: status.integrity,
        })
    }

    /// Creates a consistent, integrity-checked backup while the application is
    /// open and serving local reads and writes.
    ///
    /// The destination must be a new path. Complete replicated history is
    /// included so a restored replica can still serve long-offline peers.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage worker fails, the destination exists,
    /// or `SQLite` cannot create and verify the backup.
    pub async fn backup(&self, destination: impl AsRef<Path>) -> Result<BackupReport> {
        let destination = destination.as_ref().to_owned();
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            store
                .lock()
                .map_err(|error| storage_lock_error(&error))?
                .backup_to(destination)
        })
        .await
        .map_err(task_error)?
    }

    /// Bounds the redundant local journal without removing replicated history.
    ///
    /// `retain` is the number of recent local journal rows to preserve. A
    /// non-empty store always retains at least one row so local sequences stay
    /// monotonic. This operation cannot shorten peer catch-up history.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage worker fails or `SQLite` cannot commit the
    /// compaction.
    pub async fn compact(&self, retain: u64) -> Result<CompactionReport> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            store
                .lock()
                .map_err(|error| storage_lock_error(&error))?
                .compact_local_journal(retain)
        })
        .await
        .map_err(task_error)?
    }
}

pub(crate) fn unix_time_ms() -> Result<u64> {
    let milliseconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| Error::with_source(ErrorCode::Storage, "system clock is invalid", error))?
        .as_millis();
    u64::try_from(milliseconds).map_err(|error| {
        Error::with_source(
            ErrorCode::Storage,
            "system time is outside Cyrene's clock range",
            error,
        )
    })
}

fn task_error(error: tokio::task::JoinError) -> Error {
    Error::with_source(
        ErrorCode::Storage,
        "the local storage worker stopped unexpectedly",
        error,
    )
}

fn storage_lock_error(
    error: &std::sync::PoisonError<std::sync::MutexGuard<'_, SqliteStore>>,
) -> Error {
    Error::new(
        ErrorCode::Storage,
        format!("the local storage lock was poisoned: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use crate::{App, List};

    #[tokio::test]
    async fn actor_counter_reservations_are_never_reused_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("actor.db");
        let app = App::open(&path).await.unwrap();
        let mut first = app.actor().await.unwrap();
        let mut list = List::new();
        list.insert(&mut first, 0, "hello").unwrap();
        assert_eq!(first.counter(), 1);
        drop(app);

        let reopened = App::open(path).await.unwrap();
        let mut second = reopened.actor().await.unwrap();
        assert_eq!(second.counter(), super::CRDT_COUNTER_RESERVATION);
        List::new().insert(&mut second, 0, "safe").unwrap();
        assert_eq!(second.counter(), super::CRDT_COUNTER_RESERVATION + 1);
    }
}
