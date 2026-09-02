//! Durable local storage for Cyrene.
//!
//! This crate deliberately exposes storage-shaped values rather than
//! application types. Serialization and reactive behavior live in the public
//! facade.

use std::{
    fs::{self, OpenOptions},
    path::Path,
    time::Duration,
};

use cyrene_core::{
    DocumentId, Error, ErrorCode, ReplicaId, Result, STORAGE_VERSION, Schema, SpaceId,
};
use cyrene_sync::Change;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

const BACKUP_PAGES_PER_STEP: i32 = 128;
const BACKUP_PAUSE: Duration = Duration::from_millis(5);

/// The kind of mutation represented by a durable change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum ChangeKind {
    /// A document was inserted or replaced.
    Put = 1,
    /// A document was deleted.
    Delete = 2,
}

/// A requested mutation in an atomic local transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mutation {
    /// Insert or replace a serialized document.
    Put {
        /// Collection containing the document.
        collection: String,
        /// Stable document identity.
        id: DocumentId,
        /// Serialized application payload.
        payload: Vec<u8>,
        /// Durable schema expected by the collection.
        schema: StoredSchema,
    },
    /// Delete a document if it currently exists.
    Delete {
        /// Collection containing the document.
        collection: String,
        /// Stable document identity.
        id: DocumentId,
        /// Durable schema expected by the collection.
        schema: StoredSchema,
    },
}

/// Owned schema identity recorded alongside a collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSchema {
    /// Stable logical document name.
    pub name: String,
    /// Application-controlled schema version.
    pub version: u32,
    /// Deterministic structural fingerprint.
    pub fingerprint: u64,
}

impl From<Schema> for StoredSchema {
    fn from(schema: Schema) -> Self {
        Self {
            name: schema.name.to_owned(),
            version: schema.version,
            fingerprint: schema.fingerprint,
        }
    }
}

impl Mutation {
    fn collection(&self) -> &str {
        match self {
            Self::Put { collection, .. } | Self::Delete { collection, .. } => collection,
        }
    }
}

/// A mutation that was committed to the durable change log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedMutation {
    /// Kind of mutation that was committed.
    pub kind: ChangeKind,
    /// Collection containing the affected document.
    pub collection: String,
    /// Stable identity of the affected document.
    pub id: DocumentId,
    /// Monotonic local sequence assigned to the change.
    pub sequence: u64,
}

/// A document transformed by an explicit schema migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigratedDocument {
    /// Stable identity retained across the migration.
    pub id: DocumentId,
    /// Newly serialized application payload.
    pub payload: Vec<u8>,
    /// Durable sequence assigned to the migration change.
    pub sequence: u64,
}

/// A document restored from durable storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredDocument {
    /// Stable document identity.
    pub id: DocumentId,
    /// Serialized application payload.
    pub payload: Vec<u8>,
    /// Monotonic local change sequence that last updated the document.
    pub sequence: u64,
}

/// A snapshot of local durable-storage health and size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreStatus {
    /// Greatest committed local change sequence.
    pub frontier: u64,
    /// Number of materialized live documents.
    pub documents: u64,
    /// Number of retained durable changes.
    pub changes: u64,
    /// Number of globally identified changes retained for replication.
    pub replicated_changes: u64,
    /// Result returned by `SQLite`'s quick integrity check.
    pub integrity: String,
}

/// Result of compacting Cyrene's redundant local diagnostic journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionReport {
    /// Journal rows present before compaction.
    pub changes_before: u64,
    /// Journal rows retained after compaction.
    pub changes_after: u64,
    /// Replication records deliberately left untouched.
    pub replicated_changes: u64,
}

impl CompactionReport {
    /// Number of redundant journal rows removed.
    pub const fn removed(self) -> u64 {
        self.changes_before - self.changes_after
    }
}

/// Metadata describing a consistent application-database backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupReport {
    /// Live documents captured in the backup.
    pub documents: u64,
    /// Replicated changes captured for long-offline catch-up.
    pub replicated_changes: u64,
    /// Full `SQLite` integrity-check result for the completed backup.
    pub integrity: String,
}

impl BackupReport {
    /// Returns whether the completed backup passed its full integrity check.
    pub fn is_healthy(&self) -> bool {
        self.integrity == "ok"
    }
}

impl StoreStatus {
    /// Returns whether the database passed its integrity check.
    pub fn is_healthy(&self) -> bool {
        self.integrity == "ok"
    }
}

/// SQLite-backed durable state for one application.
#[derive(Debug)]
pub struct SqliteStore {
    connection: Connection,
}

impl SqliteStore {
    /// Opens or creates a store at `path` and applies compatible migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot open, configure, or migrate the
    /// database, or when its format is incompatible with this version.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).map_err(|error| {
            Error::with_source(
                ErrorCode::Storage,
                format!("couldn't open {}", path.as_ref().display()),
                error,
            )
        })?;
        let mut store = Self { connection };
        store.configure()?;
        store.migrate()?;
        Ok(store)
    }

    /// Opens an independent in-memory store, primarily for tests and examples.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot initialize the in-memory database.
    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().map_err(|error| {
            Error::with_source(
                ErrorCode::Storage,
                "couldn't open an in-memory store",
                error,
            )
        })?;
        let mut store = Self { connection };
        store.configure()?;
        store.migrate()?;
        Ok(store)
    }

    fn configure(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA busy_timeout = 5000;",
            )
            .map_err(|error| storage_error("couldn't configure local storage", error))?;
        Ok(())
    }

    fn migrate(&mut self) -> Result<()> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| storage_error("couldn't begin storage migration", error))?;

        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS cyrene_meta (
                     key   TEXT PRIMARY KEY NOT NULL,
                     value TEXT NOT NULL
                 ) STRICT;

                 CREATE TABLE IF NOT EXISTS documents (
                     space_id   BLOB NOT NULL,
                     collection TEXT NOT NULL,
                     document_id BLOB NOT NULL,
                     payload    BLOB NOT NULL,
                     sequence   INTEGER NOT NULL,
                     PRIMARY KEY (space_id, collection, document_id)
                 ) STRICT;

                 CREATE TABLE IF NOT EXISTS changes (
                     sequence    INTEGER PRIMARY KEY AUTOINCREMENT,
                     space_id    BLOB NOT NULL,
                     collection  TEXT NOT NULL,
                     document_id BLOB NOT NULL,
                     kind        INTEGER NOT NULL,
                     payload     BLOB,
                     committed_at_ms INTEGER NOT NULL
                 ) STRICT;

                 CREATE TABLE IF NOT EXISTS collection_schemas (
                     space_id    BLOB NOT NULL,
                     collection  TEXT NOT NULL,
                     schema_name TEXT NOT NULL,
                     version     INTEGER NOT NULL,
                     fingerprint BLOB NOT NULL,
                     PRIMARY KEY (space_id, collection)
                 ) STRICT;

                 CREATE TABLE IF NOT EXISTS replicated_changes (
                     space_id      BLOB NOT NULL,
                     author_id     BLOB NOT NULL,
                     author_counter INTEGER NOT NULL,
                     encoded       BLOB NOT NULL,
                     PRIMARY KEY (space_id, author_id, author_counter)
                 ) STRICT;",
            )
            .map_err(|error| storage_error("couldn't create storage schema", error))?;

        let found: Option<String> = transaction
            .query_row(
                "SELECT value FROM cyrene_meta WHERE key = 'storage_version'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| storage_error("couldn't read the storage version", error))?;

        match found {
            None => {
                transaction
                    .execute(
                        "INSERT INTO cyrene_meta (key, value) VALUES ('storage_version', ?1)",
                        [STORAGE_VERSION.to_string()],
                    )
                    .map_err(|error| storage_error("couldn't record the storage version", error))?;
            }
            Some(version) if version == STORAGE_VERSION.to_string() => {}
            Some(version) => {
                return Err(Error::new(
                    ErrorCode::InvalidData,
                    format!(
                        "storage version {version} is not supported by this Cyrene build (expected \
                         {STORAGE_VERSION})"
                    ),
                ));
            }
        }

        transaction
            .commit()
            .map_err(|error| storage_error("couldn't commit storage migration", error))?;
        Ok(())
    }

    /// Atomically writes a document and its corresponding durable change.
    ///
    /// # Errors
    ///
    /// Returns an error when the collection name is invalid, the system clock
    /// cannot represent the commit time, or the `SQLite` transaction fails.
    pub fn put(
        &mut self,
        space: SpaceId,
        collection: &str,
        id: DocumentId,
        payload: &[u8],
    ) -> Result<u64> {
        let applied = self.apply_batch(
            space,
            vec![Mutation::Put {
                collection: collection.to_owned(),
                id,
                payload: payload.to_vec(),
                schema: legacy_schema(collection),
            }],
        )?;
        Ok(applied[0].sequence)
    }

    /// Atomically deletes a document and records a durable tombstone change.
    ///
    /// # Errors
    ///
    /// Returns an error when the collection name is invalid or the `SQLite`
    /// transaction fails.
    pub fn delete(
        &mut self,
        space: SpaceId,
        collection: &str,
        id: DocumentId,
    ) -> Result<Option<u64>> {
        Ok(self
            .apply_batch(
                space,
                vec![Mutation::Delete {
                    collection: collection.to_owned(),
                    id,
                    schema: legacy_schema(collection),
                }],
            )?
            .first()
            .map(|mutation| mutation.sequence))
    }

    /// Applies mutations as one atomic local transaction.
    ///
    /// Every returned mutation has been appended to the change log and applied
    /// to materialized state in the same commit. Deletes of absent documents are
    /// successful no-ops and are omitted from the returned list.
    ///
    /// # Errors
    ///
    /// Returns an error if any collection name is invalid, the commit timestamp
    /// cannot be represented, or the `SQLite` transaction fails. No mutation is
    /// committed when an error is returned.
    pub fn apply_batch(
        &mut self,
        space: SpaceId,
        mutations: Vec<Mutation>,
    ) -> Result<Vec<AppliedMutation>> {
        if mutations.is_empty() {
            return Ok(Vec::new());
        }
        let committed_at_ms = commit_timestamp_ms()?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| storage_error("couldn't begin a local transaction", error))?;
        let applied = apply_mutations(&transaction, space, mutations, committed_at_ms)?;
        transaction
            .commit()
            .map_err(|error| storage_error("couldn't commit a local transaction", error))?;
        Ok(applied)
    }

    /// Commits materialized mutations and their globally identified replica
    /// changes in one durable transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid mutations, replicated change collisions,
    /// encoding failures, or a failed `SQLite` commit. Every table rolls back
    /// together on error.
    pub fn commit_local(
        &mut self,
        space: SpaceId,
        mutations: Vec<Mutation>,
        replicated: &[Change],
    ) -> Result<(Vec<AppliedMutation>, Vec<bool>)> {
        if mutations.len() != replicated.len() {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "local mutations and replicated changes must have equal lengths",
            ));
        }
        if mutations.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        if replicated.iter().any(|change| change.space != space) {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "a local commit cannot contain changes for another space",
            ));
        }
        let committed_at_ms = commit_timestamp_ms()?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| storage_error("couldn't begin a replicated local commit", error))?;
        let applied = apply_mutations(&transaction, space, mutations, committed_at_ms)?;
        let inserted = append_replicated_transaction(&transaction, replicated)?;
        transaction
            .commit()
            .map_err(|error| storage_error("couldn't commit replicated local state", error))?;
        Ok((applied, inserted))
    }

    /// Atomically retains remote changes and applies their visible
    /// materialized mutations.
    ///
    /// Unlike [`Self::commit_local`], the number of visible mutations may be
    /// smaller than the number of retained changes because duplicates and
    /// losing concurrent writes do not alter materialized state.
    ///
    /// # Errors
    ///
    /// Returns an error for a cross-space change, invalid mutation, change-ID
    /// collision, encoding failure, or failed `SQLite` commit. All durable
    /// effects roll back together.
    pub fn commit_remote(
        &mut self,
        space: SpaceId,
        mutations: Vec<Mutation>,
        replicated: &[Change],
    ) -> Result<(Vec<AppliedMutation>, Vec<bool>)> {
        if replicated.iter().any(|change| change.space != space) {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "a remote commit cannot contain changes for another space",
            ));
        }
        if replicated.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let committed_at_ms = commit_timestamp_ms()?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| storage_error("couldn't begin a remote change commit", error))?;
        let applied = apply_mutations(&transaction, space, mutations, committed_at_ms)?;
        let inserted = append_replicated_transaction(&transaction, replicated)?;
        transaction
            .commit()
            .map_err(|error| storage_error("couldn't commit remote changes", error))?;
        Ok((applied, inserted))
    }

    /// Verifies or records the durable schema for a typed collection.
    ///
    /// # Errors
    ///
    /// Returns an error when the collection name is invalid, the schema differs
    /// from existing durable metadata, or the `SQLite` transaction fails.
    pub fn ensure_collection_schema(
        &mut self,
        space: SpaceId,
        collection: &str,
        schema: &StoredSchema,
    ) -> Result<()> {
        validate_collection(collection)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| storage_error("couldn't begin a schema transaction", error))?;
        ensure_schema(&transaction, space, collection, schema)?;
        transaction
            .commit()
            .map_err(|error| storage_error("couldn't commit collection schema", error))
    }

    /// Lists current collection names and schema fingerprints for a space.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot query metadata or a fingerprint is
    /// malformed.
    pub fn collection_schemas(&self, space: SpaceId) -> Result<Vec<(String, StoredSchema)>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT collection, schema_name, version, fingerprint FROM collection_schemas
                 WHERE space_id = ?1 ORDER BY collection",
            )
            .map_err(|error| storage_error("couldn't prepare collection schemas", error))?;
        let rows = statement
            .query_map([id_bytes(space)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|error| storage_error("couldn't query collection schemas", error))?;
        rows.map(|row| {
            let (collection, name, version, fingerprint) =
                row.map_err(|error| storage_error("couldn't read collection schema", error))?;
            let fingerprint: [u8; 8] = fingerprint.try_into().map_err(|_| {
                Error::new(
                    ErrorCode::InvalidData,
                    format!("collection '{collection}' has a malformed schema fingerprint"),
                )
            })?;
            Ok((
                collection,
                StoredSchema {
                    name,
                    version,
                    fingerprint: u64::from_be_bytes(fingerprint),
                },
            ))
        })
        .collect()
    }

    /// Atomically transforms every payload in a collection and advances its
    /// durable schema identity.
    ///
    /// A logical put change is appended for each transformed document. The
    /// source descriptor must exactly match the recorded schema; migrations
    /// cannot skip an unknown intermediate version.
    ///
    /// # Errors
    ///
    /// Returns an error if the source schema does not match, a document ID is
    /// malformed, `transform` rejects a payload, or the `SQLite` transaction
    /// cannot commit. An error rolls back every payload and metadata update.
    pub fn migrate_collection<F>(
        &mut self,
        space: SpaceId,
        collection: &str,
        from: &StoredSchema,
        to: &StoredSchema,
        mut transform: F,
    ) -> Result<Vec<MigratedDocument>>
    where
        F: FnMut(DocumentId, &[u8]) -> Result<(Vec<u8>, Change)>,
    {
        validate_collection(collection)?;
        if from == to {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "a migration must change the durable schema identity",
            ));
        }
        let committed_at_ms = commit_timestamp_ms()?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| storage_error("couldn't begin a schema migration", error))?;
        require_schema(&transaction, space, collection, from)?;

        let documents = {
            let mut statement = transaction
                .prepare(
                    "SELECT document_id, payload FROM documents
                     WHERE space_id = ?1 AND collection = ?2
                     ORDER BY document_id",
                )
                .map_err(|error| storage_error("couldn't prepare schema migration", error))?;
            let rows = statement
                .query_map(params![id_bytes(space), collection], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|error| storage_error("couldn't read documents for migration", error))?;
            rows.map(|row| {
                let (id, payload) =
                    row.map_err(|error| storage_error("couldn't read a migration row", error))?;
                Ok((document_id_from_bytes(&id)?, payload))
            })
            .collect::<Result<Vec<_>>>()?
        };

        let transformed = documents
            .iter()
            .map(|(id, payload)| {
                transform(*id, payload).and_then(|(next, change)| {
                    validate_migration_change(space, collection, to, *id, &next, &change)?;
                    Ok((*id, next, change))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut migrated = Vec::with_capacity(transformed.len());
        let replicated = transformed
            .iter()
            .map(|(_, _, change)| change.clone())
            .collect::<Vec<_>>();
        for (id, payload, _) in transformed {
            let sequence = append_change(
                &transaction,
                space,
                collection,
                id,
                ChangeKind::Put,
                Some(&payload),
                committed_at_ms,
            )?;
            transaction
                .execute(
                    "UPDATE documents SET payload = ?1, sequence = ?2
                     WHERE space_id = ?3 AND collection = ?4 AND document_id = ?5",
                    params![payload, sequence, id_bytes(space), collection, id_bytes(id)],
                )
                .map_err(|error| storage_error("couldn't write a migrated document", error))?;
            migrated.push(MigratedDocument {
                id,
                payload,
                sequence,
            });
        }
        transaction
            .execute(
                "UPDATE collection_schemas
                 SET schema_name = ?1, version = ?2, fingerprint = ?3
                 WHERE space_id = ?4 AND collection = ?5",
                params![
                    to.name,
                    to.version,
                    to.fingerprint.to_be_bytes(),
                    id_bytes(space),
                    collection
                ],
            )
            .map_err(|error| storage_error("couldn't advance the collection schema", error))?;
        append_replicated_transaction(&transaction, &replicated)?;
        transaction
            .commit()
            .map_err(|error| storage_error("couldn't commit the schema migration", error))?;
        Ok(migrated)
    }

    /// Retrieves one document from its local materialized collection.
    ///
    /// # Errors
    ///
    /// Returns an error when the collection name is invalid or `SQLite` cannot
    /// execute the query.
    pub fn get(
        &self,
        space: SpaceId,
        collection: &str,
        id: DocumentId,
    ) -> Result<Option<StoredDocument>> {
        validate_collection(collection)?;
        self.connection
            .query_row(
                "SELECT payload, sequence FROM documents
                 WHERE space_id = ?1 AND collection = ?2 AND document_id = ?3",
                params![id_bytes(space), collection, id_bytes(id)],
                |row| {
                    Ok(StoredDocument {
                        id,
                        payload: row.get(0)?,
                        sequence: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(|error| storage_error("couldn't read the document", error))
    }

    /// Lists a collection in stable document-ID order.
    ///
    /// # Errors
    ///
    /// Returns an error when the collection name is invalid, `SQLite` cannot
    /// execute the query, or a stored identifier is malformed.
    pub fn list(&self, space: SpaceId, collection: &str) -> Result<Vec<StoredDocument>> {
        validate_collection(collection)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT document_id, payload, sequence FROM documents
                 WHERE space_id = ?1 AND collection = ?2
                 ORDER BY document_id",
            )
            .map_err(|error| storage_error("couldn't prepare the collection query", error))?;
        let rows = statement
            .query_map(params![id_bytes(space), collection], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok((bytes, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| storage_error("couldn't query the collection", error))?;

        rows.map(|row| {
            let (bytes, payload, sequence) =
                row.map_err(|error| storage_error("couldn't read a collection row", error))?;
            Ok(StoredDocument {
                id: document_id_from_bytes(&bytes)?,
                payload,
                sequence,
            })
        })
        .collect()
    }

    /// Returns the greatest local change sequence, or zero for an empty store.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot inspect the change log.
    pub fn frontier(&self) -> Result<u64> {
        self.connection
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM changes",
                [],
                |row| row.get(0),
            )
            .map_err(|error| storage_error("couldn't read the local frontier", error))
    }

    /// Inspects durable local state without modifying it.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot query its integrity or local counts.
    pub fn status(&self) -> Result<StoreStatus> {
        let integrity = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|error| storage_error("couldn't check local storage integrity", error))?;
        Ok(StoreStatus {
            frontier: self.frontier()?,
            documents: query_count(&self.connection, "SELECT COUNT(*) FROM documents")?,
            changes: query_count(&self.connection, "SELECT COUNT(*) FROM changes")?,
            replicated_changes: query_count(
                &self.connection,
                "SELECT COUNT(*) FROM replicated_changes",
            )?,
            integrity,
        })
    }

    /// Creates a transactionally consistent online backup at a new path.
    ///
    /// The destination must not already exist. The backup includes materialized
    /// state, schemas, replica identity, and complete replicated history, and
    /// is accepted only after a full `SQLite` integrity check succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error without replacing an existing destination, or when the
    /// online backup or its full integrity check fails.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<BackupReport> {
        let destination = destination.as_ref();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|error| {
                Error::with_source(
                    ErrorCode::Storage,
                    format!(
                        "couldn't create new backup destination {}",
                        destination.display()
                    ),
                    error,
                )
            })?;
        let result = (|| {
            let mut target = Connection::open(destination).map_err(|error| {
                storage_error("couldn't open the new backup destination", error)
            })?;
            {
                let backup = rusqlite::backup::Backup::new(&self.connection, &mut target)
                    .map_err(|error| storage_error("couldn't begin the online backup", error))?;
                backup
                    .run_to_completion(BACKUP_PAGES_PER_STEP, BACKUP_PAUSE, None)
                    .map_err(|error| storage_error("couldn't complete the online backup", error))?;
            }
            let integrity = target
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .map_err(|error| storage_error("couldn't verify the completed backup", error))?;
            let report = BackupReport {
                documents: query_count(&target, "SELECT COUNT(*) FROM documents")?,
                replicated_changes: query_count(
                    &target,
                    "SELECT COUNT(*) FROM replicated_changes",
                )?,
                integrity,
            };
            if !report.is_healthy() {
                return Err(Error::new(
                    ErrorCode::InvalidData,
                    format!(
                        "the completed backup failed its integrity check: {}",
                        report.integrity
                    ),
                ));
            }
            Ok(report)
        })();
        if result.is_err() {
            let _ = fs::remove_file(destination);
        }
        result
    }

    /// Bounds the redundant local diagnostic journal while preserving all
    /// replication history and the latest local sequence.
    ///
    /// At least one journal row is retained for a non-empty database so local
    /// sequence numbers remain monotonic across restarts. Replicated changes,
    /// including causal deletes, are never removed by this operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot compact or optimize the database.
    pub fn compact_local_journal(&mut self, retain: u64) -> Result<CompactionReport> {
        let changes_before = query_count(&self.connection, "SELECT COUNT(*) FROM changes")?;
        let replicated_changes =
            query_count(&self.connection, "SELECT COUNT(*) FROM replicated_changes")?;
        let retain = retain.max(1);
        let retain = i64::try_from(retain).map_err(|error| {
            Error::with_source(
                ErrorCode::InvalidInput,
                "the journal retention exceeds SQLite's supported range",
                error,
            )
        })?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| storage_error("couldn't begin local journal compaction", error))?;
        transaction
            .execute(
                "DELETE FROM changes
                 WHERE sequence < COALESCE(
                     (SELECT sequence FROM changes ORDER BY sequence DESC LIMIT 1 OFFSET ?1),
                     0
                 )",
                [retain - 1],
            )
            .map_err(|error| storage_error("couldn't compact the local journal", error))?;
        transaction
            .commit()
            .map_err(|error| storage_error("couldn't commit local journal compaction", error))?;
        self.connection
            .execute_batch("PRAGMA optimize;")
            .map_err(|error| storage_error("couldn't optimize compacted storage", error))?;
        Ok(CompactionReport {
            changes_before,
            changes_after: query_count(&self.connection, "SELECT COUNT(*) FROM changes")?,
            replicated_changes,
        })
    }

    /// Returns the store's stable local replica identity, creating it once.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier is malformed or `SQLite` cannot
    /// read or persist it.
    pub fn replica_id(&mut self) -> Result<ReplicaId> {
        let found: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM cyrene_meta WHERE key = 'replica_id'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| storage_error("couldn't read the replica identity", error))?;
        if let Some(value) = found {
            return value.parse().map_err(|error| {
                Error::with_source(
                    ErrorCode::InvalidData,
                    "the stored replica identity is invalid",
                    error,
                )
            });
        }
        let replica = ReplicaId::new();
        self.connection
            .execute(
                "INSERT INTO cyrene_meta (key, value) VALUES ('replica_id', ?1)",
                [replica.to_string()],
            )
            .map_err(|error| storage_error("couldn't persist the replica identity", error))?;
        Ok(replica)
    }

    /// Durably reserves the next contiguous block of merge-operation counters.
    ///
    /// The returned pair is `(previous_high_water, new_high_water)`, suitable
    /// for a reserved merge-operation actor. Gaps after a crash are intentional
    /// and safe; counters are never reused.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero-sized or overflowing reservation, malformed
    /// metadata, or a failed `SQLite` transaction.
    pub fn reserve_crdt_counters(&mut self, size: u64) -> Result<(u64, u64)> {
        if size == 0 {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "a counter reservation must contain at least one operation",
            ));
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| storage_error("couldn't begin a counter reservation", error))?;
        let found: Option<String> = transaction
            .query_row(
                "SELECT value FROM cyrene_meta WHERE key = 'crdt_counter_high_water'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| storage_error("couldn't read the CRDT counter high-water", error))?;
        let previous = found
            .as_deref()
            .unwrap_or("0")
            .parse::<u64>()
            .map_err(|error| {
                Error::with_source(
                    ErrorCode::InvalidData,
                    "the CRDT counter high-water is malformed",
                    error,
                )
            })?;
        let next = previous.checked_add(size).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidData,
                "the CRDT operation counter is exhausted",
            )
        })?;
        transaction
            .execute(
                "INSERT INTO cyrene_meta (key, value)
                 VALUES ('crdt_counter_high_water', ?1)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                [next.to_string()],
            )
            .map_err(|error| storage_error("couldn't reserve CRDT counters", error))?;
        transaction
            .commit()
            .map_err(|error| storage_error("couldn't commit CRDT counter reservation", error))?;
        Ok((previous, next))
    }

    /// Atomically retains globally identified changes for later reconciliation.
    ///
    /// The returned vector contains `true` for newly inserted changes and
    /// `false` for exact duplicates. Reusing an existing change ID with
    /// different content rejects and rolls back the complete batch.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding fails, a counter exceeds `SQLite`'s signed
    /// integer range, a change ID collides, or the transaction cannot commit.
    pub fn append_replicated(&mut self, changes: &[Change]) -> Result<Vec<bool>> {
        let transaction = self.connection.transaction().map_err(|error| {
            storage_error("couldn't begin a replicated change transaction", error)
        })?;
        let inserted = append_replicated_transaction(&transaction, changes)?;
        transaction
            .commit()
            .map_err(|error| storage_error("couldn't commit replicated changes", error))?;
        Ok(inserted)
    }

    /// Loads every retained change for `space` in stable author/counter order.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot read the log or retained bytes do
    /// not decode into a change for the requested space.
    pub fn replicated_changes(&self, space: SpaceId) -> Result<Vec<Change>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT encoded FROM replicated_changes
                 WHERE space_id = ?1 ORDER BY author_id, author_counter",
            )
            .map_err(|error| storage_error("couldn't prepare replicated change loading", error))?;
        let rows = statement
            .query_map([id_bytes(space)], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|error| storage_error("couldn't load replicated changes", error))?;
        rows.map(|row| {
            let bytes =
                row.map_err(|error| storage_error("couldn't read a replicated change row", error))?;
            let change: Change = serde_json::from_slice(&bytes).map_err(|error| {
                Error::with_source(
                    ErrorCode::InvalidData,
                    "a retained replicated change is malformed",
                    error,
                )
            })?;
            if change.space != space {
                return Err(Error::new(
                    ErrorCode::InvalidData,
                    "a retained replicated change is stored under the wrong space",
                ));
            }
            Ok(change)
        })
        .collect()
    }

    /// Returns the store's default space, creating it on first use.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot read or persist the identifier, or
    /// when an existing identifier is malformed.
    pub fn default_space(&mut self) -> Result<SpaceId> {
        let found: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM cyrene_meta WHERE key = 'default_space'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| storage_error("couldn't read the default space", error))?;
        if let Some(value) = found {
            return value.parse().map_err(|error| {
                Error::with_source(
                    ErrorCode::InvalidData,
                    "the stored default space identifier is invalid",
                    error,
                )
            });
        }

        let space = SpaceId::new();
        self.connection
            .execute(
                "INSERT INTO cyrene_meta (key, value) VALUES ('default_space', ?1)",
                [space.to_string()],
            )
            .map_err(|error| storage_error("couldn't create the default space", error))?;
        Ok(space)
    }

    /// Binds a new store to `space`, or verifies its existing binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is already bound to a different space or
    /// `SQLite` cannot persist the binding.
    pub fn bind_default_space(&mut self, space: SpaceId) -> Result<()> {
        let found: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM cyrene_meta WHERE key = 'default_space'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| storage_error("couldn't read the default space", error))?;
        if let Some(value) = found {
            let found: SpaceId = value.parse().map_err(|error| {
                Error::with_source(
                    ErrorCode::InvalidData,
                    "the stored default space identifier is invalid",
                    error,
                )
            })?;
            if found == space {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorCode::InvalidInput,
                    format!("store belongs to space {found}, not requested space {space}"),
                ))
            }
        } else {
            self.connection
                .execute(
                    "INSERT INTO cyrene_meta (key, value) VALUES ('default_space', ?1)",
                    [space.to_string()],
                )
                .map_err(|error| storage_error("couldn't bind the default space", error))?;
            Ok(())
        }
    }
}

fn validate_migration_change(
    space: SpaceId,
    collection: &str,
    schema: &StoredSchema,
    document: DocumentId,
    payload: &[u8],
    change: &Change,
) -> Result<()> {
    if change.space != space {
        return Err(Error::new(
            ErrorCode::InvalidInput,
            "a migration change targets another space",
        ));
    }
    match &change.operation {
        cyrene_sync::Operation::Put {
            collection: changed_collection,
            document: changed_document,
            schema: changed_schema,
            payload: changed_payload,
        } if changed_collection == collection
            && *changed_document == document
            && *changed_schema == schema.fingerprint
            && changed_payload == payload =>
        {
            Ok(())
        }
        _ => Err(Error::new(
            ErrorCode::InvalidInput,
            "a migration change does not match its transformed document",
        )),
    }
}

fn apply_mutations(
    transaction: &Transaction<'_>,
    space: SpaceId,
    mutations: Vec<Mutation>,
    committed_at_ms: i64,
) -> Result<Vec<AppliedMutation>> {
    for mutation in &mutations {
        validate_collection(mutation.collection())?;
    }
    let mut applied = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        match mutation {
            Mutation::Put {
                collection,
                id,
                payload,
                schema,
            } => {
                ensure_schema(transaction, space, &collection, &schema)?;
                let sequence = append_change(
                    transaction,
                    space,
                    &collection,
                    id,
                    ChangeKind::Put,
                    Some(&payload),
                    committed_at_ms,
                )?;
                transaction
                    .execute(
                        "INSERT INTO documents
                             (space_id, collection, document_id, payload, sequence)
                         VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT (space_id, collection, document_id) DO UPDATE SET
                             payload = excluded.payload,
                             sequence = excluded.sequence",
                        params![id_bytes(space), collection, id_bytes(id), payload, sequence],
                    )
                    .map_err(|error| storage_error("couldn't write a document", error))?;
                applied.push(AppliedMutation {
                    kind: ChangeKind::Put,
                    collection,
                    id,
                    sequence,
                });
            }
            Mutation::Delete {
                collection,
                id,
                schema,
            } => {
                ensure_schema(transaction, space, &collection, &schema)?;
                let deleted = transaction
                    .execute(
                        "DELETE FROM documents
                         WHERE space_id = ?1 AND collection = ?2 AND document_id = ?3",
                        params![id_bytes(space), collection, id_bytes(id)],
                    )
                    .map_err(|error| storage_error("couldn't delete a document", error))?;
                if deleted == 0 {
                    continue;
                }
                let sequence = append_change(
                    transaction,
                    space,
                    &collection,
                    id,
                    ChangeKind::Delete,
                    None,
                    committed_at_ms,
                )?;
                applied.push(AppliedMutation {
                    kind: ChangeKind::Delete,
                    collection,
                    id,
                    sequence,
                });
            }
        }
    }
    Ok(applied)
}

fn append_replicated_transaction(
    transaction: &Transaction<'_>,
    changes: &[Change],
) -> Result<Vec<bool>> {
    let encoded = changes
        .iter()
        .map(|change| {
            let counter = i64::try_from(change.id.counter).map_err(|error| {
                Error::with_source(
                    ErrorCode::InvalidData,
                    "replicated change counter exceeds the durable format limit",
                    error,
                )
            })?;
            let bytes = serde_json::to_vec(change).map_err(|error| {
                Error::with_source(
                    ErrorCode::InvalidData,
                    "couldn't encode a replicated change",
                    error,
                )
            })?;
            Ok((change, counter, bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut inserted = Vec::with_capacity(encoded.len());
    for (change, counter, bytes) in encoded {
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT encoded FROM replicated_changes
                 WHERE space_id = ?1 AND author_id = ?2 AND author_counter = ?3",
                params![id_bytes(change.space), id_bytes(change.id.replica), counter],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| storage_error("couldn't inspect a replicated change", error))?;
        match existing {
            Some(existing) if existing == bytes => inserted.push(false),
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidData,
                    format!(
                        "replicated change {}:{} collides with different durable content",
                        change.id.replica, change.id.counter
                    ),
                ));
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO replicated_changes
                             (space_id, author_id, author_counter, encoded)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            id_bytes(change.space),
                            id_bytes(change.id.replica),
                            counter,
                            bytes
                        ],
                    )
                    .map_err(|error| storage_error("couldn't append a replicated change", error))?;
                inserted.push(true);
            }
        }
    }
    Ok(inserted)
}

fn ensure_schema(
    transaction: &Transaction<'_>,
    space: SpaceId,
    collection: &str,
    schema: &StoredSchema,
) -> Result<()> {
    let found: Option<(String, u32, Vec<u8>)> = transaction
        .query_row(
            "SELECT schema_name, version, fingerprint FROM collection_schemas
             WHERE space_id = ?1 AND collection = ?2",
            params![id_bytes(space), collection],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| storage_error("couldn't inspect the collection schema", error))?;
    let fingerprint = schema.fingerprint.to_be_bytes();
    match found {
        None => {
            transaction
                .execute(
                    "INSERT INTO collection_schemas
                         (space_id, collection, schema_name, version, fingerprint)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        id_bytes(space),
                        collection,
                        schema.name,
                        schema.version,
                        fingerprint
                    ],
                )
                .map_err(|error| storage_error("couldn't record the collection schema", error))?;
            Ok(())
        }
        Some((name, version, found_fingerprint))
            if name == schema.name
                && version == schema.version
                && found_fingerprint == fingerprint =>
        {
            Ok(())
        }
        Some((name, version, _)) => Err(Error::new(
            ErrorCode::InvalidData,
            format!(
                "collection '{collection}' contains schema '{name}' version {version}, but the \
                 application requested '{}' version {}; define and run an explicit migration",
                schema.name, schema.version
            ),
        )),
    }
}

fn require_schema(
    transaction: &Transaction<'_>,
    space: SpaceId,
    collection: &str,
    expected: &StoredSchema,
) -> Result<()> {
    let found: Option<(String, u32, Vec<u8>)> = transaction
        .query_row(
            "SELECT schema_name, version, fingerprint FROM collection_schemas
             WHERE space_id = ?1 AND collection = ?2",
            params![id_bytes(space), collection],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| storage_error("couldn't inspect the source schema", error))?;
    let expected_fingerprint = expected.fingerprint.to_be_bytes();
    match found {
        Some((name, version, fingerprint))
            if name == expected.name
                && version == expected.version
                && fingerprint == expected_fingerprint =>
        {
            Ok(())
        }
        Some((name, version, _)) => Err(Error::new(
            ErrorCode::InvalidData,
            format!(
                "cannot migrate collection '{collection}' from '{}' version {}: durable data is \
                 '{name}' version {version}",
                expected.name, expected.version
            ),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidData,
            format!("collection '{collection}' has no durable source schema to migrate"),
        )),
    }
}

fn legacy_schema(collection: &str) -> StoredSchema {
    StoredSchema {
        name: format!("cyrene.untyped.{collection}"),
        version: 1,
        fingerprint: 0,
    }
}

fn append_change(
    transaction: &Transaction<'_>,
    space: SpaceId,
    collection: &str,
    id: DocumentId,
    kind: ChangeKind,
    payload: Option<&[u8]>,
    committed_at_ms: i64,
) -> Result<u64> {
    transaction
        .execute(
            "INSERT INTO changes
                 (space_id, collection, document_id, kind, payload, committed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id_bytes(space),
                collection,
                id_bytes(id),
                kind as i64,
                payload,
                committed_at_ms
            ],
        )
        .map_err(|error| storage_error("couldn't append a durable change", error))?;
    u64::try_from(transaction.last_insert_rowid()).map_err(|error| {
        Error::with_source(
            ErrorCode::Storage,
            "change sequence is outside the valid range",
            error,
        )
    })
}

fn commit_timestamp_ms() -> Result<i64> {
    let milliseconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| Error::with_source(ErrorCode::Storage, "system clock is invalid", error))?
        .as_millis();
    i64::try_from(milliseconds).map_err(|error| {
        Error::with_source(
            ErrorCode::Storage,
            "system time is outside SQLite's range",
            error,
        )
    })
}

fn validate_collection(collection: &str) -> Result<()> {
    if collection.is_empty() || collection.len() > 128 {
        return Err(Error::new(
            ErrorCode::InvalidInput,
            "collection names must contain between 1 and 128 bytes",
        ));
    }
    Ok(())
}

trait StoredId {
    fn stored_u128(self) -> u128;
}

impl StoredId for SpaceId {
    fn stored_u128(self) -> u128 {
        self.as_u128()
    }
}

impl StoredId for DocumentId {
    fn stored_u128(self) -> u128 {
        self.as_u128()
    }
}

impl StoredId for ReplicaId {
    fn stored_u128(self) -> u128 {
        self.as_u128()
    }
}

fn id_bytes(id: impl StoredId) -> [u8; 16] {
    id.stored_u128().to_be_bytes()
}

fn document_id_from_bytes(bytes: &[u8]) -> Result<DocumentId> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
        Error::new(
            ErrorCode::InvalidData,
            "a stored document identifier has an invalid length",
        )
    })?;
    Ok(DocumentId::from_u128(u128::from_be_bytes(bytes)))
}

fn storage_error(message: &'static str, error: rusqlite::Error) -> Error {
    Error::with_source(ErrorCode::Storage, message, error)
}

fn query_count(connection: &Connection, query: &'static str) -> Result<u64> {
    connection
        .query_row(query, [], |row| row.get(0))
        .map_err(|error| storage_error("couldn't inspect local storage", error))
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use cyrene_core::{DocumentId, ErrorCode, ReplicaId, SpaceId};
    use cyrene_sync::{Change, ChangeId, Operation, Timestamp};

    use super::SqliteStore;

    #[test]
    fn documents_and_changes_commit_together() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let space = SpaceId::new();
        let id = DocumentId::new();

        let sequence = store.put(space, "notes", id, br#"{"hello":true}"#).unwrap();
        let document = store.get(space, "notes", id).unwrap().unwrap();

        assert_eq!(sequence, 1);
        assert_eq!(document.sequence, sequence);
        assert_eq!(store.frontier().unwrap(), sequence);
        assert_eq!(store.delete(space, "notes", id).unwrap(), Some(2));
        assert!(store.get(space, "notes", id).unwrap().is_none());
    }

    #[test]
    fn a_file_store_survives_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.db");
        let space = SpaceId::new();
        let id = DocumentId::new();

        SqliteStore::open(&path)
            .unwrap()
            .put(space, "notes", id, b"persistent")
            .unwrap();

        let reopened = SqliteStore::open(path).unwrap();
        assert_eq!(
            reopened.get(space, "notes", id).unwrap().unwrap().payload,
            b"persistent"
        );
    }

    #[test]
    fn online_backup_is_complete_verified_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.db");
        let destination = directory.path().join("backup.db");
        let space = SpaceId::from_u128(7);
        let document = DocumentId::from_u128(11);
        let (replica, change) = {
            let mut store = SqliteStore::open(&source).unwrap();
            store.bind_default_space(space).unwrap();
            store.put(space, "notes", document, b"safe").unwrap();
            let replica = store.replica_id().unwrap();
            let change = sample_change(replica, space, 1, b"safe");
            store
                .append_replicated(std::slice::from_ref(&change))
                .unwrap();
            let report = store.backup_to(&destination).unwrap();
            assert!(report.is_healthy());
            assert_eq!(report.documents, 1);
            assert_eq!(report.replicated_changes, 1);
            assert!(store.backup_to(&destination).is_err());
            (replica, change)
        };

        let mut restored = SqliteStore::open(destination).unwrap();
        assert_eq!(restored.default_space().unwrap(), space);
        assert_eq!(restored.replica_id().unwrap(), replica);
        assert_eq!(
            restored
                .get(space, "notes", document)
                .unwrap()
                .unwrap()
                .payload,
            b"safe"
        );
        assert_eq!(restored.replicated_changes(space).unwrap(), [change]);
        let status = restored.status().unwrap();
        assert!(status.is_healthy());
        assert_eq!(status.frontier, 1);
    }

    #[test]
    fn compaction_only_bounds_the_redundant_local_journal() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let space = SpaceId::from_u128(7);
        let document = DocumentId::from_u128(11);
        let replica = store.replica_id().unwrap();
        for counter in 1..=5 {
            let payload = counter.to_string();
            store
                .put(space, "notes", document, payload.as_bytes())
                .unwrap();
            store
                .append_replicated(&[sample_change(replica, space, counter, payload.as_bytes())])
                .unwrap();
        }

        let report = store.compact_local_journal(2).unwrap();
        assert_eq!(report.changes_before, 5);
        assert_eq!(report.changes_after, 2);
        assert_eq!(report.removed(), 3);
        assert_eq!(report.replicated_changes, 5);
        assert_eq!(store.frontier().unwrap(), 5);
        assert_eq!(store.replicated_changes(space).unwrap().len(), 5);
        assert_eq!(
            store
                .get(space, "notes", document)
                .unwrap()
                .unwrap()
                .payload,
            b"5"
        );
    }

    #[test]
    fn status_explains_local_durability() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let space = SpaceId::new();
        store
            .put(space, "notes", DocumentId::new(), b"persistent")
            .unwrap();

        let status = store.status().unwrap();
        assert!(status.is_healthy());
        assert_eq!(status.documents, 1);
        assert_eq!(status.changes, 1);
        assert_eq!(status.frontier, 1);
    }

    #[test]
    fn an_acknowledged_commit_survives_process_abort() {
        const CHILD_ENV: &str = "CYRENE_CRASH_WRITER_PATH";
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("crash.db");
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::crash_writer_helper"])
            .env(CHILD_ENV, &path)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "helper should terminate by aborting"
        );

        let store = SqliteStore::open(path).unwrap();
        let status = store.status().unwrap();
        assert!(status.is_healthy());
        assert_eq!(status.documents, 1);
        assert_eq!(status.changes, 1);
    }

    #[test]
    fn crash_writer_helper() {
        let Ok(path) = std::env::var("CYRENE_CRASH_WRITER_PATH") else {
            return;
        };
        let mut store = SqliteStore::open(path).unwrap();
        store
            .put(
                SpaceId::from_u128(1),
                "notes",
                DocumentId::from_u128(1),
                b"safe",
            )
            .unwrap();
        std::process::abort();
    }

    #[test]
    fn replica_identity_and_changes_survive_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replica.db");
        let space = SpaceId::from_u128(7);
        let (replica, change) = {
            let mut store = SqliteStore::open(&path).unwrap();
            let replica = store.replica_id().unwrap();
            let change = sample_change(replica, space, 1, b"hello");
            assert_eq!(
                store
                    .append_replicated(std::slice::from_ref(&change))
                    .unwrap(),
                [true]
            );
            assert_eq!(
                store
                    .append_replicated(std::slice::from_ref(&change))
                    .unwrap(),
                [false]
            );
            (replica, change)
        };

        let mut reopened = SqliteStore::open(path).unwrap();
        assert_eq!(reopened.replica_id().unwrap(), replica);
        assert_eq!(reopened.replicated_changes(space).unwrap(), [change]);
        assert_eq!(reopened.status().unwrap().replicated_changes, 1);
    }

    #[test]
    fn a_change_id_collision_rolls_back_the_complete_batch() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let space = SpaceId::from_u128(7);
        let replica = store.replica_id().unwrap();
        let original = sample_change(replica, space, 1, b"original");
        store
            .append_replicated(std::slice::from_ref(&original))
            .unwrap();
        let next = sample_change(replica, space, 2, b"next");
        let collision = sample_change(replica, space, 1, b"different");

        let error = store.append_replicated(&[next, collision]).unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidData);
        assert_eq!(store.replicated_changes(space).unwrap(), [original]);
    }

    fn sample_change(replica: ReplicaId, space: SpaceId, counter: u64, payload: &[u8]) -> Change {
        Change {
            id: ChangeId { replica, counter },
            space,
            timestamp: Timestamp {
                physical_ms: counter,
                logical: 0,
                replica,
            },
            operation: Operation::Put {
                collection: "notes".into(),
                document: DocumentId::from_u128(1),
                schema: 1,
                payload: payload.to_vec(),
            },
        }
    }
}
