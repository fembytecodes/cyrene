use std::{collections::BTreeSet, sync::Arc};

use cyrene_core::{Error, ErrorCode, Result};
use cyrene_store::{Mutation, StoredSchema};
use cyrene_sync::{Apply, Change as ReplicationChange, Frontier, Operation};

use crate::{
    App,
    app::{MergeStrategy, unix_time_ms},
    collection::RawChange,
};

const MAX_IMPORT_CHANGES: usize = 4_096;

/// One bounded page toward a fixed replication target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplicationPage {
    pub(crate) changes: Vec<ReplicationChange>,
    pub(crate) has_more: bool,
}

/// Result of atomically importing a batch of replication changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncReceipt {
    received: usize,
    retained: usize,
    visible: usize,
    frontier: Frontier,
}

impl SyncReceipt {
    /// Number of changes presented by the peer, including duplicates.
    pub const fn received(&self) -> usize {
        self.received
    }

    /// Number of previously unknown changes retained durably.
    pub const fn retained(&self) -> usize {
        self.retained
    }

    /// Number of incoming changes that advanced a visible document winner.
    pub const fn visible(&self) -> usize {
        self.visible
    }

    /// Contiguous frontier after the import.
    pub const fn frontier(&self) -> &Frontier {
        &self.frontier
    }
}

impl App {
    /// Returns a snapshot of this replica's contiguous reconciliation frontier.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-process replica lock was poisoned.
    pub fn replication_frontier(&self) -> Result<Frontier> {
        self.replica
            .lock()
            .map(|replica| replica.frontier().clone())
            .map_err(|error| replica_lock_error(&error))
    }

    /// Returns retained changes the supplied peer frontier is known to lack.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-process replica lock was poisoned.
    pub fn changes_since(&self, peer: &Frontier) -> Result<Vec<ReplicationChange>> {
        self.replica
            .lock()
            .map(|replica| replica.missing_for(peer))
            .map_err(|error| replica_lock_error(&error))
    }

    pub(crate) fn changes_toward(
        &self,
        peer: &Frontier,
        target: &Frontier,
        limit: usize,
    ) -> Result<ReplicationPage> {
        self.replica
            .lock()
            .map(|replica| {
                let (changes, has_more) = replica.missing_for_target(peer, target, limit);
                ReplicationPage { changes, has_more }
            })
            .map_err(|error| replica_lock_error(&error))
    }

    /// Validates and atomically imports remote changes into durable and
    /// materialized local state.
    ///
    /// Schemas must first be declared by opening the corresponding typed
    /// collection. Duplicate and losing changes remain safe: duplicates are not
    /// retained again, while non-winning changes are retained for reconciliation
    /// without touching materialized documents.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch is oversized, targets another space, uses
    /// an undeclared or incompatible schema, contains malformed/colliding
    /// changes, or cannot commit locally. The entire batch rolls back and no
    /// subscriber is notified.
    pub async fn apply_changes(&self, changes: Vec<ReplicationChange>) -> Result<SyncReceipt> {
        if changes.len() > MAX_IMPORT_CHANGES {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                format!("a replication batch may contain at most {MAX_IMPORT_CHANGES} changes"),
            ));
        }
        if changes.is_empty() {
            return Ok(SyncReceipt {
                received: 0,
                retained: 0,
                visible: 0,
                frontier: self.replication_frontier()?,
            });
        }
        let received = changes.len();
        let schemas = self
            .schemas
            .lock()
            .map_err(|error| schema_lock_error(&error))?
            .clone();
        let mergers = self
            .mergers
            .lock()
            .map_err(|error| merger_lock_error(&error))?
            .clone();
        validate_schemas(&changes, &schemas)?;
        let store = Arc::clone(&self.store);
        let replica = Arc::clone(&self.replica);
        let space = self.space;
        let now_ms = unix_time_ms()?;
        let (receipt, notifications) = tokio::task::spawn_blocking(move || {
            let mut replica = replica.lock().map_err(|error| replica_lock_error(&error))?;
            let mut staged = replica.clone();
            let mut mutations = Vec::new();
            let mut notifications = Vec::new();
            let mut affected = BTreeSet::new();
            for change in &changes {
                match staged.apply(change.clone(), now_ms)? {
                    Apply::Applied { visible } => {
                        let merge_enabled = mergers
                            .get(change.operation.collection())
                            .is_some_and(|strategy| strategy.enabled);
                        if visible || merge_enabled {
                            affected.insert((
                                change.operation.collection().to_owned(),
                                change.operation.document(),
                            ));
                        }
                    }
                    Apply::Duplicate => {}
                }
            }
            for (collection, document) in affected {
                let schema = schemas.get(&collection).cloned().ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidData,
                        "validated replication schema disappeared",
                    )
                })?;
                let strategy = mergers.get(&collection).copied();
                let (mutation, notification) =
                    materialize(&staged, &collection, document, schema, strategy)?;
                mutations.push(mutation);
                notifications.push(notification);
            }
            let visible = mutations.len();
            let (_, inserted) = store
                .lock()
                .map_err(|error| storage_lock_error(&error))?
                .commit_remote(space, mutations, &changes)?;
            let retained = inserted.into_iter().filter(|inserted| *inserted).count();
            let frontier = staged.frontier().clone();
            *replica = staged;
            Ok::<_, Error>((
                SyncReceipt {
                    received,
                    retained,
                    visible,
                    frontier,
                },
                notifications,
            ))
        })
        .await
        .map_err(|error| {
            Error::with_source(
                ErrorCode::Storage,
                "the replication import worker stopped unexpectedly",
                error,
            )
        })??;

        for notification in notifications {
            let _ = self.changes.send(notification);
        }
        Ok(receipt)
    }
}

fn validate_schemas(
    changes: &[ReplicationChange],
    schemas: &std::collections::BTreeMap<String, StoredSchema>,
) -> Result<()> {
    for change in changes {
        let collection = change.operation.collection();
        let schema = schemas.get(collection).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidData,
                format!("collection '{collection}' has not been opened with a typed schema"),
            )
        })?;
        if schema.fingerprint != change.operation.schema() {
            return Err(Error::new(
                ErrorCode::InvalidData,
                format!(
                    "collection '{collection}' expects schema {:016x}, received {:016x}",
                    schema.fingerprint,
                    change.operation.schema()
                ),
            ));
        }
    }
    Ok(())
}

fn materialize(
    replica: &cyrene_sync::Replica,
    collection: &str,
    document: cyrene_core::DocumentId,
    schema: StoredSchema,
    strategy: Option<MergeStrategy>,
) -> Result<(Mutation, RawChange)> {
    let winner = replica.document(collection, document).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidData,
            "replica applied a change without a materialized winner",
        )
    })?;
    match &winner.payload {
        Some(winner_payload) => {
            let payload = if let Some(strategy) = strategy.filter(|strategy| strategy.enabled) {
                let latest_delete = replica
                    .changes_for_document(collection, document)
                    .filter(|change| matches!(change.operation, Operation::Delete { .. }))
                    .map(|change| (change.timestamp, change.id))
                    .max();
                let concurrent = replica
                    .changes_for_document(collection, document)
                    .filter(|change| change.operation.schema() == schema.fingerprint)
                    .filter(|change| {
                        latest_delete.is_none_or(|deleted| (change.timestamp, change.id) > deleted)
                    })
                    .filter(|change| change.id != winner.change)
                    .filter_map(|change| match &change.operation {
                        Operation::Put { payload, .. } => Some(payload.as_slice()),
                        Operation::Delete { .. } => None,
                    })
                    .collect::<Vec<_>>();
                (strategy.merge)(winner_payload, &concurrent)?
            } else {
                winner_payload.clone()
            };
            Ok((
                Mutation::Put {
                    collection: collection.to_owned(),
                    id: document,
                    payload: payload.clone(),
                    schema,
                },
                RawChange {
                    collection: Arc::from(collection.to_owned()),
                    id: document,
                    payload: Some(Arc::from(payload)),
                },
            ))
        }
        None => Ok((
            Mutation::Delete {
                collection: collection.to_owned(),
                id: document,
                schema,
            },
            RawChange {
                collection: Arc::from(collection.to_owned()),
                id: document,
                payload: None,
            },
        )),
    }
}

fn replica_lock_error<T>(error: &std::sync::PoisonError<T>) -> Error {
    Error::new(
        ErrorCode::Storage,
        format!("the local replica lock was poisoned: {error}"),
    )
}

fn schema_lock_error<T>(error: &std::sync::PoisonError<T>) -> Error {
    Error::new(
        ErrorCode::Storage,
        format!("the local schema lock was poisoned: {error}"),
    )
}

fn storage_lock_error<T>(error: &std::sync::PoisonError<T>) -> Error {
    Error::new(
        ErrorCode::Storage,
        format!("the local storage lock was poisoned: {error}"),
    )
}

fn merger_lock_error<T>(error: &std::sync::PoisonError<T>) -> Error {
    Error::new(
        ErrorCode::Storage,
        format!("the local merge registry lock was poisoned: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use cyrene_core::{DocumentId, SpaceId};
    use serde::{Deserialize, Serialize};

    use crate::{Actor, App, Change, Document, ErrorCode, Text};

    #[derive(Debug, Deserialize, Document, Eq, PartialEq, Serialize)]
    #[cyrene(name = "replication.note", version = 1)]
    struct Note {
        #[cyrene(id = 1)]
        text: String,
    }

    #[derive(Debug, Deserialize, Document, Eq, PartialEq, Serialize)]
    #[cyrene(name = "replication.rich-note", version = 1)]
    struct RichNote {
        #[cyrene(id = 1)]
        title: String,
        #[cyrene(id = 2, merge)]
        body: Text,
    }

    #[tokio::test]
    async fn independent_durable_apps_converge_and_resume_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first.db");
        let second_path = directory.path().join("second.db");
        let space = SpaceId::from_u128(42);
        let first = App::open_space(&first_path, space).await.unwrap();
        let second = App::open_space(&second_path, space).await.unwrap();
        let first_notes = first.collection::<Note>("notes");
        let second_notes = second.collection::<Note>("notes");
        let shared = DocumentId::from_u128(1);
        let first_only = DocumentId::from_u128(2);
        let second_only = DocumentId::from_u128(3);
        first_notes
            .put(
                shared,
                Note {
                    text: "first".into(),
                },
            )
            .await
            .unwrap();
        second_notes
            .put(
                shared,
                Note {
                    text: "second".into(),
                },
            )
            .await
            .unwrap();
        first_notes
            .put(
                first_only,
                Note {
                    text: "left".into(),
                },
            )
            .await
            .unwrap();
        second_notes
            .put(
                second_only,
                Note {
                    text: "right".into(),
                },
            )
            .await
            .unwrap();
        let mut second_events = second_notes.subscribe();

        let toward_second = first
            .changes_since(&second.replication_frontier().unwrap())
            .unwrap();
        let receipt = second.apply_changes(toward_second.clone()).await.unwrap();
        assert_eq!(receipt.received(), 2);
        assert_eq!(receipt.retained(), 2);
        assert!(receipt.visible() >= 1);
        assert!(matches!(
            second_events.recv().await.unwrap(),
            Change::Put { .. }
        ));

        let toward_first = second
            .changes_since(&first.replication_frontier().unwrap())
            .unwrap();
        first.apply_changes(toward_first).await.unwrap();
        let duplicate = second.apply_changes(toward_second).await.unwrap();
        assert_eq!(duplicate.retained(), 0);
        assert_eq!(duplicate.visible(), 0);

        assert_eq!(
            first_notes.list().await.unwrap(),
            second_notes.list().await.unwrap()
        );
        assert_eq!(first.status().await.unwrap().replicated_changes, 4);
        assert_eq!(second.status().await.unwrap().replicated_changes, 4);
        drop(first_notes);
        drop(second_notes);
        drop(first);
        drop(second);

        let first = App::open_space(first_path, space).await.unwrap();
        let second = App::open_space(second_path, space).await.unwrap();
        assert_eq!(
            first.collection::<Note>("notes").list().await.unwrap(),
            second.collection::<Note>("notes").list().await.unwrap()
        );
        assert_eq!(
            first.replication_frontier().unwrap(),
            second.replication_frontier().unwrap()
        );
    }

    #[tokio::test]
    async fn invalid_batch_does_not_partially_advance_replica_or_storage() {
        let space = SpaceId::from_u128(42);
        let source = App::in_memory_space(space).await.unwrap();
        let target = App::in_memory_space(space).await.unwrap();
        source
            .collection::<Note>("notes")
            .insert(Note { text: "ok".into() })
            .await
            .unwrap();
        target.collection::<Note>("notes");
        let mut changes = source
            .changes_since(&target.replication_frontier().unwrap())
            .unwrap();
        let mut invalid = changes[0].clone();
        invalid.space = SpaceId::from_u128(99);
        changes.push(invalid);

        let error = target.apply_changes(changes).await.unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert_eq!(target.status().await.unwrap().replicated_changes, 0);
        assert_eq!(target.replication_frontier().unwrap().iter().count(), 0);
    }

    #[tokio::test]
    async fn merge_annotated_text_preserves_both_concurrent_document_edits() {
        let space = SpaceId::from_u128(43);
        let first = App::in_memory_space(space).await.unwrap();
        let second = App::in_memory_space(space).await.unwrap();
        let first_notes = first.collection::<RichNote>("notes");
        let second_notes = second.collection::<RichNote>("notes");
        let document = DocumentId::from_u128(1);
        let mut base_actor = Actor::new(cyrene_core::ReplicaId::from_u128(999));
        let mut base = Text::new();
        base.insert(&mut base_actor, 0, "x").unwrap();
        let mut first_body = base.clone();
        let mut second_body = base;
        first_body
            .insert(&mut Actor::new(first.replica_id().unwrap()), 1, "A")
            .unwrap();
        second_body
            .insert(&mut Actor::new(second.replica_id().unwrap()), 1, "B")
            .unwrap();
        first_notes
            .put(
                document,
                RichNote {
                    title: "first title".into(),
                    body: first_body,
                },
            )
            .await
            .unwrap();
        second_notes
            .put(
                document,
                RichNote {
                    title: "second title".into(),
                    body: second_body,
                },
            )
            .await
            .unwrap();

        let toward_second = first
            .changes_since(&second.replication_frontier().unwrap())
            .unwrap();
        second.apply_changes(toward_second).await.unwrap();
        let toward_first = second
            .changes_since(&first.replication_frontier().unwrap())
            .unwrap();
        first.apply_changes(toward_first).await.unwrap();

        let first_value = first_notes.get(document).await.unwrap().unwrap();
        let second_value = second_notes.get(document).await.unwrap().unwrap();
        assert_eq!(first_value, second_value);
        assert!(matches!(
            first_value.body.to_string().as_str(),
            "xAB" | "xBA"
        ));
        assert!(matches!(
            first_value.title.as_str(),
            "first title" | "second title"
        ));
    }
}
