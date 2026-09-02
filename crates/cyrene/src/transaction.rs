use std::sync::Arc;

use cyrene_core::{DocumentId, Error, ErrorCode, Result};
use cyrene_store::{ChangeKind, Mutation, StoredSchema};
use cyrene_sync::Operation;

use crate::{App, Collection, Document, app::unix_time_ms, codec, collection::RawChange};

/// The outcome of a committed local transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Commit {
    changes: usize,
    frontier: u64,
}

impl Commit {
    /// Returns the number of durable changes produced by the transaction.
    pub const fn changes(self) -> usize {
        self.changes
    }

    /// Returns the local change-log frontier after this commit.
    pub const fn frontier(self) -> u64 {
        self.frontier
    }
}

/// A builder for mutations that commit atomically on the local replica.
///
/// Dropping this value before [`Self::commit`] has no effect. A transaction can
/// include collections of different document types, but all collections must
/// belong to the [`App`] that created it.
#[derive(Debug)]
pub struct LocalTransaction {
    app: App,
    mutations: Vec<Mutation>,
    notifications: Vec<RawChange>,
}

impl LocalTransaction {
    pub(crate) fn new(app: App) -> Self {
        Self {
            app,
            mutations: Vec::new(),
            notifications: Vec::new(),
        }
    }

    /// Stages a new typed document and returns its generated identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the collection belongs to another application or
    /// the document cannot be encoded.
    pub fn insert<T: Document>(
        &mut self,
        collection: &Collection<T>,
        value: T,
    ) -> Result<DocumentId> {
        let id = DocumentId::new();
        self.put(collection, id, value)?;
        Ok(id)
    }

    /// Stages an insert or replacement under a stable document identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the collection belongs to another application or
    /// the document cannot be encoded.
    pub fn put<T: Document>(
        &mut self,
        collection: &Collection<T>,
        id: DocumentId,
        value: T,
    ) -> Result<()> {
        self.validate_collection(collection)?;
        let payload = codec::encode(&value)?;
        // Staging takes ownership just like `Collection::put`; keeping no typed
        // value also ensures commits never depend on application references.
        drop(value);
        self.mutations.push(Mutation::Put {
            collection: collection.name.to_string(),
            id,
            payload: payload.clone(),
            schema: StoredSchema::from(T::SCHEMA),
        });
        self.notifications.push(RawChange {
            collection: Arc::clone(&collection.name),
            id,
            payload: Some(payload.into()),
        });
        Ok(())
    }

    /// Stages deletion of a document if it exists when the transaction commits.
    ///
    /// # Errors
    ///
    /// Returns an error when the collection belongs to another application.
    pub fn delete<T: Document>(
        &mut self,
        collection: &Collection<T>,
        id: DocumentId,
    ) -> Result<()> {
        self.validate_collection(collection)?;
        self.mutations.push(Mutation::Delete {
            collection: collection.name.to_string(),
            id,
            schema: StoredSchema::from(T::SCHEMA),
        });
        self.notifications.push(RawChange {
            collection: Arc::clone(&collection.name),
            id,
            payload: None,
        });
        Ok(())
    }

    /// Atomically makes every staged mutation durable and then notifies local
    /// subscribers in mutation order.
    ///
    /// # Errors
    ///
    /// Returns an error if the local storage worker fails or the complete
    /// transaction cannot be committed. No subscriber is notified on failure.
    pub async fn commit(self) -> Result<Commit> {
        let Self {
            app,
            mutations,
            mut notifications,
        } = self;
        let store = Arc::clone(&app.store);
        let replica = Arc::clone(&app.replica);
        let space = app.space;
        let now_ms = unix_time_ms()?;
        let (applied, logical_changes, frontier) = tokio::task::spawn_blocking(move || {
            let mut replica = replica.lock().map_err(|error| {
                Error::new(
                    ErrorCode::Storage,
                    format!("the local replica lock was poisoned: {error}"),
                )
            })?;
            let mut staged = replica.clone();
            let mut changes = Vec::with_capacity(mutations.len());
            for mutation in &mutations {
                let (collection, schema, operation) = match mutation {
                    Mutation::Put {
                        collection,
                        id,
                        payload,
                        schema,
                    } => (
                        collection,
                        schema,
                        Operation::Put {
                            collection: collection.clone(),
                            document: *id,
                            schema: schema.fingerprint,
                            payload: payload.clone(),
                        },
                    ),
                    Mutation::Delete {
                        collection,
                        id,
                        schema,
                    } => (
                        collection,
                        schema,
                        Operation::Delete {
                            collection: collection.clone(),
                            document: *id,
                            schema: schema.fingerprint,
                        },
                    ),
                };
                staged.register_schema(collection.clone(), schema.fingerprint)?;
                changes.push(staged.author(operation, now_ms)?);
            }
            let logical_changes = changes.len();
            let frontier = staged.frontier().get(staged.id());
            let (applied, _) = store
                .lock()
                .map_err(|error| {
                    Error::new(
                        ErrorCode::Storage,
                        format!("the local storage lock was poisoned: {error}"),
                    )
                })?
                .commit_local(space, mutations, &changes)?;
            *replica = staged;
            Ok::<_, Error>((applied, logical_changes, frontier))
        })
        .await
        .map_err(|error| {
            Error::with_source(
                ErrorCode::Storage,
                "the local storage worker stopped unexpectedly",
                error,
            )
        })??;

        for mutation in &applied {
            let is_put = mutation.kind == ChangeKind::Put;
            if let Some(position) = notifications.iter().position(|change| {
                change.collection.as_ref() == mutation.collection
                    && change.id == mutation.id
                    && change.payload.is_some() == is_put
            }) {
                let _ = app.changes.send(notifications.remove(position));
            }
        }

        Ok(Commit {
            changes: logical_changes,
            frontier,
        })
    }

    fn validate_collection<T>(&self, collection: &Collection<T>) -> Result<()> {
        if Arc::ptr_eq(&self.app.store, &collection.app.store)
            && self.app.space == collection.app.space
        {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::InvalidInput,
            "a local transaction cannot contain a collection from another application or space",
        ))
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::{App, Change, Document};

    #[derive(Debug, Deserialize, Document, Eq, PartialEq, Serialize)]
    struct Note {
        text: String,
    }

    #[derive(Debug, Deserialize, Document, Eq, PartialEq, Serialize)]
    struct Tag {
        name: String,
    }

    #[tokio::test]
    async fn commits_multiple_typed_collections_atomically() {
        let app = App::in_memory().await.unwrap();
        let notes = app.collection::<Note>("notes");
        let tags = app.collection::<Tag>("tags");
        let mut note_changes = notes.subscribe();
        let mut tag_changes = tags.subscribe();
        let mut transaction = app.transaction();
        let note_id = transaction
            .insert(
                &notes,
                Note {
                    text: "hello".into(),
                },
            )
            .unwrap();
        let tag_id = transaction
            .insert(
                &tags,
                Tag {
                    name: "welcome".into(),
                },
            )
            .unwrap();

        assert!(notes.get(note_id).await.unwrap().is_none());
        let commit = transaction.commit().await.unwrap();

        assert_eq!(commit.changes(), 2);
        assert_eq!(commit.frontier(), 2);
        assert_eq!(
            note_changes.recv().await.unwrap(),
            Change::Put {
                id: note_id,
                value: Note {
                    text: "hello".into()
                }
            }
        );
        assert_eq!(
            tag_changes.recv().await.unwrap(),
            Change::Put {
                id: tag_id,
                value: Tag {
                    name: "welcome".into()
                }
            }
        );
    }

    #[tokio::test]
    async fn rejects_collections_from_another_app_before_commit() {
        let first = App::in_memory().await.unwrap();
        let second = App::in_memory().await.unwrap();
        let foreign = second.collection::<Note>("notes");
        let mut transaction = first.transaction();

        let error = transaction
            .insert(
                &foreign,
                Note {
                    text: "nope".into(),
                },
            )
            .unwrap_err();

        assert_eq!(error.code(), crate::ErrorCode::InvalidInput);
    }
}
