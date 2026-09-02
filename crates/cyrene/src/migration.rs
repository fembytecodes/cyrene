use std::{marker::PhantomData, sync::Arc};

use cyrene_core::{Error, ErrorCode, Result};
use cyrene_store::StoredSchema;
use cyrene_sync::Operation;

use crate::{App, Collection, Document, app::unix_time_ms, codec, collection::RawChange};

/// The successful result of an atomic typed collection migration.
#[derive(Debug)]
pub struct Migration<T> {
    collection: Collection<T>,
    documents: usize,
    frontier: u64,
    marker: PhantomData<fn() -> T>,
}

impl<T> Migration<T> {
    /// Returns the number of documents transformed by the migration.
    pub const fn documents(&self) -> usize {
        self.documents
    }

    /// Returns the local change frontier after the migration.
    pub const fn frontier(&self) -> u64 {
        self.frontier
    }

    /// Returns a reference to the collection under its new schema.
    pub const fn collection(&self) -> &Collection<T> {
        &self.collection
    }

    /// Consumes the result and returns the collection under its new schema.
    pub fn into_collection(self) -> Collection<T> {
        self.collection
    }
}

impl App {
    /// Atomically migrates every document in `collection` from `From` to `To`.
    ///
    /// Cyrene verifies the exact durable source schema before invoking
    /// `transform`. Successful transformations, logical changes, materialized
    /// payloads, and the new schema descriptor commit together. The returned
    /// collection is ready to use under `To`.
    ///
    /// # Errors
    ///
    /// Returns an error if the source schema differs, decoding or encoding a
    /// document fails, `transform` rejects any document, or local storage cannot
    /// commit. No part of the migration is visible after an error.
    pub async fn migrate<From, To, F>(
        &self,
        collection: impl Into<String>,
        mut transform: F,
    ) -> Result<Migration<To>>
    where
        From: Document,
        To: Document,
        F: FnMut(From) -> Result<To> + Send + 'static,
    {
        let collection = collection.into();
        let worker_collection = collection.clone();
        let store = Arc::clone(&self.store);
        let replica = Arc::clone(&self.replica);
        let schemas = Arc::clone(&self.schemas);
        let space = self.space;
        let from = StoredSchema::from(From::SCHEMA);
        let to = StoredSchema::from(To::SCHEMA);
        let now_ms = unix_time_ms()?;
        let (migrated, frontier) = tokio::task::spawn_blocking(move || {
            let mut replica = replica.lock().map_err(|error| {
                Error::new(
                    ErrorCode::Storage,
                    format!("the local replica lock was poisoned: {error}"),
                )
            })?;
            let mut staged = replica.clone();
            staged.register_schema(worker_collection.clone(), to.fingerprint)?;
            let (migrated, frontier) = {
                let mut store = store.lock().map_err(|error| {
                    Error::new(
                        ErrorCode::Storage,
                        format!("the local storage lock was poisoned: {error}"),
                    )
                })?;
                let migrated = store.migrate_collection(
                    space,
                    &worker_collection,
                    &from,
                    &to,
                    |document, payload| {
                        let previous = codec::decode(payload)?;
                        let next = transform(previous)?;
                        let payload = codec::encode(&next)?;
                        let change = staged.author(
                            Operation::Put {
                                collection: worker_collection.clone(),
                                document,
                                schema: to.fingerprint,
                                payload: payload.clone(),
                            },
                            now_ms,
                        )?;
                        Ok((payload, change))
                    },
                )?;
                let frontier = store.frontier()?;
                (migrated, frontier)
            };
            *replica = staged;
            drop(replica);
            schemas
                .lock()
                .map_err(|error| {
                    Error::new(
                        ErrorCode::Storage,
                        format!("the local schema lock was poisoned: {error}"),
                    )
                })?
                .insert(worker_collection, to);
            Ok::<_, Error>((migrated, frontier))
        })
        .await
        .map_err(|error| {
            Error::with_source(
                ErrorCode::Storage,
                "the schema migration worker stopped unexpectedly",
                error,
            )
        })??;

        let collection_name: Arc<str> = collection.clone().into();
        for document in &migrated {
            let _ = self.changes.send(RawChange {
                collection: Arc::clone(&collection_name),
                id: document.id,
                payload: Some(Arc::from(document.payload.clone())),
            });
        }
        Ok(Migration {
            collection: self.collection(collection),
            documents: migrated.len(),
            frontier,
            marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::{App, Document, Error, ErrorCode};

    #[derive(Debug, Deserialize, Document, Eq, PartialEq, Serialize)]
    #[cyrene(name = "migration.note", version = 1)]
    struct NoteV1 {
        #[cyrene(id = 1)]
        text: String,
    }

    #[derive(Debug, Deserialize, Document, Eq, PartialEq, Serialize)]
    #[cyrene(name = "migration.note", version = 2)]
    struct NoteV2 {
        #[cyrene(id = 1)]
        text: String,
        #[cyrene(id = 2)]
        done: bool,
    }

    #[tokio::test]
    async fn migration_advances_payloads_schema_and_change_log_atomically() {
        let app = App::in_memory().await.unwrap();
        let old = app.collection::<NoteV1>("notes");
        old.insert(NoteV1 { text: "one".into() }).await.unwrap();
        old.insert(NoteV1 { text: "two".into() }).await.unwrap();

        let migration = app
            .migrate::<NoteV1, NoteV2, _>("notes", |note| {
                Ok(NoteV2 {
                    text: note.text,
                    done: false,
                })
            })
            .await
            .unwrap();

        assert_eq!(migration.documents(), 2);
        assert_eq!(migration.frontier(), 4);
        assert_eq!(app.status().await.unwrap().replicated_changes, 4);
        let values = migration.collection().list().await.unwrap();
        assert_eq!(values.len(), 2);
        assert!(values.iter().all(|(_, note)| !note.done));
        assert_eq!(old.list().await.unwrap_err().code(), ErrorCode::InvalidData);
    }

    #[tokio::test]
    async fn rejected_transform_rolls_back_every_document_and_schema() {
        let app = App::in_memory().await.unwrap();
        let old = app.collection::<NoteV1>("notes");
        old.insert(NoteV1 { text: "one".into() }).await.unwrap();
        old.insert(NoteV1 {
            text: "stop".into(),
        })
        .await
        .unwrap();

        let error = app
            .migrate::<NoteV1, NoteV2, _>("notes", |note| {
                if note.text == "stop" {
                    return Err(Error::new(ErrorCode::InvalidInput, "test rejection"));
                }
                Ok(NoteV2 {
                    text: note.text,
                    done: false,
                })
            })
            .await
            .unwrap_err();

        assert_eq!(error.message(), "test rejection");
        assert_eq!(old.list().await.unwrap().len(), 2);
        assert_eq!(app.status().await.unwrap().frontier, 2);
        assert_eq!(
            app.collection::<NoteV2>("notes")
                .list()
                .await
                .unwrap_err()
                .code(),
            ErrorCode::InvalidData
        );
        assert_eq!(app.status().await.unwrap().replicated_changes, 2);
    }

    #[tokio::test]
    async fn migrated_replication_history_rebuilds_and_continues_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("migration.db");
        let app = App::open(&path).await.unwrap();
        app.collection::<NoteV1>("notes")
            .insert(NoteV1 {
                text: "before".into(),
            })
            .await
            .unwrap();
        app.migrate::<NoteV1, NoteV2, _>("notes", |note| {
            Ok(NoteV2 {
                text: note.text,
                done: false,
            })
        })
        .await
        .unwrap();
        drop(app);

        let reopened = App::open(path).await.unwrap();
        let notes = reopened.collection::<NoteV2>("notes");
        assert_eq!(notes.list().await.unwrap().len(), 1);
        notes
            .insert(NoteV2 {
                text: "after".into(),
                done: true,
            })
            .await
            .unwrap();
        let status = reopened.status().await.unwrap();
        assert_eq!(status.replica_frontier, 3);
        assert_eq!(status.replicated_changes, 3);
    }
}
