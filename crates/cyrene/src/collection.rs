use std::{marker::PhantomData, sync::Arc};

use cyrene_core::{DocumentId, Error, ErrorCode, Result};
use cyrene_store::{Mutation, StoredSchema};
use cyrene_sync::Operation;
use tokio::{sync::broadcast, task::JoinHandle};

use crate::{App, Document, app::unix_time_ms, codec};

#[derive(Clone, Debug)]
pub(crate) struct RawChange {
    pub(crate) collection: Arc<str>,
    pub(crate) id: DocumentId,
    pub(crate) payload: Option<Arc<[u8]>>,
}

/// A committed local change to a typed collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change<T> {
    /// A document was inserted or replaced.
    Put {
        /// Stable document identity.
        id: DocumentId,
        /// The new typed value.
        value: T,
    },
    /// A document was deleted.
    Delete {
        /// Stable identity of the deleted document.
        id: DocumentId,
    },
}

/// A typed handle to a durable collection.
#[derive(Debug)]
pub struct Collection<T> {
    pub(crate) app: App,
    pub(crate) name: Arc<str>,
    marker: PhantomData<fn() -> T>,
}

impl<T> Clone for Collection<T> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            name: Arc::clone(&self.name),
            marker: PhantomData,
        }
    }
}

impl<T: Document> Collection<T> {
    pub(crate) fn new(app: App, name: String) -> Self {
        Self {
            app,
            name: name.into(),
            marker: PhantomData,
        }
    }

    /// Inserts a new document and returns its generated identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be encoded or committed locally.
    pub async fn insert(&self, value: T) -> Result<DocumentId> {
        let id = DocumentId::new();
        self.put(id, value).await?;
        Ok(id)
    }

    /// Inserts or replaces a document under a stable identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be encoded or committed locally.
    pub async fn put(&self, id: DocumentId, value: T) -> Result<()> {
        let payload = codec::encode(&value)?;
        let store = Arc::clone(&self.app.store);
        let space = self.app.space;
        let collection = Arc::clone(&self.name);
        let stored_payload = payload.clone();
        let schema = StoredSchema::from(T::SCHEMA);
        let replica = Arc::clone(&self.app.replica);
        let now_ms = unix_time_ms()?;
        tokio::task::spawn_blocking(move || {
            let mut replica = replica.lock().map_err(|error| poisoned_store(&error))?;
            let mut staged = replica.clone();
            staged.register_schema(collection.to_string(), schema.fingerprint)?;
            let change = staged.author(
                Operation::Put {
                    collection: collection.to_string(),
                    document: id,
                    schema: schema.fingerprint,
                    payload: stored_payload.clone(),
                },
                now_ms,
            )?;
            store
                .lock()
                .map_err(|error| poisoned_store(&error))?
                .commit_local(
                    space,
                    vec![Mutation::Put {
                        collection: collection.to_string(),
                        id,
                        payload: stored_payload,
                        schema,
                    }],
                    &[change],
                )?;
            *replica = staged;
            Ok::<_, Error>(())
        })
        .await
        .map_err(task_error)??;

        let _ = self.app.changes.send(RawChange {
            collection: Arc::clone(&self.name),
            id,
            payload: Some(payload.into()),
        });
        Ok(())
    }

    /// Retrieves one document from local durable state.
    ///
    /// # Errors
    ///
    /// Returns an error if local storage fails or the payload does not match
    /// the collection's Rust type.
    pub async fn get(&self, id: DocumentId) -> Result<Option<T>> {
        let store = Arc::clone(&self.app.store);
        let space = self.app.space;
        let collection = Arc::clone(&self.name);
        let schema = StoredSchema::from(T::SCHEMA);
        let document = tokio::task::spawn_blocking(move || {
            let mut store = store.lock().map_err(|error| poisoned_store(&error))?;
            store.ensure_collection_schema(space, &collection, &schema)?;
            store.get(space, &collection, id)
        })
        .await
        .map_err(task_error)??;
        document
            .map(|document| decode(&document.payload))
            .transpose()
    }

    /// Lists every document in stable identity order.
    ///
    /// # Errors
    ///
    /// Returns an error if local storage fails or a payload does not match the
    /// collection's Rust type.
    pub async fn list(&self) -> Result<Vec<(DocumentId, T)>> {
        let store = Arc::clone(&self.app.store);
        let space = self.app.space;
        let collection = Arc::clone(&self.name);
        let schema = StoredSchema::from(T::SCHEMA);
        let documents = tokio::task::spawn_blocking(move || {
            let mut store = store.lock().map_err(|error| poisoned_store(&error))?;
            store.ensure_collection_schema(space, &collection, &schema)?;
            store.list(space, &collection)
        })
        .await
        .map_err(task_error)??;
        documents
            .into_iter()
            .map(|document| decode(&document.payload).map(|value| (document.id, value)))
            .collect()
    }

    /// Deletes a document, returning whether it existed locally.
    ///
    /// # Errors
    ///
    /// Returns an error if the local delete transaction cannot be committed.
    pub async fn delete(&self, id: DocumentId) -> Result<bool> {
        let store = Arc::clone(&self.app.store);
        let space = self.app.space;
        let collection = Arc::clone(&self.name);
        let schema = StoredSchema::from(T::SCHEMA);
        let replica = Arc::clone(&self.app.replica);
        let now_ms = unix_time_ms()?;
        let deleted = !tokio::task::spawn_blocking(move || {
            let mut replica = replica.lock().map_err(|error| poisoned_store(&error))?;
            let mut staged = replica.clone();
            staged.register_schema(collection.to_string(), schema.fingerprint)?;
            let change = staged.author(
                Operation::Delete {
                    collection: collection.to_string(),
                    document: id,
                    schema: schema.fingerprint,
                },
                now_ms,
            )?;
            let (applied, _) = store
                .lock()
                .map_err(|error| poisoned_store(&error))?
                .commit_local(
                    space,
                    vec![Mutation::Delete {
                        collection: collection.to_string(),
                        id,
                        schema,
                    }],
                    &[change],
                )?;
            *replica = staged;
            Ok::<_, Error>(applied)
        })
        .await
        .map_err(task_error)??
        .is_empty();
        if deleted {
            let _ = self.app.changes.send(RawChange {
                collection: Arc::clone(&self.name),
                id,
                payload: None,
            });
        }
        Ok(deleted)
    }

    /// Subscribes to changes committed after this call.
    ///
    /// Call `list` first when an initial snapshot is required. If a slow
    /// subscriber falls behind, `recv` returns a structured error rather than
    /// silently skipping changes.
    pub fn subscribe(&self) -> Subscription<T> {
        Subscription {
            collection: Arc::clone(&self.name),
            receiver: self.app.changes.subscribe(),
            marker: PhantomData,
        }
    }

    /// Runs a callback for each subsequently committed local change.
    pub fn watch<F>(&self, mut callback: F) -> JoinHandle<Result<()>>
    where
        F: FnMut(Change<T>) + Send + 'static,
    {
        let mut subscription = self.subscribe();
        tokio::spawn(async move {
            loop {
                callback(subscription.recv().await?);
            }
        })
    }
}

/// A loss-detecting subscription to a typed collection.
#[derive(Debug)]
pub struct Subscription<T> {
    collection: Arc<str>,
    receiver: broadcast::Receiver<RawChange>,
    marker: PhantomData<fn() -> T>,
}

impl<T: Document> Subscription<T> {
    /// Waits for the next committed change in this collection.
    ///
    /// # Errors
    ///
    /// Returns an error if the application closes the channel, this subscriber
    /// falls behind, or a payload cannot be decoded as `T`.
    pub async fn recv(&mut self) -> Result<Change<T>> {
        loop {
            let raw = self.receiver.recv().await.map_err(|error| match error {
                broadcast::error::RecvError::Closed => Error::new(
                    ErrorCode::Storage,
                    "the application closed this subscription",
                ),
                broadcast::error::RecvError::Lagged(count) => Error::new(
                    ErrorCode::InvalidData,
                    format!("subscription fell behind by {count} changes; reload its snapshot"),
                ),
            })?;
            if raw.collection != self.collection {
                continue;
            }
            return match raw.payload {
                Some(payload) => Ok(Change::Put {
                    id: raw.id,
                    value: decode(&payload)?,
                }),
                None => Ok(Change::Delete { id: raw.id }),
            };
        }
    }
}

fn decode<T: Document>(payload: &[u8]) -> Result<T> {
    codec::decode(payload)
}

fn poisoned_store<T>(error: &std::sync::PoisonError<T>) -> Error {
    Error::new(
        ErrorCode::Storage,
        format!("the local storage lock was poisoned: {error}"),
    )
}

fn task_error(error: tokio::task::JoinError) -> Error {
    Error::with_source(
        ErrorCode::Storage,
        "the local storage worker stopped unexpectedly",
        error,
    )
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
    #[cyrene(name = "schema-test", version = 1)]
    struct EarlierNote {
        #[cyrene(id = 1)]
        text: String,
    }

    #[derive(Debug, Deserialize, Document, Eq, PartialEq, Serialize)]
    #[cyrene(name = "schema-test", version = 1)]
    struct IncompatibleNote {
        #[cyrene(id = 1)]
        title: String,
    }

    #[tokio::test]
    async fn typed_documents_are_durable_and_reactive() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notes.db");
        let app = App::open(&path).await.unwrap();
        let notes = app.collection::<Note>("notes");
        let mut changes = notes.subscribe();

        let id = notes
            .insert(Note {
                text: "hello".into(),
            })
            .await
            .unwrap();
        assert_eq!(
            changes.recv().await.unwrap(),
            Change::Put {
                id,
                value: Note {
                    text: "hello".into()
                }
            }
        );

        drop(notes);
        drop(app);
        let reopened = App::open(path).await.unwrap();
        let notes = reopened.collection::<Note>("notes");
        assert_eq!(notes.get(id).await.unwrap().unwrap().text, "hello");
    }

    #[tokio::test]
    async fn incompatible_schema_is_rejected_before_payload_decode() {
        let app = App::in_memory().await.unwrap();
        app.collection::<EarlierNote>("notes")
            .insert(EarlierNote {
                text: "hello".into(),
            })
            .await
            .unwrap();

        let error = app
            .collection::<IncompatibleNote>("notes")
            .list()
            .await
            .unwrap_err();

        assert_eq!(error.code(), crate::ErrorCode::InvalidData);
        assert!(error.message().contains("explicit migration"));
    }

    #[tokio::test]
    async fn public_writes_retain_restart_safe_replication_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replicated.db");
        let app = App::open(&path).await.unwrap();
        let replica = app.replica_id().unwrap();
        let notes = app.collection::<Note>("notes");
        notes.insert(Note { text: "one".into() }).await.unwrap();
        notes.insert(Note { text: "two".into() }).await.unwrap();
        assert_eq!(app.status().await.unwrap().replica_frontier, 2);
        drop(notes);
        drop(app);

        let reopened = App::open(path).await.unwrap();
        assert_eq!(reopened.replica_id().unwrap(), replica);
        reopened
            .collection::<Note>("notes")
            .insert(Note {
                text: "three".into(),
            })
            .await
            .unwrap();
        let status = reopened.status().await.unwrap();
        assert_eq!(status.replica_frontier, 3);
        assert_eq!(status.replicated_changes, 3);
        assert_eq!(status.documents, 3);
    }
}
