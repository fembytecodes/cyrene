# Cyrene cookbook

These recipes use public APIs only.
If this is your first visit, run the [starter](../templates/local-app/README.md) before reading the recipes.

## Start a typed local application

```rust,ignore
use cyrene::prelude::*;

#[derive(Debug, Serialize, Deserialize, Document)]
#[cyrene(name = "acme.task", version = 1)]
struct Task {
    #[cyrene(id = 1)]
    title: String,
    #[cyrene(id = 2)]
    done: bool,
}

let app = App::open("tasks.db").await?;
let tasks = app.collection::<Task>("tasks");
let id = tasks.insert(Task { title: "Ship it".into(), done: false }).await?;
let durable = tasks.get(id).await?;
assert!(durable.is_some());
```

`insert`, `put`, and a successful transaction return only after materialized
state and its authenticated replication change share one `synchronous=FULL`
SQLite commit.

## Feed a desktop UI

Take one snapshot, then consume the loss-detecting subscription on a Tokio task.
This pattern fits Tauri commands, Dioxus signals, iced messages, Slint model
updates, and egui repaint channels without making those frameworks persistent
dependencies of Cyrene.

```rust,ignore
let initial = tasks.list().await?;
ui.replace_all(initial);

let mut changes = tasks.subscribe();
tokio::spawn(async move {
    loop {
        match changes.recv().await {
            Ok(cyrene::Change::Put { id, value }) => ui.upsert(id, value),
            Ok(cyrene::Change::Delete { id }) => ui.remove(id),
            Err(error) => {
                ui.request_snapshot_reload(error.to_string());
                break;
            }
        }
    }
});
```

Lag is explicit: reload `list()` rather than pretending dropped events were
seen. UI state is a projection; Cyrene's database remains authoritative.

For Tauri, construct `App` once in setup, place typed collection handles in
managed state, and make commands thin async calls. Do not hold a framework
mutex across `.await`; `Collection<T>` is cloneable and internally serialized
at its storage boundary.

## Commit related edits atomically

```rust,ignore
let mut tx = app.transaction();
tx.put(&tasks, first_id, first)?;
tx.put(&tasks, second_id, second)?;
let committed = tx.commit().await?;
println!("{} logical changes are durable", committed.changes());
```

Transactions cannot span spaces. Model a cross-space workflow as explicit
local steps with recovery state.

## Preserve concurrent text intent

Use ordinary fields for deterministic whole-document winners. Mark `Text` or
`List<T>` fields with `#[cyrene(merge)]` only where concurrent intent matters.

```rust,ignore
#[derive(Serialize, Deserialize, Document)]
struct Page {
    #[cyrene(id = 1)]
    title: String,
    #[cyrene(id = 2, merge)]
    body: cyrene::Text,
}

let mut actor = app.actor().await?;
page.body.insert(&mut actor, page.body.len(), "offline words")?;
pages.put(id, page).await?;
```

## Diagnose safety before connectivity

`App::status()` and `cyrene inspect --json` answer whether storage passes its
integrity check, what is durably retained, and which local replica frontier is
known. A sync result is always relative to a named peer/frontier; an offline
unknown device can never be declared synchronized.

## Back up application and trust state

```console
cyrene database backup tasks.db tasks-backup.db
cyrene recovery export --vault trust.db --output trust.cyrene-recovery
```

Keep the recovery secret separately.

## Move from LAN to relay fallback

Applications keep the same collections and transactions. Pair/share first,
then call `sync_peer_or_relay` or use the notes example's `connect` command.
Direct QUIC is attempted for a bounded interval; the fallback relay sees only
pseudonymous mailbox keys, ciphertext sizes, expiry, and timing.

## Evolve a schema

Keep `#[cyrene(name = ...)]` and field IDs stable across Rust renames. Additive
changes still require a versioned type definition; semantic changes use
`App::migrate` with an explicit old type and transformation. Migration
is all-or-nothing and emits normal replication changes. Test it against a copy
of the oldest supported database fixture before release.
