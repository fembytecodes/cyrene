# Cyrene

**Local-first application state for Rust, without a backend by default.**

Cyrene gives Rust applications typed, durable, reactive state that works fully
offline. When your product needs more, the same state can synchronize between
authenticated devices, be shared with another person, or travel through an
optional end-to-end encrypted relay.

```rust,ignore
use cyrene::prelude::*;

#[derive(Debug, Serialize, Deserialize, Document)]
#[cyrene(name = "notes.note", version = 1)]
struct Note {
    #[cyrene(id = 1)]
    title: String,
    #[cyrene(id = 2)]
    done: bool,
}

let app = App::open("notes.db").await?;
let notes = app.collection::<Note>("notes");

let id = notes
    .insert(Note { title: "Stored here".into(), done: false })
    .await?;

println!("{:?}", notes.get(id).await?);
```

No database server, account, daemon, or network required.

## Try it

TODO: publish to crates.io

## The daily API

### Read and write typed documents

```rust,ignore
let tasks = app.collection::<Task>("tasks");
let id = tasks.insert(task).await?;
let task = tasks.get(id).await?;
let all_tasks = tasks.list().await?;
tasks.delete(id).await?;
```

Every successful write commits materialized state and its replication record in
the same SQLite transaction with `synchronous=FULL`.

### Commit related changes together

```rust,ignore
let mut transaction = app.transaction();
transaction.put(&tasks, first_id, first)?;
transaction.put(&tasks, second_id, second)?;
let commit = transaction.commit().await?;

println!("{} changes are durable", commit.changes());
```

Transactions are local and atomic within one space. They never wait for a peer.

### Keep a UI up to date

```rust,ignore
let initial = tasks.list().await?;
let mut changes = tasks.subscribe();

while let Ok(change) = changes.recv().await {
    match change {
        cyrene::Change::Put { id, value } => view.upsert(id, value),
        cyrene::Change::Delete { id } => view.remove(id),
    }
}
```

Subscriptions report lag instead of silently losing events. Reload `list()` if
a slow consumer falls behind.

### Preserve concurrent editing intent where it matters

Ordinary fields use a deterministic whole-document winner. Fields explicitly
marked for merging can use Cyrene's `Text` or `List<T>` CRDTs:

```rust,ignore
#[derive(Serialize, Deserialize, Document)]
struct Page {
    #[cyrene(id = 1)]
    title: String,
    #[cyrene(id = 2, merge)]
    body: cyrene::Text,
}
```

The choice is visible in the data model; Cyrene does not pretend every value
has one universally correct merge rule.

### Pair your own devices

Create an encrypted trust vault on each device, then use a short-lived pairing
code:

```console
# Device one
cargo run -p cyrene-cli -- device init --vault trust.db
cargo run -p cyrene-cli -- pair listen --vault trust.db \
  --share-database notes.db --bind 0.0.0.0:0

# Device two: use the address and code printed above
cargo run -p cyrene-cli -- pair join --vault trust.db ADDRESS CODE
```

Pairing authenticates both device keys and their exact QUIC certificates. LAN
discovery helps find an already trusted device; it never creates trust.

### Share one space

Sharing is scoped. A recipient receives access to one application space, not
your other data or an ambient account:

```console
# Owner
cyrene space init --vault alice-trust.db alice-notes.db
cyrene invite listen --vault alice-trust.db alice-notes.db \
  --permission read-write

# Recipient: use the secret token printed by the owner
cyrene invite join --vault bob-trust.db bob-notes.db 'TOKEN'
```

Invitations expire, capabilities are device-bound, and read-only versus
read-write permission is checked before disclosure or import. Revocation is
forward-looking: it prevents future access but cannot erase content someone
was previously allowed to receive.

### Fall back to an opaque relay

The reference relay stores bounded ciphertext in pseudonymous mailboxes. It
does not receive space IDs, durable device identities, content keys, schemas,
document IDs, or plaintext.

```console
cargo run -p cyrene-relay -- \
  --bind 127.0.0.1:8787 \
  --database relay.db
```

Applications prefer a direct connection for a caller-bounded interval and can
then use relay store-and-forward without changing their collection APIs.

## Know what is safe

```console
cargo run -p cyrene-cli -- inspect notes.db
cargo run -p cyrene-cli -- database backup notes.db notes-backup.db
cargo run -p cyrene-cli -- database compact notes.db --retain 10000
```

`inspect` reports integrity, identities, durable frontiers, and retained
history. Backups are consistent, integrity-checked, and never overwrite an
existing destination. Compaction bounds only a redundant diagnostic journal,
it does not discard the history needed by an offline peer.

Trust vaults have a separate encrypted recovery flow because application data
and authorization material are different assets.

## How Cyrene thinks

- **App:** one open local runtime and database.
- **Collection:** a typed group of documents.
- **Space:** the unit of ownership, replication, encryption, and backup.
- **Replica:** one durable copy with its own change identity.
- **Device:** a locally generated cryptographic identity.
- **Capability:** permission for one device in one space and key epoch.
- **Frontier:** the exact history known for a named set of replicas.

"Synced" is always relative to a peer or frontier. An offline device Cyrene
does not know about cannot be declared current.

## Documentation

Start with the path that matches your job:

- [Cookbook](docs/COOKBOOK.md) — application patterns and UI integration.
- [Contributing](CONTRIBUTING.md) — build, test, and propose changes.

## Development

Cyrene uses Rust 2024 and pins its toolchain. The complete local quality gate is:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --manifest-path fuzz/Cargo.toml --bins
cargo check --manifest-path templates/local-app/Cargo.toml
```

The workspace is dual-licensed under MIT or Apache-2.0.
