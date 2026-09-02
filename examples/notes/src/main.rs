//! Durable notes locally, or synchronized with one linked LAN device.

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use cyrene::prelude::*;
use cyrene::{
    ConnectivityOptions, ConnectivityReceipt, OsKeyStore, RelayClient, TrustStore, WrappingKey,
};

#[derive(Debug, Deserialize, Document, Serialize)]
#[cyrene(name = "notes.note", version = 1)]
struct Note {
    #[cyrene(id = 1)]
    title: String,
    #[cyrene(id = 2)]
    body: String,
    #[cyrene(id = 3)]
    done: bool,
}

#[derive(Parser)]
#[command(about = "Cyrene's tiny local-first notes demo")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Args)]
struct Credentials {
    #[arg(long)]
    vault: PathBuf,
    /// Named slot in the operating-system credential store.
    #[arg(long, default_value = "default")]
    keyring_id: String,
    /// Explicit raw-key fallback for headless or development environments.
    #[arg(long)]
    key_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Open notes with no networking, the default experience.
    Local {
        #[arg(default_value = "notes.db")]
        database: PathBuf,
    },
    /// Advertise and synchronize this replica with one paired device.
    Serve {
        database: PathBuf,
        #[command(flatten)]
        credentials: Credentials,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
    },
    /// Join the authenticated space and synchronize with its nearby replica.
    Sync {
        database: PathBuf,
        #[command(flatten)]
        credentials: Credentials,
        #[arg(long, default_value_t = 15)]
        wait: u64,
    },
    /// Prefer direct QUIC and fall back to an opaque internet relay.
    Connect {
        database: PathBuf,
        #[command(flatten)]
        credentials: Credentials,
        /// Last known direct QUIC address for the paired peer.
        #[arg(long)]
        direct: SocketAddr,
        /// Cyrene relay address.
        #[arg(long)]
        relay: SocketAddr,
        /// Seconds before an unavailable direct path falls back.
        #[arg(long, default_value_t = 3)]
        direct_timeout: u64,
        /// Days to retain newly published opaque objects.
        #[arg(long, default_value_t = 7)]
        retention_days: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        None => local(Path::new("notes.db")).await,
        Some(Command::Local { database }) => local(&database).await,
        Some(Command::Serve {
            database,
            credentials,
            bind,
        }) => serve(&database, &credentials, bind).await,
        Some(Command::Sync {
            database,
            credentials,
            wait,
        }) => sync(&database, &credentials, Duration::from_secs(wait)).await,
        Some(Command::Connect {
            database,
            credentials,
            direct,
            relay,
            direct_timeout,
            retention_days,
        }) => {
            connect(
                &database,
                &credentials,
                direct,
                relay,
                Duration::from_secs(direct_timeout),
                Duration::from_secs(retention_days.saturating_mul(24 * 60 * 60)),
            )
            .await
        }
    }
}

async fn connect(
    database: &Path,
    credentials: &Credentials,
    direct: SocketAddr,
    relay: SocketAddr,
    direct_deadline: Duration,
    relay_retention: Duration,
) -> Result<()> {
    let mut vault = open_vault(credentials)?;
    let device = require_device(&vault)?;
    let peer = single_peer(&vault)?;
    let spaces = vault.peer_spaces(peer.public_key)?;
    let [space] = spaces.as_slice() else {
        bail!("expected exactly one linked space, found {}", spaces.len());
    };
    let app = App::open_space(database, *space).await?;
    let notes = app.collection::<Note>("notes");
    seed(&notes, "Written locally before connectivity was available.").await?;
    let relay = RelayClient::new(relay, Duration::from_secs(30));
    match app
        .sync_peer_or_relay(
            direct,
            &relay,
            &device,
            &peer,
            &mut vault,
            ConnectivityOptions {
                direct_deadline,
                relay_retention,
            },
        )
        .await?
    {
        ConnectivityReceipt::Direct(receipt) => println!(
            "Direct sync: sent {}, received {}, retained {}, rounds {}.",
            receipt.sent, receipt.received, receipt.retained, receipt.rounds
        ),
        ConnectivityReceipt::Relay { pushed, pulled } => println!(
            "Relay fallback: offered {}, stored {}, received {}, retained {}, acknowledged {}.",
            pushed.offered, pushed.stored, pulled.received, pulled.retained, pulled.acknowledged
        ),
    }
    print_notes(&notes).await
}

async fn local(database: &Path) -> Result<()> {
    let app = App::open(database).await?;
    let notes = app.collection::<Note>("notes");
    seed(&notes, "Stored here. Safe offline. Ready to share.").await?;
    print_notes(&notes).await
}

async fn serve(database: &Path, credentials: &Credentials, bind: SocketAddr) -> Result<()> {
    let vault = open_vault(credentials)?;
    let device = require_device(&vault)?;
    let peer = single_peer(&vault)?;
    let app = App::open(database).await?;
    let notes = app.collection::<Note>("notes");
    seed(&notes, "Written on the inviting device while offline.").await?;
    let server = app.lan_server(bind, &device)?;
    println!(
        "Serving space {} as device {} on {}…",
        app.space_id(),
        device.identity.id(),
        server.local_addr()?
    );
    let credentials = vault.space_credentials(app.space_id())?;
    let receipt = if credentials.is_some() {
        server.accept_shared(&peer, &vault).await?
    } else {
        server.accept(&peer).await?
    };
    println!(
        "Synchronized: sent {}, received {}, retained {}, rounds {}.",
        receipt.sent, receipt.received, receipt.retained, receipt.rounds
    );
    print_notes(&notes).await
}

async fn sync(database: &Path, credentials: &Credentials, wait: Duration) -> Result<()> {
    let mut vault = open_vault(credentials)?;
    let device = require_device(&vault)?;
    let peer = single_peer(&vault)?;
    let spaces = vault.peer_spaces(peer.public_key)?;
    let [space] = spaces.as_slice() else {
        bail!(
            "expected exactly one linked personal space, found {}; pair again with `--share-database`",
            spaces.len()
        );
    };
    let app = App::open_space(database, *space).await?;
    let notes = app.collection::<Note>("notes");
    seed(&notes, "Written on the joining device while offline.").await?;
    println!("Looking for paired device {}…", peer.public_key.id());
    let credentials = vault.space_credentials(app.space_id())?;
    let receipt = if credentials.is_some() {
        app.sync_nearby_shared(&device, &peer, &mut vault, wait)
            .await?
    } else {
        app.sync_nearby(&device, &peer, wait).await?
    };
    println!(
        "Synchronized: sent {}, received {}, retained {}, rounds {}.",
        receipt.sent, receipt.received, receipt.retained, receipt.rounds
    );
    print_notes(&notes).await
}

async fn seed(notes: &Collection<Note>, body: &str) -> cyrene::Result<()> {
    if notes.list().await?.is_empty() {
        notes
            .insert(Note {
                title: "Hello".into(),
                body: body.into(),
                done: false,
            })
            .await?;
    }
    Ok(())
}

async fn print_notes(notes: &Collection<Note>) -> Result<()> {
    for (_, note) in notes.list().await? {
        let mark = if note.done { "x" } else { " " };
        println!("[{mark}] {}\n    {}", note.title, note.body);
    }
    Ok(())
}

fn open_vault(credentials: &Credentials) -> Result<TrustStore> {
    let key = if let Some(key_file) = &credentials.key_file {
        let key = fs::read(key_file)
            .with_context(|| format!("could not read wrapping key {}", key_file.display()))?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|key: Vec<u8>| anyhow!("wrapping key is {} bytes, expected 32", key.len()))?;
        WrappingKey::from_bytes(key)
    } else {
        OsKeyStore::open(&credentials.keyring_id)?.load()?
    };
    Ok(TrustStore::open(&credentials.vault, key)?)
}

fn require_device(vault: &TrustStore) -> Result<DeviceMaterial> {
    vault
        .load_device()?
        .ok_or_else(|| anyhow!("vault has no device; run `cyrene device init` first"))
}

fn single_peer(vault: &TrustStore) -> Result<PeerRecord> {
    let peers = vault.peers()?;
    let [peer] = peers.as_slice() else {
        bail!("expected exactly one paired device, found {}", peers.len());
    };
    Ok(peer.clone())
}
