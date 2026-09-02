//! Command-line diagnostics, identity bootstrap, and device pairing for Cyrene.

mod recovery;
mod sharing;
mod user;

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use cyrene::{
    Acknowledgement, Answer, App, DeviceIdentity, DeviceLink, DeviceMaterial, DiscoveryBrowser,
    Inviter, Joiner, Offer, OsKeyStore, PairingCode, PeerRecord, QuicCertificate, TrustStore,
    WrappingKey,
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const PAIRING_FRAME_LIMIT: usize = 16 * 1024;

#[derive(Parser)]
#[command(
    name = "cyrene",
    version,
    about = "Make local-first application state legible"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect the durability and integrity of an application database.
    Inspect {
        /// Path to the Cyrene application database.
        database: PathBuf,
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Back up or compact an application database safely.
    Database {
        #[command(subcommand)]
        command: DatabaseCommand,
    },
    /// List devices admitted to an encrypted trust vault.
    Peers {
        #[command(flatten)]
        vault: VaultArgs,
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Browse the LAN for this many seconds and correlate trusted peers.
        #[arg(long, default_value_t = 0)]
        discover: u64,
    },
    /// Create or inspect this device's protected identity.
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Pair devices using a short, expiring code.
    Pair {
        #[command(subcommand)]
        command: PairCommand,
    },
    /// Initialize or inspect authority for an application space.
    Space {
        #[command(subcommand)]
        command: sharing::SpaceCommand,
    },
    /// Invite another person into one application space.
    Invite {
        #[command(subcommand)]
        command: sharing::InviteCommand,
    },
    /// Manage the user identity shared by explicitly linked devices.
    User {
        #[command(subcommand)]
        command: user::UserCommand,
    },
    /// Export or restore an encrypted trust-vault snapshot.
    Recovery {
        #[command(subcommand)]
        command: recovery::RecoveryCommand,
    },
}

#[derive(Subcommand)]
enum DatabaseCommand {
    /// Create a consistent, integrity-checked backup at a new path.
    Backup {
        /// Path to the live Cyrene application database.
        database: PathBuf,
        /// New path to create for the backup; existing files are never replaced.
        destination: PathBuf,
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Bound the redundant local journal without shortening sync history.
    Compact {
        /// Path to the Cyrene application database.
        database: PathBuf,
        /// Number of recent local diagnostic changes to retain.
        #[arg(long, default_value_t = 10_000)]
        retain: u64,
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// Generate a device identity, QUIC certificate, and wrapping key.
    Init {
        #[command(flatten)]
        vault: VaultArgs,
    },
    /// Show the local device ID and certificate pin.
    Status {
        #[command(flatten)]
        vault: VaultArgs,
        /// Emit stable machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PairCommand {
    /// Issue one invitation and wait for another device.
    Listen {
        #[command(flatten)]
        vault: VaultArgs,
        /// TCP address for the one-shot bootstrap listener.
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        /// Invitation lifetime in seconds.
        #[arg(long, default_value_t = 300)]
        ttl: u64,
        /// Include this application's personal space in the authenticated link.
        #[arg(long)]
        share_database: Option<PathBuf>,
    },
    /// Join a listening device using the displayed code.
    Join {
        #[command(flatten)]
        vault: VaultArgs,
        /// Address printed by `cyrene pair listen`.
        address: SocketAddr,
        /// Eight-character code printed by the inviting device.
        code: String,
    },
}

#[derive(Clone, Args)]
pub(crate) struct VaultArgs {
    /// Path to the encrypted Cyrene trust vault.
    #[arg(long)]
    vault: PathBuf,
    /// Named slot in the operating-system credential store.
    #[arg(long, default_value = "default")]
    keyring_id: String,
    /// Explicit raw-key fallback for headless or development environments.
    #[arg(long)]
    key_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Inspect { database, json } => inspect(&database, json).await,
        Command::Database { command } => database(command).await,
        Command::Peers {
            vault,
            json,
            discover,
        } => peers(&vault, json, discover).await,
        Command::Device { command } => match command {
            DeviceCommand::Init { vault } => initialize_device(&vault),
            DeviceCommand::Status { vault, json } => device_status(&vault, json),
        },
        Command::Pair { command } => match command {
            PairCommand::Listen {
                vault,
                bind,
                ttl,
                share_database,
            } => pair_listen(&vault, bind, ttl, share_database.as_deref()).await,
            PairCommand::Join {
                vault,
                address,
                code,
            } => pair_join(&vault, address, &code).await,
        },
        Command::Space { command } => sharing::space(command).await,
        Command::Invite { command } => sharing::invite(command).await,
        Command::User { command } => user::user(command),
        Command::Recovery { command } => recovery::recovery(command),
    }
}

async fn database(command: DatabaseCommand) -> Result<()> {
    match command {
        DatabaseCommand::Backup {
            database,
            destination,
            json,
        } => {
            let app = App::open(&database)
                .await
                .with_context(|| format!("could not open {}", database.display()))?;
            let report = app
                .backup(&destination)
                .await
                .with_context(|| format!("could not back up to {}", destination.display()))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "source": database,
                        "destination": destination,
                        "documents": report.documents,
                        "replicated_changes": report.replicated_changes,
                        "integrity": report.integrity,
                        "healthy": report.is_healthy(),
                    }))?
                );
            } else {
                println!(
                    "Backup ready at {}\n  documents          {}\n  replicated changes {}\n  integrity          {}",
                    destination.display(),
                    report.documents,
                    report.replicated_changes,
                    report.integrity
                );
            }
            Ok(())
        }
        DatabaseCommand::Compact {
            database,
            retain,
            json,
        } => {
            let app = App::open(&database)
                .await
                .with_context(|| format!("could not open {}", database.display()))?;
            let report = app.compact(retain).await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "database": database,
                        "local_changes_before": report.changes_before,
                        "local_changes_after": report.changes_after,
                        "local_changes_removed": report.removed(),
                        "replicated_changes_preserved": report.replicated_changes,
                    }))?
                );
            } else {
                println!(
                    "Compaction complete\n  local journal      {} → {} ({} removed)\n  replicated history {} preserved",
                    report.changes_before,
                    report.changes_after,
                    report.removed(),
                    report.replicated_changes
                );
            }
            Ok(())
        }
    }
}

async fn inspect(database: &Path, json: bool) -> Result<()> {
    let app = App::open(database)
        .await
        .with_context(|| format!("could not inspect {}", database.display()))?;
    let status = app.status().await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "database": database,
                "space": status.space.to_string(),
                "replica": status.replica.to_string(),
                "documents": status.documents,
                "local_changes": status.changes,
                "replicated_changes": status.replicated_changes,
                "local_frontier": status.frontier,
                "replica_frontier": status.replica_frontier,
                "integrity": status.integrity,
                "healthy": status.is_healthy(),
            }))?
        );
    } else {
        println!("{}", render_inspection(database, &status));
    }
    Ok(())
}

async fn peers(arguments: &VaultArgs, json: bool, discover: u64) -> Result<()> {
    let store = open_vault(arguments)?;
    let peers = store.peers()?;
    let discovered = discover_peers(&peers, discover).await?;
    if json {
        let peers = peers
            .iter()
            .map(|peer| {
                let spaces = store
                    .peer_spaces(peer.public_key)?
                    .into_iter()
                    .map(|space| space.to_string())
                    .collect::<Vec<_>>();
                Result::<_>::Ok(serde_json::json!({
                    "device_id": full_hex(peer.public_key.id().as_bytes()),
                    "public_key": full_hex(&peer.public_key.to_bytes()),
                    "certificate_pin": full_hex(peer.certificate_pin().as_bytes()),
                    "paired_at": peer.paired_at,
                    "linked_spaces": spaces,
                    "lan_addresses": discovered
                        .get(peer.public_key.id().as_bytes())
                        .cloned()
                        .unwrap_or_default(),
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        println!("{}", serde_json::to_string_pretty(&peers)?);
    } else if peers.is_empty() {
        println!("No paired devices yet.\n\nStart with: cyrene pair listen --vault …");
    } else {
        println!("Paired devices ({})", peers.len());
        for peer in peers {
            let spaces = store.peer_spaces(peer.public_key)?;
            let addresses = discovered.get(peer.public_key.id().as_bytes());
            let reachability = addresses.map_or_else(
                || "not observed".to_owned(),
                |addresses| {
                    addresses
                        .iter()
                        .map(SocketAddr::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            );
            println!(
                "  {}  certificate {}  paired at {}  spaces {}  LAN {reachability}",
                peer.public_key.id(),
                peer.certificate_pin(),
                peer.paired_at,
                spaces.len()
            );
        }
    }
    Ok(())
}

async fn discover_peers(
    peers: &[PeerRecord],
    seconds: u64,
) -> Result<BTreeMap<[u8; 32], Vec<SocketAddr>>> {
    let mut found = BTreeMap::new();
    if seconds == 0 || peers.is_empty() {
        return Ok(found);
    }
    if seconds > 60 {
        bail!("peer discovery duration must not exceed 60 seconds");
    }
    let browser = DiscoveryBrowser::start()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Some(advertisement) = browser.next(remaining).await? else {
            break;
        };
        if let Some(peer) = peers
            .iter()
            .find(|peer| advertisement.matches(peer.public_key, peer.certificate_pin()))
        {
            let addresses = found
                .entry(*peer.public_key.id().as_bytes())
                .or_insert_with(Vec::new);
            addresses.extend(advertisement.addresses);
            addresses.sort_unstable();
            addresses.dedup();
        }
    }
    Ok(found)
}

fn initialize_device(arguments: &VaultArgs) -> Result<()> {
    if let Some(path) = &arguments.key_file
        && path.exists()
    {
        bail!(
            "{} already exists; refusing to replace a wrapping key",
            path.display()
        );
    }
    let wrapping_key = WrappingKey::generate()?;
    let key_location = if let Some(path) = &arguments.key_file {
        persist_wrapping_key(path, wrapping_key.secret_bytes())?;
        path.display().to_string()
    } else {
        OsKeyStore::open(&arguments.keyring_id)?.store_new(&wrapping_key)?;
        format!("OS credential store ({})", arguments.keyring_id)
    };
    let mut store = TrustStore::open(
        &arguments.vault,
        WrappingKey::from_bytes(*wrapping_key.secret_bytes()),
    )?;
    let material = DeviceMaterial {
        identity: DeviceIdentity::generate()?,
        certificate: QuicCertificate::generate()?,
    };
    if let Err(error) = store.initialize_device(&material) {
        // The new key contains no useful state if vault initialization fails.
        // Keep it for diagnosis rather than deleting a secret behind the
        // caller's back.
        return Err(error.into());
    }
    println!(
        "Device ready.\n  id           {}\n  certificate  {}\n  vault        {}\n  wrapping key {}",
        material.identity.id(),
        material.certificate.pin(),
        arguments.vault.display(),
        key_location
    );
    Ok(())
}

fn device_status(arguments: &VaultArgs, json: bool) -> Result<()> {
    let store = open_vault(arguments)?;
    let material = require_device(&store)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "device_id": full_hex(material.identity.id().as_bytes()),
                "public_key": full_hex(&material.identity.public_key().to_bytes()),
                "certificate_pin": full_hex(material.certificate.pin().as_bytes()),
            }))?
        );
    } else {
        println!(
            "Cyrene device\n  id           {}\n  certificate  {}\n  paired peers {}",
            material.identity.id(),
            material.certificate.pin(),
            store.peers()?.len()
        );
    }
    Ok(())
}

async fn pair_listen(
    arguments: &VaultArgs,
    bind: SocketAddr,
    ttl: u64,
    share_database: Option<&Path>,
) -> Result<()> {
    if ttl == 0 || ttl > 3_600 {
        bail!("pairing lifetime must be between 1 and 3600 seconds");
    }
    let mut store = open_vault(arguments)?;
    let material = require_device(&store)?;
    let code = PairingCode::generate()?;
    let now = unix_time()?;
    let link = if let Some(database) = share_database {
        if !database.exists() {
            bail!(
                "{} does not exist; refusing to create a space accidentally",
                database.display()
            );
        }
        let app = App::open(database)
            .await
            .with_context(|| format!("could not open shared space in {}", database.display()))?;
        DeviceLink::new().with_space(app.space_id())
    } else {
        DeviceLink::new()
    };
    let context = link.encode()?;
    let (inviter, offer) = Inviter::start_with_context(
        &material.identity,
        &code,
        material.certificate.certificate_der(),
        &context,
        now,
        Duration::from_secs(ttl),
    )?;
    store.record_invitation(offer.invitation_id(), offer.expires_at())?;
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("could not listen on {bind}"))?;
    let address = listener.local_addr()?;
    println!(
        "Pairing invitation ready.\n  address  {address}\n  code     {code}\n  expires  in {ttl} seconds\n\nOn the other device:\n  cyrene pair join --vault … {address} {code}"
    );

    let exchange = async {
        let (mut stream, remote) = listener.accept().await?;
        write_frame(&mut stream, &offer).await?;
        let answer: Answer = read_frame(&mut stream).await?;
        let (peer, acknowledgement) = inviter.finish(&answer, unix_time()?)?;
        write_frame(&mut stream, &acknowledgement).await?;
        let record = PeerRecord::from_pairing(&peer, unix_time()?);
        let peer_link = DeviceLink::decode(peer.context())?;
        store.redeem_invitation_with_spaces(
            offer.invitation_id(),
            unix_time()?,
            &record,
            peer_link.spaces(),
        )?;
        println!("Paired {} from {remote}.", record.public_key.id());
        Result::<()>::Ok(())
    };
    timeout(Duration::from_secs(ttl), exchange)
        .await
        .map_err(|_| anyhow!("pairing invitation expired before a device completed it"))??;
    Ok(())
}

async fn pair_join(arguments: &VaultArgs, address: SocketAddr, code: &str) -> Result<()> {
    let mut store = open_vault(arguments)?;
    let material = require_device(&store)?;
    let code = PairingCode::parse(code)?;
    let mut stream = TcpStream::connect(address)
        .await
        .with_context(|| format!("could not connect to pairing listener at {address}"))?;
    let offer: Offer = read_frame(&mut stream).await?;
    let (joiner, answer) = Joiner::start(
        &material.identity,
        &code,
        material.certificate.certificate_der(),
        &offer,
        unix_time()?,
    )?;
    write_frame(&mut stream, &answer).await?;
    let acknowledgement: Acknowledgement = read_frame(&mut stream).await?;
    let peer = joiner.finish(&acknowledgement)?;
    let record = PeerRecord::from_pairing(&peer, unix_time()?);
    let link = DeviceLink::decode(peer.context())?;
    store.admit_peer_with_spaces(&record, link.spaces())?;
    println!(
        "Paired with {}. Linked {} personal space(s).",
        record.public_key.id(),
        link.spaces().len()
    );
    Ok(())
}

pub(crate) fn open_vault(arguments: &VaultArgs) -> Result<TrustStore> {
    let key = if let Some(path) = &arguments.key_file {
        WrappingKey::from_bytes(read_wrapping_key(path).with_context(|| {
            format!(
                "could not load {}; run `cyrene device init --vault {} --key-file {}` first",
                path.display(),
                arguments.vault.display(),
                path.display()
            )
        })?)
    } else {
        OsKeyStore::open(&arguments.keyring_id)?.load().with_context(|| {
            format!(
                "could not load OS credential-store slot {:?}; run `cyrene device init --vault {} --keyring-id {}` first",
                arguments.keyring_id,
                arguments.vault.display(),
                arguments.keyring_id
            )
        })?
    };
    TrustStore::open(&arguments.vault, key).map_err(Into::into)
}

pub(crate) fn require_device(store: &TrustStore) -> Result<DeviceMaterial> {
    store.load_device()?.ok_or_else(|| {
        anyhow!("the trust vault has no device identity; run `cyrene device init` first")
    })
}

pub(crate) fn read_wrapping_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!("wrapping key must be exactly 32 bytes, got {}", bytes.len())
    })
}

pub(crate) fn persist_wrapping_key(path: &Path, key: &[u8; 32]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(key)?;
    file.sync_all()?;
    Ok(())
}

async fn write_frame<T: Serialize>(stream: &mut TcpStream, message: &T) -> Result<()> {
    let encoded = serde_json::to_vec(message)?;
    if encoded.len() > PAIRING_FRAME_LIMIT {
        bail!("pairing message exceeds the {PAIRING_FRAME_LIMIT} byte limit");
    }
    let length = u32::try_from(encoded.len()).context("pairing message length overflow")?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<T> {
    let length = stream.read_u32().await?;
    let length = usize::try_from(length).context("pairing message length overflow")?;
    if length > PAIRING_FRAME_LIMIT {
        bail!("peer sent a pairing message above the {PAIRING_FRAME_LIMIT} byte limit");
    }
    let mut encoded = vec![0; length];
    stream.read_exact(&mut encoded).await?;
    serde_json::from_slice(&encoded).context("peer sent a malformed pairing message")
}

pub(crate) fn unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

fn full_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

fn render_inspection(path: &Path, status: &cyrene::LocalStatus) -> String {
    let health = if status.is_healthy() {
        "healthy"
    } else {
        "attention needed"
    };
    format!(
        "Cyrene local state\n  database     {}\n  space        {}\n  replica      {}\n  documents    {}\n  changes      {} local / {} replicated\n  frontier     {} local / {} replica\n  integrity    {} ({health})",
        path.display(),
        status.space,
        status.replica,
        status.documents,
        status.changes,
        status.replicated_changes,
        status.frontier,
        status.replica_frontier,
        status.integrity,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_hex_preserves_leading_zeroes() {
        assert_eq!(full_hex(&[0, 1, 254, 255]), "0001feff");
    }

    #[test]
    fn cli_shape_is_stable_and_complete() {
        use clap::CommandFactory as _;
        Cli::command().debug_assert();
    }
}
