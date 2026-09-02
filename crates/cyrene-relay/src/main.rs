//! Self-hostable Cyrene opaque relay service.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Parser;
use cyrene_relay::{RelayLimits, RelayStore, serve_connection};
use tokio::{
    net::TcpListener,
    sync::Mutex,
    task::JoinSet,
    time::{MissedTickBehavior, interval, timeout},
};

const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "cyrene-relay", about = "Run a bounded opaque Cyrene relay")]
struct Arguments {
    /// TCP address to listen on; terminate TLS at a trusted reverse proxy.
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: SocketAddr,
    /// `SQLite` database path.
    #[arg(long, default_value = "cyrene-relay.db")]
    database: PathBuf,
    /// Per-mailbox retained ciphertext MiB.
    #[arg(long, default_value_t = 64)]
    mailbox_mib: u64,
    /// Service-wide retained ciphertext MiB.
    #[arg(long, default_value_t = 1024)]
    total_mib: u64,
    /// Per-mailbox object count.
    #[arg(long, default_value_t = 10_000)]
    mailbox_objects: u64,
    /// Seconds between local usage metrics; zero disables periodic output.
    #[arg(long, default_value_t = 60)]
    stats_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let mebibyte = 1024_u64 * 1024;
    let limits = RelayLimits {
        mailbox_bytes: arguments
            .mailbox_mib
            .checked_mul(mebibyte)
            .context("mailbox byte limit overflow")?,
        mailbox_objects: arguments.mailbox_objects,
        total_bytes: arguments
            .total_mib
            .checked_mul(mebibyte)
            .context("total byte limit overflow")?,
    };
    if limits.mailbox_bytes == 0
        || limits.mailbox_objects == 0
        || limits.total_bytes < limits.mailbox_bytes
    {
        bail!("limits must be non-zero and total MiB must cover one mailbox");
    }
    let store = Arc::new(Mutex::new(RelayStore::open(&arguments.database, limits)?));
    let listener = TcpListener::bind(arguments.bind).await?;
    println!("Cyrene relay listening on {}", listener.local_addr()?);
    let mut tasks = JoinSet::new();
    let mut statistics = interval(Duration::from_secs(arguments.stats_seconds.max(1)));
    statistics.set_missed_tick_behavior(MissedTickBehavior::Skip);
    statistics.tick().await;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let store = Arc::clone(&store);
                tasks.spawn(async move {
                    timeout(REQUEST_DEADLINE, serve_connection(stream, &store)).await
                });
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(Ok(Err(error)))) => eprintln!("relay_request_error error={error}"),
                    Some(Ok(Err(_))) => eprintln!("relay_request_timeout"),
                    Some(Err(error)) => eprintln!("relay_task_error error={error}"),
                    Some(Ok(Ok(Ok(())))) | None => {}
                }
            }
            _ = statistics.tick(), if arguments.stats_seconds != 0 => {
                match store.lock().await.usage() {
                    Ok((objects, bytes)) => {
                        println!("relay_usage objects={objects} ciphertext_bytes={bytes}");
                    }
                    Err(error) => eprintln!("relay_usage_error error={error}"),
                }
            }
            result = tokio::signal::ctrl_c() => {
                result.context("could not install shutdown signal handler")?;
                println!("Cyrene relay shutting down; draining active requests…");
                break;
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    let (objects, bytes) = store.lock().await.usage()?;
    println!("Cyrene relay stopped. objects={objects} ciphertext_bytes={bytes}");
    Ok(())
}
