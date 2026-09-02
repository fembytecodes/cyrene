//! Release-mode smoke benchmark for Cyrene's common local path.

use std::time::Instant;

use cyrene::App;
use serde::{Deserialize, Serialize};

const OPERATIONS: u32 = 2_000;

#[derive(Clone, Debug, Deserialize, Serialize, cyrene::Document)]
#[cyrene(name = "bench.note", version = 1)]
struct Note {
    #[cyrene(id = 1)]
    text: String,
}

#[tokio::main]
async fn main() -> cyrene::Result<()> {
    let startup = Instant::now();
    let app = App::in_memory().await?;
    let startup = startup.elapsed();
    let notes = app.collection::<Note>("notes");

    let writes = Instant::now();
    let mut ids = Vec::with_capacity(OPERATIONS as usize);
    for index in 0..OPERATIONS {
        ids.push(
            notes
                .insert(Note {
                    text: format!("offline note {index}"),
                })
                .await?,
        );
    }
    let writes = writes.elapsed();

    let reads = Instant::now();
    for id in ids {
        std::hint::black_box(notes.get(id).await?);
    }
    let reads = reads.elapsed();

    println!("Cyrene local-store benchmark ({OPERATIONS} operations)");
    println!("  startup              {startup:?}");
    println!("  acknowledged writes  {:?}/op", writes / OPERATIONS);
    println!("  point reads          {:?}/op", reads / OPERATIONS);
    Ok(())
}
