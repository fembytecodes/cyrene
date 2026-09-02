//! Minimal durable counter example.

use cyrene::prelude::*;

#[derive(Debug, Deserialize, Document, Serialize)]
#[cyrene(name = "counter.value", version = 1)]
struct Counter {
    #[cyrene(id = 1)]
    value: i64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let app = App::open("counter.db").await?;
    let counters = app.collection::<Counter>("counter");

    let (id, mut counter) = if let Some(found) = counters.list().await?.pop() {
        found
    } else {
        let counter = Counter { value: 0 };
        let id = counters.insert(counter).await?;
        (id, Counter { value: 0 })
    };
    counter.value += 1;
    counters.put(id, counter).await?;

    let counter = counters
        .get(id)
        .await?
        .expect("the counter was just stored");
    println!("This program has run {} time(s).", counter.value);
    Ok(())
}
