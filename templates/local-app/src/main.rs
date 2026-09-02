use cyrene::prelude::*;

#[derive(Debug, Deserialize, Document, Serialize)]
#[cyrene(name = "starter.task", version = 1)]
struct Task {
    #[cyrene(id = 1)]
    title: String,
    #[cyrene(id = 2)]
    done: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let app = App::open("tasks.db").await?;
    let tasks = app.collection::<Task>("tasks");
    if tasks.list().await?.is_empty() {
        tasks
            .insert(Task {
                title: "Make something kind".into(),
                done: false,
            })
            .await?;
    }
    for (id, task) in tasks.list().await? {
        let mark = if task.done { "x" } else { " " };
        println!("[{mark}] {id}  {}", task.title);
    }
    Ok(())
}
