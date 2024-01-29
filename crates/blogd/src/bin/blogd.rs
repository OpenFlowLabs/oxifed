use blogd::{listen, read_config, Args};
use clap::Parser;

#[tokio::main]
async fn main() -> miette::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = read_config(&args)?;
    listen(config).await?;
    Ok(())
}
