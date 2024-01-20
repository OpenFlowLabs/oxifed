use clap::Parser;
use oxifed::domainservd::*;

#[tokio::main]
async fn main() -> miette::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = read_config(&args)?;
    listen(config).await?;
    Ok(())
}
