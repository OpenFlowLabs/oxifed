use clap::Parser;
use oxifed::domainservd::*;

#[tokio::main]
async fn main() -> miette::Result<()> {
    let args = Args::parse();
    let config = read_config(&args)?;
    listen(config, &args).await?;
    Ok(())
}
