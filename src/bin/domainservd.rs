use clap::Parser;
use oxifed::*;

#[tokio::main]
async fn main() -> miette::Result<()> {
    let args = Args::parse();
    let config = read_config(&args)?;
    run_command(config, &args).await?;
    Ok(())
}
