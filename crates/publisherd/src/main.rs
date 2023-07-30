use std::path::PathBuf;

use clap::{Parser, Subcommand};
use publisherd::*;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Start,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Start => {
            let cfg = build_config(args.config)?;
            listen(&cfg).await?;
            Ok(())
        }
    }
}
