use clap::{Parser, Subcommand};
use publisherd::*;
use std::path::PathBuf;
use tracing_subscriber::prelude::*;

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
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        // axum logs rejections from built-in extractors with the `axum::rejection`
                        // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                        "publisherd=trace,tower_http=trace,axum::rejection=trace".into()
                    }),
                )
                .with(tracing_subscriber::fmt::layer())
                .init();
            let cfg = build_config(args.config)?;
            listen(&cfg).await?;
            Ok(())
        }
    }
}
