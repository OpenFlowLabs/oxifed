use clap::{Parser, Subcommand};
use oxiblog::*;
use std::{fs::File, io::Write, path::PathBuf};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    Start,
    GenToken,
}

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                "oxiblog=trace,tower_http=trace,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    let args = Args::parse();
    tracing::trace!("parsing commandline!");
    let cfg = load_config(args.config)?;
    match args.command {
        Commands::Start => {
            listen(cfg).await?;
        }
        Commands::GenToken => {
            let couch_client = oxiblog::couchdb::Client::new(cfg.couchdb);
            let token = gen_token(&couch_client).await?;
            let mut token_file = File::create("auth_token")?;
            token_file.write_all(token.to_base64()?.as_bytes())?;
        }
    };

    Ok(())
}
