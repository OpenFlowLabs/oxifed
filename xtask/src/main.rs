mod identd;

use std::thread;

use ::identd::ServerConfig;
use clap::{Parser, Subcommand};
use miette::Diagnostic;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    TestInit,
}

fn main() -> miette::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                "xtask=trace,tower_http=trace,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    let args = Args::parse();
    match args.commands {
        Commands::TestInit => test_init()?,
    };

    Ok(())
}

fn test_init() -> miette::Result<()> {
    let cfg = ServerConfig::default();
    thread::spawn(|| async move {
        crate::identd::run_test_server(cfg).await.unwrap();
    });
    Ok(())
}
