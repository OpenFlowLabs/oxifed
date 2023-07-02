use activitypub_federation::config::FederationConfig;
use miette::Context;
use miette::IntoDiagnostic;
use oxifed_server::*;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    let app_data = AppData::new().await?;

    let fedi_config = FederationConfig::builder()
        .app_data(app_data)
        .domain(app_data.get_domain())
        .build()
        .into_diagnostic()?;

    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::TRACE)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).into_diagnostic()?;

    listen(&fedi_config).await
}
