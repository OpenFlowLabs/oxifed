use activitypub_federation::config::FederationConfig;
use bonsaidb::local::config::Builder;
use bonsaidb::local::config::StorageConfiguration;
use bonsaidb::local::AsyncDatabase;
use dotenvy::dotenv;
use miette::IntoDiagnostic;
use oxifed_server::*;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> miette::Result<()> {
    dotenv().into_diagnostic()?;
    let db_storage_conf = StorageConfiguration::new(env_var("DATABASE")?);
    let db = AsyncDatabase::open::<AppSchema>(db_storage_conf)
        .await
        .into_diagnostic()?;

    let app_data = AppData { db };

    let fedi_config = FederationConfig::builder()
        .app_data(app_data)
        .domain(env_var("DOMAIN")?)
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

    let number_of_yaks = 3;
    // this creates a new event, outside of any spans.
    info!(number_of_yaks, "preparing to shave yaks");

    let number_shaved = 2;
    info!(
        all_yaks_shaved = number_shaved == number_of_yaks,
        "yak shaving completed."
    );

    Ok(())
}
