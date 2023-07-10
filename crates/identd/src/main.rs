use clap::{Parser, Subcommand};
#[cfg(debug_assertions)]
use identd::realm_migration::RealmMigrator;
use identd::{user_migration::Migrator, *};
use sea_orm_migration::MigratorTrait;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand, Clone, Default)]
pub enum Commands {
    #[default]
    Start,
    Migrate,
    #[cfg(debug_assertions)]
    CreateRealmDBOnDisk,
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
                        "identd=trace,tower_http=trace,axum::rejection=trace".into()
                    }),
                )
                .with(tracing_subscriber::fmt::layer())
                .init();
            let cfg = ServerConfig::default();
            let server = ServerState::new(&cfg).await?;

            identd::listen(server).await
        }
        Commands::Migrate => {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        // axum logs rejections from built-in extractors with the `axum::rejection`
                        // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                        "identd=trace,tower_http=trace,axum::rejection=trace,sqlx=trace,sea_orm=trace"
                            .into()
                    }),
                )
                .with(tracing_subscriber::fmt::layer())
                .init();
            tracing::info!("Starting migrations by manual command");
            let cfg = ServerConfig::default();
            tracing::info!("Connecting to database URL: {}", &cfg.db_url);
            let conn = cfg.open_db_conn().await?;
            tracing::debug!("Mark: Staring migration; connection was sucessfull");
            Migrator::up(&conn, None).await?;
            Ok(())
        }
        #[cfg(debug_assertions)]
        Commands::CreateRealmDBOnDisk => {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        // axum logs rejections from built-in extractors with the `axum::rejection`
                        // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                        "identd=trace,tower_http=trace,axum::rejection=trace,sqlx=trace,sea_orm=trace"
                            .into()
                    }),
                )
                .with(tracing_subscriber::fmt::layer())
                .init();
            tracing::info!("Starting migrations by manual command");
            let cfg = ServerConfig::default();
            tracing::info!("Connecting to database URL: sqlite://realms.db?mode=rwc");
            let conn = cfg
                .open_realm_db_conn(Some(String::from("realms.db")))
                .await?;
            tracing::debug!("Mark: Staring migration; connection was sucessfull");
            RealmMigrator::up(&conn, None).await?;
            Ok(())
        }
    }
}
