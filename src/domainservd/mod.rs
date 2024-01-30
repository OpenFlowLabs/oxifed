mod actors;
mod collections;
mod inbox;
mod webfinger;

use crate::{
    domainservd::{
        actors::get_actor,
        collections::get_outbox_collection,
        inbox::{post_inbox, post_shared_inbox},
    },
    PrismaClient,
};
use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use config::File;
use lapin::{options::ExchangeDeclareOptions, types::FieldTable};
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, info};
use webfinger::*;

#[derive(Debug, Error, Diagnostic)]
pub enum DomainServdError {
    #[error(transparent)]
    PrismaError(#[from] prisma_client_rust::NewClientError),

    #[error(transparent)]
    RelationNotFetched(#[from] prisma_client_rust::RelationNotFetchedError),

    #[error(transparent)]
    QueryError(#[from] prisma_client_rust::QueryError),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    Config(#[from] config::ConfigError),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    MongoDB(#[from] mongodb::error::Error),

    #[error(transparent)]
    MongoValueAccessError(#[from] mongodb::bson::raw::ValueAccessError),

    #[error(transparent)]
    CreatePoolError(#[from] deadpool_lapin::CreatePoolError),

    #[error(transparent)]
    LapinError(#[from] lapin::Error),

    #[error(transparent)]
    LapinPoolError(#[from] deadpool_lapin::PoolError),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    #[error("could not find {0}")]
    NotFound(String),
}

type Result<T> = std::result::Result<T, DomainServdError>;

#[derive(Debug, Serialize)]
struct ErrorJson {
    message: String,
}

impl IntoResponse for DomainServdError {
    fn into_response(self) -> axum::response::Response {
        match self {
            DomainServdError::QueryError(x) => (
                StatusCode::NOT_FOUND,
                Json(ErrorJson {
                    message: x.to_string(),
                }),
            ),
            x => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorJson {
                    message: x.to_string(),
                }),
            ),
        }
        .into_response()
    }
}

#[derive(Debug, Parser)]
pub struct Args {
    pub connection_string: Option<String>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Deserialize)]
pub struct Config {
    pub postgres: PostgresConfig,
    pub mongodb: MongoDBConfig,
    pub rabbitmq: deadpool_lapin::Config,
    pub acitivity_process_channel: String,
    pub listen: String,
    pub use_ssl: bool,
}

#[derive(Deserialize)]
pub struct MongoDBConfig {
    pub connection_string: String,
}

#[derive(Deserialize)]
pub struct PostgresConfig {
    pub connection_string: String,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    Start,
}

#[derive(Debug)]
struct ServerState {
    use_ssl: bool,
    prisma: crate::PrismaClient,
    mongo: mongodb::Client,
    rbmq_pool: deadpool_lapin::Pool,
    acitivity_process_channel: String,
}

type SharedState = Arc<Mutex<ServerState>>;

pub fn read_config(args: &Args) -> Result<Config> {
    let cfg = config::Config::builder()
        .set_default(
            "mongodb.connection_string",
            "mongodb://dev:dev@localhost:27017/oxifed?authSource=admin&retryWrites=true&w=majority",
        )?
        .set_default(
            "postgres.connection_string",
            "postgres://dev:dev@localhost:5432/oxifed",
        )?
        .set_default("listen", "127.0.0.1:3000")?
        .set_default("use_ssl", false)?
        .set_default("rabbitmq.url", "amqp://dev:dev@localhost:5672/dev")?
        .set_default("acitivity_process_channel", "activity.process")?
        .add_source(File::with_name("domainservd").required(false))
        .add_source(File::with_name("/etc/oxifed/domainservd").required(false))
        .set_override_option("connection_string", args.connection_string.clone())?
        .build()?;
    Ok(cfg.try_deserialize()?)
}

pub async fn listen(cfg: Config) -> Result<()> {
    debug!("Starting domainservd");
    let prisam_client = PrismaClient::_builder()
        .with_url(cfg.postgres.connection_string.clone())
        .build()
        .await?;

    let mongo_client = mongodb::Client::with_uri_str(&cfg.mongodb.connection_string).await?;

    let shared_state = SharedState::new(Mutex::new(ServerState {
        use_ssl: cfg.use_ssl,
        prisma: prisam_client,
        mongo: mongo_client.clone(),
        rbmq_pool: cfg.rabbitmq.create_pool(Some(deadpool::Runtime::Tokio1))?,
        acitivity_process_channel: cfg.acitivity_process_channel,
    }));

    {
        let conn = shared_state.lock().await.rbmq_pool.get().await?;
        let init_channel = conn.create_channel().await?;
        let base_queue_name = shared_state.lock().await.acitivity_process_channel.clone();
        debug!("Initializing processing exchanges");
        for kind in vec!["create", "follow", "accept", "announce", "like"] {
            let exchange_name = format!("{base_queue_name}.{kind}");

            init_channel
                .exchange_declare(
                    &exchange_name,
                    lapin::ExchangeKind::Fanout,
                    ExchangeDeclareOptions::default(),
                    FieldTable::default(),
                )
                .await?;
        }
    }

    let app = Router::new()
        .route("/.well-known/webfinger", get(get_webfinger))
        .route("/actors/:actor", get(get_actor))
        .route("/actors/:actor/outbox", get(get_outbox_collection))
        .route("/actors/:actor/inbox", post(post_inbox))
        .route("/inbox", post(post_shared_inbox))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    info!("Listening on {}", &cfg.listen);
    axum::serve(listener, app).await?;
    mongo_client.shutdown().await;
    Ok(())
}
