mod actors;
mod collections;
mod webfinger;

use crate::{
    domainservd::{actors::get_actor, collections::get_outbox_collection},
    PrismaClient,
};
use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use clap::{Parser, Subcommand};
use config::File;
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
    pub connection_string: String,
    pub listen: String,
    pub use_ssl: bool,
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
}

type SharedState = Arc<Mutex<ServerState>>;

pub fn read_config(args: &Args) -> Result<Config> {
    let cfg = config::Config::builder()
        .set_default(
            "connection_string",
            "mongodb://dev:dev@localhost:27017/oxifed?authSource=admin&retryWrites=true&w=majority",
        )?
        .set_default("listen", "127.0.0.1:3000")?
        .set_default("use_ssl", false)?
        .add_source(File::with_name("domainservd").required(false))
        .add_source(File::with_name("/etc/oxifed/domainservd").required(false))
        .set_override_option("connection_string", args.connection_string.clone())?
        .build()?;
    Ok(cfg.try_deserialize()?)
}

pub async fn listen(cfg: Config) -> Result<()> {
    debug!("Starting domainservd");
    let prisam_client = PrismaClient::_builder()
        .with_url(cfg.connection_string.clone())
        .build()
        .await?;

    let mongo_client = mongodb::Client::with_uri_str(&cfg.connection_string).await?;

    let shared_state = SharedState::new(Mutex::new(ServerState {
        use_ssl: cfg.use_ssl,
        prisma: prisam_client,
        mongo: mongo_client.clone(),
    }));

    let app = Router::new()
        .route("/.well-known/webfinger", get(get_webfinger))
        .route("/actors/:actor", get(get_actor))
        .route("/actors/:actor/outbox", get(get_outbox_collection))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    info!("Listening on {}", &cfg.listen);
    axum::serve(listener, app).await?;
    mongo_client.shutdown();
    Ok(())
}
