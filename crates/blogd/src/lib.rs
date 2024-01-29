mod mutation;
mod query;

use async_graphql::{
    http::{playground_source, GraphQLPlaygroundConfig},
    EmptySubscription, Schema,
};
use async_graphql_axum::{GraphQL, GraphQLSubscription};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use clap::{Parser, Subcommand};
use config::File;
use lapin::{
    options::{ExchangeBindOptions, ExchangeDeclareOptions, QueueDeclareOptions},
    types::{FieldTable, LongString, ShortString},
};
use miette::Diagnostic;
#[allow(unused_imports)]
use oxifed::prisma::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::{mutation::MutationRoot, query::QueryRoot};

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    PrismaError(#[from] prisma_client_rust::NewClientError),

    #[error(transparent)]
    QueryError(#[from] prisma_client_rust::QueryError),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    Config(#[from] config::ConfigError),

    #[error("please specify an actor in the format name@domain")]
    WrongActorFormat,

    #[error("post has no frontmatter can not create")]
    NoFrontmatter,

    #[error(transparent)]
    SerdeJSON(#[from] serde_json::error::Error),

    #[error(transparent)]
    PKCS8Priv(#[from] ed25519_dalek::pkcs8::Error),

    #[error(transparent)]
    PKCS8Pub(#[from] ed25519_dalek::pkcs8::spki::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    MongoDB(#[from] mongodb::error::Error),

    #[error(transparent)]
    MongoValueAccessError(#[from] mongodb::bson::raw::ValueAccessError),

    #[error(transparent)]
    CreatePoolError(#[from] deadpool_lapin::CreatePoolError),

    #[error(transparent)]
    OxiFed(#[from] oxifed::Error),

    #[error(transparent)]
    LapinError(#[from] lapin::Error),

    #[error(transparent)]
    LapinPoolError(#[from] deadpool_lapin::PoolError),

    #[error("could not find {0}")]
    NotFound(String),
}

#[derive(Debug, Serialize)]
struct ErrorJson {
    message: String,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            Error::QueryError(x) => (
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

pub type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Parser)]
pub struct Args {
    pub connection_string: Option<String>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Deserialize)]
pub struct Config {
    pub postgres: PostgresConfig,
    pub rabbitmq: deadpool_lapin::Config,
    pub acitivity_publish_channel: String,
    pub listen: String,
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
    prisma: crate::PrismaClient,
    rbmq_pool: deadpool_lapin::Pool,
    activity_publish_channel: String,
}

type SharedState = Arc<Mutex<ServerState>>;

pub fn read_config(_args: &Args) -> Result<Config> {
    let cfg = config::Config::builder()
        .set_default(
            "postgres.connection_string",
            "postgres://dev:dev@localhost:5432/oxifed",
        )?
        .set_default("listen", "127.0.0.1:3100")?
        .set_default("rabbitmq.url", "amqp://dev:dev@localhost:5672/dev")?
        .set_default("acitivity_publish_channel", "activity.publish")?
        .add_source(File::with_name("oxiblog").required(false))
        .add_source(File::with_name("/etc/oxifed/blog").required(false))
        .build()?;
    Ok(cfg.try_deserialize()?)
}

pub async fn listen(cfg: Config) -> Result<()> {
    debug!("Starting blog api daemon");
    let prisam_client = PrismaClient::_builder()
        .with_url(cfg.postgres.connection_string.clone())
        .build()
        .await?;

    let shared_state = SharedState::new(Mutex::new(ServerState {
        prisma: prisam_client,
        rbmq_pool: cfg.rabbitmq.create_pool(Some(deadpool::Runtime::Tokio1))?,
        activity_publish_channel: cfg.acitivity_publish_channel.clone(),
    }));

    let conn = shared_state.lock().await.rbmq_pool.get().await?;
    let init_channel = conn.create_channel().await?;
    let queue_name = shared_state.lock().await.activity_publish_channel.clone();
    let queue_dlx_name = format!("{queue_name}.dlx");
    debug!("Initializing deadletter queue {queue_dlx_name}");
    init_channel
        .queue_declare(
            &queue_dlx_name,
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;
    init_channel
        .exchange_declare(
            &queue_dlx_name,
            lapin::ExchangeKind::Direct,
            ExchangeDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;
    init_channel
        .exchange_bind(
            &queue_dlx_name,
            &queue_dlx_name,
            &queue_dlx_name,
            ExchangeBindOptions::default(),
            FieldTable::default(),
        )
        .await?;

    let mut dlx_declare_table = FieldTable::default();
    dlx_declare_table.insert(
        ShortString::from("x-dead-letter-exchange"),
        lapin::types::AMQPValue::LongString(LongString::from(queue_dlx_name)),
    );
    init_channel
        .queue_declare(
            &queue_name,
            QueueDeclareOptions::default(),
            dlx_declare_table,
        )
        .await?;

    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(shared_state)
        .finish();

    let blog_router = Router::new()
        .route(
            "/",
            get(graphql_playground).post_service(GraphQL::new(schema.clone())),
        )
        .route_service("/ws", GraphQLSubscription::new(schema));

    let app = Router::new().nest("/api/v1/blog", blog_router);

    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    info!("Listening on {}", &cfg.listen);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn graphql_playground() -> impl IntoResponse {
    Html(playground_source(
        GraphQLPlaygroundConfig::new("/api/v1/blog").subscription_endpoint("/api/v1/blog/ws"),
    ))
}
