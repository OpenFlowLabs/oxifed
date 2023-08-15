mod couchdb;

use crate::couchdb::*;
use axum::{
    extract::State,
    headers::{authorization::Bearer, Authorization},
    response::IntoResponse,
    routing::post,
    Json, Router, TypedHeader,
};
use config::{builder::DefaultState, File};
use hyper::StatusCode;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use std::{net::AddrParseError, path::PathBuf, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    ParseString(#[from] AddrParseError),
    #[error(transparent)]
    HyperError(#[from] hyper::Error),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error("couchdb error {0}")]
    CouchClientError(String),
}

pub type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    address: String,
    port: String,
    couchdb: CouchDBConfig,
    rabbitmq: RabbitMQConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RabbitMQConfig {
    username: String,
    password: String,
    host: String,
    port: Option<String>,
    vhost: String,
    ssl: bool,
}

impl RabbitMQConfig {
    pub fn get_url(&self) -> String {
        let scheme = if self.ssl { "amqps" } else { "amqp" };
        let port = if let Some(port) = &self.port {
            port.clone()
        } else {
            if self.ssl {
                String::from("5671")
            } else {
                String::from("5672")
            }
        };

        format!(
            "{}://{}:{}@{}:{}/{}",
            scheme, self.username, self.password, self.host, port, self.vhost
        )
    }
}

pub fn load_config(config_path: Option<PathBuf>) -> Result<Config> {
    tracing::trace!("Loading config");
    let mut builder = config::ConfigBuilder::<DefaultState>::default()
        .set_default("address", "127.0.0.1")?
        .set_default("port", "3012")?
        .set_default("couchdb.username", "dev")?
        .set_default("couchdb.password", "dev")?
        .set_default("couchdb.host", "localhost")?
        .set_default("couchdb.port", "5984")?
        .set_default("couchdb.ssl", false)?
        .set_default("rabbitmq.username", "dev")?
        .set_default("rabbitmq.password", "dev")?
        .set_default("rabbitmq.host", "localhost")?
        .set_default("rabbitmq.port", "5672")?
        .set_default("rabbitmq.ssl", false)?
        .set_default("rabbitmq.vhost", "dev")?
        .add_source(File::with_name("oxiblog.toml").required(false))
        .add_source(File::with_name("/etc/oxiblog.yaml").required(false));

    if let Some(p) = config_path {
        builder = builder.add_source(File::with_name(p.to_string_lossy().to_string().as_str()));
    }

    let cfg = builder.build()?;
    Ok(cfg.try_deserialize()?)
}

#[derive(Clone)]
struct AppState {
    couch_client: Client,
}

type SharedState = Arc<AppState>;

pub async fn listen(cfg: Config) -> Result<()> {
    tracing::trace!("Starting axum router setup");
    let client = Client::new(cfg.couchdb);
    let app = Router::new()
        .route("/", post(create_blog))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(Arc::new(AppState {
            couch_client: client,
        }));

    // run it with hyper on localhost:3000
    tracing::info!("Listening on {}:{}", cfg.address, cfg.port);
    let addr = format!("{}:{}", cfg.address, cfg.port);
    axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

#[derive(Debug, Error)]
enum HTTPError {
    UnAuthorized,
    #[error(transparent)]
    InternalError(#[from] Error),
}
impl std::fmt::Display for HTTPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match &self {
                HTTPError::UnAuthorized => String::from("unauthorized"),
                HTTPError::InternalError(err) => format!("internal error: {}", err),
            }
        )
    }
}
impl IntoResponse for HTTPError {
    fn into_response(self) -> axum::response::Response {
        match self {
            HTTPError::UnAuthorized => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
            HTTPError::InternalError(err) => {
                tracing::error!("internal error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
            }
        }
    }
}

type HTTPResult<T> = std::result::Result<T, HTTPError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBlogRequest {
    pub name: String,
    pub domain: String,
}
async fn create_blog(
    State(state): State<SharedState>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    Json(request): Json<CreateBlogRequest>,
) -> HTTPResult<StatusCode> {
    tracing::debug!("{:?}", request);
    tracing::debug!("{:?}", authorization);
    state
        .couch_client
        .create_db(&request.name.to_lowercase())
        .await?;
    Ok(StatusCode::CREATED)
}
