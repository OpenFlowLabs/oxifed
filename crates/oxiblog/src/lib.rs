pub mod couchdb;
extern crate biscuit_auth as biscuit;

use crate::couchdb::*;
use axum::{
    extract::{Path, State},
    headers::{authorization::Bearer, Authorization},
    response::IntoResponse,
    routing::post,
    Json, Router, TypedHeader,
};
use biscuit::{Authorizer, Biscuit, KeyPair, PrivateKey, PublicKey};
use comrak::{markdown_to_html, ComrakOptions};
use config::{builder::DefaultState, File};
use deadpool_lapin::Pool;
use hyper::StatusCode;
use lapin::{options::BasicPublishOptions, protocol::basic::AMQPProperties};
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use slugify::slugify;
use std::{collections::HashMap, net::AddrParseError, path::PathBuf, sync::Arc};
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
    #[error(transparent)]
    BiscuitTokenError(#[from] biscuit::error::Token),
    #[error(transparent)]
    BiscuitFormatError(#[from] biscuit::error::Format),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    Lapin(#[from] lapin::Error),
    #[error(transparent)]
    URL(#[from] url::ParseError),
    #[error("couchdb error {0}")]
    CouchClientError(String),
    #[error("rabbitmq error {0}")]
    RabbitMQPool(String),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

pub type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub address: String,
    pub port: String,
    pub couchdb: CouchDBConfig,
    pub rabbitmq: RabbitMQConfig,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct DBKeypair {
    pub private: String,
    pub public: String,
}

pub async fn gen_new_keypair(couch_client: &couchdb::Client) -> Result<()> {
    let root = KeyPair::new();
    if !couch_client.has_db("internal").await? {
        couch_client.create_db("internal").await?;
    }
    let kp = DBKeypair {
        private: root.private().to_bytes_hex(),
        public: root.public().to_bytes_hex(),
    };
    couch_client
        .upsert_document("internal", "keypair", &kp)
        .await?;
    Ok(())
}

pub async fn gen_token(couch_client: &couchdb::Client) -> Result<Biscuit> {
    if !couch_client.has_document("internal", "keypair").await? {
        gen_new_keypair(couch_client).await?;
    }
    let kp: DBKeypair = couch_client.get_document("internal", "keypair").await?;
    let pk = PrivateKey::from_bytes_hex(&kp.private)?;
    let root = KeyPair::from(&pk);
    let tk = biscuit::macros::biscuit!(
        r#"
          right("blogs", "create");
          right("blogs", "post");
        "#
    )
    .build(&root)?;
    Ok(tk)
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
        .set_default("rabbitmq.vhost", "master")?
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
    blog_create_authorizer: Authorizer,
    blog_post_authorizer: Authorizer,
    private_key: PrivateKey,
    public_key: PublicKey,
    mq_pool: Pool,
}

type SharedState = Arc<AppState>;

pub async fn listen(cfg: Config) -> Result<()> {
    tracing::trace!("Starting axum router setup");

    let blog_create_authorizer = biscuit::macros::authorizer!(
        r#"
     resource("blogs");
     operation("create");
     allow if right("blogs", "create");
  "#
    );

    let blog_post_authorizer = biscuit::macros::authorizer!(
        r#"
     resource("blogs");
     operation("post");
     allow if right("blogs", "post");
  "#
    );

    let client = Client::new(cfg.couchdb);
    let kp: DBKeypair = client.get_document("internal", "keypair").await?;
    let private_key = PrivateKey::from_bytes_hex(&kp.private)?;
    let public_key = PublicKey::from_bytes_hex(&kp.public)?;
    let mut pool_config = deadpool_lapin::Config::default();
    pool_config.url = Some(if cfg.rabbitmq.ssl {
        let port = if let Some(port) = cfg.rabbitmq.port {
            port.clone()
        } else {
            String::from("5671")
        };
        format!(
            "amqps://{}:{}@{}:{}/{}",
            cfg.rabbitmq.username,
            cfg.rabbitmq.password,
            cfg.rabbitmq.host,
            port,
            cfg.rabbitmq.vhost
        )
    } else {
        let port = if let Some(port) = cfg.rabbitmq.port {
            port.clone()
        } else {
            String::from("5672")
        };
        format!(
            "amqp://{}:{}@{}:{}/{}",
            cfg.rabbitmq.username,
            cfg.rabbitmq.password,
            cfg.rabbitmq.host,
            port,
            cfg.rabbitmq.vhost
        )
    });

    let mq_pool = pool_config
        .create_pool(Some(deadpool_lapin::Runtime::Tokio1))
        .map_err(|e| Error::RabbitMQPool(e.to_string()))?;
    let app = Router::new()
        .route("/", post(create_blog))
        .route("/:blog", post(publish_post))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(Arc::new(AppState {
            couch_client: client,
            blog_create_authorizer,
            blog_post_authorizer,
            private_key,
            public_key,
            mq_pool,
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
    #[error(transparent)]
    Download(#[from] reqwest::Error),
}
impl std::fmt::Display for HTTPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match &self {
                HTTPError::UnAuthorized => String::from("unauthorized"),
                HTTPError::InternalError(err) => format!("internal error: {}", err),
                HTTPError::Download(err) => format!("internal error: {}", err),
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
            HTTPError::Download(err) => {
                tracing::error!("content download error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
            }
        }
    }
}

type HTTPResult<T> = std::result::Result<T, HTTPError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBlogRequest {
    pub name: String,
    pub settings: BlogSettings,
}

#[derive(Debug, Serialize, Deserialize)]
enum BlogSettingsName {
    Settings,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlogSettings {
    _id: Option<BlogSettingsName>,
    pub domain: String,
    pub author: String,
    pub info_text: String,
}

impl BlogSettings {
    pub fn new(domain: String, author: String, info_text: String) -> Self {
        Self {
            _id: Some(BlogSettingsName::Settings),
            domain,
            author,
            info_text,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateBlogResponse {
    name: String,
}

async fn create_blog(
    State(state): State<SharedState>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    Json(request): Json<CreateBlogRequest>,
) -> HTTPResult<Json<CreateBlogResponse>> {
    tracing::debug!("{:?}", request);
    let token =
        Biscuit::from_base64(authorization.0.token(), &state.public_key).map_err(|err| {
            tracing::error!("token could not be verified: {}", err);
            HTTPError::UnAuthorized
        })?;
    token
        .authorize(&state.blog_create_authorizer)
        .map_err(|err| {
            tracing::error!("token not authorized: {}", err);
            HTTPError::UnAuthorized
        })?;
    let blog_db_name = slugify(&request.name, "", "-", Some(63));
    state.couch_client.create_db(&blog_db_name).await?;
    let mut settings = request.settings;
    settings._id = Some(BlogSettingsName::Settings);
    state
        .couch_client
        .post_document(&blog_db_name, &settings)
        .await?;
    Ok(Json(CreateBlogResponse { name: blog_db_name }))
}

#[derive(Debug, Serialize, Deserialize)]
struct BlogPost {
    pub title: String,
    pub summary: String,
    pub content: String,
    #[serde(rename = "_attachments")]
    pub attachments: couchdb::Attachments,
}

fn base64_encode(input: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};
    let encoded: String = general_purpose::STANDARD_NO_PAD.encode(input);
    encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Content {
    Url(url::Url),
    Embedded(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadBlogRequest {
    pub title: String,
    pub summary: String,
    pub content: Content,
    pub to: Option<String>,
}
async fn publish_post(
    State(state): State<SharedState>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    Path(blog): Path<String>,
    Json(request): Json<UploadBlogRequest>,
) -> HTTPResult<StatusCode> {
    tracing::debug!("{:?}", request);

    let token =
        Biscuit::from_base64(authorization.0.token(), &state.public_key).map_err(|err| {
            tracing::error!("error deserializing and verifying token: {}", err);
            HTTPError::UnAuthorized
        })?;
    token
        .authorize(&state.blog_post_authorizer)
        .map_err(|err| {
            tracing::error!("error authorizing token: {}", err);
            HTTPError::UnAuthorized
        })?;
    let content = match &request.content {
        Content::Url(url) => {
            let content = reqwest::get(url.clone()).await?.text().await?;
            content
        }
        Content::Embedded(s) => s.clone(),
    };
    let html_content = markdown_to_html(&content, &ComrakOptions::default());
    let html_summary = markdown_to_html(&request.summary, &ComrakOptions::default());
    let base64_content = base64_encode(content.as_bytes());
    let base64_summary = base64_encode(request.summary.as_bytes());
    let post = BlogPost {
        title: request.title,
        summary: html_summary,
        content: html_content.clone(),
        attachments: HashMap::from([
            (
                String::from("src"),
                Attachment::new_upload(String::from("text/plain"), base64_content),
            ),
            (
                String::from("summary_src"),
                Attachment::new_upload(String::from("text/plain"), base64_summary),
            ),
        ]),
    };
    state.couch_client.post_document(&blog, &post).await?;

    tracing::trace!("Getting blog settings from database");
    let blog_settings: BlogSettings = state.couch_client.get_document(&blog, "Settings").await?;

    tracing::trace!("Post saved to database sending to rabbitmq");
    let chan = state
        .mq_pool
        .get()
        .await
        .map_err(|err| {
            tracing::error!("cannot get connection: {}", err);
            HTTPError::InternalError(Error::RabbitMQPool(err.to_string()))
        })?
        .create_channel()
        .await
        .map_err(|err| {
            tracing::error!("cannot open channel: {}", err);

            HTTPError::InternalError(Error::RabbitMQPool(err.to_string()))
        })?;

    let kp = KeyPair::from(&state.private_key);
    let biscuit = biscuit::macros::biscuit!(
        r#"
          right({blog}, "read");
        "#,
        blog = blog.clone(),
    )
    .build(&kp)
    .map_err(|err| Error::from(err))?;

    let title_slug = slugify(post.title.as_str(), "", "/", None);
    let full_id = format!(
        "https://{}/articles/{}",
        blog_settings.domain.as_str(),
        &title_slug
    );
    let author_actor = format!(
        "https://{}/actors/{}",
        blog_settings.domain.as_str(),
        blog_settings.author.as_str()
    );
    let article = activitypub::Article {
        id: (&full_id).parse().map_err(|err| Error::from(err))?,
        attributed_to: (&author_actor).parse().map_err(|err| Error::from(err))?,
        content: html_content.clone(),
    };
    let to = if let Some(to) = request.to {
        vec![to.parse().map_err(|err| Error::from(err))?]
    } else {
        vec![]
    };
    let msg = oxilib::Message {
        activity: oxilib::Activity::Create {
            id: full_id.clone(),
            object: article,
            recipients: oxilib::Recipients {
                to,
                cc: None,
                bto: None,
                bcc: None,
            },
        },
        biscuit: biscuit.to_base64().map_err(|err| Error::from(err))?,
    };
    let payload = serde_json::to_vec(&msg).map_err(|err| Error::from(err))?;

    tracing::trace!("Sending out message to rabbitmq");
    chan.basic_publish(
        "outbox",
        "",
        BasicPublishOptions::default(),
        &payload,
        AMQPProperties::default(),
    )
    .await
    .map_err(|err| Error::from(err))?;
    Ok(StatusCode::CREATED)
}
