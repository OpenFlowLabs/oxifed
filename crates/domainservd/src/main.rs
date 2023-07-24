use activitypub::{activities::Activity, *};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use lapin::{
    options::{BasicPublishOptions, QueueDeclareOptions},
    protocol::basic::AMQPProperties,
    types::FieldTable,
};
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing_subscriber::prelude::*;
use url::Url;
use webfinger::{Link, Webfinger};

#[derive(Debug, Error, Diagnostic)]
enum Error {
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),

    #[error(transparent)]
    ConfigError(#[from] config::ConfigError),

    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    #[error(transparent)]
    LapinError(#[from] lapin::Error),

    #[error(transparent)]
    LapinPool(#[from] deadpool_lapin::PoolError),

    #[error("{0}")]
    HyperError(String),

    #[error("bad resource query")]
    BadWebfingerResource,

    #[error("unknown account")]
    UnknownUser,

    #[error("internal server error: {0}")]
    InternalError(String),
}

#[derive(Debug, Serialize)]
struct ErrorJson {
    message: String,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            Error::BadWebfingerResource => (
                StatusCode::BAD_REQUEST,
                Json(ErrorJson {
                    message: self.to_string(),
                }),
            )
                .into_response(),
            Error::UnknownUser => (
                StatusCode::NOT_FOUND,
                Json(ErrorJson {
                    message: self.to_string(),
                }),
            )
                .into_response(),
            x => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorJson {
                    message: x.to_string(),
                }),
            )
                .into_response(),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Start,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    domain: String,
    addr: Option<String>,
    use_ssl: bool,
    accounts: HashMap<String, String>,
    amqp_url: String,
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Start => {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        // axum logs rejections from built-in extractors with the `axum::rejection`
                        // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                        "domainservd=trace,tower_http=trace,axum::rejection=trace".into()
                    }),
                )
                .with(tracing_subscriber::fmt::layer())
                .init();
            let cfg = load_config().await?;
            listen(&cfg).await?;
        }
    };

    Ok(())
}

#[derive(Debug, Clone)]
struct ServerState {
    domain: String,
    use_ssl: bool,
    accounts: HashMap<String, String>,
    mq_pool: deadpool_lapin::Pool,
}

type SharedState = Arc<Mutex<ServerState>>;

const INBOX_RECEIVE_QUEUE: &str = "inbox.receive";
const SHARED_INBOX_RECEIVE_QUEUE: &str = "inbox.shared.receive";

async fn load_config() -> Result<Config> {
    use config::{builder::DefaultState, ConfigBuilder, File};
    let builder = ConfigBuilder::<DefaultState>::default()
        .set_default("addr", "127.0.0.1:3001")?
        .set_default("domain", "localhost:3001")?
        .set_default("use_ssl", false)?
        .set_default("amqp_url", "amqp://dev:dev@localhost:5672/master")?
        .add_source(File::with_name("/etc/domainservd.toml"))
        .add_source(File::with_name("domainservd.toml"));

    let cfg = builder.build()?;
    Ok(cfg.try_deserialize()?)
}

async fn listen(cfg: &Config) -> Result<()> {
    let addr = if let Some(addr) = &cfg.addr {
        addr.clone()
    } else {
        String::from("localhost:3001")
    };

    let mut pool_config = deadpool_lapin::Config::default();
    pool_config.url = Some(cfg.amqp_url.clone());

    let mq_pool = pool_config
        .create_pool(Some(deadpool_lapin::Runtime::Tokio1))
        .map_err(|e| Error::InternalError(e.to_string()))?;

    let channel = mq_pool.get().await?.create_channel().await?;
    channel
        .queue_declare(
            INBOX_RECEIVE_QUEUE,
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;
    channel
        .queue_declare(
            SHARED_INBOX_FORMAT,
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;

    let state = ServerState {
        domain: cfg.domain.clone(),
        use_ssl: cfg.use_ssl,
        accounts: cfg.accounts.clone(),
        mq_pool,
    };

    let app = Router::new()
        .route("/.well-known/webfinger", get(get_webfinger))
        .route("/actors/{:actor}", get(get_actor))
        .route("/actors/{:actor}/inbox", get(get_inbox).post(post_inbox))
        .route("/inbox", post(post_shared_inbox))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(Arc::new(Mutex::new(state)));

    axum::Server::try_bind(&addr.parse()?)
        .map_err(|e| Error::HyperError(e.to_string()))?
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::HyperError(e.to_string()))?;

    Ok(())
}

async fn post_shared_inbox(
    State(state): State<SharedState>,
    Json(activity): Json<Activity>,
) -> Result<StatusCode> {
    let base_url = if state.lock().await.use_ssl {
        format!("https://{}", state.lock().await.domain)
    } else {
        format!("http://{}", state.lock().await.domain)
    };
    //TODO check if actor is on block list
    let accounts = state
        .lock()
        .await
        .accounts
        .keys()
        .map(|account| format!("{}/actors/{}", &base_url, account))
        .collect::<Vec<String>>();
    let accounts: HashSet<String> = HashSet::from_iter(accounts);
    match activity {
        Activity::Create {
            context,
            id,
            actor,
            published,
            to,
            cc,
            object,
        } => {
            let to = to
                .into_iter()
                .filter_map(|receiver| {
                    if accounts.contains(&receiver.to_string()) {
                        Some(receiver)
                    } else {
                        None
                    }
                })
                .collect::<Vec<Url>>();

            let cc = cc
                .into_iter()
                .filter_map(|receiver| {
                    if accounts.contains(&receiver.to_string()) {
                        Some(receiver)
                    } else {
                        None
                    }
                })
                .collect::<Vec<Url>>();
            if to.len() > 0 {
                let payload_obj = Activity::Create {
                    context,
                    id,
                    actor,
                    published,
                    to,
                    cc,
                    object,
                };
                let payload = serde_json::to_vec(&payload_obj)?;
                let conn = state.lock().await.mq_pool.get().await?;
                let channel = conn.create_channel().await?;

                channel
                    .basic_publish(
                        "",
                        SHARED_INBOX_FORMAT,
                        BasicPublishOptions::default(),
                        &payload,
                        AMQPProperties::default(),
                    )
                    .await?;

                Ok(StatusCode::CREATED)
            } else {
                Err(Error::UnknownUser)
            }
        }
    }
}

async fn post_inbox(
    Path(actor): Path<String>,
    State(state): State<SharedState>,
    Json(activity): Json<Activity>,
) -> Result<StatusCode> {
    let base_url = if state.lock().await.use_ssl {
        format!("https://{}", state.lock().await.domain)
    } else {
        format!("http://{}", state.lock().await.domain)
    };
    //TODO check if actor is on block list
    //TODO check Signature of receiving actor

    if let Some(_public_key) = state.lock().await.accounts.get(&actor) {
        let accounts = state
            .lock()
            .await
            .accounts
            .keys()
            .map(|account| format!("{}/actors/{}", &base_url, account))
            .collect::<Vec<String>>();
        let accounts: HashSet<String> = HashSet::from_iter(accounts);
        match activity {
            Activity::Create {
                context,
                id,
                actor,
                published,
                to,
                cc,
                object,
            } => {
                let to = to
                    .into_iter()
                    .filter_map(|receiver| {
                        if accounts.contains(&receiver.to_string()) {
                            Some(receiver)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<Url>>();

                let cc = cc
                    .into_iter()
                    .filter_map(|receiver| {
                        if accounts.contains(&receiver.to_string()) {
                            Some(receiver)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<Url>>();
                if to.len() > 0 {
                    let payload_obj = Activity::Create {
                        context,
                        id,
                        actor,
                        published,
                        to,
                        cc,
                        object,
                    };
                    let payload = serde_json::to_vec(&payload_obj)?;
                    let conn = state.lock().await.mq_pool.get().await?;
                    let channel = conn.create_channel().await?;

                    channel
                        .basic_publish(
                            "",
                            INBOX_RECEIVE_QUEUE,
                            BasicPublishOptions::default(),
                            &payload,
                            AMQPProperties::default(),
                        )
                        .await?;

                    Ok(StatusCode::CREATED)
                } else {
                    Err(Error::UnknownUser)
                }
            }
        }
    } else {
        Err(Error::UnknownUser)
    }
}

async fn get_inbox(
    Path(actor): Path<String>,
    State(state): State<SharedState>,
) -> Result<StatusCode> {
    todo!()
}

async fn get_actor(
    Path(actor): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<PersonActor>> {
    if let Some(public_key) = state.lock().await.accounts.get(&actor) {
        let base_url = if state.lock().await.use_ssl {
            format!("https://{}", state.lock().await.domain)
        } else {
            format!("http://{}", state.lock().await.domain)
        };

        let public_key = PublicKey::new(
            format!("{}/actors/{}", &base_url, &actor).parse()?,
            public_key.clone(),
        );

        let actor = PersonActor::new(&base_url, &actor, public_key);

        Ok(Json(actor))
    } else {
        Err(Error::UnknownUser)
    }
}

fn split_webfinger_uri(uri: &str) -> Option<(String, String, String)> {
    if let Some((prefix, account)) = uri.split_once(':') {
        if let Some((name, domain)) = account.split_once('@') {
            Some((prefix.to_owned(), name.to_owned(), domain.to_owned()))
        } else {
            None
        }
    } else {
        None
    }
}

#[derive(Debug, Deserialize)]
struct WebfingerQuery {
    resource: String,
}

//TODO extend user capabilities to point to other pages and such

async fn get_webfinger(
    Query(query): Query<WebfingerQuery>,
    State(state): State<SharedState>,
) -> Result<Json<Webfinger>> {
    let (_prefix, account, domain) =
        split_webfinger_uri(&query.resource).ok_or(Error::BadWebfingerResource)?;

    if state.lock().await.domain != domain {
        return Err(Error::UnknownUser);
    }

    if !state.lock().await.accounts.contains_key(&account) {
        return Err(Error::UnknownUser);
    }

    let base_url = if state.lock().await.use_ssl {
        format!("https://{}", state.lock().await.domain)
    } else {
        format!("http://{}", state.lock().await.domain)
    };

    Ok(Json(Webfinger {
        subject: query.resource,
        aliases: vec![
            format!("{}/@{}", &base_url, &account),
            format!("{}/actors/{}", &base_url, &account),
        ],
        links: vec![Link {
            rel: String::from("self"),
            href: Some(format!("{}/actors/{}", &base_url, &account)),
            template: None,
            mime_type: Some(String::from("application/activity+json")),
        }],
    }))
}
