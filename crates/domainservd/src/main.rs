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
    fs::File,
    io::Read,
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::debug;
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

    #[error(transparent)]
    IOError(#[from] std::io::Error),

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
    addr: String,
    use_ssl: bool,
    accounts: Option<Vec<ConfigUser>>,
    amqp_url: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ConfigUser {
    name: String,
    public_key: String,
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

const INBOX_RECEIVE_QUEUE: &str = "inbox";

async fn load_config() -> Result<Config> {
    use config::{builder::DefaultState, ConfigBuilder, File};
    let builder = ConfigBuilder::<DefaultState>::default()
        .set_default("addr", "0.0.0.0:3001")?
        .set_default("domain", "localhost:3001")?
        .set_default("use_ssl", false)?
        .set_default("amqp_url", "amqp://dev:dev@localhost:5672/master")?
        .add_source(File::with_name("/etc/domainservd/config.yaml").required(false))
        .add_source(File::with_name("domainservd.toml").required(false));

    let cfg = builder.build()?;
    tracing::debug!("Loading configuration");
    Ok(cfg.try_deserialize()?)
}

async fn listen(cfg: &Config) -> Result<()> {
    let mut pool_config = deadpool_lapin::Config::default();
    pool_config.url = Some(cfg.amqp_url.clone());

    let mq_pool = pool_config
        .create_pool(Some(deadpool_lapin::Runtime::Tokio1))
        .map_err(|e| Error::InternalError(e.to_string()))?;

    tracing::debug!("Opening RabbitMQ Connection: {}", &cfg.amqp_url);
    let conn = mq_pool.get().await?;
    tracing::debug!(
        "Connected to {} as {}",
        conn.status().vhost(),
        conn.status().username()
    );

    let channel = conn.create_channel().await?;

    tracing::debug!(
        "Defining inbox: {} queue from channel id {}",
        INBOX_RECEIVE_QUEUE,
        channel.id()
    );
    channel
        .queue_declare(
            INBOX_RECEIVE_QUEUE,
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;

    let accounts = if let Some(users) = &cfg.accounts {
        let mut map = HashMap::new();
        for u in users {
            let mut pem_file = File::open(&u.public_key)?;
            let mut pem_string = String::new();
            pem_file.read_to_string(&mut pem_string)?;

            map.insert(u.name.clone(), pem_string);
        }
        map
    } else {
        HashMap::new()
    };

    let state = ServerState {
        domain: cfg.domain.clone(),
        use_ssl: cfg.use_ssl,
        accounts,
        mq_pool,
    };

    let app = Router::new()
        .route("/.well-known/webfinger", get(get_webfinger))
        .route("/actors/:actor", get(get_actor))
        .route("/actors/:actor/inbox", post(post_inbox))
        .route("/inbox", post(post_shared_inbox))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(Arc::new(Mutex::new(state)));

    tracing::debug!("Starting Webserver on: {}", &cfg.addr);
    axum::Server::try_bind(&cfg.addr.parse()?)
        .map_err(|e| Error::HyperError(e.to_string()))?
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::HyperError(e.to_string()))?;

    Ok(())
}

fn filter_recipients(accounts: &HashSet<String>, recipients: &[Url]) -> Vec<Url> {
    recipients
        .iter()
        .filter_map(|receiver| {
            if accounts.contains(&receiver.to_string()) || receiver.as_str() == PUBLIC_ACTOR_URL {
                Some(receiver.clone())
            } else {
                None
            }
        })
        .collect::<Vec<Url>>()
}

async fn queue_activity(state: SharedState, activity: impl Serialize, queue: &str) -> Result<()> {
    let payload = serde_json::to_vec(&activity)?;
    let conn = state.lock().await.mq_pool.get().await?;
    let channel = conn.create_channel().await?;

    channel
        .basic_publish(
            "",
            queue,
            BasicPublishOptions::default(),
            &payload,
            AMQPProperties::default(),
        )
        .await?;
    Ok(())
}

async fn post_shared_inbox(
    State(state): State<SharedState>,
    Json(activity): Json<Activity>,
) -> Result<StatusCode> {
    let use_ssl = state.lock().await.use_ssl;
    let domain = state.lock().await.domain.clone();
    let base_url = if use_ssl {
        format!("https://{}", &domain)
    } else {
        format!("http://{}", &domain)
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
        Activity::Create(activity) => {
            let mut activity = activity.clone();
            activity.to = filter_recipients(&accounts, &activity.to);

            if let Some(cc) = &activity.cc {
                activity.cc = Some(filter_recipients(&accounts, &cc));
            }

            if activity.to.len() > 0 {
                queue_activity(state, activity, INBOX_RECEIVE_QUEUE).await?;
                Ok(StatusCode::CREATED)
            } else {
                Err(Error::UnknownUser)
            }
        }
        Activity::Follow(follow) => {
            if accounts.contains(&follow.object.to_string()) {
                queue_activity(state, follow, INBOX_RECEIVE_QUEUE).await?;
                Ok(StatusCode::CREATED)
            } else {
                Err(Error::UnknownUser)
            }
        }
        Activity::Accept(accept) => {
            if accounts.contains(&accept.object.actor.to_string()) {
                queue_activity(state, accept, INBOX_RECEIVE_QUEUE).await?;
                Ok(StatusCode::CREATED)
            } else {
                Err(Error::UnknownUser)
            }
        }
        Activity::Announce(activity) => {
            let mut activity = activity.clone();
            activity.to = filter_recipients(&accounts, &activity.to);

            if let Some(cc) = &activity.cc {
                activity.cc = Some(filter_recipients(&accounts, &cc));
            }

            if activity.to.len() > 0 {
                queue_activity(state, activity, INBOX_RECEIVE_QUEUE).await?;
                Ok(StatusCode::CREATED)
            } else {
                Err(Error::UnknownUser)
            }
        }
        Activity::EchoRequest(_) => {
            debug!("Received an echo request");
            Ok(StatusCode::CREATED)
        }
        Activity::Like(like) => {
            let mut activity = like.clone();
            activity.to = filter_recipients(&accounts, &activity.to);

            if activity.to.len() > 0 {
                queue_activity(state, activity, INBOX_RECEIVE_QUEUE).await?;
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
    let maybe_pk = state.lock().await.accounts.get(&actor).map(|v| v.clone());
    let use_ssl = state.lock().await.use_ssl;
    let domain = state.lock().await.domain.clone();
    let base_url = if use_ssl {
        format!("https://{}", &domain)
    } else {
        format!("http://{}", &domain)
    };
    //TODO check if actor is on block list
    //TODO check Signature of receiving actor

    if let Some(_public_key) = maybe_pk {
        let accounts = state
            .lock()
            .await
            .accounts
            .keys()
            .map(|account| format!("{}/actors/{}", &base_url, account))
            .collect::<Vec<String>>();
        let accounts: HashSet<String> = HashSet::from_iter(accounts);
        match activity {
            Activity::Create(activity) => {
                let mut activity = activity.clone();
                activity.to = filter_recipients(&accounts, &activity.to);

                if let Some(cc) = &activity.cc {
                    activity.cc = Some(filter_recipients(&accounts, &cc));
                }

                if activity.to.len() > 0 {
                    queue_activity(state, activity, INBOX_RECEIVE_QUEUE).await?;
                    Ok(StatusCode::CREATED)
                } else {
                    Err(Error::UnknownUser)
                }
            }
            Activity::Follow(follow) => {
                if accounts.contains(&follow.object.to_string()) {
                    queue_activity(state, follow, INBOX_RECEIVE_QUEUE).await?;
                    Ok(StatusCode::CREATED)
                } else {
                    Err(Error::UnknownUser)
                }
            }
            Activity::Accept(accept) => {
                if accounts.contains(&accept.object.actor.to_string()) {
                    queue_activity(state, accept, INBOX_RECEIVE_QUEUE).await?;
                    Ok(StatusCode::CREATED)
                } else {
                    Err(Error::UnknownUser)
                }
            }
            Activity::Announce(activity) => {
                let mut activity = activity.clone();
                activity.to = filter_recipients(&accounts, &activity.to);

                if let Some(cc) = &activity.cc {
                    activity.cc = Some(filter_recipients(&accounts, &cc));
                }

                if activity.to.len() > 0 {
                    queue_activity(state, activity, INBOX_RECEIVE_QUEUE).await?;
                    Ok(StatusCode::CREATED)
                } else {
                    Err(Error::UnknownUser)
                }
            }
            Activity::EchoRequest(_) => {
                debug!("Received an echo request");
                Ok(StatusCode::CREATED)
            }
            Activity::Like(like) => {
                let mut activity = like.clone();
                let actor = format!("{}/actors/{}", &base_url, &actor);
                activity.to = vec![actor.parse()?];

                if activity.to.len() > 0 {
                    queue_activity(state, activity, INBOX_RECEIVE_QUEUE).await?;
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

async fn get_actor(
    Path(actor): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<PersonActor>> {
    let maybe_pk = state.lock().await.accounts.get(&actor).map(|pk| pk.clone());
    let use_ssl = state.lock().await.use_ssl;
    let domain = state.lock().await.domain.clone();

    if let Some(public_key) = maybe_pk {
        let base_url = if use_ssl {
            format!("https://{}", &domain)
        } else {
            format!("http://{}", &domain)
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
    tracing::debug!("Getting webfinger resources for {}", &query.resource);
    let (_prefix, account, domain) =
        split_webfinger_uri(&query.resource).ok_or(Error::BadWebfingerResource)?;

    let use_ssl = state.lock().await.use_ssl;
    let server_domain = state.lock().await.domain.clone();

    if server_domain != domain {
        return Err(Error::UnknownUser);
    }

    if !state.lock().await.accounts.contains_key(&account) {
        return Err(Error::UnknownUser);
    }

    let base_url = if use_ssl {
        format!("https://{}", &server_domain)
    } else {
        format!("http://{}", &server_domain)
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
