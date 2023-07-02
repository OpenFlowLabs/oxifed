mod activities;
mod objects;

use crate::objects::person::PersonAcceptedActivities;
use activitypub_federation::{
    axum::{
        inbox::{receive_activity, ActivityData},
        json::FederationJson,
    },
    config::{Data, FederationConfig, FederationMiddleware},
    fetch::webfinger::{build_webfinger_response, extract_webfinger_name, Webfinger},
    protocol::context::WithContext,
    traits::Object,
};
use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_macros::debug_handler;
use config::{builder::AsyncState, ConfigBuilder, File, FileFormat};
use lapin::{
    options::{BasicAckOptions, BasicConsumeOptions, BasicPublishOptions, QueueDeclareOptions},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, Consumer, Queue,
};
use miette::Diagnostic;
use objects::person::{InternalPerson, Person};
use serde::Deserialize;
use std::net::ToSocketAddrs;
use thiserror::Error;
use tracing::info;
use url::Url;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    VarError(#[from] std::env::VarError),

    #[error(transparent)]
    URLParseError(#[from] url::ParseError),

    #[error(transparent)]
    ActivityPubError(#[from] activitypub_federation::error::Error),

    #[error(transparent)]
    ConfigError(#[from] config::ConfigError),

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error("delivery error: {0}")]
    DeliveryError(String),

    #[error("no such person {0}")]
    NoSuchPerson(String),

    #[error("no reply from data server")]
    NoReply,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let error_str = format!("{}", &self);
        (StatusCode::INTERNAL_SERVER_ERROR, error_str).into_response()
    }
}

pub type Result<T> = miette::Result<T, Error>;

#[derive(Debug)]
pub struct AppData {
    pub(crate) mq_conn: Connection,
    pub(crate) mq_chan: Channel,
    pub(crate) mq_callback_queue: Queue,
    pub(crate) mq_callback_consumer: Consumer,
    pub(crate) domain: String,
}

impl AppData {
    pub async fn new() -> Result<Self> {
        let builder = ConfigBuilder::<AsyncState>::default()
            .set_default("domain", "localhost")?
            .set_default("amqp_addr", "amqp://127.0.0.1:5672")?
            .add_source(File::new("config", FileFormat::Toml));
        let cfg = builder.build().await?;

        let conn = Connection::connect(
            cfg.get_string("amqp_addr")?.as_str(),
            ConnectionProperties::default(),
        )
        .await?;
        let channel = conn.create_channel().await?;

        let callback_queue = channel
            .queue_declare(
                "",
                QueueDeclareOptions {
                    exclusive: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await?;

        let callback_consumer = channel
            .basic_consume(
                callback_queue.name().as_str(),
                "domain_connector_callback",
                BasicConsumeOptions {
                    no_ack: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await?;

        Ok(AppData {
            mq_conn: conn,
            mq_chan: channel,
            mq_callback_queue: callback_queue,
            mq_callback_consumer: callback_consumer,
            domain: cfg.get_string("domain")?,
        })
    }

    pub fn get_domain(&self) -> String {
        self.domain.clone()
    }

    pub async fn get_object_by_id<T>(&mut self, object_id: Url, correlation_id: &str) -> Result<T> {
        self.mq_chan
            .basic_publish(
                "",
                "get_obejct_by_id",
                BasicPublishOptions::default(),
                object_id.into(),
                BasicProperties::default()
                    .with_reply_to(self.mq_callback_queue.name().clone())
                    .with_correlation_id(correlation_id.into()),
            )
            .await?
            .await?;
        while let Some(delivery) = self.mq_callback_consumer.next().await {
            match delivery {
                Ok(delivery) => {
                    if delivery.properties.correlation_id().as_ref() == Some(correlation_id) {
                        let object = serde_json::from_slice(delivery.data.as_slice())?;
                        delivery.ack(BasicAckOptions::default()).await?;
                        return Ok(object);
                    }
                }
                Err(error) => return Err(Error::DeliveryError(error)),
            }
        }

        Err(Error::NoReply)
    }

    pub async fn receive_object<'de, T>(&mut self, object: &T, correlation_id: &str) -> Result<T>
    where
        T: serde::Serialize + serde::Deserialize<'de>,
    {
        self.mq_chan
            .basic_publish(
                "",
                "receive_obkect",
                BasicPublishOptions::default(),
                &serde_json::to_vec(object)?,
                BasicProperties::default()
                    .with_reply_to(self.mq_callback_queue.name().clone())
                    .with_correlation_id(correlation_id.into()),
            )
            .await?
            .await?;
        while let Some(delivery) = self.mq_callback_consumer.next().await {
            match delivery {
                Ok(delivery) => {
                    if delivery.properties.correlation_id().as_ref() == Some(correlation_id) {
                        let object = serde_json::from_slice(delivery.data.as_slice())?;
                        delivery.ack(BasicAckOptions::default()).await?;
                        return Ok(object);
                    }
                }
                Err(error) => return Err(Error::DeliveryError(error)),
            }
        }

        Err(Error::NoReply)
    }
}

pub async fn listen(config: &FederationConfig<AppData>) -> Result<()> {
    let hostname = config.domain();
    info!("Listening on {hostname}");
    let config = config.clone();
    let app = Router::new()
        .route("/:user/inbox", post(http_post_user_inbox))
        .route("/:user", get(http_get_user))
        .route("/.well-known/webfinger", get(webfinger))
        .layer(FederationMiddleware::new(config));

    let addr = hostname
        .to_socket_addrs()?
        .next()
        .expect("Failed to lookup domain name");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
}

#[debug_handler]
async fn http_get_user(
    Path(name): Path<String>,
    data: Data<AppData>,
) -> std::result::Result<FederationJson<WithContext<Person>>, Error> {
    let db_user = data.get_user(&name).await?;
    let json_user = db_user.into_json(&data).await?;
    Ok(FederationJson(WithContext::new_default(json_user)))
}

#[debug_handler]
async fn http_post_user_inbox(
    data: Data<AppData>,
    activity_data: ActivityData,
) -> impl IntoResponse {
    receive_activity::<WithContext<PersonAcceptedActivities>, InternalPerson, AppData>(
        activity_data,
        &data,
    )
    .await
}

#[derive(Deserialize)]
struct WebfingerQuery {
    resource: String,
}

#[debug_handler]
async fn webfinger(
    Query(query): Query<WebfingerQuery>,
    data: Data<AppData>,
) -> std::result::Result<Json<Webfinger>, Error> {
    let name = extract_webfinger_name(&query.resource, &data)?;
    let db_user = data.read_user(&name)?;
    Ok(Json(build_webfinger_response(
        query.resource,
        db_user.ap_id.into_inner(),
    )))
}
