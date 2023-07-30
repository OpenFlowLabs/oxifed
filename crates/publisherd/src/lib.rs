use activitypub::{
    activities::{Activity, Announce, Create, Follow},
    collection::OrderedCollection,
    fetch_actor, get_inbox, post_to_inbox, Context, KnownContext,
};
use biscuit_auth::{format, Biscuit, PublicKey};
use config::{builder::DefaultState, File};
use futures::StreamExt;
use lapin::{
    options::{
        BasicAckOptions, BasicConsumeOptions, BasicNackOptions, ExchangeDeclareOptions,
        QueueBindOptions, QueueDeclareOptions,
    },
    types::{AMQPValue, FieldTable, LongString, ShortString},
};
use miette::Diagnostic;
use minio::s3::args::{
    BucketExistsArgs, MakeBucketArgs, ObjectConditionalReadArgs, PutObjectApiArgs, PutObjectArgs,
    UploadObjectArgs,
};
use oxilib::{Message, TokenContext, OUTBOX_EXCHANGE};
use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::oneshot::channel;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    Lapin(#[from] lapin::Error),

    #[error(transparent)]
    Pool(#[from] deadpool_lapin::PoolError),

    #[error(transparent)]
    Config(#[from] config::ConfigError),

    #[error(transparent)]
    CreatePool(#[from] deadpool_lapin::CreatePoolError),

    #[error(transparent)]
    Minio(#[from] minio::s3::error::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Biscuit(#[from] biscuit_auth::error::Token),

    #[error(transparent)]
    PublicKey(#[from] biscuit_auth::error::Format),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    ParseUrl(#[from] url::ParseError),

    #[error(transparent)]
    ActivityPub(#[from] activitypub::Error),

    #[error("{0}")]
    ErrorValue(String),

    #[error("no actor in Token")]
    NoActorInToken,
}

pub type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Clone, Deserialize)]
pub struct MinioConfig {
    url: url::Url,
    access_key: String,
    secret_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    amqp_url: String,
    public_key: String,
    internal_s3: MinioConfig,
    external_s3: MinioConfig,
}

pub fn build_config(path: Option<PathBuf>) -> Result<Config> {
    let mut cfg_builder = config::builder::ConfigBuilder::<DefaultState>::default()
        .set_default("amqp_url", "amqp://dev:dev@localhost:5672/master")?
        .add_source(File::with_name("/etc/publisherd.toml").required(false))
        .add_source(File::with_name("publisherd.toml").required(false));
    if let Some(path) = path {
        cfg_builder =
            cfg_builder.add_source(File::with_name(path.to_string_lossy().to_string().as_str()));
    }

    let cfg = cfg_builder.build()?;

    Ok(cfg.try_deserialize()?)
}

const OUTBOX_BUCKET_NAME: &str = "outbox";

pub async fn listen(cfg: &Config) -> Result<()> {
    let pk = PublicKey::from_bytes_hex(&cfg.public_key)?;

    let mut pool_config = deadpool_lapin::Config::default();
    pool_config.url = Some(cfg.amqp_url.clone());

    let pool = pool_config.create_pool(Some(deadpool_lapin::Runtime::Tokio1))?;

    let external_minio_base_url =
        minio::s3::http::BaseUrl::from_string(cfg.external_s3.url.to_string())?;

    let static_external_provider = minio::s3::creds::StaticProvider::new(
        &cfg.external_s3.access_key,
        &cfg.external_s3.secret_key,
        None,
    );

    let external_client = minio::s3::client::Client::new(
        external_minio_base_url.clone(),
        Some(&static_external_provider),
    );

    let outbox_exists = external_client
        .bucket_exists(&BucketExistsArgs::new(OUTBOX_BUCKET_NAME)?)
        .await?;

    if !outbox_exists {
        external_client
            .make_bucket(&MakeBucketArgs::new(OUTBOX_BUCKET_NAME)?)
            .await?;
    }

    let rmq_con = pool
        .get()
        .await
        .map_err(|e| Error::ErrorValue(e.to_string()))?;
    let channel = rmq_con.create_channel().await?;

    let dlx_name = format!("{}.dlx", OUTBOX_EXCHANGE);
    let mut exchange_args = FieldTable::default();
    exchange_args.insert(
        ShortString::from("x-dead-letter-exchange"),
        AMQPValue::LongString(LongString::from(dlx_name.clone())),
    );
    channel
        .exchange_declare(
            OUTBOX_EXCHANGE,
            lapin::ExchangeKind::Direct,
            ExchangeDeclareOptions {
                ..Default::default()
            },
            exchange_args,
        )
        .await?;

    channel
        .queue_bind(
            OUTBOX_EXCHANGE,
            OUTBOX_EXCHANGE,
            OUTBOX_EXCHANGE,
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await?;

    let queue = channel
        .queue_declare(
            oxilib::OUTBOX_EXCHANGE,
            QueueDeclareOptions {
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await?;
    tracing::info!("Declared queue {:?}", queue);

    let dlx_queue = channel
        .queue_declare(
            &dlx_name,
            QueueDeclareOptions {
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await?;
    tracing::info!("Declared Dead Letter queue {:?}", dlx_queue);

    let mut consumer = channel
        .basic_consume(
            OUTBOX_EXCHANGE,
            "publisherd.outbox.consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await?;

    tracing::info!("rmq consumer connected, waiting for messages");
    while let Some(delivery) = consumer.next().await {
        if let Ok(delivery) = delivery {
            match handle_admin_message(&external_client, &pk, delivery.data.as_slice()).await {
                Ok(_) => delivery.ack(BasicAckOptions::default()).await?,
                Err(err) => {
                    tracing::error!(error = err.to_string(), "failed to handle message");
                    delivery
                        .nack(BasicNackOptions {
                            requeue: false,
                            ..Default::default()
                        })
                        .await?;
                }
            }
        }
    }
    Ok(())
}

async fn handle_admin_message<'a>(
    minio_client: &minio::s3::client::Client<'a>,
    pk: &biscuit_auth::PublicKey,
    data: &[u8],
) -> Result<()> {
    let msg: Message = serde_json::from_slice(data)?;
    let token = Biscuit::from_base64(&msg.biscuit, pk)?;
    let t = token
        .context()
        .into_iter()
        .filter_map(|v| {
            if let Some(s) = v {
                serde_json::from_str::<TokenContext>(&s).ok()
            } else {
                None
            }
        })
        .collect::<Vec<TokenContext>>();
    let ctx = t.first().ok_or(Error::NoActorInToken)?;

    let outbox_name = format!("{}/outbox.json", &ctx.actor);

    let outbox_json = match minio_client
        .get_object(&ObjectConditionalReadArgs::new(
            OUTBOX_BUCKET_NAME,
            &outbox_name,
        )?)
        .await
    {
        Ok(resp) => Some(resp.bytes().await?),
        Err(_) => None,
    };

    let mut outbox: OrderedCollection = if let Some(j) = outbox_json {
        serde_json::from_slice(&j)?
    } else {
        OrderedCollection::new(&ctx.actor, "outbox.json", &ctx.base_url)?
    };

    match msg.activity {
        oxilib::Activity::Follow {
            name,
            server,
            actor_url,
        } => {
            let actor = fetch_actor(actor_url.clone()).await?;

            let follow = Activity::Follow(Follow {
                context: Context::List(vec![KnownContext::ActivityStreams]),
                id: format!("{}/activity/{}@{}", &ctx.base_url, name, server).parse()?,
                kind: activitypub::activities::FollowType::Follow,
                actor: ctx.actor.parse()?,
                to: Some([actor_url.clone()]),
                object: actor_url,
            });

            let inbox = get_inbox(&actor, true).await;

            let return_val = post_to_inbox(inbox, &follow).await?;
            tracing::debug!("Recieved answer from counterpart: {}", return_val);
        }
        oxilib::Activity::Create {
            id,
            object,
            recipients,
        } => {
            let recp = recipients.get_actors();
            let activity = Activity::Create(Create {
                context: Context::List(vec![KnownContext::ActivityStreams]),
                id: format!("{}/objects/{}", &ctx.base_url, &id).parse()?,
                kind: activitypub::activities::CreateType::Create,
                actor: ctx.actor.clone().parse()?,
                published: chrono::Utc::now().naive_utc(),
                to: vec![activitypub::PUBLIC_ACTOR_URL.parse()?],
                cc: Some(vec![format!("{}/followers", &ctx.actor).parse()?]),
                object,
            });

            let mut inboxes = Vec::new();
            for act in recp.0 {
                let act = fetch_actor(act).await?;
                inboxes.push(get_inbox(&act, false).await);
            }

            if let Some(blind_actors) = recp.1 {
                for act in blind_actors {
                    let act = fetch_actor(act).await?;
                    inboxes.push(get_inbox(&act, false).await);
                }
            }

            for inbox in inboxes {
                let resp = post_to_inbox(inbox, &activity).await?;

                tracing::debug!("Recieved answer from counterpart: {}", resp);
            }

            outbox.ordered_items.push(activity);
        }
        oxilib::Activity::Update {
            object,
            update,
            recipients,
        } => todo!(),
        oxilib::Activity::Delete { object } => todo!(),
        oxilib::Activity::Announce { object, recipients } => {
            let recp = recipients.get_actors();
            let activity = Activity::Announce(Announce {
                context: Context::List(vec![KnownContext::ActivityStreams]),
                id: format!("{}/activity", &object).parse()?,
                kind: activitypub::activities::AnnounceType::Announce,
                actor: ctx.actor.clone().parse()?,
                to: vec![activitypub::PUBLIC_ACTOR_URL.parse()?],
                cc: Some(vec![format!("{}/followers", &ctx.actor).parse()?]),
                object,
            });

            let mut inboxes = Vec::new();
            for act in recp.0 {
                let act = fetch_actor(act).await?;
                inboxes.push(get_inbox(&act, false).await);
            }

            if let Some(blind_actors) = recp.1 {
                for act in blind_actors {
                    let act = fetch_actor(act).await?;
                    inboxes.push(get_inbox(&act, false).await);
                }
            }

            for inbox in inboxes {
                let resp = post_to_inbox(inbox, &activity).await?;

                tracing::debug!("Recieved answer from counterpart: {}", resp);
            }

            outbox.ordered_items.push(activity);
        }
        oxilib::Activity::Accept { object } => todo!(),
        oxilib::Activity::TentativeAccept { object } => todo!(),
        oxilib::Activity::Add { object, target } => todo!(),
        oxilib::Activity::Ignore { url } => todo!(),
        oxilib::Activity::Join { target } => todo!(),
        oxilib::Activity::Leave { target } => todo!(),
        oxilib::Activity::Like { target } => todo!(),
        oxilib::Activity::Offer { object, recipients } => todo!(),
        oxilib::Activity::Invite { object, recipients } => todo!(),
        oxilib::Activity::Reject { object } => todo!(),
        oxilib::Activity::TentativeReject { object } => todo!(),
        oxilib::Activity::Remove { object, target } => todo!(),
        oxilib::Activity::Undo { target } => todo!(),
        oxilib::Activity::Move {
            object,
            target,
            origin,
        } => todo!(),
        oxilib::Activity::Block { object } => todo!(),
        oxilib::Activity::Dislike { object } => todo!(),
    }

    let payload = serde_json::to_vec(&outbox)?;

    minio_client
        .put_object_api(&PutObjectApiArgs {
            bucket: OUTBOX_BUCKET_NAME,
            object: &outbox_name,
            data: &payload,
            ..Default::default()
        })
        .await?;

    Ok(())
}
