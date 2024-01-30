use super::{Result, SharedState};
use crate::activitypub::activities::{Activity, PUBLIC_TARGET};
use axum::{
    extract::{Host, Path, State},
    Json,
};
use lapin::{options::BasicPublishOptions, protocol::basic::AMQPProperties};
use scanf::sscanf;
use url::Url;

fn get_target_actors(
    optional_target: Option<String>,
    domain: String,
    to: Vec<Url>,
    cc: Vec<Url>,
) -> Result<Vec<String>> {
    let mut actor_list: Vec<String> = vec![];
    for receipient in vec![to, cc].concat() {
        let recp_str = receipient.to_string();
        if &recp_str == PUBLIC_TARGET {
            continue;
        }
        let mut actor_name: String = String::new();
        let mut scheme: String = String::new();
        let mut domain_scanned: String = String::new();
        sscanf!(
            &recp_str,
            "{}://{}/actors/{}",
            scheme,
            domain_scanned,
            actor_name
        )?;
        if &domain == &domain_scanned {
            actor_list.push(actor_name);
        }
    }
    if let Some(actor) = optional_target {
        actor_list.push(actor);
    }
    Ok(actor_list)
}

pub async fn post_inbox(
    Host(domain): Host,
    Path(actor): Path<String>,
    State(state): State<SharedState>,
    Json(activity): Json<Activity>,
) -> Result<()> {
    post_inbox_handler(domain, Some(actor), state, activity).await
}

pub async fn post_shared_inbox(
    Host(domain): Host,
    State(state): State<SharedState>,
    Json(activity): Json<Activity>,
) -> Result<()> {
    post_inbox_handler(domain, None, state, activity).await
}

async fn post_inbox_handler(
    domain: String,
    actor: Option<String>,
    state: SharedState,
    activity: Activity,
) -> Result<()> {
    let mongo_client = state.lock().await.mongo.clone();
    let conn = state.lock().await.rbmq_pool.get().await?;
    let channel = conn.create_channel().await?;
    let base_exchange = state.lock().await.acitivity_process_channel.clone();
    //TODO: HTTP Signature verification

    match activity {
        Activity::Create(create) => {
            // Actor is receiving a message from someone
            let targets = get_target_actors(
                actor,
                domain.clone(),
                create.to.clone(),
                create.cc.clone().unwrap_or(vec![]),
            )?;
            let exchange = format!("{base_exchange}.create");
            for target in targets {
                let handle = format!("{target}@{domain}");

                let timeline_collection = mongo_client
                    .database("inboxes")
                    .collection::<Activity>(&handle);
                let doc = Activity::Create(create.clone());
                timeline_collection.insert_one(&doc, None).await?;
                channel
                    .basic_publish(
                        &exchange,
                        "",
                        BasicPublishOptions::default(),
                        &serde_json::to_vec(&doc)?,
                        AMQPProperties::default(),
                    )
                    .await?;
            }
            Ok(())
        }
        Activity::Follow(follow) => {
            let exchange = format!("{base_exchange}.follow");
            channel
                .basic_publish(
                    &exchange,
                    "",
                    BasicPublishOptions::default(),
                    &serde_json::to_vec(&follow)?,
                    AMQPProperties::default(),
                )
                .await?;

            Ok(())
        }
        Activity::Accept(accept) => {
            let exchange = format!("{base_exchange}.accept");

            channel
                .basic_publish(
                    &exchange,
                    "",
                    BasicPublishOptions::default(),
                    &serde_json::to_vec(&accept)?,
                    AMQPProperties::default(),
                )
                .await?;

            Ok(())
        }
        Activity::Announce(announce) => {
            let targets = get_target_actors(
                actor,
                domain.clone(),
                announce.to.clone(),
                announce.cc.clone().unwrap_or(vec![]),
            )?;
            let exchange = format!("{base_exchange}.announce");
            for target in targets {
                let handle = format!("{target}@{domain}");

                let timeline_collection = mongo_client
                    .database("inboxes")
                    .collection::<Activity>(&handle);
                let doc = Activity::Announce(announce.clone());
                timeline_collection.insert_one(&doc, None).await?;
                channel
                    .basic_publish(
                        &exchange,
                        "",
                        BasicPublishOptions::default(),
                        &serde_json::to_vec(&doc)?,
                        AMQPProperties::default(),
                    )
                    .await?;
            }
            Ok(())
        }
        Activity::Like(like) => {
            let exchange = format!("{base_exchange}.like");
            channel
                .basic_publish(
                    &exchange,
                    "",
                    BasicPublishOptions::default(),
                    &serde_json::to_vec(&like)?,
                    AMQPProperties::default(),
                )
                .await?;

            Ok(())
        }
        Activity::EchoRequest(_) => Ok(()),
    }
}
