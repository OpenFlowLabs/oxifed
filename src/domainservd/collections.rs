use super::{DomainServdError, Result, SharedState};
use crate::{
    activitypub::{activities::Activity, collection::Collection},
    build_base_url, prisma,
};
use axum::{
    extract::{Host, Path, Query, State},
    Json,
};
use mongodb::{bson::doc, options::FindOptions};
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_PAGE_SIZE: u64 = 30;

#[derive(Debug, Serialize, Deserialize)]
/// Structure to communicate the exact collection details we want as a client
pub(crate) struct OutboxQuery {
    #[serde(default)]
    /// Set to true to display the first page and not the summary
    page: bool,
    #[serde(default)]
    /// Set to true to get the earliest posts rather than the latest
    last: bool,
    /// If defined we start from this position with the page.
    cursor: Option<String>,
    /// Used to construct the previous URL
    prev: Option<String>,
}

pub(crate) async fn get_outbox_collection(
    Host(domain): Host,
    Path(actor): Path<String>,
    Query(query): Query<OutboxQuery>,
    State(state): State<SharedState>,
) -> Result<Json<Collection>> {
    let handle = format!("{actor}@{domain}");
    let mongo_client = state.lock().await.mongo.clone();
    let actor = state
        .lock()
        .await
        .prisma
        .actor()
        .find_unique(prisma::actor::handle::equals(handle.clone()))
        .exec()
        .await?
        .ok_or(DomainServdError::NotFound(handle.clone()))?;
    let acticity_collection = mongo_client
        .database("activities")
        .collection::<Activity>(&handle);
    let base_url = build_base_url(state.lock().await.use_ssl, &domain);
    let outbox_url = format!("{base_url}/actors/{}/outbox", actor.display_name);
    if query.page {
        let count = acticity_collection.count_documents(None, None).await?;
        let mut activity_cursor = if let Some(cursor) = query.cursor.clone() {
            acticity_collection
                .find(
                    Some(doc! {"_id": cursor}),
                    Some(
                        FindOptions::builder()
                            .limit(DEFAULT_PAGE_SIZE as i64)
                            .build(),
                    ),
                )
                .await?
        } else {
            // Get one of the default pages. Either first or last.
            if query.last {
                acticity_collection
                    .find(
                        None,
                        Some(
                            FindOptions::builder()
                                .skip(Some(count - DEFAULT_PAGE_SIZE))
                                .build(),
                        ),
                    )
                    .await?
            } else {
                acticity_collection
                    .find(
                        None,
                        Some(
                            FindOptions::builder()
                                .limit(Some(DEFAULT_PAGE_SIZE as i64))
                                .build(),
                        ),
                    )
                    .await?
            }
        };

        let mut activities: Vec<Activity> = vec![];
        let mut next_cursor: Option<String> = None;
        while activity_cursor.advance().await? {
            let acticity = activity_cursor.deserialize_current()?;
            if next_cursor.is_none() {
                next_cursor = Some(activity_cursor.current().get_object_id("_id")?.to_string());
            }
            activities.push(acticity);
        }

        let id_url: Url = if let Some(cursor) = query.cursor {
            format!("{outbox_url}?page=true&cursor={cursor}").parse()?
        } else {
            format!("{outbox_url}?page=true").parse()?
        };

        let prev_url: Option<Url> = if let Some(cursor) = query.prev {
            Some(format!("{outbox_url}?page=true&cursor={cursor}").parse()?)
        } else {
            None
        };

        let next_url: Option<Url> = if let Some(cursor) = next_cursor {
            Some(format!("{outbox_url}?page=true&cursor={cursor}").parse()?)
        } else {
            None
        };

        Ok(Json(Collection::OrderedCollectionPage {
            context: crate::activitypub::Context::Single(
                crate::activitypub::KnownContext::ActivityStreams,
            ),
            id: id_url,
            next: next_url,
            prev: prev_url,
            part_of: outbox_url.parse()?,
            ordered_items: activities,
        }))
    } else {
        let activities = acticity_collection.count_documents(None, None).await?;

        Ok(Json(Collection::OrderedCollection {
            context: crate::activitypub::Context::Single(
                crate::activitypub::KnownContext::ActivityStreams,
            ),
            id: outbox_url.parse()?,
            total_items: activities,
            first: format!("{outbox_url}?page=true").parse()?,
            last: format!("{outbox_url}?page=true&last=true").parse()?,
        }))
    }
}
