use super::SharedState;
use crate::build_base_url;
use crate::domainservd::DomainServdError;
use crate::webfinger::WebfingerQuery;
use crate::{domainservd::Result, prisma};
use axum::{
    extract::{Query, State},
    Json,
};
use tracing::debug;
use webfinger::{Link, Webfinger};

pub(crate) async fn get_webfinger(
    Query(query): Query<WebfingerQuery>,
    State(state): State<SharedState>,
) -> Result<Json<Webfinger>> {
    debug!("Trying to find actor {}", query.resource.get_handle());
    let actor = state
        .lock()
        .await
        .prisma
        .actor()
        .find_unique(prisma::actor::handle::equals(query.resource.get_handle()))
        .with(prisma::actor::domain::fetch())
        .exec()
        .await?
        .ok_or(DomainServdError::NotFound(query.resource.get_handle()))?;

    let base_url = build_base_url(state.lock().await.use_ssl, &actor.domain()?.dns_name);

    Ok(Json(Webfinger {
        subject: query.resource.to_string(),
        aliases: vec![
            format!("{}/@{}", &base_url, query.resource.get_account()),
            format!("{}/actors/{}", &base_url, query.resource.get_account()),
        ],
        links: vec![Link {
            rel: String::from("self"),
            href: Some(format!(
                "{}/actors/{}",
                &base_url,
                query.resource.get_account()
            )),
            template: None,
            mime_type: Some(String::from("application/activity+json")),
        }],
    }))
}
