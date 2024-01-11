use super::{Result, SharedState};
use crate::{
    activitypub::{PersonActor, PublicKey},
    build_base_url,
    domainservd::DomainServdError,
    prisma,
};
use axum::{
    extract::{Host, Path, State},
    Json,
};
use tracing::debug;
use url::Url;

pub(crate) async fn get_actor(
    Host(domain): Host,
    Path(actor): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<PersonActor>> {
    let handle = format!("{actor}@{domain}");
    debug!("Trying to find actor {handle}");
    let actor = state
        .lock()
        .await
        .prisma
        .actor()
        .find_unique(prisma::actor::handle::equals(handle.clone()))
        .with(prisma::actor::domain::fetch())
        .exec()
        .await?
        .ok_or(DomainServdError::NotFound(handle.clone()))?;

    let base_url = build_base_url(state.lock().await.use_ssl, &actor.domain()?.dns_name);

    let actor_url: Url = format!("{}/actors/{}", &base_url, &actor.display_name).parse()?;

    let keys = actor
        .keys
        .iter()
        .map(|k| PublicKey::new(actor_url.clone(), k.name.clone(), k.public_key.clone()))
        .collect::<Vec<PublicKey>>();

    let actor = PersonActor::new(&base_url, &actor.display_name, keys[0].clone());

    Ok(Json(actor))
}
