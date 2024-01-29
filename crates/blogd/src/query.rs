use async_graphql::{Context, Object};
use oxifed::{
    actor::Actor,
    article::Article,
    prisma::{actor, domain},
};

use crate::{Error, Result, SharedState};

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn blogs(&self, ctx: &Context<'_>) -> Result<Vec<Actor>> {
        let state = ctx.data_unchecked::<SharedState>();

        let domains: Vec<domain::Data> = state
            .lock()
            .await
            .prisma
            .domain()
            .find_many(vec![domain::applications::has(Some("blog".to_owned()))])
            .with(domain::actors::fetch(vec![]))
            .exec()
            .await?;

        let blogs: Vec<Actor> = domains
            .into_iter()
            .filter_map(|d| {
                if let Some(actors) = d.actors {
                    Some(
                        actors
                            .into_iter()
                            .map(|actor| {
                                let actor: Actor = actor.into();
                                actor
                            })
                            .collect::<Vec<Actor>>(),
                    )
                } else {
                    None
                }
            })
            .flatten()
            .collect();

        Ok(blogs)
    }

    async fn articles(&self, ctx: &Context<'_>, actor: String) -> Result<Vec<Article>> {
        let state = ctx.data_unchecked::<SharedState>();

        let actor = state
            .lock()
            .await
            .prisma
            .actor()
            .find_first(vec![actor::handle::equals(actor.clone())])
            .with(oxifed::prisma::actor::articles::fetch(vec![]))
            .exec()
            .await?
            .ok_or(Error::NotFound(actor))?;

        let articles: Vec<Article> = actor.articles.map_or(vec![], |articles| {
            articles.into_iter().map(|a| a.into()).collect()
        });

        Ok(articles)
    }
}
