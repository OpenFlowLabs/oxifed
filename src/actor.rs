use async_graphql::SimpleObject;

use crate::prisma::actor::Data;

#[derive(Clone, SimpleObject)]
pub struct Actor {
    name: String,
    domain: String,
}

impl From<Data> for Actor {
    fn from(value: Data) -> Self {
        let (_, domain) = value.handle.split_once('@').unwrap_or(("", "localhost"));
        Self {
            name: value.display_name,
            domain: domain.to_owned(),
        }
    }
}
