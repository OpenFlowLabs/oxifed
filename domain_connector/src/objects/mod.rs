use activitypub_federation::{fetch::object_id::ObjectId as ActivityPubId, traits::Object};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use url::Url;

pub(crate) mod article;
pub(crate) mod person;
pub(crate) mod post;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectKind {
    Person,
    Article,
    Post,
}

impl Display for ObjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectKind::Person => write!(f, "person"),
            ObjectKind::Article => write!(f, "article"),
            ObjectKind::Post => write!(f, "post"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectId {
    Local {
        id: uuid::Uuid,
        domain: String,
        kind: ObjectKind,
    },
    Remote {
        id: Url,
    },
}

impl ObjectId {
    pub fn to_object_id<K>(&self) -> crate::Result<ActivityPubId<K>>
    where
        K: Object,
        for<'de2> <K as activitypub_federation::traits::Object>::Kind: Deserialize<'de2>,
        K: Send,
    {
        match self {
            ObjectId::Local { id, domain, kind } => Ok(ActivityPubId::<K>::parse(
                format!("//{}/{}/{}", domain, kind, id).as_str(),
            )?),
            ObjectId::Remote { id } => Ok(ActivityPubId::<K>::parse(id.to_string().as_str())?),
        }
    }
}

impl Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectId::Local { id, domain, kind } => write!(f, "//{}/{}/{}", domain, kind, id),
            ObjectId::Remote { id } => write!(f, "{}", id),
        }
    }
}

impl ObjectId {
    pub fn new_local(domain: &str, kind: ObjectKind) -> Self {
        Self::Local {
            id: uuid::Uuid::new_v4(),
            domain: domain.to_owned(),
            kind,
        }
    }

    pub fn new_remote(url: Url) -> Self {
        Self::Remote { id: url }
    }
}
