use crate::objects::article::Article;
use crate::objects::{article::InternalArticle, person::InternalPerson};
use crate::AppData;
use activitypub_federation::{
    config::Data,
    fetch::object_id::ObjectId,
    kinds::activity::CreateType,
    protocol::helpers::deserialize_one_or_many,
    traits::{ActivityHandler, Object},
};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateArticle {
    pub(crate) actor: ObjectId<InternalPerson>,
    #[serde(deserialize_with = "deserialize_one_or_many")]
    pub(crate) to: Vec<Url>,
    pub(crate) object: Article,
    #[serde(rename = "type")]
    pub(crate) kind: CreateType,
    pub(crate) id: Url,
}

#[async_trait::async_trait]
impl ActivityHandler for CreateArticle {
    type DataType = AppData;
    type Error = crate::Error;

    fn id(&self) -> &Url {
        &self.id
    }

    fn actor(&self) -> &Url {
        self.actor.inner()
    }

    async fn verify(&self, data: &Data<Self::DataType>) -> std::result::Result<(), Self::Error> {
        InternalArticle::verify(&self.object, &self.id, data).await?;
        Ok(())
    }

    async fn receive(self, data: &Data<Self::DataType>) -> std::result::Result<(), Self::Error> {
        InternalArticle::from_json(self.object, data).await?;
        Ok(())
    }
}
