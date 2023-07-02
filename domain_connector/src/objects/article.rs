use activitypub_federation::{
    config::Data,
    fetch::object_id::ObjectId,
    kinds::object::ArticleType,
    protocol::{helpers::deserialize_one_or_many, verification::verify_domains_match},
    traits::Object,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use url::Url;

use super::person::InternalPerson;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InternalArticle {
    pub id: super::ObjectId,
    pub raw_content: String,
    pub version: Version,
    pub local: bool,
    pub content: String,
    pub author: Url,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Article {
    id: ObjectId<InternalArticle>,
    #[serde(rename = "type")]
    kind: ArticleType,
    name: String,
    content: String,
    pub(crate) attributed_to: ObjectId<InternalPerson>,
    #[serde(deserialize_with = "deserialize_one_or_many")]
    pub(crate) to: Vec<Url>,
    pub(crate) cc: Option<Vec<Url>>,
}

#[async_trait::async_trait]
impl Object for InternalArticle {
    type DataType = crate::AppData;
    type Kind = Article;
    type Error = crate::Error;

    async fn read_from_id(
        object_id: Url,
        data: &Data<Self::DataType>,
    ) -> std::result::Result<Option<Self>, Self::Error> {
        todo!()
    }

    async fn into_json(
        self,
        _data: &Data<Self::DataType>,
    ) -> std::result::Result<Self::Kind, Self::Error> {
        todo!()
    }

    async fn verify(
        json: &Self::Kind,
        expected_domain: &Url,
        _data: &Data<Self::DataType>,
    ) -> std::result::Result<(), Self::Error> {
        todo!()
    }

    async fn from_json(
        json: Self::Kind,
        data: &Data<Self::DataType>,
    ) -> std::result::Result<Self, Self::Error> {
        todo!()
    }
}
