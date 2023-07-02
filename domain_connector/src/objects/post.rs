use crate::{objects::person::InternalPerson, AppData, Error};
use activitypub_federation::fetch::object_id::ObjectId as ActivityPubId;
use activitypub_federation::{
    config::Data,
    fetch::object_id::ObjectId,
    kinds::{object::NoteType, public},
    protocol::{helpers::deserialize_one_or_many, verification::verify_domains_match},
    traits::Object,
};
use bonsaidb::core::schema::{Collection, SerializedCollection};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Collection, PartialEq, Serialize, Deserialize)]
#[collection(name = "Post", primary_key = String, natural_id = |post: &DbPost| Some(post.id.to_string()))]
pub struct DbPost {
    pub id: super::ObjectId,
    pub text: String,
    pub creator: ObjectId<InternalPerson>,
}

impl DbPost {
    pub fn new_local(text: String, creator: ObjectId<InternalPerson>) -> Result<DbPost, Error> {
        let id = super::ObjectId::new_local(
            creator.inner().domain().unwrap_or("localhost"),
            super::ObjectKind::Post,
        );
        Ok(DbPost { id, text, creator })
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    #[serde(rename = "type")]
    kind: NoteType,
    id: ObjectId<DbPost>,
    pub(crate) attributed_to: ObjectId<InternalPerson>,
    #[serde(deserialize_with = "deserialize_one_or_many")]
    pub(crate) to: Vec<Url>,
    pub(crate) cc: Option<Vec<Url>>,
}

#[async_trait::async_trait]
impl Object for DbPost {
    type DataType = AppData;
    type Kind = Note;
    type Error = Error;

    async fn read_from_id(
        object_id: Url,
        data: &Data<Self::DataType>,
    ) -> Result<Option<Self>, Self::Error> {
        Ok(DbPost::get_async(object_id.to_string(), &data.db)
            .await?
            .map(|doc| doc.contents))
    }

    async fn into_json(self, data: &Data<Self::DataType>) -> Result<Self::Kind, Self::Error> {
        let creator = self.creator.dereference_local(data).await?;
        Ok(Note {
            kind: Default::default(),
            id: self.id.to_object_id::<Self>()?,
            attributed_to: self.creator,
            to: vec![public(), creator.followers_url()?],
            content: self.text,
        })
    }

    async fn verify(
        json: &Self::Kind,
        expected_domain: &Url,
        _data: &Data<Self::DataType>,
    ) -> Result<(), Self::Error> {
        verify_domains_match(json.id.inner(), expected_domain)?;
        Ok(())
    }

    async fn from_json(json: Self::Kind, data: &Data<Self::DataType>) -> Result<Self, Self::Error> {
        let post = DbPost {
            text: json.content,
            ap_id: json.id,
            creator: json.attributed_to,
            local: false,
        };

        let mut lock = data.posts.lock().unwrap();
        lock.push(post.clone());
        Ok(post)
    }
}
