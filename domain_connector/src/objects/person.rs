use crate::activities::create_post::CreateArticle;
use crate::AppData;
use crate::{Error, Result};
use activitypub_federation::config::Data;
use activitypub_federation::http_signatures::generate_actor_keypair;
use activitypub_federation::protocol::public_key::PublicKey;
use activitypub_federation::protocol::verification::verify_domains_match;
use activitypub_federation::traits::{Actor, Object};
use activitypub_federation::{fetch::object_id::ObjectId, kinds::actor::PersonType};

use chrono::Local;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use url::Url;
use Debug;

use super::article::InternalArticle;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InternalPerson {
    pub prefered_username: String,
    pub display_name: String,
    pub password_hash: Option<String>,
    pub email: Option<String>,
    pub ap_id: Url,
    pub inbox: Url,
    pub outbox: Url,
    pub local: bool,
    pub public_key: String,
    pub private_key: Option<String>,
    pub last_refreshed_at: NaiveDateTime,
    pub followers: Vec<Url>,
}

impl InternalPerson {
    pub fn build_ap_id(hostname: &str, name: &str) -> Result<Url> {
        Ok(Url::parse(&format!("//{}/{}", hostname, name))?)
    }

    pub fn new_local(hostname: &str, name: String) -> Result<InternalPerson> {
        let ap_id = InternalPerson::build_ap_id(hostname, &name)?.into();
        let inbox = Url::parse(&format!("//{}/{}/inbox", hostname, &name))?;
        let outbox = Url::parse(&format!("//{}/{}/outbox", hostname, &name))?;
        let keypair = generate_actor_keypair()?;
        Ok(InternalPerson {
            prefered_username: name.clone(),
            ap_id,
            inbox,
            public_key: keypair.public_key,
            private_key: Some(keypair.private_key),
            last_refreshed_at: Local::now().naive_local(),
            local: true,
            display_name: name.clone(),
            password_hash: None,
            email: None,
            outbox,
            followers: vec![],
        })
    }

    pub fn followers(&self) -> &Vec<Url> {
        &self.followers
    }

    pub fn followers_url(&self) -> Result<Url> {
        Ok(Url::parse(&format!(
            "{}/followers",
            self.ap_id.to_string()
        ))?)
    }

    pub async fn follow(&self, other: &str, data: &Data<AppData>) -> Result<()> {
        /*
        let other: InternalPerson = webfinger_resolve_actor(other, data).await?;
        let id = generate_object_id(data.domain())?;
        let follow = Follow::new(self.ap_id.clone(), other.ap_id.clone(), id.clone());
        self.send(follow, vec![other.shared_inbox_or_inbox()], data)
            .await?;
        Ok(())
        */
        todo!()
    }

    pub async fn post(&self, post: InternalArticle, data: &Data<AppData>) -> Result<()> {
        /*
        let id = generate_object_id(data.domain())?;
        let create = CreatePost::new(post.into_json(data).await?, id.clone());
        let mut inboxes = vec![];
        for f in self.followers.clone() {
            let user: InternalPerson = ObjectId::from(f).dereference(data).await?;
            inboxes.push(user.shared_inbox_or_inbox());
        }
        self.send(create, inboxes, data).await?;
        Ok(())
        */
        todo!()
    }
}

impl From<Person> for InternalPerson {
    fn from(value: Person) -> Self {
        InternalPerson {
            prefered_username: value.preferred_username,
            display_name: value.name,
            password_hash: None,
            email: None,
            ap_id: value.id.inner().clone(),
            inbox: value.inbox,
            outbox: value.outbox,
            local: false,
            public_key: value.public_key.public_key_pem,
            private_key: None,
            last_refreshed_at: Local::now().naive_local(),
            followers: vec![],
        }
    }
}

#[async_trait::async_trait]
impl Object for InternalPerson {
    type DataType = AppData;

    type Kind = Person;

    type Error = Error;

    async fn read_from_id(
        object_id: Url,
        data: &Data<Self::DataType>,
    ) -> std::result::Result<Option<Self>, Self::Error> {
        //TODO: Implement Serializable Option Type so I can send over the wire of nothing got found
        Ok(data.get_object_by_id(object_id, "person").await.ok())
    }

    async fn into_json(
        self,
        _data: &Data<Self::DataType>,
    ) -> std::result::Result<Self::Kind, Self::Error> {
        Ok(self.into())
    }

    async fn verify(
        json: &Self::Kind,
        expected_domain: &Url,
        _data: &Data<Self::DataType>,
    ) -> std::result::Result<(), Self::Error> {
        verify_domains_match(json.id.inner(), expected_domain)?;
        Ok(())
    }

    async fn from_json(
        json: Self::Kind,
        data: &Data<Self::DataType>,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(data.receive_object(&json, "receive_person").await?.into())
    }
}

impl Actor for InternalPerson {
    fn id(&self) -> Url {
        self.ap_id.clone()
    }

    fn public_key_pem(&self) -> &str {
        &self.public_key
    }

    fn private_key_pem(&self) -> Option<String> {
        self.private_key.clone()
    }

    fn inbox(&self) -> Url {
        self.inbox.clone()
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    id: ObjectId<InternalPerson>,
    #[serde(rename = "type")]
    kind: PersonType,
    preferred_username: String,
    name: String,
    inbox: Url,
    outbox: Url,
    public_key: PublicKey,
}

impl From<InternalPerson> for Person {
    fn from(value: InternalPerson) -> Self {
        Self {
            id: ObjectId::from(value.ap_id.clone()),
            kind: PersonType::Person,
            preferred_username: value.prefered_username.clone(),
            name: value.display_name.clone(),
            inbox: value.inbox.clone(),
            outbox: value.outbox.clone(),
            public_key: value.public_key().clone(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(untagged)]
pub enum PersonAcceptedActivities {
    CreateArticle(CreateArticle),
}
