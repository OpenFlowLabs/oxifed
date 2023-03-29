use activitypub_federation::config::Data;
use activitypub_federation::http_signatures::generate_actor_keypair;
use activitypub_federation::protocol::public_key::PublicKey;
use activitypub_federation::protocol::verification::verify_domains_match;
use activitypub_federation::traits::{Actor, Object};
use activitypub_federation::{fetch::object_id::ObjectId, kinds::actor::PersonType};
use bonsaidb::core::schema::InsertError;
use bonsaidb::{
    core::schema::{Collection, Schema, SerializedCollection},
    local::AsyncDatabase,
};
use chrono::Local;
use chrono::NaiveDateTime;
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    VarError(#[from] std::env::VarError),

    #[error(transparent)]
    BonsaiDBError(#[from] bonsaidb::core::Error),

    #[error(transparent)]
    URLParseError(#[from] url::ParseError),

    #[error(transparent)]
    ActivityPubError(#[from] activitypub_federation::error::Error),

    #[error(transparent)]
    InsertError(#[from] InsertError<DBPerson>),
}

pub type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Schema)]
#[schema(name="Oxifed", collections = [DBPerson])]
pub struct AppSchema;

#[derive(Collection, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[collection(name = "Person", primary_key = String, natural_id = |user: &DBPerson| Some(user.federation_id.to_string()))]
pub struct DBPerson {
    pub prefered_username: String,
    pub display_name: String,
    pub password_hash: Option<String>,
    pub email: Option<String>,
    pub federation_id: Url,
    pub inbox: Url,
    pub outbox: Url,
    pub local: bool,
    pub public_key: String,
    pub private_key: Option<String>,
    pub last_refreshed_at: NaiveDateTime,
}

impl DBPerson {
    pub fn new_local(hostname: &str, name: String) -> Result<DBPerson> {
        let ap_id = Url::parse(&format!("//{}/{}", hostname, &name))?.into();
        let inbox = Url::parse(&format!("//{}/{}/inbox", hostname, &name))?;
        let outbox = Url::parse(&format!("//{}/{}/outbox", hostname, &name))?;
        let keypair = generate_actor_keypair()?;
        Ok(DBPerson {
            prefered_username: name.clone(),
            federation_id: ap_id,
            inbox,
            public_key: keypair.public_key,
            private_key: Some(keypair.private_key),
            last_refreshed_at: Local::now().naive_local(),
            local: true,
            display_name: name.clone(),
            password_hash: None,
            email: None,
            outbox,
        })
    }
}

impl From<Person> for DBPerson {
    fn from(value: Person) -> Self {
        DBPerson {
            prefered_username: value.preferred_username,
            display_name: value.name,
            password_hash: None,
            email: None,
            federation_id: value.id.inner().clone(),
            inbox: value.inbox,
            outbox: value.outbox,
            local: false,
            public_key: value.public_key.public_key_pem,
            private_key: None,
            last_refreshed_at: Local::now().naive_local(),
        }
    }
}

#[async_trait::async_trait]
impl Object for DBPerson {
    type DataType = AppData;

    type Kind = Person;

    type Error = Error;

    async fn read_from_id(
        object_id: Url,
        data: &Data<Self::DataType>,
    ) -> std::result::Result<Option<Self>, Self::Error> {
        let db_person = DBPerson::get_async(object_id.to_string(), &data.db).await?;
        Ok(db_person.map(|d| d.contents))
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
        let db_person = DBPerson::push_async(json.into(), &data.db).await?;
        Ok(db_person.contents)
    }
}

impl Actor for DBPerson {
    fn id(&self) -> Url {
        self.federation_id.clone()
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
    id: ObjectId<DBPerson>,
    #[serde(rename = "type")]
    kind: PersonType,
    preferred_username: String,
    name: String,
    inbox: Url,
    outbox: Url,
    public_key: PublicKey,
}

impl From<DBPerson> for Person {
    fn from(value: DBPerson) -> Self {
        Self {
            id: ObjectId::from(value.federation_id.clone()),
            kind: PersonType::Person,
            preferred_username: value.prefered_username.clone(),
            name: value.display_name.clone(),
            inbox: value.inbox.clone(),
            outbox: value.outbox.clone(),
            public_key: value.public_key().clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppData {
    pub db: AsyncDatabase,
}

pub fn env_var(name: &str) -> Result<String> {
    Ok(std::env::var(name)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
