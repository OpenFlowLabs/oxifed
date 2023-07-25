pub mod activities;

use activitypub_federation::protocol::{
    helpers::{deserialize_one_or_many, deserialize_skip_error},
    values::{MediaTypeMarkdown, MediaTypeMarkdownOrHtml},
};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use url::Url;

pub const PUBLIC_ACTOR_URL: &str = "";

/// Public key of actors which is used for HTTP signatures.
///
/// This needs to be federated in the `public_key` field of all actors.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    /// Id of this private key.
    pub id: String,
    /// ID of the actor that this public key belongs to
    pub owner: Url,
    /// The actual public key in PEM format
    pub public_key_pem: String,
}

impl PublicKey {
    /// Create a new [PublicKey] struct for the `owner` with `public_key_pem`.
    ///
    /// It uses an standard key id of `{actor_id}#main-key`
    pub fn new(owner: Url, public_key_pem: String) -> Self {
        let id = main_key_id(&owner);
        PublicKey {
            id,
            owner,
            public_key_pem,
        }
    }
}

pub fn main_key_id(owner: &Url) -> String {
    format!("{}#main-key", &owner)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Context {
    Single(KnownContext),
    List(Vec<KnownContext>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KnownContext {
    #[serde(rename = "https://www.w3.org/ns/activitystreams")]
    ActivityStreams,
    #[serde(rename = "https://w3id.org/security/v1")]
    SecurityV1,
    #[serde(rename = "@language")]
    Language(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Object {
    Person(Person),
    Note(Note),
    Article(Article),
    Document(Document),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub content: String,
    pub media_type: MediaTypeMarkdown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageObject {
    pub url: Url,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoints {
    pub shared_inbox: Url,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    pub id: Url,
    pub preferred_username: String,
    pub public_key: PublicKey,

    /// displayname
    pub name: Option<String>,
    pub summary: Option<String>,
    #[serde(deserialize_with = "deserialize_skip_error", default)]
    pub source: Option<Source>,
    /// user avatar
    pub icon: Option<ImageObject>,
    /// user banner
    pub image: Option<ImageObject>,
    pub matrix_user_id: Option<String>,
    pub endpoints: Option<Endpoints>,
    pub published: Option<DateTime<FixedOffset>>,
    pub updated: Option<DateTime<FixedOffset>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MentionOrValue {
    Mention(Mention),
    Value(Value),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Mention {
    pub href: Url,
    name: Option<String>,
}

/// As specified in https://schema.org/Language
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanguageTag {
    pub identifier: String,
    pub name: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub id: Url,
    pub attributed_to: Url,
    #[serde(deserialize_with = "deserialize_one_or_many")]
    pub to: Vec<Url>,
    #[serde(deserialize_with = "deserialize_one_or_many", default)]
    pub cc: Vec<Url>,
    pub content: String,
    pub in_reply_to: Url,

    pub media_type: Option<MediaTypeMarkdownOrHtml>,
    #[serde(deserialize_with = "deserialize_skip_error", default)]
    pub source: Option<Source>,
    pub published: Option<DateTime<FixedOffset>>,
    pub updated: Option<DateTime<FixedOffset>>,
    #[serde(default)]
    pub tag: Vec<MentionOrValue>,
    // lemmy extension
    pub distinguished: Option<bool>,
    pub language: Option<LanguageTag>,
    pub audience: Option<Url>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Article {
    pub id: Url,
    pub attributed_to: Url,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Document {
    pub id: Url,
    pub name: String,
    pub url: Url,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Actors {
    Person(PersonActor),
}

pub const ACTOR_ID_FORMAT: &str = "{}/actors/{}";
pub const ACTOR_PROFILE_URL: &str = "{}/@{}";
pub const ACTOR_INBOX_FORMAT: &str = "{}/actors/{}/inbox";
pub const ACTOR_OUTBOX_FORMAT: &str = "{}/actors/{}/outbox";
pub const SHARED_INBOX_FORMAT: &str = "{}/inbox";

#[derive(Debug, Serialize, Deserialize)]
pub struct PersonActor {
    pub id: Url,
    pub inbox: Url,
    pub outbox: Url,
    pub endpoints: Vec<Endpoint>,
    pub preferred_username: String,
    pub public_key: PublicKey,
}

impl PersonActor {
    pub fn new(domain: &str, username: &str, public_key: PublicKey) -> Self {
        Self {
            id: format!("{}/actors/{}", domain, username).parse().unwrap(),
            inbox: format!("{}/actors/{}/inbox", domain, username)
                .parse()
                .unwrap(),
            outbox: format!("{}/actors/{}/outbox", domain, username)
                .parse()
                .unwrap(),
            endpoints: vec![Endpoint {
                shared_inbox: format!("{}/inbox", domain).parse().unwrap(),
            }],
            preferred_username: username.clone().to_owned(),
            public_key,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    shared_inbox: Url,
}
