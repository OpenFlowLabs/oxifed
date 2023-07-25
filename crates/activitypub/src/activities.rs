use crate::*;
use activitypub_federation::protocol::helpers::deserialize_skip_error;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Activity {
    Create(Create),
    Follow(Follow),
    Accept(Accept),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CreateType {
    Create,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Create {
    pub context: Context,
    pub id: Url,
    #[serde(rename = "type")]
    pub kind: CreateType,
    pub actor: Url,
    pub published: chrono::NaiveDateTime,
    pub to: Vec<Url>,
    pub cc: Option<Vec<Url>>,
    pub object: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FollowType {
    Follow,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Follow {
    pub context: Context,
    pub id: Url,
    #[serde(rename = "type")]
    pub kind: FollowType,
    pub actor: Url,
    #[serde(deserialize_with = "deserialize_skip_error", default)]
    pub to: Option<[Url; 1]>,
    pub object: Url,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AcceptType {
    Accept,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Accept {
    pub context: Context,
    pub id: Url,
    #[serde(rename = "type")]
    pub kind: AcceptType,
    pub actor: Url,
    #[serde(deserialize_with = "deserialize_skip_error", default)]
    pub to: Option<[Url; 1]>,
    pub object: Follow,
}
