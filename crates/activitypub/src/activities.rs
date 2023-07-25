use crate::*;
use activitypub_federation::protocol::helpers::deserialize_skip_error;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Activity {
    Create(Create),
    Follow(Follow),
    Accept(Accept),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Create {
    pub context: Context,
    pub id: Url,
    pub actor: Url,
    pub published: chrono::NaiveDateTime,
    pub to: Vec<Url>,
    pub cc: Option<Vec<Url>>,
    pub object: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Follow {
    pub context: Context,
    pub id: Url,
    pub actor: Url,
    #[serde(deserialize_with = "deserialize_skip_error", default)]
    pub to: Option<[Url; 1]>,
    pub object: Url,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Accept {
    pub context: Context,
    pub id: Url,
    pub actor: Url,
    #[serde(deserialize_with = "deserialize_skip_error", default)]
    pub to: Option<[Url; 1]>,
    pub object: Follow,
}
