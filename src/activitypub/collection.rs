use super::{activities::Activity, *};

#[derive(Debug, Serialize, Deserialize)]
pub enum CollectionType {
    OrderedCollectionPage,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderedCollection {
    pub context: Context,
    pub id: Url,
    #[serde(rename = "type")]
    pub kind: CollectionType,
    pub next: Option<Url>,
    pub prev: Option<Url>,
    pub part_of: Url,
    pub ordered_items: Vec<Activity>,
}

impl OrderedCollection {
    pub fn new(
        actor: &str,
        name: &str,
        base_url: &str,
    ) -> std::result::Result<Self, url::ParseError> {
        let id = Url::parse(&format!("{}/actors/{}/{}", base_url, actor, name))?;
        Ok(Self {
            context: Context::List(vec![KnownContext::ActivityStreams]),
            id: id.clone(),
            kind: CollectionType::OrderedCollectionPage,
            next: None,
            prev: None,
            part_of: id,
            ordered_items: vec![],
        })
    }
}
