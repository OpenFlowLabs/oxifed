use super::{activities::Activity, *};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Collection {
    OrderedCollection {
        context: Context,
        id: Url,
        total_items: u64,
        first: Url,
        last: Url,
    },
    OrderedCollectionPage {
        context: Context,
        id: Url,
        next: Option<Url>,
        prev: Option<Url>,
        part_of: Url,
        ordered_items: Vec<Activity>,
    },
}
