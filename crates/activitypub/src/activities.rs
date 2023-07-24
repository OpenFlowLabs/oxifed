use crate::*;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Activity {
    Create {
        context: Context,
        id: Url,
        actor: Url,
        published: chrono::NaiveDateTime,
        to: Vec<Url>,
        cc: Vec<Url>,
        object: Object,
    },
}
