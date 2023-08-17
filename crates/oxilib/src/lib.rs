use lapin::{options::BasicPublishOptions, protocol::basic::AMQPProperties, Channel};
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    Lapin(#[from] lapin::Error),

    #[error(transparent)]
    JSON(#[from] serde_json::Error),
}

type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Serialize, Deserialize)]
pub enum Activity<O>
where
    O: Serialize,
{
    Follow {
        name: String,
        server: String,
        actor_url: Url,
    },
    Create {
        id: String,
        object: O,
        #[serde(flatten)]
        recipients: Recipients,
    },
    Update {
        object: Url,
        update: O,
        #[serde(flatten)]
        recipients: Recipients,
    },
    Delete {
        object: Url,
    },
    Announce {
        object: Url,
        #[serde(flatten)]
        recipients: Recipients,
    },
    Accept {
        object: Url,
    },
    TentativeAccept {
        object: Url,
    },
    Add {
        object: Url,
        target: Url,
    },
    Ignore {
        url: Url,
    },
    Join {
        target: Url,
    },
    Leave {
        target: Url,
    },
    Like {
        target: Url,
    },
    Offer {
        object: O,
        #[serde(flatten)]
        recipients: Recipients,
    },
    Invite {
        object: O,
        #[serde(flatten)]
        recipients: Recipients,
    },
    Reject {
        object: Url,
    },
    TentativeReject {
        object: Url,
    },
    Remove {
        object: Url,
        target: Url,
    },
    Undo {
        target: Url,
    },
    Move {
        object: Url,
        target: Url,
        origin: Url,
    },
    Block {
        object: Url,
    },
    Dislike {
        object: Url,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Recipients {
    pub to: Vec<Url>,
    pub cc: Option<Vec<Url>>,
    pub bto: Option<Vec<Url>>,
    pub bcc: Option<Vec<Url>>,
}

impl Recipients {
    pub fn get_actors(&self) -> (Vec<Url>, Option<Vec<Url>>) {
        let mut v = self.to.clone();
        let mut blind = Vec::new();

        if let Some(cc) = &self.cc {
            for act in cc {
                v.push(act.clone());
            }
        }

        if let Some(bto) = &self.bto {
            for act in bto {
                blind.push(act.clone());
            }
        }
        if let Some(bcc) = &self.bcc {
            for act in bcc {
                blind.push(act.clone());
            }
        }

        let bv = if blind.len() > 0 { Some(blind) } else { None };

        (v, bv)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message<O>
where
    O: Serialize,
{
    pub activity: Activity<O>,
    pub biscuit: String,
}

pub const OUTBOX_EXCHANGE: &str = "outbox";

pub async fn post<O>(channel: Channel, routing_key: &str, msg: &Message<O>) -> Result<()>
where
    O: Serialize,
{
    let payload = serde_json::to_vec(msg)?;
    channel
        .basic_publish(
            OUTBOX_EXCHANGE,
            routing_key,
            BasicPublishOptions::default(),
            payload.as_slice(),
            AMQPProperties::default(),
        )
        .await?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenContext {
    pub actor: String,
    pub base_url: String,
}
