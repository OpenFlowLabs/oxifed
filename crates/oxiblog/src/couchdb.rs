use std::collections::HashMap;

use hyper::{header::ACCEPT, Method, StatusCode};
use reqwest::RequestBuilder;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CouchDBConfig {
    pub username: String,
    pub password: String,
    host: String,
    port: Option<String>,
    ssl: bool,
}

impl CouchDBConfig {
    pub fn get_url(&self) -> String {
        let scheme = if self.ssl { "https" } else { "http" };

        format!(
            "{}://{}:{}",
            scheme,
            self.host,
            self.port.clone().unwrap_or(String::from("5984"))
        )
    }
}

pub struct Document {
    pub id: String,
    pub version: Option<String>,
    pub size: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CouchDBResponse {
    pub id: String,
    pub ok: bool,
    pub rev: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Attachment {
    pub content_type: String,
    pub data: Option<String>,
    pub digest: Option<String>,
    pub encoded_length: Option<u64>,
    pub encoding: Option<String>,
    pub length: Option<u64>,
    pub revpos: Option<u64>,
    pub stub: Option<bool>,
}

impl Attachment {
    pub fn new_upload(mime: String, data: String) -> Self {
        Self {
            content_type: mime,
            data: Some(data),
            digest: None,
            encoded_length: None,
            encoding: None,
            length: None,
            revpos: None,
            stub: None,
        }
    }
}

pub type Attachments = HashMap<String, Attachment>;

#[derive(Clone)]
pub struct Client {
    cfg: CouchDBConfig,
}

impl Client {
    pub fn new(cfg: CouchDBConfig) -> Self {
        Self { cfg }
    }

    fn base_request(&self, method: Method, path: &str) -> RequestBuilder {
        reqwest::Client::new()
            .request(method, self.cfg.get_url() + path)
            .basic_auth(self.cfg.username.clone(), Some(self.cfg.password.clone()))
    }

    pub async fn create_db(&self, name: &str) -> crate::Result<()> {
        let path = format!("/{}", name);
        let resp = self.base_request(Method::PUT, &path).send().await?;
        if !resp.status().is_success() {
            Err(crate::Error::CouchClientError(resp.text().await?))
        } else {
            Ok(())
        }
    }

    pub async fn has_db(&self, db: &str) -> crate::Result<bool> {
        let path = format!("/{}", db);
        let resp = self.base_request(Method::HEAD, &path).send().await?;
        if resp.status() == StatusCode::OK || resp.status() == StatusCode::NOT_MODIFIED {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn delete_db(&self, name: &str) -> crate::Result<()> {
        let path = format!("/{}", name);
        let resp = self.base_request(Method::DELETE, &path).send().await?;
        if !resp.status().is_success() {
            Err(crate::Error::CouchClientError(resp.text().await?))
        } else {
            Ok(())
        }
    }

    pub async fn post_document<S: Serialize>(&self, db: &str, doc: &S) -> crate::Result<Document> {
        let path = format!("/{}", db);
        let resp = self
            .base_request(Method::POST, &path)
            .json(doc)
            .header(ACCEPT, "application/json")
            .send()
            .await?;
        let resp_obj: CouchDBResponse = resp.json().await?;
        if resp_obj.ok {
            let d = Document {
                id: resp_obj.id,
                version: Some(resp_obj.rev),
                size: None,
            };

            Ok(d)
        } else {
            Err(crate::Error::CouchClientError(format!(
                "failed to create document"
            )))
        }
    }

    pub async fn upsert_document<S: Serialize>(
        &self,
        db: &str,
        id: &str,
        doc: &S,
    ) -> crate::Result<Document> {
        let path = format!("/{}/{}", db, id);
        let resp = self
            .base_request(Method::PUT, &path)
            .json(doc)
            .header(ACCEPT, "application/json")
            .send()
            .await?;
        let resp_obj: CouchDBResponse = resp.json().await?;
        if resp_obj.ok {
            let d = Document {
                id: resp_obj.id,
                version: Some(resp_obj.rev),
                size: None,
            };
            Ok(d)
        } else {
            Err(crate::Error::CouchClientError(format!(
                "falied to upsert document with id: {}",
                id
            )))
        }
    }

    pub async fn has_document(&self, db: &str, id: &str) -> crate::Result<bool> {
        let path = format!("/{}/{}", db, id);
        let resp = self.base_request(Method::HEAD, &path).send().await?;
        if resp.status() == StatusCode::OK || resp.status() == StatusCode::NOT_MODIFIED {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn get_document<D: DeserializeOwned>(&self, db: &str, id: &str) -> crate::Result<D> {
        let path = format!("/{}/{}", db, id);
        let resp = self
            .base_request(Method::GET, &path)
            .header(ACCEPT, "application/json")
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }

    pub async fn delete_document(&self, db: &str, id: &str) -> crate::Result<()> {
        let path = format!("/{}/{}", db, id);
        let resp = self.base_request(Method::DELETE, &path).send().await?;
        let resp_obj: CouchDBResponse = resp.json().await?;
        if resp_obj.ok {
            Ok(())
        } else {
            Err(crate::Error::CouchClientError(format!(
                "failed to delete document with id: {}",
                id
            )))
        }
    }
}
