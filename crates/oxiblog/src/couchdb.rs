use hyper::Method;
use reqwest::RequestBuilder;
use serde::{Deserialize, Serialize};

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

    pub async fn delete_db(&self, name: &str) -> crate::Result<()> {
        let path = format!("/{}", name);
        let resp = self.base_request(Method::DELETE, &path).send().await?;
        if !resp.status().is_success() {
            Err(crate::Error::CouchClientError(resp.text().await?))
        } else {
            Ok(())
        }
    }
}
