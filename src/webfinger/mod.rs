use chrono::format::format;
use serde::{
    de::{self, Visitor},
    Deserialize,
};
use std::{fmt::Display, str::FromStr};
use thiserror::Error;

#[derive(Debug, Error)]
enum WebfingerError {
    #[error("webfinger URI has no scheme")]
    NoScheme,

    #[error("webfinger URI has no account")]
    NoAccount,

    #[error("scheme {0} is not known")]
    UnknownScheme(String),
}

#[derive(Deserialize)]
pub struct WebfingerQuery {
    pub resource: WebfingerUri,
}

pub enum WebfingerUriScheme {
    Acct,
}

impl Display for WebfingerUriScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebfingerUriScheme::Acct => write!(f, "acct"),
        }
    }
}

impl FromStr for WebfingerUriScheme {
    type Err = WebfingerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "acct" => Ok(Self::Acct),
            x => Err(WebfingerError::UnknownScheme(x.to_owned())),
        }
    }
}

pub struct WebfingerUri {
    scheme: WebfingerUriScheme,
    account: String,
    domain: String,
}

impl WebfingerUri {
    pub fn get_account(&self) -> String {
        self.account.clone()
    }

    pub fn get_domain(&self) -> String {
        self.domain.clone()
    }

    pub fn get_handle(&self) -> String {
        format!("{}@{}", self.account, self.domain)
    }

    pub fn get_scheme(&self) -> String {
        self.scheme.to_string()
    }
}

impl Display for WebfingerUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}@{}", self.scheme, self.account, self.domain)
    }
}

impl FromStr for WebfingerUri {
    type Err = WebfingerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, account) = s.split_once(':').ok_or(WebfingerError::NoScheme)?;
        let (account, domain) = account.split_once('@').ok_or(WebfingerError::NoAccount)?;
        Ok(Self {
            scheme: WebfingerUriScheme::from_str(scheme)?,
            account: account.to_owned(),
            domain: domain.to_owned(),
        })
    }
}

impl<'de> Deserialize<'de> for WebfingerUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct WebfingerUriVisitor;

        impl<'de> Visitor<'de> for WebfingerUriVisitor {
            type Value = WebfingerUri;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "resource must be a valid webfinger URI")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                WebfingerUri::from_str(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_any(WebfingerUriVisitor)
    }
}
