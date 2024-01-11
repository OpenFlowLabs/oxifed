pub mod activitypub;
pub mod actor;
pub mod domainservd;
#[allow(warnings, unused)]
pub mod prisma;
pub mod webfinger;

use clap::{Parser, Subcommand};
use config::File;
use miette::Diagnostic;
#[allow(unused_imports)]
use prisma::*;
use serde::Deserialize;
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    PrismaError(#[from] prisma_client_rust::NewClientError),

    #[error(transparent)]
    QueryError(#[from] prisma_client_rust::QueryError),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    Config(#[from] config::ConfigError),

    #[error("please specify an actor in the format name@domain")]
    WrongActorFormat,

    #[error("post has no frontmatter can not create")]
    NoFrontmatter,

    #[error(transparent)]
    SerdeJSON(#[from] serde_json::error::Error),

    #[error(transparent)]
    PKCS8Priv(#[from] ed25519_dalek::pkcs8::Error),

    #[error(transparent)]
    PKCS8Pub(#[from] ed25519_dalek::pkcs8::spki::Error),
}

pub type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Parser)]
pub struct Args {
    pub connection_string: Option<String>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Deserialize)]
pub struct Config {
    pub connection_string: String,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    CreateBlog { actor: String },
    ListBlogs,
    PublishArticle { actor: String, file: PathBuf },
}

pub fn read_config(args: &Args) -> Result<Config> {
    let cfg = config::Config::builder()
        .set_default(
            "connection_string",
            "mongodb://dev:dev@localhost:27017/oxifed?authSource=admin&retryWrites=true&w=majority",
        )?
        .add_source(File::with_name("oxiblog").required(false))
        .add_source(File::with_name("/etc/oxifed/blog").required(false))
        .set_override_option("connection_string", args.connection_string.clone())?
        .build()?;
    Ok(cfg.try_deserialize()?)
}

pub fn generate_descriptor(content: &str, actor: &str) -> Result<String> {
    let (actor_name, domain_name) = actor.split_once("@").ok_or(Error::WrongActorFormat)?;
    let mut hasher = Sha3_256::new();
    hasher.update(content.as_bytes());
    let hash = hasher.finalize();
    Ok(format!("oxifed:{actor_name}:{domain_name}:{hash:x}"))
}

pub fn build_base_url(use_ssl: bool, domain: &str) -> String {
    if use_ssl {
        format!("https://{domain}")
    } else {
        format!("http://{domain}")
    }
}
