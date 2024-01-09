#[allow(warnings, unused)]
mod prisma;

use clap::{Parser, Subcommand};
use config::File;
use miette::Diagnostic;
use prisma::*;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, info};

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
}

type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Parser)]
pub struct Args {
    connection_string: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Deserialize)]
pub struct Config {
    connection_string: String,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    CreateBlog { actor: String },
}

pub fn read_config(args: &Args) -> Result<Config> {
    let cfg = config::Config::builder()
        .set_default(
            "connection_string",
            "mongodb://dev:dev@localhost:27017/oxifed?authSource=admin&retryWrites=true&w=majority",
        )?
        .add_source(File::with_name("oxiblog").required(false))
        .add_source(File::with_name("/etc/oxifed/blog.yaml").required(false))
        .set_override_option("connection_string", args.connection_string.clone())?
        .build()?;
    Ok(cfg.try_deserialize()?)
}

pub async fn run_command(config: Config, args: &Args) -> Result<()> {
    let client = PrismaClient::_builder()
        .with_url(config.connection_string)
        .build()
        .await?;
    match args.command.clone() {
        Commands::CreateBlog { actor } => create_blog(client, actor).await,
    }
}

pub async fn create_blog(client: PrismaClient, actor: String) -> Result<()> {
    let (actor_name, domain_name) = actor.split_once("@").ok_or(Error::WrongActorFormat)?;

    debug!("Creating or updating blog domain");
    client
        .domain()
        .upsert(
            domain::dns_name::equals(domain_name.to_owned()),
            (
                domain_name.to_owned(),
                vec![domain::applications::set(vec!["blog".to_owned()])],
            ),
            vec![domain::applications::push(vec!["blog".to_owned()])],
        )
        .exec()
        .await?;

    client
        .actor()
        .create(
            actor_name.to_owned(),
            domain::dns_name::equals(domain_name.to_owned()),
            vec![],
        )
        .exec()
        .await?;

    info!("Created blog {actor_name}@{domain_name}");
    Ok(())
}

pub async fn publish_article(client: PrismaClient, actor: String, content: String) -> Result<()> {
    Ok(())
}
