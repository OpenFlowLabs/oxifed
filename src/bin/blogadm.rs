use std::{fs::File, path::Path};

use chrono::{DateTime, FixedOffset};
use clap::Parser;
use ed25519_dalek::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    SigningKey,
};
use gray_matter::Matter;
use oxifed::prisma::*;
use oxifed::*;
use pulldown_cmark::{html, Options};
use rand::rngs::OsRng;
use serde::Deserialize;
use tracing::{debug, info};

#[tokio::main]
async fn main() -> miette::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let config = read_config(&args)?;
    run_command(config, &args).await?;
    Ok(())
}

pub async fn run_command(config: Config, args: &Args) -> Result<()> {
    let client = PrismaClient::_builder()
        .with_url(config.connection_string)
        .build()
        .await?;
    match args.command.clone() {
        Commands::CreateBlog { actor } => create_blog(client, actor).await,
        Commands::ListBlogs => list_blogs(client).await,
        Commands::PublishArticle { actor, file } => publish_article(client, actor, file).await,
    }
}

pub async fn create_blog(client: PrismaClient, actor: String) -> Result<()> {
    let (actor_name, domain_name) = {
        let values = actor.split_once("@").ok_or(Error::WrongActorFormat)?;
        (values.0.to_owned(), values.1.to_owned())
    };

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

    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    let actor = client
        .actor()
        .create(
            actor_name.clone(),
            actor,
            domain::dns_name::equals(domain_name.clone()),
            vec![],
        )
        .exec()
        .await?;

    let _main_key = client
        .key()
        .create(
            prisma::actor::id::equals(actor.id),
            "main".to_owned(),
            signing_key
                .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?
                .to_string(),
            signing_key
                .verifying_key()
                .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?
                .to_string(),
            vec![],
        )
        .exec()
        .await?;

    info!("Created blog {actor_name}@{domain_name}");
    Ok(())
}

pub async fn list_blogs(client: PrismaClient) -> Result<()> {
    let domains: Vec<domain::Data> = client
        .domain()
        .find_many(vec![domain::applications::has(Some("blog".to_owned()))])
        .with(domain::actors::fetch(vec![]))
        .exec()
        .await?;

    println!("BLOG\tAPPLICATIONS");
    for d in domains {
        if let Some(actors) = d.actors {
            for actor in actors {
                println!(
                    "{}@{}\t{}",
                    actor.display_name,
                    d.dns_name,
                    d.applications.join(";")
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct Frontmatter {
    title: String,
    #[serde(default)]
    draft: bool,
    date: DateTime<FixedOffset>,
    tags: Option<Vec<String>>,
}

pub async fn publish_article<P: AsRef<Path>>(
    client: PrismaClient,
    actor: String,
    file_path: P,
) -> Result<()> {
    let content = {
        use std::io::read_to_string;
        let file = File::open(file_path)?;
        read_to_string(file)?
    };
    let matter = Matter::<gray_matter::engine::YAML>::new();
    let parsed_content = matter.parse(&content);

    let (note_content_html, note_content) = if let Some(excerpt) = parsed_content.excerpt {
        (parse_markdown(&excerpt), excerpt)
    } else {
        (
            parse_markdown(&parsed_content.content),
            parsed_content.content.clone(),
        )
    };

    let frontmatter = parsed_content
        .data
        .ok_or(Error::NoFrontmatter)?
        .deserialize::<Frontmatter>()?;

    let note_descriptor = generate_descriptor(&note_content, &actor)?;
    let article_descriptor = generate_descriptor(&frontmatter.title, &actor)?;

    client
        ._transaction()
        .run(|client| async move {
            let note = client
                .note()
                .upsert(
                    prisma::note::descriptor::equals(note_descriptor.clone()),
                    (
                        note_descriptor,
                        note_content.clone(),
                        note_content_html.clone(),
                        prisma::actor::handle::equals(actor),
                        vec![],
                    ),
                    vec![
                        prisma::note::body::set(note_content),
                        prisma::note::body_html::set(note_content_html),
                    ],
                )
                .exec()
                .await?;
            client
                .article()
                .upsert(
                    prisma::article::descriptor::equals(article_descriptor.clone()),
                    (
                        article_descriptor.clone(),
                        frontmatter.title.clone(),
                        frontmatter.date,
                        parsed_content.content.clone(),
                        parse_markdown(&parsed_content.content),
                        prisma::note::id::equals(note.id.clone()),
                        vec![
                            prisma::article::draft::set(frontmatter.draft),
                            prisma::article::tags::set(frontmatter.tags.clone().unwrap_or(vec![])),
                        ],
                    ),
                    vec![
                        prisma::article::descriptor::set(article_descriptor),
                        prisma::article::title::set(frontmatter.title),
                        prisma::article::date::set(frontmatter.date),
                        prisma::article::draft::set(frontmatter.draft),
                        prisma::article::tags::set(frontmatter.tags.unwrap_or(vec![])),
                    ],
                )
                .exec()
                .await
        })
        .await?;
    Ok(())
}

fn parse_markdown(source: &str) -> String {
    let options = Options::all();
    let parser = pulldown_cmark::Parser::new_ext(source, options);
    let mut content_html = String::new();
    html::push_html(&mut content_html, parser);
    content_html
}
