use std::io::read_to_string;

use async_graphql::{Context, Object, Upload};
use base64::Engine;
use ed25519_dalek::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    SigningKey,
};
use gray_matter::Matter;
use lapin::{options::BasicPublishOptions, BasicProperties};
use oxifed::{
    actor::Actor,
    article::Article,
    generate_descriptor, parse_markdown,
    prisma::{self, article, domain},
    Frontmatter,
};
use rand::rngs::OsRng;
use tracing::{debug, info};

use crate::{Error, Result, SharedState};

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    async fn create_blog(&self, ctx: &Context<'_>, actor: String) -> Result<Actor> {
        let state = ctx.data_unchecked::<SharedState>();

        let (actor_name, domain_name) = {
            let values = actor.split_once("@").ok_or(Error::WrongActorFormat)?;
            (values.0.to_owned(), values.1.to_owned())
        };

        if state
            .lock()
            .await
            .prisma
            .domain()
            .find_first(vec![domain::dns_name::equals(domain_name.clone())])
            .exec()
            .await?
            .is_none()
        {
            debug!("Creating blog domain");
            state
                .lock()
                .await
                .prisma
                .domain()
                .create(
                    domain_name.to_owned(),
                    vec![domain::applications::set(vec!["blog".to_owned()])],
                )
                .exec()
                .await?;
        }

        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);

        debug!("Creating actor");
        let actor = state
            .lock()
            .await
            .prisma
            .actor()
            .create(
                actor_name.clone(),
                actor,
                domain::dns_name::equals(domain_name.clone()),
                vec![],
            )
            .exec()
            .await?;

        debug!("Inserting main encrytion key");
        let _main_key = state
            .lock()
            .await
            .prisma
            .key()
            .create(
                prisma::actor::id::equals(actor.id.clone()),
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

        let activity_object = oxifed::activitypub::InternalActivity::Create {
            id: actor.id.clone(),
            additional_context: None,
            actor: actor.handle.clone(),
            to: vec![],
            cc: vec![],
            bcc: vec![],
            object: serde_json::to_value(&actor)?,
        };
        let key_object = oxifed::activitypub::InternalActivity::SetKey {
            key_id: "main".to_owned(),
            actor: actor.id.clone(),
            signing_key_pem_base64: base64::engine::general_purpose::URL_SAFE.encode(
                signing_key
                    .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?
                    .to_string(),
            ),
            verifying_key_pem_base64: base64::engine::general_purpose::URL_SAFE.encode(
                signing_key
                    .verifying_key()
                    .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?
                    .to_string(),
            ),
        };
        let publish_channel = state.lock().await.activity_publish_channel.clone();
        let conn = state.lock().await.rbmq_pool.get().await?;
        let channel = conn.create_channel().await?;

        debug!(state=?conn.status().state(), "Sending actor info to publisher");
        channel
            .basic_publish(
                "",
                &publish_channel,
                BasicPublishOptions::default(),
                &serde_json::to_vec(&key_object)?,
                BasicProperties::default(),
            )
            .await?;
        channel
            .basic_publish(
                "",
                &publish_channel,
                BasicPublishOptions::default(),
                &serde_json::to_vec(&activity_object)?,
                BasicProperties::default(),
            )
            .await?;
        debug!(state=?conn.status().state(),"Messages sent");

        Ok(actor.into())
    }

    async fn publish_article(
        &self,
        ctx: &Context<'_>,
        markdown_file: Upload,
        actor: String,
    ) -> Result<Article> {
        let state = ctx.data_unchecked::<SharedState>();
        let content = {
            let upload = markdown_file.value(ctx)?;
            read_to_string(upload.content)?
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
        let article_descriptor_copy = article_descriptor.clone();
        let actor_copy = actor.clone();

        state
            .lock()
            .await
            .prisma
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
                            prisma::actor::handle::equals(actor.clone()),
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
                            prisma::actor::handle::equals(actor.clone()),
                            prisma::note::id::equals(note.id.clone()),
                            vec![
                                prisma::article::draft::set(frontmatter.draft),
                                prisma::article::tags::set(
                                    frontmatter.tags.clone().unwrap_or(vec![]),
                                ),
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

        let article = state
            .lock()
            .await
            .prisma
            .article()
            .find_unique(article::descriptor::equals(article_descriptor_copy))
            .exec()
            .await?
            .ok_or(Error::NotFound("article".to_owned()))?;

        let article_activity = oxifed::activitypub::InternalActivity::Create {
            id: article.id.clone(),
            additional_context: None,
            actor: actor_copy,
            to: vec!["public".to_owned(), "followers".to_owned()],
            cc: vec![],
            bcc: vec![],
            object: serde_json::to_value(&article)?,
        };

        let publish_channel = state.lock().await.activity_publish_channel.clone();
        let conn = state.lock().await.rbmq_pool.get().await?;
        let channel = conn.create_channel().await?;

        debug!(state=?conn.status().state(),"Sending actor info to publisher");
        channel
            .basic_publish(
                "",
                &publish_channel,
                BasicPublishOptions::default(),
                &serde_json::to_vec(&article_activity)?,
                BasicProperties::default(),
            )
            .await?;

        Ok(article.into())
    }
}
