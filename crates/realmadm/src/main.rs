use clap::{Parser, Subcommand};
use futures_lite::StreamExt;
use identd::{AdminMessage, AdminResponse};
use lapin::{
    options::{BasicConsumeOptions, BasicPublishOptions, QueueDeclareOptions},
    types::FieldTable,
    BasicProperties, ConnectionProperties,
};
use miette::{Context, IntoDiagnostic, Result};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    RsaPrivateKey,
};
use std::{collections::HashMap, io::Write};
use std::{fs::File, path::Path};
use tracing_subscriber::prelude::*;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    commands: Commands,

    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    GenerateKey {
        name: String,
    },
    CreateUser {
        username: String,
        email: String,
        password: String,
        realm: String,
        attributes: Option<Vec<String>>,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    let config = identd::ServerConfig::new(args.config)?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "realmadm=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    match args.commands {
        Commands::GenerateKey { name } => {
            let mut rng = rand::thread_rng();
            let bits = 4096;
            let priv_key = RsaPrivateKey::new(&mut rng, bits)
                .into_diagnostic()
                .wrap_err("could not generate Private key")?;

            let pem_key = priv_key
                .to_pkcs1_pem(LineEnding::LF)
                .into_diagnostic()
                .wrap_err("could not convert key to pkcs1")?;
            let pem_path = Path::new("keys").join(name).with_extension("pem");

            let mut pem_file = File::create(pem_path)
                .into_diagnostic()
                .wrap_err("could not open file handle")?;
            pem_file
                .write_all(pem_key.as_bytes())
                .into_diagnostic()
                .wrap_err("could not write key")?;
            Ok(())
        }
        Commands::CreateUser {
            username,
            email,
            password,
            realm,
            attributes,
        } => {
            let attributes = if let Some(attrs) = attributes {
                let mut hm: HashMap<String, String> = HashMap::new();
                for att in attrs {
                    if let Some((k, v)) = att.split_once('=') {
                        hm.insert(k.to_owned(), v.to_owned());
                    }
                }
                Some(hm)
            } else {
                None
            };
            let msg = AdminMessage::CreateUser {
                username,
                password,
                email,
                realm_id: realm,
                attributes,
            };

            async_global_executor::block_on(async {
                match send_message(msg, &config.amqp_url).await {
                    Ok(_) => {}
                    Err(err) => tracing::error!("Send failed {}", err),
                }
            });

            Ok(())
        }
    }
}

async fn send_message(msg: AdminMessage, amqp_url: &str) -> Result<()> {
    let conn = lapin::Connection::connect(amqp_url, ConnectionProperties::default())
        .await
        .into_diagnostic()?;
    let payload = serde_json::to_string(&msg).into_diagnostic()?;
    let channel = conn.create_channel().await.into_diagnostic()?;
    let callback_queue = channel
        .queue_declare(
            "",
            QueueDeclareOptions {
                exclusive: true,
                auto_delete: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .into_diagnostic()?;
    channel
        .basic_publish(
            "",
            identd::ADMIN_QUEUE_NAME,
            BasicPublishOptions::default(),
            payload.as_bytes(),
            BasicProperties::default().with_reply_to(callback_queue.name().to_owned()),
        )
        .await
        .into_diagnostic()?
        .await
        .into_diagnostic()?;
    let mut consumer = channel
        .basic_consume(
            callback_queue.name().as_str(),
            "realmadm.callback",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .into_diagnostic()?;

    if let Some(delivery) = consumer.next().await {
        let delivery = delivery.into_diagnostic()?;
        let resp_msg: AdminResponse = serde_json::from_slice(&delivery.data).into_diagnostic()?;
        match resp_msg {
            AdminResponse::Success => {}
            AdminResponse::Error { message } => tracing::error!("{}", message),
        }
    }

    channel.close(0, "bye bye").await.into_diagnostic()?;
    conn.close(0, "bye bye").await.into_diagnostic()?;
    Ok(())
}
