use identd::Result;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    RsaPrivateKey,
};
use std::sync::Once;
use std::{fs::File, io::Write, path::PathBuf};
use testdir::testdir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static INIT_LOGGING: Once = Once::new();

fn init_logging() {
    INIT_LOGGING.call_once(|| {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    // axum logs rejections from built-in extractors with the `axum::rejection`
                    // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                    "auth_flow=trace,tower_http=trace,axum::rejection=trace".into()
                }),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();
    });
}

async fn setup_server() -> Result<()> {
    init_logging();
    let keys_dir: PathBuf = testdir!();
    let mut rng = rand::thread_rng();

    let mut cfg = identd::ServerConfig::default();
    cfg.realm_keys_base_path = keys_dir.clone();

    let bits = 4096;
    let priv_key = RsaPrivateKey::new(&mut rng, bits)?;

    {
        let pem_key = priv_key.to_pkcs1_pem(LineEnding::LF)?;
        let pem_path = keys_dir.join("master.pem");

        let mut pem_file = File::create(pem_path)?;
        pem_file.write_all(pem_key.as_bytes())?;
    }

    let conn = cfg.open_db_conn().await?;

    let server = identd::ServerState::new(cfg, conn)?;
    tracing::debug!("listening on localhost:4200");
    tokio::spawn(async move {
        identd::listen(server).await.unwrap();
    });
    Ok(())
}

fn setup_callback_server() {}

#[tokio::test]
async fn test_discovery() -> Result<()> {
    setup_server().await?;
    let _provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("http://localhost:4200".to_string())?,
        async_http_client,
    )
    .await
    .map_err(|e| identd::Error::MappedError(e.to_string()))?;
    Ok(())
}

#[tokio::test]
async fn test_pkce() -> Result<()> {
    setup_server().await?;
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("http://localhost:4200".to_string())?,
        async_http_client,
    )
    .await
    .map_err(|e| identd::Error::MappedError(e.to_string()))?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new("client_id".to_string()),
        Some(ClientSecret::new("client_secret".to_string())),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new("http://redirect".to_string())?);

    // Generate a PKCE challenge.
    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, _csrf_token, _nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // Set the desired scopes.
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    tracing::info!("Browse to: {}", auth_url);
    Ok(())
}
