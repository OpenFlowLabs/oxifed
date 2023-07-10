use identd::{Error, Result};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use reqwest::redirect::Policy;
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    RsaPrivateKey,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Once;
use std::{fs::File, io::Write, path::PathBuf};
use testdir::testdir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

static INIT_LOGGING: Once = Once::new();

fn init_logging() {
    INIT_LOGGING.call_once(|| {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    // axum logs rejections from built-in extractors with the `axum::rejection`
                    // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                    "identd=trace,auth_flow=trace,tower_http=trace,axum::rejection=trace".into()
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

    cfg.db_url = String::from("sqlite://");

    cfg.realms.push(identd::ConfigRealm {
        name: String::from("master"),
        domain: None,
        clients: vec![identd::Client::new(
            "client_id",
            None,
            "https://localhost:4300/callback",
        )],
    });

    let server = identd::ServerState::new(&cfg).await?;

    server
        .create_user("admin", "password", "master", "admin@example.com")
        .await?;

    tracing::debug!("listening on localhost:4200");
    tokio::spawn(async move {
        match identd::listen(server).await {
            Ok(_) => {}
            Err(_) => {
                tracing::debug!("Server already running ignoring error");
            }
        }
    });
    Ok(())
}

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
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, _csrf_token, nonce) = client
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
    tracing::info!("Starting auth flow: {}", auth_url);
    let login_form = reqwest::get(auth_url).await?;
    if login_form.status().is_server_error() || login_form.status().is_client_error() {
        tracing::debug!("Authorize Failed: {:#?}", login_form.text().await?);
        return Ok(());
    }
    tracing::info!("Authenticating User");
    let mut login_data = HashMap::from([
        ("username", String::from("admin")),
        ("password", String::from("password")),
        ("realm_id", String::from("master")),
    ]);
    let mut post_url = login_form.url().clone();
    post_url.set_query(None);
    for query_params in login_form.url().query_pairs() {
        if query_params.0 == Cow::Borrowed("request_id") {
            login_data.insert("request_id", query_params.1.to_string());
        }
    }

    let resp = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()?
        .post(post_url.clone())
        .form(&login_data)
        .send()
        .await?;

    let location_header = resp.headers().get("location");
    if let Some(location_header) = location_header {
        let callback_url: Url = location_header.to_str()?.parse()?;

        let mut code: Option<String> = None;
        for query_params in callback_url.query_pairs() {
            if query_params.0 == Cow::Borrowed("code") {
                code = Some(query_params.1.to_string());
            }
        }

        if let Some(code) = code {
            tracing::info!("Getting Token");
            let token_response = client
                .exchange_code(AuthorizationCode::new(code))
                .set_pkce_verifier(pkce_verifier)
                .request_async(async_http_client)
                .await
                .map_err(|e| Error::ErrorValue(e.to_string()))?;
            // Extract the ID token claims after verifying its authenticity and nonce.
            let id_token = token_response.id_token().ok_or_else(|| {
                Error::ErrorValue(String::from("Server did not return an ID token"))
            })?;
            let claims = id_token.claims(&client.id_token_verifier(), &nonce)?;

            // Verify the access token hash to ensure that the access token hasn't been substituted for
            // another user's.
            if let Some(expected_access_token_hash) = claims.access_token_hash() {
                let actual_access_token_hash = AccessTokenHash::from_token(
                    token_response.access_token(),
                    &id_token.signing_alg()?,
                )?;
                if actual_access_token_hash != *expected_access_token_hash {
                    return Err(Error::ErrorValue(String::from("Invalid access token")));
                }
            }

            // The authenticated user's identity is now available. See the IdTokenClaims struct for a
            // complete listing of the available claims.
            println!(
                "User {} with e-mail address {} has authenticated successfully",
                claims.subject().as_str(),
                claims
                    .email()
                    .map(|email| email.as_str())
                    .unwrap_or("<not provided>"),
            );

            // See the OAuth2TokenResponse trait for a listing of other available fields such as
            // access_token() and refresh_token().
        } else {
            tracing::debug!("{:#?}", resp);
            return Err(Error::ErrorValue(String::from(
                "no code found in the reponse URL",
            )));
        }
    }

    Ok(())
}
