use axum::extract::{Query, State};
use axum::response::{Html, Redirect};
use axum::routing::get;
use axum::{headers::Host, TypedHeader};
use axum::{Form, Json, Router};
use dioxus::prelude::*;
use miette::Diagnostic;
use openidconnect::core::{
    CoreClaimName, CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
};
use openidconnect::{
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl,
    PrivateSigningKey, ResponseTypes, TokenUrl, UserInfoUrl,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    OpenIDUrlParseError(#[from] openidconnect::url::ParseError),

    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("{0}")]
    HyperError(String),

    #[error("{0}")]
    MappedError(String),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    RSAError(#[from] rsa::Error),

    #[error(transparent)]
    Pkcs1Error(#[from] rsa::pkcs1::Error),

    #[error("could not open key of realm {0}")]
    CouldNotOpenRealmKey(String),
}

pub type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub domain: String,
    pub use_ssl: bool,
    pub realm_keys_base_path: PathBuf,
    pub realms: Vec<ConfigRealm>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::from("127.0.0.1:4200"),
            domain: String::from("localhost:4200"),
            use_ssl: false,
            realm_keys_base_path: Path::new("keys").to_path_buf(),
            realms: vec![],
        }
    }
}

// A realm as it is in the config file
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigRealm {
    pub name: String,
    pub domain: Option<String>,
    pub clients: Vec<Client>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    id: String,
    secret: Option<String>,
    redirect_uri: String,
}

#[derive(Debug, Clone)]
pub struct Realm {
    #[allow(dead_code)]
    name: String,
    clients: Vec<Client>,
    domain: String,
    provider_metadata: CoreProviderMetadata,
    jwks: CoreJsonWebKeySet,
    requests: Vec<AuthRequest>,
}

impl Realm {
    pub fn new<P: AsRef<Path>>(
        name: &str,
        domain: &str,
        scheme: &str,
        clients: Vec<Client>,
        realm_keys_base_path: P,
    ) -> Result<Self> {
        let mut realm_key_file = File::open(
            &realm_keys_base_path
                .as_ref()
                .join(name)
                .with_extension("pem"),
        )?;
        let mut realm_key_str = String::new();
        realm_key_file
            .read_to_string(&mut realm_key_str)
            .map_err(|_| Error::CouldNotOpenRealmKey(name.to_owned()))?;

        Ok(Self {
            name: name.to_owned(),
            domain: domain.to_owned(),
            clients,
            requests: vec![],
            provider_metadata: CoreProviderMetadata::new(
                // Parameters required by the OpenID Connect Discovery spec.
                IssuerUrl::new(format!("{}://{}", scheme, domain))?,
                AuthUrl::new(format!("{}://{}/authorize", scheme, domain))?,
                // Use the JsonWebKeySet struct to serve the JWK Set at this URL.
                JsonWebKeySetUrl::new(format!("{}://{}/jwk", scheme, domain))?,
                // Supported response types (flows).
                vec![
                    // Recommended: support the code flow.
                    ResponseTypes::new(vec![CoreResponseType::Code]),
                ],
                // For user privacy, the Pairwise subject identifier type is preferred. This prevents
                // distinct relying parties (clients) from knowing whether their users represent the same
                // real identities. This identifier type is only useful for relying parties that don't
                // receive the 'email', 'profile' or other personally-identifying scopes.
                // The Public subject identifier type is also supported.
                vec![CoreSubjectIdentifierType::Pairwise],
                // Support the RS256 signature algorithm.
                vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
                // OpenID Connect Providers may supply custom metadata by providing a struct that
                // implements the AdditionalProviderMetadata trait. This requires manually using the
                // generic ProviderMetadata struct rather than the CoreProviderMetadata type alias,
                // however.
                EmptyAdditionalProviderMetadata {},
            )
            // Specify the token endpoint (required for the code flow).
            .set_token_endpoint(Some(TokenUrl::new(format!(
                "{}://{}/token",
                scheme, domain
            ))?))
            // Recommended: support the UserInfo endpoint.
            .set_userinfo_endpoint(Some(UserInfoUrl::new(format!(
                "{}://{}/userinfo",
                scheme, domain
            ))?))
            // Recommended: specify the supported scopes.
            .set_scopes_supported(Some(vec![
                openidconnect::Scope::new("openid".to_string()),
                openidconnect::Scope::new("email".to_string()),
                openidconnect::Scope::new("profile".to_string()),
            ]))
            // Recommended: specify the supported ID token claims.
            .set_claims_supported(Some(vec![
                // Providers may also define an enum instead of using CoreClaimName.
                CoreClaimName::new("sub".to_string()),
                CoreClaimName::new("aud".to_string()),
                CoreClaimName::new("email".to_string()),
                CoreClaimName::new("email_verified".to_string()),
                CoreClaimName::new("exp".to_string()),
                CoreClaimName::new("iat".to_string()),
                CoreClaimName::new("iss".to_string()),
                CoreClaimName::new("name".to_string()),
                CoreClaimName::new("given_name".to_string()),
                CoreClaimName::new("family_name".to_string()),
                CoreClaimName::new("picture".to_string()),
                CoreClaimName::new("locale".to_string()),
            ])),
            jwks: CoreJsonWebKeySet::new(vec![
                // RSA keys may also be constructed directly using CoreJsonWebKey::new_rsa(). Providers
                // aiming to support other key types may provide their own implementation of the
                // JsonWebKey trait or submit a PR to add the desired support to this crate.
                CoreRsaPrivateSigningKey::from_pem(
                    &realm_key_str,
                    Some(JsonWebKeyId::new(format!("{}_key", name))),
                )
                .expect("Invalid RSA private key")
                .as_verification_key(),
            ]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServerState {
    addr: String,
    realms: Vec<Realm>,
    master_realm: Realm,
}

type SharedState = Arc<RwLock<ServerState>>;

fn helper_get_scheme_from_config(use_ssl: bool) -> &'static str {
    if use_ssl {
        "https"
    } else {
        "http"
    }
}

impl ServerState {
    pub fn new(config: ServerConfig) -> Result<Self> {
        let realms = config
            .realms
            .iter()
            .filter_map(|r| {
                Realm::new(
                    &r.name,
                    &r.domain.clone().unwrap_or(config.domain.clone()),
                    helper_get_scheme_from_config(config.use_ssl),
                    r.clients.clone(),
                    config.realm_keys_base_path.clone(),
                )
                .ok()
            })
            .collect::<Vec<Realm>>();
        Ok(Self {
            addr: config.listen_addr,
            realms,
            master_realm: Realm::new(
                "master",
                &config.domain,
                helper_get_scheme_from_config(config.use_ssl),
                vec![Client {
                    id: String::from("master_client"),
                    secret: None,
                    redirect_uri: String::from("/callback"),
                }],
                config.realm_keys_base_path.clone(),
            )?,
        })
    }
}

pub async fn listen(server: ServerState) -> Result<()> {
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(openid_discover_handler),
        )
        .route("/jwk", get(openid_jwks_handler))
        .route("/authorize", get(authorize_handler))
        .route(
            "/:realm/login",
            get(get_realm_login_form).post(post_realm_login),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(Arc::new(RwLock::new(server.clone())));

    axum::Server::try_bind(&server.addr.parse()?)
        .map_err(|e| Error::HyperError(e.to_string()))?
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::HyperError(e.to_string()))?;
    Ok(())
}

async fn openid_discover_handler(
    State(state): State<SharedState>,
    TypedHeader(host): TypedHeader<Host>,
) -> Json<CoreProviderMetadata> {
    for realm in state.read().unwrap().realms.iter() {
        if &realm.domain == host.hostname() {
            return Json(realm.provider_metadata.clone());
        }
    }

    Json(state.read().unwrap().master_realm.provider_metadata.clone())
}

async fn openid_jwks_handler(
    State(state): State<SharedState>,
    TypedHeader(host): TypedHeader<Host>,
) -> Json<CoreJsonWebKeySet> {
    for realm in state.read().unwrap().realms.iter() {
        if &realm.domain == host.hostname() {
            return Json(realm.jwks.clone());
        }
    }

    Json(state.read().unwrap().master_realm.jwks.clone())
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    redirect_uri: Url,
    scope: String,
    nonce: String,
}

#[derive(Debug, Clone)]
struct AuthRequest {
    id: uuid::Uuid,
    code: Option<String>,
    created_at: chrono::NaiveDateTime,
    state: String,
    code_challenge: String,
    nonce: String,
}

async fn authorize_handler(
    Query(query): Query<AuthorizeQuery>,
    State(state): State<SharedState>,
) -> Redirect {
    let req = AuthRequest {
        id: uuid::Uuid::new_v4(),
        code_challenge: query.code_challenge,
        code: None,
        created_at: chrono::Utc::now().naive_utc(),
        state: query.state,
        nonce: query.nonce,
    };
    for realm in state.write().unwrap().realms.iter_mut() {
        for client in realm.clients.iter() {
            if &client.id == &query.client_id {
                realm.requests.push(req);
                let realm_login_url = format!("/{}/login", &realm.name);
                return Redirect::to(&realm_login_url);
            }
        }
    }

    for client in state.read().unwrap().master_realm.clients.iter() {
        if &client.id == &query.client_id {
            state.write().unwrap().master_realm.requests.push(req);
            let realm_login_url = format!("/{}/login", &state.read().unwrap().master_realm.name);
            return Redirect::to(&realm_login_url);
        }
    }

    Redirect::to("/misconfiguration")
}

fn login_form(cx: Scope) -> Element {
    cx.render(rsx!(form {
        method: "post",
        input {"type":"text", id:"username", name: "username"},
        input {"type":"password", id:"password", name: "password"},
        input {"type": "submit", id: "submit", value: "Submit"}
    }))
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    request_id: String,
}

async fn get_realm_login_form(
    axum::extract::Path(realm): axum::extract::Path<String>,
    Query(query): Query<LoginQuery>,
) -> Html<String> {
    // create a VirtualDom with the app component
    let mut app = VirtualDom::new(login_form);
    // rebuild the VirtualDom before rendering
    let _ = app.rebuild();

    tracing::debug!(
        "Rendering form for request_id={} and realm={}",
        query.request_id,
        realm
    );

    // render the VirtualDom to HTML
    Html(dioxus_ssr::render(&app))
}

#[derive(Debug, Deserialize)]
struct LoginFormData {
    username: String,
    password: String,
}

async fn post_realm_login(Form(login_form): Form<LoginFormData>) -> Html<String> {
    tracing::debug!(
        "username: {}, password: {}",
        login_form.username,
        login_form.password
    );

    Html(String::from("<div>Success</div>"))
}
