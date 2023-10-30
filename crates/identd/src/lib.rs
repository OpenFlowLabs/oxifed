pub mod realm;
pub mod realm_migration;
pub mod user;
pub mod user_migration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{headers::Host, TypedHeader};
use axum::{Form, Json, Router};
use base64::{engine::general_purpose, Engine as _};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use config::{Config, Environment};
use deadpool_lapin::Pool;
use futures::{join, StreamExt};
use lapin::BasicProperties;
use lapin::{options::*, types::FieldTable};
use miette::Diagnostic;
use openidconnect::core::{
    CoreClaimName, CoreGenderClaim, CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet,
    CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
    CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, AuthUrl, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata,
    EndUserEmail, ExtraTokenFields, IdTokenFields, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl,
    Nonce, PrivateSigningKey, ResponseTypes, StandardClaims, StandardTokenResponse,
    SubjectIdentifier, TokenUrl, UserInfoUrl,
};
use reqwest::header::ToStrError;
use sea_orm::*;
use sea_orm_migration::MigratorTrait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tera::Context;
use thiserror::Error;
use tokio::sync::Mutex;

use url::Url;

pub const ADMIN_QUEUE_NAME: &str = "identd.admin";

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

    #[error(transparent)]
    DeserializeError(#[from] serde_json::Error),

    #[error(transparent)]
    BCrypt(#[from] bcrypt::BcryptError),

    #[error(transparent)]
    DBErr(#[from] sea_orm::DbErr),

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    TeraError(#[from] tera::Error),

    #[error(transparent)]
    UuidError(#[from] uuid::Error),

    #[error(transparent)]
    JWTError(#[from] jwt_simple::Error),

    #[error(transparent)]
    RMQ(#[from] lapin::Error),

    #[error("{0}")]
    ErrorValue(String),

    #[error(transparent)]
    ClaimsVerificationError(#[from] openidconnect::ClaimsVerificationError),

    #[error(transparent)]
    OpenIdSigninError(#[from] openidconnect::SigningError),

    #[error(transparent)]
    ToStrError(#[from] ToStrError),

    #[error(transparent)]
    JsonWebTokenError(#[from] openidconnect::JsonWebTokenError),

    #[error(transparent)]
    ConfigError(#[from] config::ConfigError),

    #[error("unautorized")]
    Unauthorized,

    #[error("{0} not found")]
    NotFound(String),
}

#[derive(Debug, Serialize, Default)]
enum ErrorCode {
    #[default]
    Internal,
    Unauthorized,
    NotFound,
}

#[derive(Debug, Serialize)]
struct ErrorJson {
    code: ErrorCode,
    message: String,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        tracing::debug!("Error occured {}", &self);
        match &self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorJson {
                    code: ErrorCode::Unauthorized,
                    message: format!("{}", self),
                }),
            )
                .into_response(),
            Self::NotFound(_) => (
                StatusCode::NOT_FOUND,
                Json(ErrorJson {
                    code: ErrorCode::NotFound,
                    message: format!("{}", self),
                }),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorJson {
                    code: ErrorCode::default(),
                    message: format!("{}", self),
                }),
            )
                .into_response(),
        }
    }
}

pub type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub amqp_url: String,
    pub listen_addr: String,
    pub domain: String,
    pub use_ssl: bool,
    pub realm_keys_base_path: PathBuf,
    pub realms: Option<Vec<ConfigRealm>>,
    pub db_url: String,
    pub realm_db_url: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            amqp_url: String::from("amqp://dev:dev@127.0.0.1:5672/master"),
            listen_addr: String::from("127.0.0.1:4200"),
            domain: String::from("localhost:4200"),
            use_ssl: false,
            realm_keys_base_path: Path::new("keys").to_path_buf(),
            realms: None,
            db_url: String::from("sqlite://identd.db?mode=rwc"),
            realm_db_url: String::from("sqlite://"),
        }
    }
}

impl ServerConfig {
    pub async fn open_db_conn(&self) -> Result<DatabaseConnection> {
        let conn = Database::connect(&self.db_url).await?;

        Ok(conn)
    }

    pub async fn open_realm_db_conn(
        &self,
        realm_file: Option<String>,
    ) -> Result<DatabaseConnection> {
        if let Some(realm_file) = realm_file {
            let conn = Database::connect(format!("sqlite://{}?mode=rwc", realm_file)).await?;

            Ok(conn)
        } else {
            let conn = Database::connect(&self.realm_db_url).await?;

            Ok(conn)
        }
    }

    pub fn new(config_file: Option<String>) -> Result<Self> {
        let mut cfg = Config::builder()
            .add_source(config::File::with_name("/etc/identd.toml").required(false))
            .add_source(config::File::with_name("identd.toml").required(false));

        if let Some(path) = config_file {
            cfg = cfg.add_source(config::File::with_name(&path));
        }

        cfg = cfg.add_source(Environment::with_prefix("identd"));
        cfg = cfg.set_default("amqp_url", "amqp://dev:dev@localhost:5672/master")?;
        cfg = cfg.set_default("listen_addr", "127.0.0.1:4200")?;
        cfg = cfg.set_default("domain", "localhost:4200")?;
        cfg = cfg.set_default("use_ssl", false)?;
        cfg = cfg.set_default("realm_keys_base_path", "keys")?;
        cfg = cfg.set_default("db_url", "sqlite://identd.db?mode=rwc")?;
        cfg = cfg.set_default("realm_db_url", "sqlite://")?;

        let s = cfg.build()?;

        Ok(s.try_deserialize()?)
    }
}

// A realm as it is in the config file
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigRealm {
    pub name: String,
    pub domain: Option<String>,
    pub clients: Vec<Client>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    id: String,
    secret: Option<String>,
    biscuit_private_key: String,
    redirect_uri: String,
}

impl Client {
    pub fn new<S: Into<String>>(id: S, secret: Option<S>, redirect_uri: S) -> Self {
        Self {
            id: id.into(),
            secret: secret.map(|s| s.into()),
            biscuit_private_key: String::new(),
            redirect_uri: redirect_uri.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerState {
    addr: String,
    keys_path: PathBuf,
    realm_db: DatabaseConnection,
    db: DatabaseConnection,
    mq_pool: deadpool_lapin::Pool,
}

type SharedState = Arc<Mutex<ServerState>>;

fn helper_get_scheme_from_config(use_ssl: bool) -> &'static str {
    if use_ssl {
        "https"
    } else {
        "http"
    }
}

impl ServerState {
    pub async fn new(config: &ServerConfig) -> Result<Self> {
        let db = Database::connect(&config.db_url).await?;
        let realm_db = Database::connect(&config.realm_db_url).await?;

        use user_migration::Migrator as UserMigrator;
        UserMigrator::up(&db, None).await?;

        use realm_migration::RealmMigrator;

        RealmMigrator::up(&realm_db, None).await?;

        let mut pool_config = deadpool_lapin::Config::default();
        pool_config.url = Some(config.amqp_url.clone());

        let mq_pool = pool_config
            .create_pool(Some(deadpool_lapin::Runtime::Tokio1))
            .map_err(|e| Error::ErrorValue(e.to_string()))?;

        if let Some(realms) = config.realms.clone() {
            for cfg_realm in realms.iter() {
                let domain_or_default = cfg_realm.domain.clone().unwrap_or(config.domain.clone());
                Self::create_realm(
                    &realm_db,
                    &cfg_realm.name,
                    &domain_or_default,
                    helper_get_scheme_from_config(config.use_ssl),
                    cfg_realm.scopes.as_slice(),
                    cfg_realm.clients.clone(),
                    &config.realm_keys_base_path,
                )
                .await?;
            }
        }

        Ok(Self {
            addr: config.listen_addr.clone(),
            keys_path: config.realm_keys_base_path.clone(),
            realm_db,
            db,
            mq_pool,
        })
    }

    pub async fn create_realm<P: AsRef<Path>>(
        realm_db: &DatabaseConnection,
        name: &str,
        domain: &str,
        scheme: &str,
        scopes: &[String],
        clients: Vec<Client>,
        realm_keys_base_path: P,
    ) -> Result<()> {
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
        use realm::realm::ActiveModel as RealmActiveModel;

        let base_url = format!("{}://{}", scheme, domain);

        let scopes = scopes
            .iter()
            .map(|s| openidconnect::Scope::new(s.clone()))
            .collect::<Vec<openidconnect::Scope>>();

        let metadata = CoreProviderMetadata::new(
            // Parameters required by the OpenID Connect Discovery spec.
            IssuerUrl::new(base_url.clone())?,
            AuthUrl::new(format!("{}/authorize", &base_url))?,
            // Use the JsonWebKeySet struct to serve the JWK Set at this URL.
            JsonWebKeySetUrl::new(format!("{}/jwk", &base_url))?,
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
            "{}/{}/token",
            &base_url, &name,
        ))?))
        // Recommended: support the UserInfo endpoint.
        .set_userinfo_endpoint(Some(UserInfoUrl::new(format!("{}/userinfo", &base_url))?))
        // Recommended: specify the supported scopes.
        .set_scopes_supported(Some(scopes))
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
        ]));

        let jwks = CoreJsonWebKeySet::new(vec![
            // RSA keys may also be constructed directly using CoreJsonWebKey::new_rsa(). Providers
            // aiming to support other key types may provide their own implementation of the
            // JsonWebKey trait or submit a PR to add the desired support to this crate.
            CoreRsaPrivateSigningKey::from_pem(
                &realm_key_str,
                Some(JsonWebKeyId::new(name.to_owned())),
            )
            .expect("Invalid RSA private key")
            .as_verification_key(),
        ]);

        let provider_meta_string = serde_json::to_string(&metadata)?;
        let jwks_string = serde_json::to_string(&jwks)?;

        let realm = RealmActiveModel {
            name: ActiveValue::Set(name.to_owned()),
            domain: ActiveValue::Set(Some(domain.to_owned())),
            provider_metadata: ActiveValue::Set(provider_meta_string),
            jwks: ActiveValue::Set(jwks_string),
            issuer_url: ActiveValue::Set(base_url),
        };

        realm.insert(realm_db).await?;

        use realm::client::ActiveModel as ClientModel;
        for client in clients {
            let c = ClientModel {
                id: ActiveValue::Set(client.id),
                secret: ActiveValue::Set(client.secret),
                realm_id: ActiveValue::Set(name.to_owned()),
                redirect_uri: ActiveValue::Set(client.redirect_uri),
            };
            c.insert(realm_db).await?;
        }

        Ok(())
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        realm_id: &str,
        email: &str,
    ) -> Result<()> {
        use user::user::ActiveModel as UserModel;
        let pwhash = hash(password, DEFAULT_COST)?;
        let u = UserModel {
            id: ActiveValue::Set(uuid::Uuid::new_v4().as_hyphenated().to_string()),
            username: ActiveValue::Set(username.to_owned()),
            realm_id: ActiveValue::Set(realm_id.to_owned()),
            email: ActiveValue::Set(email.to_owned()),
            pwhash: ActiveValue::Set(pwhash),
            attributes: ActiveValue::NotSet,
        };

        u.insert(&self.db).await?;

        Ok(())
    }
}

pub async fn listen(server: ServerState) -> Result<()> {
    let addr = server.addr.clone();
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
        .route("/:realm/token", post(token_endpoint))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(Arc::new(Mutex::new(server.clone())));

    let _ = join!(
        axum::Server::try_bind(&addr.parse()?)
            .map_err(|e| Error::HyperError(e.to_string()))?
            .serve(app.into_make_service()),
        rmq_listen(server.mq_pool.clone(), server.db.clone())
    );
    Ok(())
}

async fn rmq_listen(pool: Pool, user_db: DatabaseConnection) -> Result<()> {
    let mut retry_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    loop {
        retry_interval.tick().await;
        tracing::info!("connecting rmq consumer...");
        match init_rmq_listen(pool.clone(), user_db.clone()).await {
            Ok(_) => tracing::info!("rmq listen returned"),
            Err(e) => tracing::error!(error = e.to_string(), "rmq listen had an error"),
        };
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AdminMessage {
    CreateUser {
        username: String,
        password: String,
        email: String,
        realm_id: String,
        attributes: Option<HashMap<String, String>>,
    },
    UpdateUser {
        username: String,
        password: Option<String>,
        email: Option<String>,
        attributes: Option<HashMap<String, String>>,
    },
    DeleteUser {
        username: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AdminResponse {
    Success,
    Error { message: String },
}

impl std::fmt::Display for AdminResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminResponse::Success => write!(f, "success"),
            AdminResponse::Error { message } => write!(f, "{}", message),
        }
    }
}

async fn init_rmq_listen(pool: Pool, user_db: DatabaseConnection) -> Result<()> {
    let rmq_con = pool
        .get()
        .await
        .map_err(|e| Error::ErrorValue(e.to_string()))?;
    let channel = rmq_con.create_channel().await?;

    let queue = channel
        .queue_declare(
            ADMIN_QUEUE_NAME,
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;
    tracing::info!("Declared queue {:?}", queue);

    let mut consumer = channel
        .basic_consume(
            ADMIN_QUEUE_NAME,
            "admin.consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await?;

    tracing::info!("rmq consumer connected, waiting for messages");
    while let Some(delivery) = consumer.next().await {
        if let Ok(delivery) = delivery {
            match handle_admin_message(&user_db, delivery.data.as_slice()).await {
                Ok(_) => {
                    if let Some(reply_queue) = delivery.properties.reply_to() {
                        let err_msg = AdminResponse::Success;
                        let err_payload = serde_json::to_vec(&err_msg)?;
                        channel
                            .basic_publish(
                                "",
                                reply_queue.as_str(),
                                BasicPublishOptions::default(),
                                &err_payload,
                                BasicProperties::default(),
                            )
                            .await?;
                    }

                    delivery.ack(BasicAckOptions::default()).await?
                }
                Err(err) => {
                    tracing::error!(error = err.to_string(), "failed to handle message");
                    if let Some(reply_queue) = delivery.properties.reply_to() {
                        let err_msg = AdminResponse::Error {
                            message: err.to_string(),
                        };
                        let err_payload = serde_json::to_vec(&err_msg)?;
                        channel
                            .basic_publish(
                                "",
                                reply_queue.as_str(),
                                BasicPublishOptions::default(),
                                &err_payload,
                                BasicProperties::default(),
                            )
                            .await?;
                    }
                    delivery.ack(BasicAckOptions::default()).await?;
                }
            }
        }
    }
    Ok(())
}

async fn handle_admin_message(user_db: &DatabaseConnection, data: &[u8]) -> Result<()> {
    let msg: AdminMessage = serde_json::from_slice(data)?;
    use user::user::Column;
    use user::user::{ActiveModel as Model, Entity as UserEntity};
    tracing::debug!("received message {:?}, processing.", msg);
    match msg {
        AdminMessage::CreateUser {
            username,
            password,
            email,
            realm_id,
            attributes,
        } => {
            let hashed = hash(password, DEFAULT_COST)?;
            let attrs = if let Some(attrs) = attributes {
                Some(serde_json::to_string(&attrs)?)
            } else {
                None
            };
            let new_user = Model {
                id: ActiveValue::Set(uuid::Uuid::new_v4().as_hyphenated().to_string()),
                username: ActiveValue::Set(username),
                realm_id: ActiveValue::Set(realm_id),
                email: ActiveValue::Set(email),
                pwhash: ActiveValue::Set(hashed),
                attributes: ActiveValue::Set(attrs),
            };
            tracing::debug!("Inserting user: {:?}", new_user);
            new_user.insert(user_db).await?;
            Ok(())
        }
        AdminMessage::UpdateUser {
            username,
            password,
            email,
            attributes,
        } => {
            let user = UserEntity::find()
                .filter(Column::Username.eq(username))
                .one(user_db)
                .await?;
            if let Some(user) = user {
                let cloned_attrs = user.attributes.clone();
                let mut mod_user = user.into_active_model();
                if let Some(password) = password {
                    let hashed = hash(password, DEFAULT_COST)?;
                    mod_user.pwhash = ActiveValue::Set(hashed);
                }

                if let Some(email) = email {
                    mod_user.email = ActiveValue::Set(email);
                }

                if let Some(attributes) = attributes {
                    let updated_attributes = if let Some(cur_raw_attrs) = cloned_attrs {
                        let mut currents_attrs: HashMap<String, String> =
                            serde_json::from_str(&cur_raw_attrs)?;
                        for (key, val) in attributes {
                            currents_attrs.insert(key, val);
                        }
                        currents_attrs
                    } else {
                        attributes
                    };
                    let updated_str = serde_json::to_string(&updated_attributes)?;
                    mod_user.attributes = ActiveValue::Set(Some(updated_str));
                }

                tracing::debug!("Updating user to: {:?}", mod_user);
                mod_user.update(user_db).await?;

                Ok(())
            } else {
                Err(Error::NotFound(String::from("no user with username")))
            }
        }
        AdminMessage::DeleteUser { username } => {
            let user = UserEntity::find()
                .filter(Column::Username.eq(username))
                .one(user_db)
                .await?;
            if let Some(user) = user {
                tracing::debug!("deleting user {:?}", user);
                user.delete(user_db).await?;
                Ok(())
            } else {
                Err(Error::NotFound(String::from("no user with username")))
            }
        }
    }
}

async fn openid_discover_handler(
    State(state): State<SharedState>,
    TypedHeader(host): TypedHeader<Host>,
) -> Result<Json<CoreProviderMetadata>> {
    use realm::realm::Entity as RealmEntity;
    let realm = RealmEntity::find()
        .filter(realm::realm::Column::Domain.eq(host.hostname()))
        .one(&state.lock().await.realm_db)
        .await?;
    if let Some(realm) = realm {
        let data: CoreProviderMetadata = serde_json::from_str(&realm.provider_metadata)?;
        return Ok(Json(data));
    }

    let master_realm = RealmEntity::find()
        .filter(realm::realm::Column::Name.eq("master"))
        .one(&state.lock().await.realm_db)
        .await?;
    if let Some(realm) = master_realm {
        let data: CoreProviderMetadata = serde_json::from_str(&realm.provider_metadata)?;
        return Ok(Json(data));
    }

    Err(Error::NotFound(String::from("realm")))
}

async fn openid_jwks_handler(
    State(state): State<SharedState>,
    TypedHeader(host): TypedHeader<Host>,
) -> Result<Json<CoreJsonWebKeySet>> {
    use realm::realm::Entity as RealmEntity;
    let realm = RealmEntity::find()
        .filter(realm::realm::Column::Domain.eq(host.hostname()))
        .one(&state.lock().await.realm_db)
        .await?;
    if let Some(realm) = realm {
        let jwks: CoreJsonWebKeySet = serde_json::from_str(&realm.jwks)?;
        return Ok(Json(jwks));
    }

    let master_realm = RealmEntity::find()
        .filter(realm::realm::Column::Name.eq("master"))
        .one(&state.lock().await.realm_db)
        .await?;
    if let Some(realm) = master_realm {
        let jwks: CoreJsonWebKeySet = serde_json::from_str(&realm.jwks)?;
        return Ok(Json(jwks));
    }

    Err(Error::NotFound(String::from("web keys")))
}

#[derive(Debug, Deserialize, Default)]
enum CodeChallengeMethod {
    #[default]
    Plain,
    S256,
}

impl ToString for CodeChallengeMethod {
    fn to_string(&self) -> String {
        match self {
            CodeChallengeMethod::Plain => String::from("plain"),
            CodeChallengeMethod::S256 => String::from("S256"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    state: String,
    code_challenge: String,
    code_challenge_method: CodeChallengeMethod,
    redirect_uri: String,
    scope: String,
    nonce: String,
}

async fn authorize_handler(
    Query(query): Query<AuthorizeQuery>,
    State(state): State<SharedState>,
) -> Result<Redirect> {
    use realm::auth_request::ActiveModel as AuthRequestModel;
    use realm::client::Entity as ClientEntity;
    use realm::realm::Entity as RealmEntity;

    let client = ClientEntity::find()
        .filter(realm::client::Column::Id.eq(&query.client_id))
        .one(&state.lock().await.realm_db)
        .await?;

    if let Some(client) = client {
        let realm = RealmEntity::find()
            .filter(realm::realm::Column::Name.eq(&client.realm_id))
            .one(&state.lock().await.realm_db)
            .await?;

        if let Some(realm) = realm {
            let request_id = uuid::Uuid::new_v4();
            let req = AuthRequestModel {
                id: ActiveValue::Set(request_id.as_hyphenated().to_string()),
                code_challenge: ActiveValue::Set(query.code_challenge),
                code: ActiveValue::NotSet,
                created_at: ActiveValue::Set(chrono::Utc::now().naive_utc().to_string()),
                state: ActiveValue::Set(query.state),
                nonce: ActiveValue::Set(query.nonce),
                client_id: ActiveValue::Set(client.id.clone()),
                scope: ActiveValue::Set(query.scope),
                redirect_uri: ActiveValue::Set(query.redirect_uri),
            };

            let login_url = format!(
                "/{}/login?request_id={}",
                &realm.name,
                &request_id.as_urn().to_string()
            );

            req.insert(&state.lock().await.realm_db).await?;
            return Ok(Redirect::to(&login_url));
        }
    }

    Err(Error::Unauthorized)
}

#[derive(Debug, Deserialize, Clone)]
struct LoginQuery {
    request_id: String,
}

static LOGIN_FORM_TEMPLATE: &str = r#"
<html>
<head>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/dark.css">
</head>
<body>
<form method="post">
        <input type="text" id="username" name="username" />
        <input type="password" id="password" name="password" />
        <input type="hidden" id="request_id" name="request_id" value="{{request_id}}" />
        <input type="submit" id="submit" value="Submit" />
</form>
</body>
</html>
"#;

async fn get_realm_login_form(Query(query): Query<LoginQuery>) -> Result<Html<String>> {
    let mut tera = tera::Tera::default();
    tera.add_raw_template("login.html", LOGIN_FORM_TEMPLATE)?;
    let mut context = Context::new();
    context.insert("request_id", query.request_id.as_str());
    let login_form = tera.render("login.html", &context)?;
    Ok(Html(login_form))
}

#[derive(Debug, Deserialize)]
struct LoginFormData {
    username: String,
    password: String,
    request_id: String,
}

async fn post_realm_login(
    State(state): State<SharedState>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Form(login_form): Form<LoginFormData>,
) -> Result<Redirect> {
    tracing::debug!(
        "username: {}, password: {}",
        &login_form.username,
        &login_form.password
    );

    use crate::user::user::Entity as UserEntity;
    use realm::auth_request::Entity as AuthRequestEntity;

    let user = UserEntity::find()
        .filter(
            user::user::Column::RealmId
                .contains(&realm)
                .and(user::user::Column::Username.eq(&login_form.username)),
        )
        .one(&state.lock().await.db)
        .await?;

    if let Some(user) = user {
        if verify(&login_form.password, &user.pwhash)? {
            let request_uuid: uuid::Uuid = login_form.request_id.parse()?;
            let auth_request =
                AuthRequestEntity::find_by_id(request_uuid.as_hyphenated().to_string())
                    .one(&state.lock().await.realm_db)
                    .await?;
            if let Some(auth_request) = auth_request {
                use realm::client::Entity as ClientEntity;
                let client = ClientEntity::find_by_id(&auth_request.client_id)
                    .one(&state.lock().await.realm_db)
                    .await?;
                if let Some(client) = client {
                    use jwt_simple::prelude::*;
                    let keys_path = state.lock().await.keys_path.clone();
                    let mut pem_file = File::open(&keys_path.join(&realm).with_extension("pem"))?;
                    let mut pem_contents = String::new();
                    pem_file.read_to_string(&mut pem_contents)?;

                    let pk = RS384KeyPair::from_pem(&pem_contents)?;
                    let claims = Claims::create(Duration::from_secs(30))
                        .with_issuer(&realm)
                        .with_subject(&user.id)
                        .with_nonce(&auth_request.nonce)
                        .with_jwt_id(&auth_request.id);
                    let token = pk.sign(claims)?;

                    let uri = build_callback_url(client, auth_request.clone(), token);

                    return Ok(Redirect::to(&uri));
                }
            }
        } else {
            return Err(Error::Unauthorized);
        }
    }

    Err(Error::Unauthorized)
}

fn build_callback_url(
    client: realm::client::Model,
    auth_request: realm::auth_request::Model,
    code: String,
) -> String {
    format!(
        "{}?state={}&code={}",
        client.redirect_uri, auth_request.state, code,
    )
}

#[derive(Debug, Deserialize)]
enum GrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: GrantType,
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
enum OAuthError {
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,
    #[serde(rename = "access_denied")]
    AccessDenied,
    #[serde(rename = "unsupported_response_type")]
    UnsupportedResponseType,
    #[serde(rename = "invalid_scope")]
    InvalidScope,
    #[serde(rename = "server_error")]
    ServerError(Option<String>),
    #[serde(rename = "temporarily_unavialable")]
    TemporarilyUnavailable,
}

#[derive(Debug, Serialize)]
struct OAuthErrorResponse {
    error: OAuthError,
    error_description: Option<String>,
    error_uri: Option<Url>,
}

impl OAuthErrorResponse {
    fn new(error: OAuthError) -> Self {
        match error {
            OAuthError::InvalidRequest => Self {
                error,
                error_description: None,
                error_uri: None,
            },
            OAuthError::UnauthorizedClient => Self {
                error,
                error_description: None,
                error_uri: None,
            },
            OAuthError::AccessDenied => Self {
                error,
                error_description: None,
                error_uri: None,
            },
            OAuthError::UnsupportedResponseType => Self {
                error,
                error_description: None,
                error_uri: None,
            },
            OAuthError::InvalidScope => Self {
                error,
                error_description: None,
                error_uri: None,
            },
            OAuthError::ServerError(details) => Self {
                error: OAuthError::ServerError(None),
                error_description: details,
                error_uri: None,
            },
            OAuthError::TemporarilyUnavailable => Self {
                error,
                error_description: None,
                error_uri: None,
            },
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            OAuthError::InvalidRequest => {
                (StatusCode::BAD_REQUEST, Json(OAuthErrorResponse::new(self)))
            }
            OAuthError::UnauthorizedClient => (
                StatusCode::UNAUTHORIZED,
                Json(OAuthErrorResponse::new(self)),
            ),
            OAuthError::AccessDenied => (
                StatusCode::UNAUTHORIZED,
                Json(OAuthErrorResponse::new(self)),
            ),
            OAuthError::UnsupportedResponseType => {
                (StatusCode::BAD_REQUEST, Json(OAuthErrorResponse::new(self)))
            }
            OAuthError::InvalidScope => {
                (StatusCode::BAD_REQUEST, Json(OAuthErrorResponse::new(self)))
            }
            OAuthError::ServerError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthErrorResponse::new(self)),
            ),
            OAuthError::TemporarilyUnavailable => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(OAuthErrorResponse::new(self)),
            ),
        }
        .into_response()
    }
}

pub type IdentdTokenResponse = StandardTokenResponse<IdentdIdTokenFields, CoreTokenType>;
pub type IdentdIdTokenFields = IdTokenFields<
    EmptyAdditionalClaims,
    ExtraFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ExtraFields {}
impl ExtraTokenFields for ExtraFields {}

async fn token_endpoint(
    State(state): State<SharedState>,
    axum::extract::Path(realm): axum::extract::Path<String>,
    Form(token_form): Form<TokenRequest>,
) -> std::result::Result<Json<IdentdTokenResponse>, OAuthError> {
    use jwt_simple::prelude::*;
    let realm_key_file_path = &state.lock().await.keys_path.clone();
    let mut realm_key_file = File::open(&realm_key_file_path.join(&realm).with_extension("pem"))
        .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

    let mut pem_contents = String::new();
    realm_key_file
        .read_to_string(&mut pem_contents)
        .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

    let keypair = RS384KeyPair::from_pem(&pem_contents)
        .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

    let public_key = keypair.public_key();

    use realm::realm::Entity as RealmEntity;
    let realm = RealmEntity::find_by_id(&realm)
        .one(&state.lock().await.realm_db)
        .await
        .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

    if let Some(realm) = realm {
        let claims = public_key
            .verify_token::<NoCustomClaims>(&token_form.code, None)
            .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

        if let Some(auth_request_id) = claims.jwt_id {
            if let Some(user_id) = claims.subject {
                use realm::auth_request::Entity as AuthRequestEntity;
                let auth_request = AuthRequestEntity::find_by_id(&auth_request_id)
                    .one(&state.lock().await.realm_db)
                    .await
                    .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

                if let Some(auth_request) = auth_request {
                    use sha2::Digest;
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(&token_form.code_verifier);
                    let hashed = hasher.finalize();
                    let encoded_verifier: String = general_purpose::URL_SAFE_NO_PAD.encode(hashed);
                    // Check https://www.rfc-editor.org/rfc/rfc7636#page-8
                    if encoded_verifier == auth_request.code_challenge {
                        if auth_request.redirect_uri == token_form.redirect_uri {
                            use user::user::Entity as UserEntity;
                            let user = UserEntity::find_by_id(user_id)
                                .one(&state.lock().await.db)
                                .await
                                .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

                            if let Some(user) = user {
                                use jwt_simple::prelude::*;
                                let claims = Claims::create(Duration::from_days(60))
                                    .with_issuer(&realm.name)
                                    .with_subject(&user.id)
                                    .with_nonce(&auth_request.nonce)
                                    .with_audience(&auth_request.client_id);

                                let token = keypair
                                    .sign(claims)
                                    .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

                                let access_token = AccessToken::new(token.to_string());
                                let id_token = CoreIdToken::new(
                                    CoreIdTokenClaims::new(
                                        // Specify the issuer URL for the OpenID Connect Provider.
                                        IssuerUrl::new(realm.issuer_url.clone()).map_err(|e| {
                                            OAuthError::ServerError(Some(e.to_string()))
                                        })?,
                                        // The audience is usually a single entry with the client ID of the client for whom
                                        // the ID token is intended. This is a required claim.
                                        vec![Audience::new(auth_request.client_id.clone())],
                                        // The ID token expiration is usually much shorter than that of the access or refresh
                                        // tokens issued to clients.
                                        Utc::now() + chrono::Duration::seconds(300),
                                        // The issue time is usually the current time.
                                        Utc::now(),
                                        // Set the standard claims defined by the OpenID Connect Core spec.
                                        StandardClaims::new(
                                            // Stable subject identifiers are recommended in place of e-mail addresses or other
                                            // potentially unstable identifiers. This is the only required claim.
                                            SubjectIdentifier::new(user.id.clone()),
                                        )
                                        // Optional: specify the user's e-mail address. This should only be provided if the
                                        // client has been granted the 'profile' or 'email' scopes.
                                        .set_email(Some(EndUserEmail::new(user.email.clone())))
                                        // Optional: specify whether the provider has verified the user's e-mail address.
                                        .set_email_verified(Some(true)),
                                        // OpenID Connect Providers may supply custom claims by providing a struct that
                                        // implements the AdditionalClaims trait. This requires manually using the
                                        // generic IdTokenClaims struct rather than the CoreIdTokenClaims type alias,
                                        // however.
                                        EmptyAdditionalClaims {},
                                    )
                                    .set_nonce(Some(Nonce::new(auth_request.nonce.clone()))),
                                    // The private key used for signing the ID token. For confidential clients (those able
                                    // to maintain a client secret), a CoreHmacKey can also be used, in conjunction
                                    // with one of the CoreJwsSigningAlgorithm::HmacSha* signing algorithms. When using an
                                    // HMAC-based signing algorithm, the UTF-8 representation of the client secret should
                                    // be used as the HMAC key.
                                    &CoreRsaPrivateSigningKey::from_pem(
                                        &pem_contents,
                                        Some(JsonWebKeyId::new(realm.name.clone())),
                                    )
                                    .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?,
                                    // Uses the RS256 signature algorithm. This crate supports any RS*, PS*, or HS*
                                    // signature algorithm.
                                    CoreJwsSigningAlgorithm::RsaSsaPssSha256,
                                    // When returning the ID token alongside an access token (e.g., in the Authorization Code
                                    // flow), it is recommended to pass the access token here to set the `at_hash` claim
                                    // automatically.
                                    Some(&access_token),
                                    // When returning the ID token alongside an authorization code (e.g., in the implicit
                                    // flow), it is recommended to pass the authorization code here to set the `c_hash` claim
                                    // automatically.
                                    None,
                                )
                                .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

                                let extra_fields = ExtraFields {};

                                auth_request
                                    .delete(&state.lock().await.realm_db)
                                    .await
                                    .map_err(|e| OAuthError::ServerError(Some(e.to_string())))?;

                                let id_token_resp = IdentdTokenResponse::new(
                                    access_token,
                                    CoreTokenType::Bearer,
                                    IdentdIdTokenFields::new(Some(id_token), extra_fields),
                                );

                                tracing::trace!(
                                    "token: {:#?}",
                                    serde_json::to_string_pretty(&id_token_resp).map_err(|e| {
                                        OAuthError::ServerError(Some(e.to_string()))
                                    })?
                                );

                                return Ok(Json(id_token_resp));
                            } else {
                                tracing::warn!("user not found");
                            }
                        } else {
                            tracing::warn!("redirec_uri does not match");
                        }
                    } else {
                        tracing::warn!(
                            "Client code challenge failed {} != {}",
                            encoded_verifier,
                            auth_request.code_challenge
                        );
                    }
                } else {
                    tracing::warn!("Could not find auth request in Database");
                }
            } else {
                tracing::warn!("could not get username from token");
            }
        } else {
            tracing::warn!("Could not get authrequest id from token");
        }
    } else {
        tracing::warn!("realm not found");
    }
    Err(OAuthError::UnauthorizedClient)
}
