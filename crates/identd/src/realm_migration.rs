use sea_orm::sea_query::ColumnDef;
use sea_orm_migration::prelude::*;

pub struct RealmMigrator;

#[async_trait::async_trait]
impl MigratorTrait for RealmMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(DBInitializer)]
    }
}

#[derive(DeriveMigrationName)]
pub struct DBInitializer;

#[async_trait::async_trait]
impl MigrationTrait for DBInitializer {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Realm::Table)
                    .col(
                        ColumnDef::new(Realm::Name)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Realm::Domain).string().null())
                    .col(ColumnDef::new(Realm::BiscuitPrivateKey).string().not_null())
                    .col(ColumnDef::new(Realm::BiscuitPublicKey).string().not_null())
                    .col(ColumnDef::new(Realm::ProviderMetadata).json().not_null())
                    .col(ColumnDef::new(Realm::Jwks).json().not_null())
                    .col(ColumnDef::new(Realm::IssuerUrl).string().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Client::Table)
                    .col(ColumnDef::new(Client::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Client::Secret).string().null())
                    .col(ColumnDef::new(Client::RealmId).string().not_null())
                    .col(ColumnDef::new(Client::RedirectUri).string().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_realm")
                            .from(Client::Table, Client::RealmId)
                            .to(Realm::Table, Realm::Name),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AuthRequest::Table)
                    .col(
                        ColumnDef::new(AuthRequest::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AuthRequest::Code).string().null())
                    .col(
                        ColumnDef::new(AuthRequest::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuthRequest::State).string().not_null())
                    .col(
                        ColumnDef::new(AuthRequest::CodeChallenge)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuthRequest::Scope).string().not_null())
                    .col(ColumnDef::new(AuthRequest::Nonce).string().not_null())
                    .col(ColumnDef::new(AuthRequest::ClientId).string().not_null())
                    .col(ColumnDef::new(AuthRequest::RedirectUri).string().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_request_client")
                            .from(AuthRequest::Table, AuthRequest::ClientId)
                            .to(Client::Table, Client::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuthRequest::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Client::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Realm::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum Client {
    Table,
    Id,
    Secret,
    RedirectUri,
    RealmId,
}

#[derive(Iden)]
enum Realm {
    Table,
    Name,
    Domain,
    BiscuitPrivateKey,
    BiscuitPublicKey,
    IssuerUrl,
    ProviderMetadata,
    Jwks,
}

#[derive(Iden)]
enum AuthRequest {
    Table,
    Id,
    Code,
    CreatedAt,
    RedirectUri,
    Scope,
    State,
    CodeChallenge,
    Nonce,
    ClientId,
}
