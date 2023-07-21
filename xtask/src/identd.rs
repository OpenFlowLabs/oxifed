use ::identd::*;

pub async fn run_test_server(cfg: ServerConfig) -> miette::Result<()> {
    let server = ServerState::new(&cfg).await?;

    identd::listen(server).await?;

    Ok(())
}
