use oxiblog::*;
use std::sync::Once;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static INIT_LOGGING: Once = Once::new();
const LOCALTESTADDR: &str = "http://localhost:3012";

fn init_logging() {
    INIT_LOGGING.call_once(|| {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    // axum logs rejections from built-in extractors with the `axum::rejection`
                    // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                    "oxiblog=trace,auth_flow=trace,tower_http=trace,axum::rejection=trace".into()
                }),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();
    });
}

async fn spawn_server() -> Result<()> {
    init_logging();
    let cfg = load_config(None)?;
    tokio::spawn(async move {
        match listen(cfg).await {
            Ok(_) => {}
            Err(_) => {
                tracing::debug!("Testserver already started ignoring error");
            }
        }
    });

    Ok(())
}

#[tokio::test]
async fn test_new_blog() -> Result<()> {
    spawn_server().await?;
    let blog_data = CreateBlogRequest {
        name: String::from("SimpleCreateBlog"),
        domain: String::from("test.blog.org"),
    };
    let resp = reqwest::Client::new()
        .post(LOCALTESTADDR)
        .bearer_auth("the faked token")
        .json(&blog_data)
        .send()
        .await?;

    assert!(resp.status().is_success());

    let resp = reqwest::Client::new()
        .delete("http://localhost:5984/simplecreateblog")
        .basic_auth("dev", Some("dev"))
        .send()
        .await?;
    assert!(resp.status().is_success());
    Ok(())
}