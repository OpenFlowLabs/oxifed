use std::{fs::File, io::Read, path::Path};

use clap::{Parser, Subcommand};
use microxdg::XdgApp;
use miette::{IntoDiagnostic, Result};
use oxiblog::{BlogSettings, Content};
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Ctx {
        #[command(subcommand)]
        command: ContextCommands,
    },
    Blog {
        #[arg(short, long)]
        name: String,

        #[command(subcommand)]
        command: BlogCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ContextCommands {
    Add {
        name: String,
        url: String,
        token: String,
    },
    List,
    SetCurrent {
        name: String,
    },
    Delete {
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum BlogCommands {
    Create {
        author: String,
        domain: String,
        info_text: String,
    },
    Post {
        title: String,
        summary: String,
        content: String,
        to: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    current_context: String,
    contexts: Vec<Context>,
}

impl Config {
    pub fn get_current_context(&self) -> Result<Context> {
        for ctx in self.contexts.iter() {
            if ctx.name == self.current_context {
                return Ok(ctx.clone());
            }
        }
        Err(miette::miette!("no current context set please add one"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Context {
    name: String,
    url: String,
    token: String,
}

fn load_config() -> Result<Config> {
    let xdg_app = XdgApp::new("fedi").into_diagnostic()?;
    let config_path = xdg_app.config_file("config.yaml").into_diagnostic()?;
    let config = if config_path.exists() {
        let f = File::open(&config_path).into_diagnostic()?;
        let c: Config = serde_yaml::from_reader(f).into_diagnostic()?;
        c
    } else {
        Config {
            current_context: String::new(),
            contexts: vec![],
        }
    };
    Ok(config)
}

fn save_config(config: Config) -> Result<()> {
    let xdg_app = XdgApp::new("fedi").into_diagnostic()?;
    let config_path = xdg_app.config_file("config.yaml").into_diagnostic()?;
    let mut f = File::create(config_path).into_diagnostic()?;
    serde_yaml::to_writer(&mut f, &config).into_diagnostic()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Commands::Ctx { command } => match command {
            ContextCommands::Add { name, url, token } => {
                let mut config = load_config()?;
                let token_path = Path::new(&token);
                let token = if token_path.exists() {
                    let mut f = File::open(token_path).into_diagnostic()?;
                    let mut tk = String::new();
                    f.read_to_string(&mut tk).into_diagnostic()?;
                    tk.trim().clone().to_owned()
                } else {
                    token.clone()
                };

                config.contexts.push(Context {
                    name: name.clone(),
                    url,
                    token,
                });
                config.current_context = name;
                save_config(config)?;
                Ok(())
            }
            ContextCommands::Delete { name } => {
                let mut config = load_config()?;
                config.contexts = config
                    .contexts
                    .into_iter()
                    .filter(|ctx| ctx.name != name)
                    .collect();
                if config.current_context == name {
                    config.current_context = if let Some(first) = config.contexts.first() {
                        first.name.clone()
                    } else {
                        String::new()
                    };
                }
                save_config(config)?;
                Ok(())
            }
            ContextCommands::List => {
                let config = load_config()?;
                println!("Current Context: {}", config.current_context);
                println!("NAME\tURL");
                for ctx in config.contexts {
                    println!("{}\t{}", ctx.name, ctx.url);
                }
                Ok(())
            }
            ContextCommands::SetCurrent { name } => {
                let mut config = load_config()?;
                let mut found = false;
                for ctx in config.contexts.iter() {
                    if ctx.name == name {
                        found = true;
                    }
                }
                if !found {
                    return Err(miette::miette!("No such context exists"));
                }

                config.current_context = name;
                save_config(config)?;
                Ok(())
            }
        },
        Commands::Blog { name, command } => match command {
            BlogCommands::Create {
                author,
                domain,
                info_text,
            } => {
                let config = load_config()?;
                let req_content = oxiblog::CreateBlogRequest {
                    name: name.clone(),
                    settings: BlogSettings::new(domain, author, info_text),
                };
                let ctx = config.get_current_context()?;
                let url = format!("{}", ctx.url);
                let resp = reqwest::blocking::Client::new()
                    .post(&url)
                    .bearer_auth(ctx.token)
                    .json(&req_content)
                    .send()
                    .into_diagnostic()?;
                if !resp.status().is_success() {
                    Err(miette::miette!(
                        "failed to create blog: {}",
                        resp.text().into_diagnostic()?
                    ))
                } else {
                    Ok(())
                }
            }
            BlogCommands::Post {
                content,
                title,
                summary,
                to,
            } => {
                let config = load_config()?;
                let req_content = oxiblog::UploadBlogRequest {
                    title,
                    summary,
                    content: Content::Embedded(content),
                    to,
                };
                let ctx = config.get_current_context()?;
                let url = format!("{}/{}", ctx.url, name);
                let resp = reqwest::blocking::Client::new()
                    .post(&url)
                    .bearer_auth(ctx.token)
                    .json(&req_content)
                    .send()
                    .into_diagnostic()?;
                if !resp.status().is_success() {
                    Err(miette::miette!(
                        "failed to post blog post: {}",
                        resp.text().into_diagnostic()?
                    ))
                } else {
                    Ok(())
                }
            }
        },
    }
}
