use clap::Parser;
use clap::Subcommand;
use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
enum Error {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

type Result<T> = miette::Result<T, Error>;

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Hello,
}

fn main() -> miette::Result<()> {
    let args = Args::parse();
    match args.command {
        Commands::Hello => hello()?,
    }
    Ok(())
}

fn hello() -> Result<()> {
    println!("There would be help is it had one!!!");
    Ok(())
}
