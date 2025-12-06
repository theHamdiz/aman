use clap::Parser;
use miette::Result;

mod cli;
mod utils;
mod doctor;
mod version;
mod sign;

use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor => doctor::run()?,
        Commands::Version => version::run()?,
        Commands::Sign => sign::run()?,
    }

    Ok(())
}
