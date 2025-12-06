use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xaman", version, about = "the orchestrator")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// check env
    Doctor,
    /// version stuff
    Version,
    /// sign things
    Sign,
}
