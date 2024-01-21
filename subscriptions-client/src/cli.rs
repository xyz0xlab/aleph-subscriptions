use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Utilities to interact with Aleph Zero chain, especially:
/// subscriptions smart contract
/// zero knowledge proofs required to be verified by the subscriptions smart contract
#[derive(Parser, Debug)]
pub struct Cli {
    #[clap(
        short = 'l',
        long,
        default_value = "info",
        value_name = "error|warn|info|debug|trace"
    )]
    pub log_level: String,

    #[clap(subcommand)]
    pub commands: Commands,
}

/// Commands that interacts with zero knowledge proofs
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Commands {
    SetupProof {
        #[arg(short='p', long, default_value="setup.dat", value_parser = parsing::parse_path)]
        path: PathBuf,
    },
}

mod parsing {
    use std::{path::PathBuf, str::FromStr};

    use anyhow::{Context, Result};

    pub(super) fn parse_path(path: &str) -> Result<PathBuf> {
        let path = shellexpand::full(path).context("failed to exapand path")?;
        PathBuf::from_str(&path).context("failed to parse path ")
    }
}
