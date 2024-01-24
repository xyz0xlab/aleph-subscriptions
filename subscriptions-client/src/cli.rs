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
    GenerateSetup {
        /// Path to file where serialized trusted setup (ZKP requirement) is stored
        #[arg(short='p', long, default_value="setup.dat", value_parser = parsing::parse_path)]
        path: PathBuf,
    },

    GenerateProof {
        /// Path to file with serialized trusted setup
        #[arg(short='s', long, default_value="setup.dat", value_parser = parsing::parse_path)]
        setup_path: PathBuf,

        /// Path to file where ZKP proof is stored
        #[arg(short='p', long, default_value="proof.dat", value_parser = parsing::parse_path)]
        proof_path: PathBuf,

        /// Seed of an account for which ZKP proof is generated
        #[arg(long, value_name = "Seed of an account for which proof is generated")]
        seed: String,

        /// Age of a person associated with account for which ZKP proof is generated
        #[arg(long, value_name = "unsigned integer")]
        age: u64,
    },

    RegisterVK {
        /// Path to file with serialized trusted setup (ZKP requirement)
        #[arg(short='s', long, default_value="setup.dat", value_parser = parsing::parse_path)]
        setup_path: PathBuf,

        /// Webservice endpoint address of the Aleph Zero node
        #[arg(short = 'n', long, default_value = "ws://localhost:9944")]
        node_address: String,

        /// Seed of an account that submits and pays for verification key registration on aleph
        /// chain
        #[arg(long, value_name = "Seed of an account registering verification key")]
        seed: String,
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
