use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use env_logger::Env;
use min_age_proof_ops::MinAgeProofOps;

mod cli;
mod min_age_proof_ops;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::from_env(Env::default().default_filter_or(&cli.log_level)).init();

    log::info!("{:?}", cli);

    match cli.commands {
        Commands::SetupProof { path } => {
            let proof_ops = MinAgeProofOps::<18>::new();
            proof_ops.generate_setup(&path)?;
            log::info!("Setup generated to: {:?}", path);
        }
    }

    Ok(())
}
