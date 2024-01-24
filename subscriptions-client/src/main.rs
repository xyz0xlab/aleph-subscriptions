use aleph_client::Connection;
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
        Commands::GenerateSetup { path } => {
            let mut proof_ops = MinAgeProofOps::<18>::new();
            proof_ops.generate_setup(&path).await?;
            log::info!("Trusted setup stored to file: {:?}", path);
        }
        Commands::GenerateProof {
            setup_path,
            proof_path,
            seed,
            age,
        } => {
            let mut proof_ops = MinAgeProofOps::<18>::new();
            proof_ops.load_setup(&setup_path).await?;
            proof_ops.generate_proof(&proof_path, &seed, age).await?;
            log::info!("ZKP stored to file: {:?}", proof_path);
        }
        Commands::RegisterVK {
            setup_path,
            node_address,
            seed,
        } => {
            let mut proof_ops = MinAgeProofOps::<18>::new();
            proof_ops.load_setup(&setup_path).await?;
            let aleph_conn = Connection::new(&node_address).await;
            proof_ops.register_vk(aleph_conn, &seed).await?;
            log::info!("Verification key registered on aleph chain");
        }
    }

    Ok(())
}
