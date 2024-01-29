use aleph_client::Connection;
use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use env_logger::Env;
use min_age_proof_ops::MinAgeProofOps;
use subscription_contract_ops::SubscriptionContractOps;

mod cli;
mod min_age_proof_ops;
mod subscription_contract_ops;

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
            let vk_hash = proof_ops.register_vk(aleph_conn, &seed).await?;
            log::info!(
                "Verification key registered on aleph chain with hash: {}",
                vk_hash
            );
        }
        Commands::AddSubscription {
            node_address,
            contract_account,
            contract_metadata,
            proof_path,
            seed,
            payment_interval,
            intervals,
            external_channel_handle,
        } => {
            let proof_ops = MinAgeProofOps::<18>::new();
            let proof = proof_ops.load_proof(&proof_path).await?;
            let contract_ops =
                SubscriptionContractOps::new(contract_account, &node_address, &contract_metadata)?;
            log::info!("Calling subscription smart contract");
            contract_ops
                .add_subscription(
                    &seed,
                    &payment_interval,
                    intervals,
                    &external_channel_handle,
                    proof,
                )
                .await?;
        }
    }

    Ok(())
}
