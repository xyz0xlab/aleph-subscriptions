use std::path::Path;

use aleph_client::{contract::ContractInstance, AccountId, Connection, SignedConnection};
use anyhow::{Context, Result};

/// Provides commands interactive with subscription smart contract
pub struct SubscriptionContractOps {
    /// A connection to the aleph zero node
    conn: Connection,

    /// A client for the subscription smart contract
    contract: ContractInstance,
}

impl std::fmt::Debug for SubscriptionContractOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0b{:?}", self.contract)
    }
}

impl SubscriptionContractOps {
    /// Creates new instance of the subscription smart contract client
    /// params:
    /// * address - smart contract address
    /// * node_address - aleph network connection address
    /// * metadata_path - a path to smart contract metadata
    /// returns:
    /// * Subscription smart contract operations
    pub fn new(address: AccountId, node_address: &str, metadata_path: &Path) -> Result<Self> {
        let metadata_path = metadata_path
            .to_str()
            .context("contract's metadata not set")?;

        let conn = futures::executor::block_on(aleph_client::Connection::new(node_address));

        Ok(Self {
            contract: ContractInstance::new(address, metadata_path)?,
            conn,
        })
    }

    /// Registers new subscription by calling the subscriptions smart contract.
    /// Zero knowledge proof is required which proofs that a given user is older than the minimum
    /// required age
    /// params:
    /// * conn - a connection to the aleph zero network
    /// * seed - a seed of a caller
    /// * payment_interval - one of WEEK|MONTH
    /// * intervals - number of payment intervals
    /// * external_channel_handle - for example Telegram channel handle
    /// * proof - zero knowledge proof requried to proof that the called is older then minimum
    /// required age
    pub async fn add_subscription(
        &self,
        seed: &str,
        payment_interval: &str,
        intervals: u32,
        external_channel_handle: &str,
        proof: Vec<u8>,
    ) -> Result<()> {
        let keypair = aleph_client::keypair_from_string(seed);
        let signed_conn = SignedConnection::from_connection(self.conn.clone(), keypair);

        let tx_info = self
            .contract
            .contract_exec(
                &signed_conn,
                "add_subscription",
                &[
                    format!("{payment_interval}"),
                    format!("{intervals}"),
                    format!("\"{external_channel_handle}\""),
                    format!("{proof:?}"),
                ],
            )
            .await?;
        log::info!("Add subscription transaction info: {:?}", tx_info);

        Ok(())
    }
}
