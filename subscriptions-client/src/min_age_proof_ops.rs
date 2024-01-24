use std::path::Path;

use aleph_client::{pallets::vk_storage::VkStorageUserApi, Connection, SignedConnection};
use anyhow::{bail, Context, Result};
use subscription_proofs::proofs::{MinAgeProof, Setup};

/// Provides commands to generate trusted setup and min age zero knowledge proof
/// params:
/// * REQUIRED_AGE - minimum age to be proven by the zero knowledge proof
#[derive(Debug, Clone)]
pub struct MinAgeProofOps<const REQUIRED_AGE: usize> {
    /// Trusted setup
    setup: Option<Setup>,
}

impl<const REQUIRED_AGE: usize> MinAgeProofOps<REQUIRED_AGE> {
    /// Creates an instance of minimum age zero knowledge proof operations
    pub fn new() -> Self {
        assert!(REQUIRED_AGE > 0);
        Self { setup: None }
    }

    /// Generates trusted setup with max circuit polynomial degree (k) and stores its serialized
    /// binary version in a file define by `path`
    /// params:
    /// * path - file path of where serialized binary setup is stored
    pub async fn generate_setup(&mut self, path: &Path) -> Result<()> {
        let setup = MinAgeProof::<REQUIRED_AGE>::generate_setup()?;
        let bs = setup.to_bytes()?;
        self.setup = Some(setup);
        std::fs::write(path, bs).context("failed to write ZKP setup to file")
    }

    /// Loads trusted setup stored under a given path.
    /// params:
    /// * path - path where trusted setup has been serialized
    /// returns:
    /// * Deserialized trusted setup
    pub async fn load_setup(&mut self, path: &Path) -> Result<()> {
        self.setup = None;
        let bs = std::fs::read(path).context("failed to read ZKP setup from file")?;
        self.setup = Some(MinAgeProof::<REQUIRED_AGE>::load_setup(bs)?);
        Ok(())
    }

    /// Generates zero knowlege proof for an account defined by a given seed
    /// params:
    /// * path - path where generated proof must be stored
    /// * seed - seed of account for which proof is generated
    /// * age - age of an owner of the account for which proof is generated
    pub async fn generate_proof(&self, path: &Path, seed: &str, age: u64) -> Result<()> {
        let keypair = aleph_client::keypair_from_string(seed);
        let account_id = keypair.account_id();

        let proof = MinAgeProof::<REQUIRED_AGE>::new();
        match &self.setup {
            Some(setup) => {
                let bs = proof.generate_proof(setup, age, account_id.as_ref())?;
                std::fs::write(path, bs).context("failed to write ZKP proof to file")?;
            }
            None => {
                bail!("Missing trusted setup");
            }
        }
        Ok(())
    }

    /// Registers a verification key in the aleph network's `VkStorage` pallet.
    /// Pallet is used for storing a map of verification key hash to verification key
    /// The register is charged for the storage.
    /// params:
    /// * conn - a connection to the aleph zero network
    /// * seed - a seed of a caller that signs aleph network transaction
    pub async fn register_vk(&self, conn: Connection, seed: &str) -> Result<()> {
        let keypair = aleph_client::keypair_from_string(seed);
        let signed_conn = SignedConnection::from_connection(conn, keypair);

        match &self.setup {
            Some(setup) => {
                let vk_bs = setup.vk_to_bytes();
                let tx_info = signed_conn
                    .store_key(vk_bs, aleph_client::TxStatus::Finalized)
                    .await
                    .context("failed to register verification key on aleph chain")?;
                log::debug!("Verification key registration tx info: {:?}", tx_info);
            }
            None => {
                bail!("Missing trusted setup");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use filepath::FilePath;

    use super::MinAgeProofOps;

    #[tokio::test]
    async fn test_setup_write_load() {
        let tmp_file = tempfile::tempfile().unwrap();
        let path = tmp_file.path().unwrap();

        let mut ops = MinAgeProofOps::<18>::new();

        assert!(ops.generate_setup(&path).await.is_ok());
        assert!(ops.load_setup(&path).await.is_ok());
    }

    #[tokio::test]
    async fn test_failed_load_setup() {
        let tmp_file = tempfile::tempfile().unwrap();
        let path = tmp_file.path().unwrap();

        let mut ops = MinAgeProofOps::<18>::new();

        assert!(ops.load_setup(&path).await.is_err());
    }

    #[test]
    #[should_panic]
    fn test_failed_generate_setup() {
        MinAgeProofOps::<0>::new();
    }

    #[tokio::test]
    async fn test_generate_proof() {
        let tmp_file_setup = tempfile::tempfile().unwrap();
        let path_setup = tmp_file_setup.path().unwrap();
        let tmp_file_proof = tempfile::tempfile().unwrap();
        let path_proof = tmp_file_proof.path().unwrap();

        let mut ops = MinAgeProofOps::<18>::new();

        assert!(ops.generate_setup(&path_setup).await.is_ok());
        assert!(ops.generate_proof(&path_proof, "//Alice", 23).await.is_ok());

        let proof = std::fs::read(path_proof).unwrap();
        assert!(proof.len() > 0);
    }
}
