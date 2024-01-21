use std::path::Path;

use anyhow::{Context, Result};
use subscription_proofs::proofs::{MinAgeProof, Setup};

/// Provides commands to generate trusted setup and min age zero knowledge proof
/// params:
/// * REQUIRED_AGE - minimum age to be proven by the zero knowledge proof
#[derive(Debug, Clone)]
pub struct MinAgeProofOps<const REQUIRED_AGE: usize> {}

impl<const REQUIRED_AGE: usize> MinAgeProofOps<REQUIRED_AGE> {
    /// Creates an instance of minimum age zero knowledge proof operations
    pub fn new() -> Self {
        assert!(REQUIRED_AGE > 0);
        Self {}
    }

    /// Generates trusted setup with max circuit polynomial degree (k) and stores its serialized
    /// binary version in a file define by `path`
    /// params:
    /// * path - file path of where serialized binary setup is stored
    pub fn generate_setup(&self, path: &Path) -> Result<()> {
        let setup = MinAgeProof::<REQUIRED_AGE>::generate_setup()?;
        let bs = setup.to_bytes()?;
        std::fs::write(path, bs).context("failed to write ZKP setup to file")
    }

    pub fn load_setup(&self, path: &Path) -> Result<Setup> {
        let bs = std::fs::read(path).context("failed to read ZKP setup from file")?;
        MinAgeProof::<REQUIRED_AGE>::load_setup(bs)
    }
}

#[cfg(test)]
mod tests {
    use filepath::FilePath;

    use super::MinAgeProofOps;

    #[test]
    fn test_setup_write_load() {
        let tmp_file = tempfile::tempfile().unwrap();
        let path = tmp_file.path().unwrap();

        let ops = MinAgeProofOps::<18>::new();

        assert!(ops.generate_setup(&path).is_ok());
        assert!(ops.load_setup(&path).is_ok());
    }

    #[test]
    fn test_failed_load_setup() {
        let tmp_file = tempfile::tempfile().unwrap();
        let path = tmp_file.path().unwrap();

        let ops = MinAgeProofOps::<18>::new();

        assert!(ops.load_setup(&path).is_err());
    }

    #[test]
    #[should_panic]
    fn test_failed_generate_setup() {
        MinAgeProofOps::<0>::new();
    }
}
