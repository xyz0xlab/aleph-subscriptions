use std::marker::PhantomData;

use anyhow::{Context, Result};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
};

/// Represents all attributes required to generate and serialize zero knowledge proof
#[derive(Debug, Clone)]
pub struct Setup<C: Circuit<Fp> + Default> {
    /// Maximum polynomial degree
    pub k: u32,
    /// Proving key which allows for the creation of proofs for a given circuit
    pub pk: ProvingKey<G1Affine>,
    /// Verifying key which allows for verification of proofs for a given circuit
    pub vk: VerifyingKey<G1Affine>,
    /// Trusted setup - public parameters for the polynomial commitment schema
    pub params: ParamsKZG<Bn256>,
    /// Marker for Circuit type used to parametrize this setup
    _marker: PhantomData<C>,
}

impl<C: Circuit<Fp> + Default> Setup<C> {
    /// Generate initial setup and
    /// params:
    /// * k - maximum polynomial degree
    pub fn generate(k: u32) -> Result<Self> {
        let circuit = C::default();
        let params = ParamsKZG::<Bn256>::setup(k, ParamsKZG::<Bn256>::mock_rng());
        //let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        let vk = keygen_vk(&params, &circuit).context("vk generation failed")?;
        let pk = keygen_pk(&params, vk.clone(), &circuit).context("pk generation failed")?;
        Ok(Self {
            k,
            pk,
            vk,
            params,
            _marker: PhantomData,
        })
    }
}

/// Represents on-chain account for which proof is generated
pub type Account = [u8; 32];

pub mod age_proof {
    use halo2_proofs::{
        circuit::Value,
        halo2curves::ff::PrimeField,
        plonk::create_proof,
        poly::kzg::multiopen::ProverGWC,
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    };
    use rand::rngs::OsRng;

    use super::*;
    use crate::circuits::in_range1::InRangeCircuit;

    const RANGE_TO: usize = 120;

    #[derive(Debug, Clone)]
    pub struct MinAgeProof<const RANGE_FROM: usize> {}

    impl<const RANGE_FROM: usize> MinAgeProof<RANGE_FROM> {
        pub fn new() -> Self {
            Self {}
        }

        pub fn generate(
            &self,
            setup: &Setup<InRangeCircuit<Fp, RANGE_FROM, RANGE_TO>>,
            age: u64,
            for_account: Account,
        ) -> Result<Vec<u8>> {
            let circuit = InRangeCircuit::<Fp, RANGE_FROM, RANGE_TO> {
                value: Value::known(Fp::from(age)),
            };
            let instances = self.public_input(for_account);

            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof::<_, ProverGWC<'_, Bn256>, _, _, _, _>(
                &setup.params,
                &setup.pk,
                &[circuit],
                &[&[&instances]],
                OsRng,
                &mut transcript,
            )?;
            Ok(transcript.finalize())
        }

        pub fn public_input(&self, account: Account) -> [Fp; 3] {
            [
                Fp::from_u128(RANGE_FROM as u128),
                Fp::from_u128(u128::from_le_bytes(account[..16].try_into().unwrap())),
                Fp::from_u128(u128::from_le_bytes(account[16..].try_into().unwrap())),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use std::usize;

    use halo2_proofs::{
        plonk::verify_proof,
        poly::kzg::{multiopen::VerifierGWC, strategy::SingleStrategy},
        transcript::{Blake2bRead, TranscriptReadBuffer},
    };

    use self::age_proof::MinAgeProof;
    use super::*;

    struct TestAgeSetup {
        proof: Vec<u8>,
        instances: [Fp; 3],
        vk: VerifyingKey<G1Affine>,
        params: ParamsKZG<Bn256>,
    }

    const CIRCUIT_MAX_K: u32 = 4;
    const REQUIRED_AGE_18: usize = 18;
    const REQUIRED_AGE_21: usize = 21;
    const ACCOUNT: [u8; 32] = [1u8; 32];
    const INVALID_ACCOUNT: [u8; 32] = [2u8; 32];

    fn generate_proof<const REQUIRED_AGE: usize>(
        age: u64,
        for_account: Account,
    ) -> Result<TestAgeSetup> {
        // generate trusted setup
        let setup = Setup::generate(CIRCUIT_MAX_K)?;
        let min_age_proof = age_proof::MinAgeProof::<REQUIRED_AGE>::new();
        let proof = min_age_proof.generate(&setup, age, for_account)?;

        Ok(TestAgeSetup {
            proof,
            instances: min_age_proof.public_input(for_account),
            vk: setup.vk,
            params: setup.params,
        })
    }

    fn validate(setup: TestAgeSetup) -> Result<()> {
        verify_proof::<_, VerifierGWC<_>, _, _, _>(
            &setup.params,
            &setup.vk,
            SingleStrategy::new(&setup.params),
            &[&[&setup.instances]],
            &mut Blake2bRead::init(&setup.proof[..]),
        )
        .map_err(anyhow::Error::msg)
    }

    #[test]
    fn test_valid_proof() {
        assert!(validate(generate_proof::<REQUIRED_AGE_18>(19, ACCOUNT).unwrap()).is_ok());
    }

    #[test]
    fn test_invalid_proof() {
        assert!(validate(generate_proof::<REQUIRED_AGE_18>(6, ACCOUNT).unwrap()).is_err());
    }

    #[test]
    fn test_invalid_account() {
        let valid_setup = generate_proof::<REQUIRED_AGE_18>(21, ACCOUNT).unwrap();
        let invalid_setup = TestAgeSetup {
            instances: MinAgeProof::<REQUIRED_AGE_18>::new().public_input(INVALID_ACCOUNT),
            ..valid_setup
        };
        assert!(validate(invalid_setup).is_err());
    }

    #[test]
    fn test_invalid_public_params() {
        let valid_setup = generate_proof::<REQUIRED_AGE_18>(21, ACCOUNT).unwrap();
        let invalid_setup = TestAgeSetup {
            instances: MinAgeProof::<REQUIRED_AGE_21>::new().public_input(ACCOUNT),
            ..valid_setup
        };
        assert!(validate(invalid_setup).is_err());
    }

    #[test]
    fn test_replaced_proof() {
        let valid_setup = generate_proof::<REQUIRED_AGE_18>(21, ACCOUNT).unwrap();
        let another_setup = generate_proof::<REQUIRED_AGE_21>(32, ACCOUNT).unwrap();
        let invalid_setup = TestAgeSetup {
            proof: another_setup.proof,
            ..valid_setup
        };
        assert!(validate(invalid_setup).is_err());
    }
}
