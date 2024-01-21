use anyhow::{Context, Result};
use halo2_proofs::{
    circuit::Value,
    halo2curves::{
        bn256::{Bn256, Fr as Fp, G1Affine},
        ff::PrimeField,
    },
    plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::Params,
        kzg::{commitment::ParamsKZG, multiopen::ProverGWC},
    },
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use rand::rngs::OsRng;

use crate::circuits::in_range::InRangeCircuit;

/// Represents on-chain account for which proof is generated
pub type Account = [u8; 32];

/// Represents all attributes required to generate and serialize zero knowledge proof
#[derive(Debug, Clone)]
pub struct Setup {
    /// Maximum polynomial degree
    pub k: u32,
    /// Proving key which allows for the creation of proofs for a given circuit
    pub pk: ProvingKey<G1Affine>,
    /// Verifying key which allows for verification of proofs for a given circuit
    pub vk: VerifyingKey<G1Affine>,
    /// Trusted setup - public parameters for the polynomial commitment schema
    pub params: ParamsKZG<Bn256>,
}

impl Setup {
    /// Generate initial setup and
    /// params:
    /// * k - maximum polynomial degree
    pub fn generate<C: Circuit<Fp> + Default + Clone>(k: u32) -> Result<Self> {
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
            // _marker: PhantomData,
        })
    }

    /// Serializes ZKP params and prooving key to array of bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![];
        self.params
            .write_custom(&mut buffer, halo2_proofs::SerdeFormat::RawBytesUnchecked)
            .context("failed to serialize ZKP params")?;
        buffer.extend(
            self.pk
                .to_bytes(halo2_proofs::SerdeFormat::RawBytesUnchecked),
        );
        Ok(buffer)
    }

    /// Serializes verification key together with polynomial degree
    /// returns:
    /// * array of bytes including serialized polynomial degree (k) and verification key (vk)
    pub fn vk_to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.extend(self.k.to_le_bytes());
        buffer.extend(
            self.vk
                .to_bytes(halo2_proofs::SerdeFormat::RawBytesUnchecked),
        );
        buffer
    }

    /// Restores ZKP setup from array of bytes.
    /// params:
    /// * buffer - serialized ZKP setup
    /// returns:
    /// * Deserialized ZKP setup or error
    pub fn from_bytes<C: Circuit<Fp> + Default + Clone>(buffer: &mut &[u8]) -> Result<Self> {
        let params =
            ParamsKZG::<Bn256>::read_custom(buffer, halo2_proofs::SerdeFormat::RawBytesUnchecked)
                .context("failed to read ZKP params")?;
        let pk = ProvingKey::<G1Affine>::from_bytes::<C>(
            buffer,
            halo2_proofs::SerdeFormat::RawBytesUnchecked,
        )
        .context("failed to read proving key")?;
        Ok(Self {
            k: params.k(),
            vk: pk.get_vk().clone(),
            pk,
            params,
            // _marker: PhantomData,
        })
    }
}

const RANGE_TO: usize = 120;
const CIRCUIT_MAX_K: u32 = 4;

#[derive(Debug, Clone)]
pub struct MinAgeProof<const RANGE_FROM: usize> {}

impl<const RANGE_FROM: usize> MinAgeProof<RANGE_FROM> {
    pub fn new() -> Self {
        Self {}
    }

    /// Generates trusted setup for minimum age zero knowledge proof
    pub fn generate_setup() -> Result<Setup> {
        Setup::generate::<InRangeCircuit<Fp, RANGE_FROM, RANGE_TO>>(CIRCUIT_MAX_K)
    }

    /// Deserializes vector of bytes to the zero knowledge proof setup
    /// params:
    /// * buffer - serialized to byte array zero knowledge proof setup
    /// returns:
    /// * trusted setup for minimum age zero knowlege proof
    pub fn load_setup(buffer: Vec<u8>) -> Result<Setup> {
        Setup::from_bytes::<InRangeCircuit<Fp, RANGE_FROM, RANGE_TO>>(&mut buffer.as_slice())
    }

    /// Generates zero knowledge proof that proofs age to be greater than RANGE_FROM
    /// params:
    /// * setup - trusted setup which can be generated using `generate_setup()` function
    /// * age - age that is a witness
    /// * for_account - account address for which proof of age being greater than RANGE_FROM is
    /// generated
    pub fn generate_proof(&self, setup: &Setup, age: u64, for_account: Account) -> Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        plonk::verify_proof,
        poly::kzg::{multiopen::VerifierGWC, strategy::SingleStrategy},
        transcript::{Blake2bRead, TranscriptReadBuffer},
    };

    use super::*;

    struct TestMinAgeSetup {
        proof: Vec<u8>,
        instances: [Fp; 3],
        vk: VerifyingKey<G1Affine>,
        params: ParamsKZG<Bn256>,
    }

    const REQUIRED_AGE_18: usize = 18;
    const REQUIRED_AGE_21: usize = 21;
    const ACCOUNT: [u8; 32] = [1u8; 32];
    const INVALID_ACCOUNT: [u8; 32] = [2u8; 32];

    fn generate_proof<const REQUIRED_AGE: usize>(
        age: u64,
        for_account: Account,
    ) -> Result<TestMinAgeSetup> {
        // generate trusted setup
        let setup = MinAgeProof::<REQUIRED_AGE>::generate_setup()?;
        let min_age_proof = MinAgeProof::<REQUIRED_AGE>::new();
        let proof = min_age_proof.generate_proof(&setup, age, for_account)?;

        Ok(TestMinAgeSetup {
            proof,
            instances: min_age_proof.public_input(for_account),
            vk: setup.vk,
            params: setup.params,
        })
    }

    fn validate(setup: TestMinAgeSetup) -> Result<()> {
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
        let invalid_setup = TestMinAgeSetup {
            instances: MinAgeProof::<REQUIRED_AGE_18>::new().public_input(INVALID_ACCOUNT),
            ..valid_setup
        };
        assert!(validate(invalid_setup).is_err());
    }

    #[test]
    fn test_invalid_public_params() {
        let valid_setup = generate_proof::<REQUIRED_AGE_18>(21, ACCOUNT).unwrap();
        let invalid_setup = TestMinAgeSetup {
            instances: MinAgeProof::<REQUIRED_AGE_21>::new().public_input(ACCOUNT),
            ..valid_setup
        };
        assert!(validate(invalid_setup).is_err());
    }

    #[test]
    fn test_replaced_proof() {
        let valid_setup = generate_proof::<REQUIRED_AGE_18>(21, ACCOUNT).unwrap();
        let another_setup = generate_proof::<REQUIRED_AGE_21>(32, ACCOUNT).unwrap();
        let invalid_setup = TestMinAgeSetup {
            proof: another_setup.proof,
            ..valid_setup
        };
        assert!(validate(invalid_setup).is_err());
    }

    #[test]
    fn test_serialization() {
        let setup = Setup::generate::<InRangeCircuit<Fp, 18, 120>>(CIRCUIT_MAX_K).unwrap();
        let bs = setup.clone().to_bytes().unwrap();
        let setup_deserialized =
            Setup::from_bytes::<InRangeCircuit<Fp, 18, 120>>(&mut bs.as_slice()).unwrap();

        assert_eq!(setup.k, setup_deserialized.k);
        assert_eq!(setup.params.s_g2(), setup_deserialized.params.s_g2());
        assert_eq!(
            setup
                .pk
                .to_bytes(halo2_proofs::SerdeFormat::RawBytesUnchecked),
            setup_deserialized
                .pk
                .to_bytes(halo2_proofs::SerdeFormat::RawBytesUnchecked)
        );
    }
}
