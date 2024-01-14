use halo2_proofs::{
    arithmetic::Field,
    circuit::{SimpleFloorPlanner, Value},
    plonk::Circuit,
};

use crate::chips::in_range1::{InRangeChip, InRangeConfig};

/// Circuit for proving if value is between RANGE_FROM (inclusive) and RANGE_TO (exclusive)
#[derive(Default)]
pub struct InRangeCircuit<F: Field + From<u64>, const RANGE_FROM: usize, const RANGE_TO: usize> {
    value: Value<F>,
}

impl<F: Field + From<u64>, const RANGE_FROM: usize, const RANGE_TO: usize> Circuit<F>
    for InRangeCircuit<F, RANGE_FROM, RANGE_TO>
{
    type Config = InRangeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let value = meta.advice_column();
        InRangeChip::<F, RANGE_FROM, RANGE_TO>::configure(meta, value)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let chip = InRangeChip::<F, RANGE_FROM, RANGE_TO>::construct(config);
        chip.assign(layouter.namespace(|| "assign value"), self.value)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};

    use super::InRangeCircuit;

    #[test]
    fn test_in_range() {
        let k = 4;

        for i in 18..119 {
            let circuit = InRangeCircuit::<Fp, 18, 120> {
                value: Value::known(Fp::from(i as u64)),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_ok());
        }
    }

    #[test]
    fn test_out_of_range() {
        let k = 4;

        for i in 1..17 {
            let circuit = InRangeCircuit::<Fp, 18, 120> {
                value: Value::known(Fp::from(i as u64)),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }
    }
}
