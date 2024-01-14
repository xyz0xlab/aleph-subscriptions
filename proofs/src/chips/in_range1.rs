use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};

/// A gadget that checks that the value witnessed is in a given range
/// given
///     value v
///     [from..to)
/// to check
///     (from-v)(from+1-v)..(to-1-v)

/// Represents configuration file for `in_range` chip.
#[derive(Debug, Clone)]
pub struct InRangeConfig<F: Field> {
    selector: Selector,
    value: Column<Advice>,
    _marker: PhantomData<F>,
}

/// Configures zero knowledge proof gates and allows for assignment of all witnessed values
/// (advices)
/// This chip configurates all gates to check if witness in between RANGE_FROM (inclusive) and RANGE_TO (exclusive).
pub struct InRangeChip<F: Field + From<u64>, const RANGE_FROM: usize, const RANGE_TO: usize> {
    config: InRangeConfig<F>,
}

impl<F: Field + From<u64>, const RANGE_FROM: usize, const RANGE_TO: usize>
    InRangeChip<F, RANGE_FROM, RANGE_TO>
{
    /// Creates new instance of the in range chip
    pub fn construct(config: InRangeConfig<F>) -> Self {
        Self { config }
    }

    /// Configures gates that checks if a given witnessed value is in the [RANGE_FROM..RANGE_TO)
    pub fn configure(meta: &mut ConstraintSystem<F>, value: Column<Advice>) -> InRangeConfig<F> {
        let selector = meta.selector();

        meta.create_gate("in range", |meta| {
            let s = meta.query_selector(selector);
            let v = meta.query_advice(value, Rotation::cur());

            let in_range_exp = |range_from: usize, range_to: usize, v: Expression<F>| {
                (range_from..range_to).fold(Expression::Constant(F::ONE), |expr, i| {
                    expr * (Expression::Constant(F::from(i as u64)) - v.clone())
                })
            };

            Constraints::with_selector(s, [("in range", in_range_exp(RANGE_FROM, RANGE_TO, v))])
        });

        InRangeConfig {
            selector,
            value,
            _marker: PhantomData,
        }
    }

    /// Assigns witnessed value using the layouter
    pub fn assign(&self, mut layouter: impl Layouter<F>, value: Value<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "assign value",
            |mut region| {
                // enable range check
                self.config.selector.enable(&mut region, 0)?;
                // assign value
                region.assign_advice(|| "assign value", self.config.value, 0, || value)?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::{FailureLocation, MockProver, VerifyFailure},
        pasta::Fp,
        plonk::{Any, Circuit},
    };

    use super::*;

    #[derive(Default)]
    struct TestCircuit<F: Field, const RANGE_FROM: usize, const RANGE_TO: usize> {
        value: Value<F>,
    }

    impl<F: Field + From<u64>, const RANGE_FROM: usize, const RANGE_TO: usize> Circuit<F>
        for TestCircuit<F, RANGE_FROM, RANGE_TO>
    {
        type Config = InRangeConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let value = meta.advice_column();
            InRangeChip::<F, RANGE_FROM, RANGE_TO>::configure(meta, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = InRangeChip::<F, RANGE_FROM, RANGE_TO>::construct(config);
            chip.assign(layouter.namespace(|| "assign value"), self.value)?;
            Ok(())
        }
    }

    #[test]
    fn test_in_range() {
        let k = 4;
        for i in 18..119 {
            // given circuit and value in range
            let circuit = TestCircuit::<Fp, 18, 120> {
                value: Value::known(Fp::from(i as u64)),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_ok());
        }
    }

    #[test]
    fn test_out_of_range() {
        let k = 4;
        for i in 2..17 {
            // given circuit and value out of range
            let circuit = TestCircuit::<Fp, 18, 120> {
                value: Value::known(Fp::from(i as u64)),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((0, "in range").into(), 0, "in range").into(),
                    location: FailureLocation::InRegion {
                        region: (0, "assign value").into(),
                        offset: 0
                    },
                    cell_values: vec![(
                        ((Any::Advice, 0).into(), 0).into(),
                        format!("{:#x}", i).to_string()
                    )]
                }])
            );
        }
    }
}
