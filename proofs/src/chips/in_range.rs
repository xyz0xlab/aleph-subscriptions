use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

/// A gadget that checks that the value witnessed is in a given range
/// given
///     value v
///     [from..to)
/// to check
///     (from-v)(from+1-v)..(to-1-v)
/// We take 3 public attributes passed as vector if instances which represent:
///     * value 0 (placeholder)
///     * first part of account address, a subject of the proof
///     * second part of account address, a subject of the proof
/// Expression
/// selector_v * (from-v)(from+1-v)..(to-1-v) + selector_i*q_i*i + instance = 0
///     | selector_v | selector_a | v | a          | q_a | instance
///     |          1 |          0 | x | RANGE_FROM | -1  | instance_0 (range from)
///     |          0 |          1 | 0 | instance_1 | -1  | instance_1 (account lower bits)
///     |          0 |          1 | 0 | instance_2 | -1  | instance_2 (account upper bits)

/// Represents configuration file for `in_range` chip.
#[derive(Debug, Clone)]
pub struct InRangeConfig<F: Field> {
    selector_v: Selector,
    value: Column<Advice>,
    a: Column<Advice>,
    q_a: Column<Fixed>,
    instance: Column<Instance>,
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
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        value: Column<Advice>,
        instance: Column<Instance>,
    ) -> InRangeConfig<F> {
        let selector_v = meta.selector();

        let a = meta.advice_column();
        let q_a = meta.fixed_column();

        meta.enable_equality(value);
        meta.enable_equality(a);
        meta.enable_equality(q_a);
        meta.enable_equality(instance);

        meta.create_gate("in range", |meta| {
            let selector_v = meta.query_selector(selector_v);
            let value = meta.query_advice(value, Rotation::cur());

            let a = meta.query_advice(a, Rotation::cur());
            let q_a = meta.query_fixed(q_a, Rotation::cur());
            let instance = meta.query_instance(instance, Rotation::cur());

            let in_range_exp = |range_from: usize, range_to: usize, v: Expression<F>| {
                (range_from..range_to).fold(Expression::Constant(F::ONE), |expr, i| {
                    expr * (Expression::Constant(F::from(i as u64)) - v.clone())
                })
            };

            Constraints::with_selector(
                selector_v,
                [(
                    "in range",
                    in_range_exp(RANGE_FROM, RANGE_TO, value) + q_a * a + instance,
                )],
            )
        });

        InRangeConfig {
            selector_v,
            value,
            a,
            q_a,
            instance,
            _marker: PhantomData,
        }
    }

    /// Assigns witnessed value using the layouter
    pub fn assign(&self, mut layouter: impl Layouter<F>, value: Value<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "assign value",
            |mut region| {
                // enable range check
                self.config.selector_v.enable(&mut region, 0)?;
                // assign value
                region.assign_advice(|| "assign value", self.config.value, 0, || value)?;

                region.assign_advice(
                    || "range from",
                    self.config.a,
                    0,
                    || Value::known(F::from(RANGE_FROM as u64)),
                )?;
                // region.assign_advice_from_instance(
                // || "account low",
                // self.config.instance,
                // 0,
                // self.config.a,
                // 0,
                // )?;
                region.assign_fixed(
                    || "fake instance",
                    self.config.q_a,
                    0,
                    || Value::known(F::ONE.neg()),
                )?;

                self.config.selector_v.enable(&mut region, 1)?;
                region.assign_advice(
                    || "assign value fake",
                    self.config.value,
                    1,
                    || Value::known(F::from(RANGE_FROM as u64)),
                )?;
                // self.config.selector_a.enable(&mut region, 1)?;
                region.assign_advice_from_instance(
                    || "account low",
                    self.config.instance,
                    1,
                    self.config.a,
                    1,
                )?;
                region.assign_fixed(
                    || "account low selector",
                    self.config.q_a,
                    1,
                    || Value::known(F::ONE.neg()),
                )?;

                self.config.selector_v.enable(&mut region, 2)?;
                region.assign_advice(
                    || "assign value fake",
                    self.config.value,
                    2,
                    || Value::known(F::from(RANGE_FROM as u64)),
                )?;
                // self.config.selector_a.enable(&mut region, 2)?;
                region.assign_advice_from_instance(
                    || "account high",
                    self.config.instance,
                    2,
                    self.config.a,
                    2,
                )?;
                region.assign_fixed(
                    || "account high selector",
                    self.config.q_a,
                    2,
                    || Value::known(F::ONE.neg()),
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::{bn256::Fr as Fp, ff::PrimeField},
        plonk::Circuit,
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
            let instance = meta.instance_column();
            InRangeChip::<F, RANGE_FROM, RANGE_TO>::configure(meta, value, instance)
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

    type Account = [u8; 32];

    fn init_public_input(required_range_from: usize, account: Account) -> [Fp; 3] {
        [
            Fp::from_u128(required_range_from as u128),
            Fp::from_u128(u128::from_le_bytes(account[..16].try_into().unwrap())),
            Fp::from_u128(u128::from_le_bytes(account[16..].try_into().unwrap())),
        ]
    }

    #[test]
    fn test_in_range() {
        let k = 4;
        let account = [1u8; 32];
        for i in 18..119 {
            // given circuit and value in range
            let circuit = TestCircuit::<Fp, 18, 120> {
                value: Value::known(Fp::from(i as u64)),
            };

            let instances = init_public_input(18, account).to_vec();
            let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
            assert!(prover.verify().is_ok());
        }
    }

    #[test]
    fn test_out_of_range() {
        let k = 4;
        let account = [1u8; 32];
        for i in 2..17 {
            // given circuit and value out of range
            let circuit = TestCircuit::<Fp, 18, 120> {
                value: Value::known(Fp::from(i as u64)),
            };
            let instances = init_public_input(18, account).to_vec();
            let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
            assert!(prover.verify().is_err());
        }
    }
}
