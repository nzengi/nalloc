//! Halo2 ZK-Proof Integration Test
//!
//! This test validates that nalloc works correctly with real-world
//! Zero-Knowledge proof workloads using the Halo2 proving system.
//!
//! We use a simple "addition" circuit that proves a + b = c.

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;
use zk_nalloc::NAlloc;

/// Simple addition circuit config
#[derive(Debug, Clone)]
struct AddConfig {
    advice: [Column<Advice>; 2],
    instance: Column<Instance>,
    selector: Selector,
}

/// Simple chip that proves a + b = c
struct AddChip<F: PrimeField> {
    config: AddConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> AddChip<F> {
    fn construct(config: AddConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> AddConfig {
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let selector = meta.selector();

        meta.enable_equality(instance);
        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s = meta.query_selector(selector);

            vec![s * (lhs + rhs - out)]
        });

        AddConfig {
            advice,
            instance,
            selector,
        }
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        a: F,
        b: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "add",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                region.assign_advice(|| "a", self.config.advice[0], 0, || Value::known(a))?;
                region.assign_advice(|| "b", self.config.advice[1], 0, || Value::known(b))?;

                let c = a + b;
                let c_cell =
                    region.assign_advice(|| "c", self.config.advice[0], 1, || Value::known(c))?;

                Ok(c_cell)
            },
        )
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}

/// Simple circuit that proves a + b = c
#[derive(Default, Clone)]
struct AddCircuit<F: PrimeField> {
    pub a: F,
    pub b: F,
}

impl<F: PrimeField> Circuit<F> for AddCircuit<F> {
    type Config = AddConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        AddChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = AddChip::construct(config);
        let c_cell = chip.assign(layouter.namespace(|| "add"), self.a, self.b)?;
        chip.expose_public(layouter.namespace(|| "expose c"), &c_cell, 0)?;
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_simple_addition_circuit() {
    // Prove: 3 + 5 = 8
    let a = Fp::from(3u64);
    let b = Fp::from(5u64);
    let c = Fp::from(8u64);

    let circuit = AddCircuit { a, b };

    let k = 4;
    let prover = MockProver::run(k, &circuit, vec![vec![c]]).expect("prover failed");
    prover.verify().expect("verification failed");

    println!("✅ Addition circuit verified: 3 + 5 = 8");
}

#[test]
fn test_nalloc_with_zk_proof() {
    // Create nalloc instance
    let alloc = NAlloc::new();

    // Allocate witness memory
    let witness = alloc.witness();
    let witness_ptr = witness.alloc(1024, 64);
    assert!(!witness_ptr.is_null());
    println!("✅ Allocated 1KB witness memory");

    // Write secret data
    unsafe {
        std::ptr::write_bytes(witness_ptr, 0xAB, 1024);
    }

    // Run ZK proof
    let a = Fp::from(100u64);
    let b = Fp::from(200u64);
    let c = Fp::from(300u64);

    let circuit = AddCircuit { a, b };
    let prover = MockProver::run(4, &circuit, vec![vec![c]]).expect("prover failed");
    prover.verify().expect("verification failed");
    println!("✅ ZK proof verified: 100 + 200 = 300");

    // Secure wipe
    unsafe {
        witness.secure_wipe();
    }

    // Verify wiped
    unsafe {
        for i in 0..1024 {
            assert_eq!(*witness_ptr.add(i), 0);
        }
    }
    println!("✅ Witness data securely wiped");

    let stats = alloc.stats();
    println!("   Memory used: {} bytes", stats.total_used());
}

#[test]
fn test_polynomial_arena_with_zk() {
    let alloc = NAlloc::new();
    let poly = alloc.polynomial();

    // Allocate FFT buffers
    for _ in 0..10 {
        let ptr = poly.alloc_fft_friendly(8192);
        assert!(!ptr.is_null());
        assert_eq!((ptr as usize) % 64, 0);
    }
    println!("✅ Allocated 10 FFT-aligned buffers");

    // Run proof with allocations active
    let a = Fp::from(42u64);
    let b = Fp::from(58u64);
    let c = Fp::from(100u64);

    let circuit = AddCircuit { a, b };
    let prover = MockProver::run(4, &circuit, vec![vec![c]]).expect("prover failed");
    prover.verify().expect("verification failed");
    println!("✅ ZK proof verified with polynomial arena active");
}

#[test]
fn test_multiple_proofs() {
    let alloc = NAlloc::new();

    for i in 1..=5 {
        let a = Fp::from(i as u64);
        let b = Fp::from((i * 10) as u64);
        let c = a + b;

        let circuit = AddCircuit { a, b };
        let prover = MockProver::run(4, &circuit, vec![vec![c]]).expect("prover failed");
        prover.verify().expect("verification failed");

        println!("✅ Proof {} verified: {} + {} = {:?}", i, i, i * 10, c);
    }

    let stats = alloc.stats();
    println!("   Final memory: {} bytes", stats.total_used());
}
