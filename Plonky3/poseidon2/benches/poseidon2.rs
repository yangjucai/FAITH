use criterion::{criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_bn254_fr::{Bn254Fr, Poseidon2Bn254};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_mersenne_31::{Mersenne31, Poseidon2Mersenne31};
use p3_symmetric::Permutation;
use p3_util::pretty_name;
use rand::rngs::SmallRng;
use rand::SeedableRng;
use std::hint::black_box;

const PERMUTATION_COUNTS: [usize; 1] = [2097152];

fn bench_poseidon2(c: &mut Criterion) {
    let mut rng = SmallRng::seed_from_u64(1);

    let mut group = c.benchmark_group("Poseidon2 Batch Permutations");

    // let poseidon2_bb_16 = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);
    // let name_bb_16 = format!("poseidon2::<{}, 16>", pretty_name::<<BabyBear as Field>::Packing>());
    // // FIX: Add explicit type arguments using the "turbofish" ::<>
    // poseidon2::<BabyBear, _, 16>(&mut group, &name_bb_16, poseidon2_bb_16);

    // let poseidon2_bb_24 = Poseidon2BabyBear::<24>::new_from_rng_128(&mut rng);
    // let name_bb_24 = format!("poseidon2::<{}, 24>", pretty_name::<<BabyBear as Field>::Packing>());
    // poseidon2::<BabyBear, _, 24>(&mut group, &name_bb_24, poseidon2_bb_24);

    // let poseidon2_kb_16 = Poseidon2KoalaBear::<16>::new_from_rng_128(&mut rng);
    // let name_kb_16 = format!("poseidon2::<{}, 16>", pretty_name::<<KoalaBear as Field>::Packing>());
    // poseidon2::<KoalaBear, _, 16>(&mut group, &name_kb_16, poseidon2_kb_16);

    let poseidon2_kb_24 = Poseidon2KoalaBear::<24>::new_from_rng_128(&mut rng);
    let name_kb_24 = format!("poseidon2::<{}, 24>", pretty_name::<<KoalaBear as Field>::Packing>());
    poseidon2::<KoalaBear, _, 24>(&mut group, &name_kb_24, poseidon2_kb_24);

    // let poseidon2_m31_16 = Poseidon2Mersenne31::<16>::new_from_rng_128(&mut rng);
    // let name_m31_16 = format!("poseidon2::<{}, 16>", pretty_name::<<Mersenne31 as Field>::Packing>());
    // poseidon2::<Mersenne31, _, 16>(&mut group, &name_m31_16, poseidon2_m31_16);

    // let poseidon2_m31_24 = Poseidon2Mersenne31::<24>::new_from_rng_128(&mut rng);
    // let name_m31_24 = format!("poseidon2::<{}, 24>", pretty_name::<<Mersenne31 as Field>::Packing>());
    // poseidon2::<Mersenne31, _, 24>(&mut group, &name_m31_24, poseidon2_m31_24);

    // let poseidon2_gold_8 = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng);
    // let name_gold_8 = format!("poseidon2::<{}, 8>", pretty_name::<<Goldilocks as Field>::Packing>());
    // poseidon2::<Goldilocks, _, 8>(&mut group, &name_gold_8, poseidon2_gold_8);

    // let poseidon2_gold_12 = Poseidon2Goldilocks::<12>::new_from_rng_128(&mut rng);
    // let name_gold_12 = format!("poseidon2::<{}, 12>", pretty_name::<<Goldilocks as Field>::Packing>());
    // poseidon2::<Goldilocks, _, 12>(&mut group, &name_gold_12, poseidon2_gold_12);

    // let poseidon2_gold_16 = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
    // let name_gold_16 = format!("poseidon2::<{}, 16>", pretty_name::<<Goldilocks as Field>::Packing>());
    // poseidon2::<Goldilocks, _, 16>(&mut group, &name_gold_16, poseidon2_gold_16);

    // let poseidon2_bn254 = Poseidon2Bn254::<3>::new_from_rng(8, 22, &mut rng);
    // let name_bn254 = format!("poseidon2::<{}, 3>", pretty_name::<<Bn254Fr as Field>::Packing>());
    // poseidon2::<Bn254Fr, _, 3>(&mut group, &name_bn254, poseidon2_bn254);

    group.finish();
}

fn poseidon2<F, Perm, const WIDTH: usize>(
    group: &mut BenchmarkGroup<criterion::measurement::WallTime>,
    name_prefix: &str,
    poseidon2: Perm,
) where
    F: Field,
    Perm: Permutation<[F::Packing; WIDTH]>,
    [F::Packing; WIDTH]: Copy,
{
    for num_perms in PERMUTATION_COUNTS {
        let input = [<F as Field>::Packing::ZERO; WIDTH];
        let id = BenchmarkId::new(name_prefix, num_perms);

        group.bench_with_input(id, &input, |b, &start_input| {
            b.iter(|| {
                let mut current_state = start_input;
                for _ in 0..num_perms {
                    current_state = poseidon2.permute(current_state);
                }
                black_box(current_state)
            })
        });
    }
}

criterion_group!(benches, bench_poseidon2);
criterion_main!(benches);


//RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench poseidon2 -- --sample-size 10 