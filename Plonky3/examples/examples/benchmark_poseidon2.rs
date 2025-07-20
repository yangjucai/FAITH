use clap::Parser;
// We only need the Poseidon2 permutation types here, not the base field types.
use p3_baby_bear::Poseidon2BabyBear;
use p3_field::{Field, PrimeField};
use p3_koala_bear::Poseidon2KoalaBear;
use p3_mersenne_31::Poseidon2Mersenne31;
use p3_symmetric::Permutation;
use rand::rngs::SmallRng;
// Import Rng trait to get the .gen() method
use rand::{Rng, SeedableRng};
use std::array;
use std::time::Instant;

/// Defines the field options for the benchmark.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
enum FieldOptions {
    KoalaBear,
    BabyBear,
    Mersenne31,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = "Benchmark Poseidon2 hashing performance.")]
struct Args {
    /// The field to use for the benchmark.
    #[arg(short, long, ignore_case = true, value_enum)]
    field: FieldOptions,

    /// The log base 2 of the number of hashes to perform.
    #[arg(short, long, default_value_t = 23)]
    log_num_hashes: u32,

    /// The width of the Poseidon2 permutation.
    #[arg(short, long, default_value_t = 16)]
    width: usize,
}

/// A macro to run the benchmark with a specific field type.
macro_rules! run_with_field {
    // This macro takes the field TYPE itself ($field_ty) as an argument.
    ($field_ty:ty, $perm_ty:ident, $rng:expr, $num_hashes:expr, $width:expr) => {
        match $width {
            16 => {
                let perm = $perm_ty::<16>::new_from_rng_128($rng);
                // FIX 1: Be explicit with the type parameter.
                // Instead of `run_benchmark::<_, 16>`, we explicitly pass `$field_ty`.
                // This resolves all the type inference (E0283) errors.
                run_benchmark::<$field_ty, 16>($rng, $num_hashes, perm);
            }
            24 => {
                let perm = $perm_ty::<24>::new_from_rng_128($rng);
                // Same fix for width 24.
                run_benchmark::<$field_ty, 24>($rng, $num_hashes, perm);
            }
            _ => unsupported_width($width),
        }
    };
}

fn main() {
    let args = Args::parse();
    let num_hashes = 1 << args.log_num_hashes;

    // Use a fixed seed for reproducibility.
    // WARNING: Use a real cryptographic PRNG in applications!
    let mut rng = SmallRng::seed_from_u64(42);

    println!(
        "Benchmarking {} Poseidon2 hashes (width={}) on the {:?} field.",
        num_hashes, args.width, args.field
    );

    match args.field {
        // Pass the full type path to the macro.
        FieldOptions::KoalaBear => {
            run_with_field!(p3_koala_bear::KoalaBear, Poseidon2KoalaBear, &mut rng, num_hashes, args.width)
        }
        FieldOptions::BabyBear => {
            run_with_field!(p3_baby_bear::BabyBear, Poseidon2BabyBear, &mut rng, num_hashes, args.width)
        }
        FieldOptions::Mersenne31 => {
            run_with_field!(p3_mersenne_31::Mersenne31, Poseidon2Mersenne31, &mut rng, num_hashes, args.width)
        }
    }
}

/// Helper function for unsupported widths.
fn unsupported_width(width: usize) {
    panic!(
        "Unsupported width: {}. Only 16 and 24 are supported in this benchmark.",
        width
    );
}

/// The generic benchmark execution function.
fn run_benchmark<F, const WIDTH: usize>(
    rng: &mut SmallRng,
    num_hashes: usize,
    perm: impl Permutation<[F; WIDTH]>,
) where
    F: PrimeField,
{
    // Generate random input data.
    let mut inputs: Vec<[F; WIDTH]> = (0..num_hashes)
        .map(|_| {
            array::from_fn(|_| {
                // By fixing the type inference issue above, the compiler now correctly
                // finds `from_canonical_u32` on the `Field` trait (which `PrimeField` extends).
                // FIX 2: Use `r#gen` to avoid keyword clash.
                F::from_canonical_checked(rng.r#gen::<u32>())
            })
        })
        .collect();

    // Record start time and execute the hashes.
    let start = Instant::now();
    for input in inputs.iter_mut() {
        perm.permute_mut(input);
    }
    let duration = start.elapsed();

    print_results(num_hashes, duration);
}

/// Prints the benchmark results.
fn print_results(num_hashes: usize, duration: std::time::Duration) {
    let total_secs = duration.as_secs_f64();
    let hashes_per_sec = if total_secs > 0.0 {
        num_hashes as f64 / total_secs
    } else {
        f64::INFINITY
    };

    println!("\n--- Results ---");
    println!("Total hashes:   {}", num_hashes);
    println!("Total time:     {:.3} seconds", total_secs);
    println!("Throughput:     {:.0} hashes/sec", hashes_per_sec);
}