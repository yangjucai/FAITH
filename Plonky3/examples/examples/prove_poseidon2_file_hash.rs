use clap::Parser;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_field::Field;
use p3_symmetric::Permutation;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use std::fs::File;
use std::io::{BufReader, Read};

const P2_WIDTH: usize = 16;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The path to the file to hash (e.g. test_10mb.bin)
    #[arg(short, long)]
    file: String,
}

fn main() {
    let args = Args::parse();

    // Open and read the whole file into memory (for simplicity)
    let mut file = BufReader::new(File::open(&args.file).expect("Failed to open file"));
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("Failed to read file");

    println!("Read {} bytes from file '{}'", buf.len(), args.file);

    type F = BabyBear;
    type Perm = Poseidon2BabyBear<P2_WIDTH>;
    type Packing = <F as Field>::Packing;

    let mut rng = SmallRng::seed_from_u64(1);
    let poseidon2 = Perm::new_from_rng_128(&mut rng);

    // Hash the file in 16-byte chunks
    let mut acc = vec![];
    for chunk in buf.chunks(P2_WIDTH) {
        let mut arr = [Packing::ZERO; P2_WIDTH];
        for (i, &b) in chunk.iter().enumerate() {
            arr[i] = Packing::from_canonical_u8(b);
        }
        let hash = poseidon2.permute(arr);
        acc.extend_from_slice(&hash);
    }
    // Hash all chunk hashes together as a final hash
    let mut final_arr = [Packing::ZERO; P2_WIDTH];
    for (i, v) in acc.iter().enumerate().take(P2_WIDTH) {
        final_arr[i] = *v;
    }
    let final_hash = poseidon2.permute(final_arr);

    println!("Poseidon2 hash output (first 8 elements as u32):");
    for (i, v) in final_hash.iter().enumerate().take(8) {
        print!("{:08x} ", v.as_canonical_u32());
    }
    println!();
}