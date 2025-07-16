use anyhow::Result;
use plonky2::{
    field::{goldilocks_field::GoldilocksField as F, types::Field},
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use serde::Deserialize;
use std::{fs::File, io::BufReader, time::Instant};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

#[derive(Debug, Deserialize)]
struct ReEncryptInput {
    x_1: u64,
    y_1: u64,
    x_2: u64,
    y_2: u64,
}

#[derive(Debug, Deserialize)]
struct PairingInput {
    px: u64,
    py: u64,
    qx: u64,
    qy: u64,
    qz: u64,
    ell1_double: u64,
    ell2_double: u64,
    ell1_add: u64,
    ell2_add: u64,
    f: u64,
    f_final_exp: u64,
}

struct CircuitWires {
    // EC Add 电路
    ec_x1: Target,
    ec_y1: Target,
    ec_x2: Target,
    ec_y2: Target,
    ec_x3: Target,
    ec_y3: Target,
    
    // Pairing 电路
    pairing_px: Target,
    pairing_py: Target,
    pairing_qx: Target,
    pairing_qy: Target,
    pairing_qz: Target,
    pairing_ell1_double: Target,
    pairing_ell2_double: Target,
    pairing_ell1_add: Target,
    pairing_ell2_add: Target,
    pairing_f: Target,
}

fn build_all_circuits() -> (CircuitData<F, C, D>, CircuitWires) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // 1. 椭圆曲线点加电路
    let ec_x1 = builder.add_virtual_target();
    let ec_y1 = builder.add_virtual_target();
    let ec_x2 = builder.add_virtual_target();
    let ec_y2 = builder.add_virtual_target();

    let numerator = builder.sub(ec_y2, ec_y1);
    let denominator = builder.sub(ec_x2, ec_x1);
    let denominator_inv = builder.inverse(denominator);
    let lambda = builder.mul(numerator, denominator_inv);

    let lambda_sq = builder.mul(lambda, lambda);
    let x1_plus_x2 = builder.add(ec_x1, ec_x2);
    let ec_x3 = builder.sub(lambda_sq, x1_plus_x2);

    let x1_minus_x3 = builder.sub(ec_x1, ec_x3);
    let lambda_mul = builder.mul(lambda, x1_minus_x3);
    let ec_y3 = builder.sub(lambda_mul, ec_y1);

    // builder.register_public_input(ec_x3);
    // builder.register_public_input(ec_y3);

    // 2. 双线性配对电路
    let pairing_px = builder.add_virtual_target();
    let pairing_py = builder.add_virtual_target();
    let pairing_qx = builder.add_virtual_target();
    let pairing_qy = builder.add_virtual_target();
    let pairing_qz = builder.constant(F::ONE);

    let one = builder.constant(F::ONE);
    let mut f1 = one;
    let mut f2 = one;

    let pairing_ell1_double = builder.add_virtual_target();
    let pairing_ell2_double = builder.add_virtual_target();

    let f1_squared = builder.mul(f1, f1);
    f1 = builder.mul(pairing_ell1_double, f1_squared);

    let f2_squared = builder.mul(f2, f2);
    f2 = builder.mul(pairing_ell2_double, f2_squared);

    let pairing_ell1_add = builder.add_virtual_target();
    let pairing_ell2_add = builder.add_virtual_target();

    f1 = builder.mul(f1, pairing_ell1_add);
    f2 = builder.mul(f2, pairing_ell2_add);

    let f2_inv = builder.inverse(f2);
    let part = builder.mul(one, f2_inv);
    let pairing_f = builder.mul(f1, part);

    // builder.register_public_input(pairing_f);

    let wires = CircuitWires {
        ec_x1,
        ec_y1,
        ec_x2,
        ec_y2,
        ec_x3,
        ec_y3,
        pairing_px,
        pairing_py,
        pairing_qx,
        pairing_qy,
        pairing_qz,
        pairing_ell1_double,
        pairing_ell2_double,
        pairing_ell1_add,
        pairing_ell2_add,
        pairing_f,
    };

    (builder.build::<C>(), wires)
}

fn main() -> Result<()> {
    // 构建完整电路
    let (circuit_data, wires) = build_all_circuits();
    
    // 准备输入数据
    let mut pw = PartialWitness::new();

    // 1. 填充椭圆曲线点加电路输入
    let ec_file = File::open("./assets/reEncrypt.json")?;
    let ec_input: ReEncryptInput = serde_json::from_reader(BufReader::new(ec_file))?;

    let x1_val = F::from_canonical_u64(ec_input.x_1);
    let y1_val = F::from_canonical_u64(ec_input.y_1);
    let x2_val = F::from_canonical_u64(ec_input.x_2);
    let y2_val = F::from_canonical_u64(ec_input.y_2);

    let numerator_v = y2_val - y1_val;
    let denominator_v = x2_val - x1_val;
    let denominator_inv_v = denominator_v.inverse();
    let lambda_v = numerator_v * denominator_inv_v;
    let x3_v = lambda_v * lambda_v - x1_val - x2_val;
    let y3_v = lambda_v * (x1_val - x3_v) - y1_val;

    pw.set_target(wires.ec_x1, x1_val)?;
    pw.set_target(wires.ec_y1, y1_val)?;
    pw.set_target(wires.ec_x2, x2_val)?;
    pw.set_target(wires.ec_y2, y2_val)?;
    pw.set_target(wires.ec_x3, x3_v)?;
    pw.set_target(wires.ec_y3, y3_v)?;

    // 2. 填充双线性配对电路输入
    let pairing_file = File::open("./assets/pairing.json")?;
    let pairing_input: PairingInput = serde_json::from_reader(BufReader::new(pairing_file))?;

    pw.set_target(wires.pairing_px, F::from_canonical_u64(pairing_input.px))?;
    pw.set_target(wires.pairing_py, F::from_canonical_u64(pairing_input.py))?;
    pw.set_target(wires.pairing_qx, F::from_canonical_u64(pairing_input.qx))?;
    pw.set_target(wires.pairing_qy, F::from_canonical_u64(pairing_input.qy))?;
    // qz 已在电路中被设为常量 F::ONE

    pw.set_target(wires.pairing_ell1_double, F::from_canonical_u64(pairing_input.ell1_double))?;
    pw.set_target(wires.pairing_ell2_double, F::from_canonical_u64(pairing_input.ell2_double))?;
    pw.set_target(wires.pairing_ell1_add, F::from_canonical_u64(pairing_input.ell1_add))?;
    pw.set_target(wires.pairing_ell2_add, F::from_canonical_u64(pairing_input.ell2_add))?;
    pw.set_target(wires.pairing_f, F::from_canonical_u64(pairing_input.f))?;

    // 生成证明
    let start = Instant::now();
    let proof = circuit_data.prove(pw)?;
    println!("Proof generation time: {:?}", start.elapsed());
    println!("Proof size: {} bytes", proof.to_bytes().len());

    // 验证证明
    let start = Instant::now();
    circuit_data.verify(proof)?;
    println!("Verification time: {:?}", start.elapsed());

    Ok(())
}