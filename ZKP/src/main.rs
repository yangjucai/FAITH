mod circuit;

use anyhow::Result;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::Field},
    hash::{
        hash_types::{RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        witness::{PartialWitness, Witness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{Hasher, PoseidonGoldilocksConfig},
    },
};
use std::time::Instant;
use crate::circuit::ec::{G1Point, G2Point};
use crate::circuit::field::{Fp2, Fp12};
use crate::circuit::pairing::{miller_loop, final_exponentiation};
use crate::circuit::signature::verify_poseidon_signature;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;


fn pairing_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> (G1Point, G2Point, Fp12) {
    // G1 输入点
    let px = builder.add_virtual_target();
    let py = builder.add_virtual_target();
    let p = G1Point::new(px, py);

    // G2 输入点 (Fp2)
    let qx_c0 = builder.add_virtual_target();
    let qx_c1 = builder.add_virtual_target();
    let qy_c0 = builder.add_virtual_target();
    let qy_c1 = builder.add_virtual_target();
    let qx = Fp2::new(qx_c0, qx_c1);
    let qy = Fp2::new(qy_c0, qy_c1);
    let q = G2Point::new(qx, qy);

    let f = miller_loop(builder, &p, &q);
    let f_final = final_exponentiation(builder, &f);

    (p, q, f_final)
}

pub fn build_pairing_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> (G1Point, G2Point, Fp12) {
    let px = builder.add_virtual_target();
    let py = builder.add_virtual_target();
    let p = G1Point::new(px, py);

    let qx_c0 = builder.add_virtual_target();
    let qx_c1 = builder.add_virtual_target();
    let qy_c0 = builder.add_virtual_target();
    let qy_c1 = builder.add_virtual_target();

    let qx = Fp2::new(qx_c0, qx_c1);
    let qy = Fp2::new(qy_c0, qy_c1);
    let q = G2Point::new(qx, qy);

    let f = miller_loop(builder, &p, &q);
    let f_final = final_exponentiation(builder, &f);

    (p, q, f_final)
}


fn main() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // 签名验证
    let msg_len = 4;
    let ciphertext_msg = builder.add_virtual_targets(msg_len);
    let ciphertext_hash = builder.add_virtual_hash();
    verify_poseidon_signature(&mut builder, &ciphertext_msg, ciphertext_hash);

    let rk_msg = builder.add_virtual_targets(msg_len);
    let rk_hash = builder.add_virtual_hash();
    verify_poseidon_signature(&mut builder, &rk_msg, rk_hash);

    // pairing 电路
    // let (p, q, pairing_out) = pairing_circuit(&mut builder);
    let (p, q, _pairing_res) = build_pairing_circuit(&mut builder);

    // 新密文哈希
    let new_ciphertext = builder.add_virtual_targets(msg_len);
    let new_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(new_ciphertext.clone());

    // 注册公共输入
    builder.register_public_input(p.x);
    builder.register_public_input(p.y);
    builder.register_public_input(q.x.c0);
    builder.register_public_input(q.x.c1);
    builder.register_public_input(q.y.c0);
    builder.register_public_input(q.y.c1);
    builder.register_public_inputs(&new_hash.elements);

    let circuit_data = builder.build::<C>();
    let mut pw = PartialWitness::new();

    // 赋值填充，示例值，真实请替换为正确 BN254 点坐标
    for (i, t) in ciphertext_msg.iter().enumerate() {
        pw.set_target(*t, F::from_canonical_u64(100 + i as u64))?;
    }
    let ct_hash = PoseidonHash::hash_no_pad(
        &ciphertext_msg
            .iter()
            .map(|t| pw.get_target(*t))
            .collect::<Vec<_>>(),
    );
    pw.set_hash_target(ciphertext_hash, ct_hash);

    for (i, t) in rk_msg.iter().enumerate() {
        pw.set_target(*t, F::from_canonical_u64(200 + i as u64))?;
    }
    let rk_hash_val =
        PoseidonHash::hash_no_pad(&rk_msg.iter().map(|t| pw.get_target(*t)).collect::<Vec<_>>());
    pw.set_hash_target(rk_hash, rk_hash_val);

    for (i, t) in new_ciphertext.iter().enumerate() {
        pw.set_target(*t, F::from_canonical_u64(300 + i as u64))?;
    }

    // BN254 pairing 输入赋值（示例）
    pw.set_target(p.x, F::from_canonical_u64(1234567890))?;
    pw.set_target(p.y, F::from_canonical_u64(987654321))?;
    pw.set_target(q.x.c0, F::from_canonical_u64(11111111))?;
    pw.set_target(q.x.c1, F::from_canonical_u64(22222222))?;
    pw.set_target(q.y.c0, F::from_canonical_u64(33333333))?;
    pw.set_target(q.y.c1, F::from_canonical_u64(44444444))?;

    let now = Instant::now();
    let proof = circuit_data.prove(pw)?;
    println!(
        "Proof time: {:?}, size: {} bytes",
        now.elapsed(),
        proof.to_bytes().len()
    );

    circuit_data.verify(proof)?;
    println!("Proof verified successfully");
    Ok(())
}
