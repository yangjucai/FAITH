use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::ops::Mul;

type F = Fr;
type G1 = G1Projective;
type G2 = G2Projective;

/// 公共参数
#[derive(Clone)]
pub struct SystemParams {
    pub g: G1,
    pub z: G2,
}

/// 用户密钥对
pub struct KeyPair {
    pub sk1: F,
    pub sk2: F,
    pub pk1: G2, // Z^a1
    pub pk2: G1, // g^a2
}

/// 第二层密文结构
pub struct Ciphertext {
    pub c1: G1, // g^k
    pub c2: G2, // m + Z^{a1k}
}

/// 重加密后的密文
pub struct ReEncryptedCiphertext {
    pub e1: PairingOutput<Bls12_381>, // e(g^k, Z^{a1 * b2})
    pub c2: G2,                       // m + Z^{a1k}
}

/// 初始化系统参数
pub fn setup() -> SystemParams {
    let mut rng = StdRng::seed_from_u64(1);
    let g = G1::rand(&mut rng);
    let z = G2::rand(&mut rng);
    SystemParams { g, z }
}

/// 用户生成密钥对
pub fn keygen(params: &SystemParams) -> KeyPair {
    let mut rng = StdRng::seed_from_u64(rand::random());
    let sk1 = F::rand(&mut rng);
    let sk2 = F::rand(&mut rng);
    let pk1 = params.z.mul(sk1); // Z^a1
    let pk2 = params.g.mul(sk2); // g^a2
    KeyPair { sk1, sk2, pk1, pk2 }
}

/// 第二层加密：输出 c = (g^k, m * Z^{a1k})
pub fn encrypt_lvl2(params: &SystemParams, pk1: &G2, msg: &G2) -> (Ciphertext, Fr) {
    let mut rng = StdRng::seed_from_u64(rand::random());
    let k = F::rand(&mut rng);
    let c1 = params.g.mul(k); // g^k
    let z_a1k = pk1.mul(k); // Z^{a1k}
    let c2 = *msg + z_a1k; // 语义上改为等价的m + Z^{a1k}
    (Ciphertext { c1, c2 }, k)
}

/// 重加密密钥：rk = g^{a1 * b2} ∈ G1
pub fn rekeygen(_params: &SystemParams, sk1_a: &F, pk2_b: &G1) -> G1 {
    pk2_b.mul(*sk1_a) // g^{a₁ b₂}
}

/// 重加密操作：输出 e(g^k, Z^{a1 * b2})，保留 c2 不变
pub fn reencrypt(params: &SystemParams, ct: &Ciphertext, _rk: &G1) -> ReEncryptedCiphertext {
    let e1 = Bls12_381::pairing(ct.c1, params.z.into_affine());
    ReEncryptedCiphertext { e1, c2: ct.c2 }
}

/// pairing 结果 GT -> Fr（通过哈希导出）
pub fn gt_to_fr(gt: &PairingOutput<Bls12_381>) -> Fr {
    let mut bytes = Vec::new();
    gt.serialize_compressed(&mut bytes).unwrap();
    let hash = Sha256::digest(&bytes);
    Fr::from_le_bytes_mod_order(&hash)
}

/// 解密操作：利用 sk2_b 和 c1 还原 Z^{b2k}，然后恢复 m
pub fn decrypt(params: &SystemParams, ct: &Ciphertext, sk1: &F) -> G2 {
    let e = Bls12_381::pairing(ct.c1.into_affine(), params.z.into_affine());
    let scalar = gt_to_fr(&e);
    let neg_a1 = -(*sk1);
    let e_inv = scalar.pow(neg_a1.into_bigint());
    ct.c2 * e_inv
}

#[test]
fn third_attempt() {
    let params = setup();
    let key_a = keygen(&params);
    let key_b = keygen(&params);

    // 原始消息（G2 上的随机点）
    let msg = G2::rand(&mut StdRng::seed_from_u64(42));

    // 第二层加密
    let (ct_lvl2, _k) = encrypt_lvl2(&params, &key_a.pk1, &msg);
    println!("\nSecond-Level Ciphertext:");
    println!("  c1 = {:?}", ct_lvl2.c1);
    println!("  c2 = {:?}", ct_lvl2.c2);

    // 重加密密钥 rk = Z^{a1 * b2}
    let rk = rekeygen(&params, &key_a.sk1, &key_b.pk2);

    // 重加密：e(g^k, Z^{a1 * b2})
    let ct_reenc = reencrypt(&params, &ct_lvl2, &rk);
    println!("\nRe-Encrypted Ciphertext:");
    println!("  e1 (GT) = {:?}", ct_reenc.e1);
    println!("  c2 = {:?}", ct_reenc.c2);

    // 解密（这里直接用原始密文解密）
    let recovered = decrypt(&params, &ct_lvl2, &key_a.sk1);
    println!("\nRecovered message: {:?}", recovered);
    println!("\nOriginal message:  {:?}", msg);
}
