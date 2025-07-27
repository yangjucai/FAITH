use plonky2::{
    field::{extension::Extendable},
    hash::{
        hash_types::{RichField},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
    },
};
use crate::circuit::ec::{G1Point, G2Point};
use crate::circuit::field::{Fp2, Fp6, Fp12};

pub fn miller_loop<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    p: &G1Point,
    q: &G2Point,
) -> Fp12 {
    let mut f = Fp12::one(builder);
    let mut r = *q;

    let ate_loop_bits = [
        0,1,1,0,1,0,0,0,0,0,1,1,0,1,0,0,0,0,0,1,0,0,1,1,0,0,0,0,1,0,0,0,0,0,1
    ];

    for (_i, bit) in ate_loop_bits.iter().enumerate() {
        // f = f^2
        f = Fp12::square(builder, &f);

        // r = 2r, 获取 line function ℓ
        let (r2, ell_d) = g2_double_step(builder, &r, p);
        f = Fp12::mul(builder, &ell_d, &f);
        r = r2;

        // 只有 bit == 1 时才执行 G2 加法
        if *bit == 1 {
            let (r3, ell_a) = g2_add_step(builder, &r, q, p);
            f = Fp12::mul(builder, &ell_a, &f);
            r = r3;
        }
    }

    f
}

// Final Exponentiation
pub fn final_exponentiation<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    f: &Fp12,
) -> Fp12 {
    // Easy part: f1 = f.conjugate() / f = f^{q^6 - 1}
    let f_inv = Fp12::inverse(builder, f);
    let f_conj = Fp12::conjugate(builder, f); // f^{q^6}
    let f1 = Fp12::mul(builder, &f_conj, &f_inv);

    // Hard part: 复杂幂链（我们简化为几个连乘）
    // 示例中做 f2 = f1^2 * f1^4 * f1^16 作为组合演示（真实可用文献算法优化）

    let f1_sq = Fp12::square(builder, &f1);              // f1^2
    let f1_quad = Fp12::square(builder, &f1_sq);         // f1^4
    let f1_8 = Fp12::square(builder, &f1_quad);          // f1^8
    let f1_16 = Fp12::square(builder, &f1_8);          // f1^16

    // 组合乘：f1^2 * f1^4 * f1^16
    let temp = Fp12::mul(builder, &f1_sq, &f1_quad);
    let result = Fp12::mul(builder, &temp, &f1_16);

    result
}

fn g2_double_step<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    r: &G2Point,
    _p: &G1Point,
) -> (G2Point, Fp12) {
    // 这是 BN254 G2 的倍点操作，并计算 Miller Loop 里的线函数
    // 1. 计算斜率 λ = (3 * x_r^2) / (2 * y_r)
    // 2. 新 x = λ^2 - 2 * x_r
    // 3. 新 y = λ * (x_r - new_x) - y_r
    // 4. 计算线函数 f (具体计算线函数值，依据 Miller Loop 中的定义)

    let x = &r.x;
    let y = &r.y;

    // 计算 x^2
    let x_sq = Fp2::square(builder, x);

    // 计算 3 * x^2
    let three = builder.constant(F::from_canonical_u64(3));
    let three_x_sq_c0 = builder.mul(x_sq.c0, three);
    let three_x_sq_c1 = builder.mul(x_sq.c1, three);
    let three_x_sq = Fp2::new(three_x_sq_c0, three_x_sq_c1);

    // 计算 2 * y
    let two = builder.constant(F::from_canonical_u64(2));
    let two_y_c0 = builder.mul(y.c0, two);
    let two_y_c1 = builder.mul(y.c1, two);
    let two_y = Fp2::new(two_y_c0, two_y_c1);

    // 计算 λ = (3 * x^2) / (2 * y)
    let two_y_inv = Fp2::inverse(builder, &two_y);
    let lambda = Fp2::mul(builder, &three_x_sq, &two_y_inv);

    // 计算 λ^2
    let lambda_sq = Fp2::square(builder, &lambda);

    // 计算 new_x = λ^2 - 2*x
    let two_x_c0 = builder.mul(x.c0, two);
    let two_x_c1 = builder.mul(x.c1, two);
    let two_x = Fp2::new(two_x_c0, two_x_c1);
    let new_x = Fp2::sub(builder, &lambda_sq, &two_x);

    // 计算 new_y = λ*(x - new_x) - y
    let x_minus_new_x = Fp2::sub(builder, x, &new_x);
    let lambda_mul = Fp2::mul(builder, &lambda, &x_minus_new_x);
    let new_y = Fp2::sub(builder, &lambda_mul, y);

    let r_new = G2Point::new(new_x, new_y);

    // 线函数的计算
    let line = Fp12::one(builder); // TODO: 线函数计算（复杂，可根据你已有线函数定义替换）

    (r_new, line)
}

fn g2_add_step<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    r: &G2Point,
    q: &G2Point,
    p: &G1Point,
) -> (G2Point, Fp12) {
    // G2 加法操作 + 计算 Miller Loop 线函数
    // λ = (y_q - y_r) / (x_q - x_r)
    // new_x = λ^2 - x_r - x_q
    // new_y = λ*(x_r - new_x) - y_r

    let x_r = &r.x;
    let y_r = &r.y;
    let x_q = &q.x;
    let y_q = &q.y;

    // x_q - x_r
    let x_diff = Fp2::sub(builder, x_q, x_r);
    // y_q - y_r
    let y_diff = Fp2::sub(builder, y_q, y_r);

    // λ = (y_q - y_r) / (x_q - x_r)
    let x_diff_inv = Fp2::inverse(builder, &x_diff);
    let lambda = Fp2::mul(builder, &y_diff, &x_diff_inv);

    // λ²
    let lambda_sq = Fp2::square(builder, &lambda);

    // new_x = λ² - x_r - x_q
    let sum_xr_xq = Fp2::add(builder, x_r, x_q);
    let new_x = Fp2::sub(builder, &lambda_sq, &sum_xr_xq);

    // new_y = λ*(x_r - new_x) - y_r
    let xr_minus_newx = Fp2::sub(builder, x_r, &new_x);
    let lambda_mul = Fp2::mul(builder, &lambda, &xr_minus_newx);
    let new_y = Fp2::sub(builder, &lambda_mul, y_r);

    let r_new = G2Point::new(new_x, new_y);

    // 计算线函数：
    // line.c0 = λ * p.x - p.y (注意 p.x, p.y 是 Target，需要构造 Fp2 形式)
    // 由于 p.x, p.y 是 Fp (Target)，λ 是 Fp2，所以先计算 λ * p.x（标量乘）
    let lambda_px_c0 = builder.mul(lambda.c0, p.x);
    let lambda_px_c1 = builder.mul(lambda.c1, p.x);
    let lambda_px = Fp2::new(lambda_px_c0, lambda_px_c1);

    // p.y 转 Fp2，虚部为0
    let py_fp2 = Fp2::new(p.y, builder.constant(F::ZERO));

    // λ * p.x - p.y
    let c0_fp2 = Fp2::sub(builder, &lambda_px, &py_fp2);

    // 定义 Fp2::zero
    // let zero = builder.constant(F::ZERO);
    // pub fn zero(builder) -> Self {
    //     Self { c0: zero, c1: zero }
    // }
    let zero_fp2 = Fp2::zero(builder);

    // 构造 Fp6 零元素
    let zero_fp6 = Fp6::zero(builder);

    // 线函数 c0 = (c0_fp2, 0, 0)
    let c0 = Fp6::new(c0_fp2, zero_fp2, zero_fp2);
    let c1 = zero_fp6;

    let line = Fp12::new(c0, c1);

    (r_new, line)
}
