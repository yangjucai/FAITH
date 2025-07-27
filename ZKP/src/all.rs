use anyhow::Result;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::Field},
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, Witness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{Hasher, PoseidonGoldilocksConfig},
    },
};
use std::time::Instant;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

// Fp2 结构
#[derive(Clone, Copy)]
struct Fp2 {
    c0: Target,
    c1: Target,
}

impl Fp2 {
    fn new(c0: Target, c1: Target) -> Self {
        Self { c0, c1 }
    }

    fn zero<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let zero = builder.constant(F::ZERO);
        Self::new(zero, zero)
    }

    // Fp2 乘法 (a + bu)(c + du) = (ac - bd) + (ad + bc)u
    fn mul<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) -> Self {
        let ac = builder.mul(a.c0, b.c0);
        let bd = builder.mul(a.c1, b.c1);
        let re = builder.sub(ac, bd);

        let ad = builder.mul(a.c0, b.c1);
        let bc = builder.mul(a.c1, b.c0);
        let im = builder.add(ad, bc);

        Fp2::new(re, im)
    }

    // Fp2 加法
    fn add<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) -> Self {
        Fp2::new(builder.add(a.c0, b.c0), builder.add(a.c1, b.c1))
    }

    // Fp2 减法
    pub fn sub<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) -> Self {
        Self {
            c0: builder.sub(a.c0, b.c0),
            c1: builder.sub(a.c1, b.c1),
        }
    }

    // Fp2 取负
    fn neg<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        Fp2::new(builder.neg(a.c0), builder.neg(a.c1))
    }

    // Fp2 平方
    pub fn square<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        Self::mul(builder, a, a)
    }

    // Fp2 取逆
    fn inverse<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        let c0_sq = builder.mul(a.c0, a.c0);
        let c1_sq = builder.mul(a.c1, a.c1);
        let denom = builder.add(c0_sq, c1_sq);
        let denom_inv = builder.inverse(denom);
        let re = builder.mul(a.c0, denom_inv);
        let neg_c1 = builder.neg(a.c1);
        let im = builder.mul(neg_c1, denom_inv);
        Fp2::new(re, im)
    }

    fn mul_scalar<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        scalar: Target,
    ) -> Self {
        Self {
            c0: builder.mul(a.c0, scalar),
            c1: builder.mul(a.c1, scalar),
        }
    }

    pub fn mul_by_nonresidue<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        // ξ = u + 1
        let one = builder.constant(F::ONE);
        let xi = Fp2::new(one, one);

        Self::mul(builder, a, &xi)
    }
}

#[derive(Clone, Copy)]
struct Fp6 {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,
}

impl Fp6 {
    fn new(c0: Fp2, c1: Fp2, c2: Fp2) -> Self {
        Self { c0, c1, c2 }
    }

    pub fn zero<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let zero = builder.constant(F::ZERO);
        Fp6::new(
            Fp2::new(zero, zero),
            Fp2::new(zero, zero),
            Fp2::new(zero, zero),
        )
    }

    // Fp6 加法
    fn add<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) -> Self {
        Self {
            c0: Fp2::add(builder, &a.c0, &b.c0),
            c1: Fp2::add(builder, &a.c1, &b.c1),
            c2: Fp2::add(builder, &a.c2, &b.c2),
        }
    }

    // Fp6 减法
    fn sub<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) -> Self {
        Self {
            c0: Fp2::sub(builder, &a.c0, &b.c0),
            c1: Fp2::sub(builder, &a.c1, &b.c1),
            c2: Fp2::sub(builder, &a.c2, &b.c2),
        }
    }

    // Fp6 乘法
    fn mul<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) -> Self {
        // Karatsuba-like multiplication in Fp6:
        // Let A = (a0, a1, a2), B = (b0, b1, b2)
        // Compute intermediates
        let a0b0 = Fp2::mul(builder, &a.c0, &b.c0);
        let a1b1 = Fp2::mul(builder, &a.c1, &b.c1);
        let a2b2 = Fp2::mul(builder, &a.c2, &b.c2);

        // Compute c0
        let t0 = Fp2::add(builder, &a.c1, &a.c2);
        let t1 = Fp2::add(builder, &b.c1, &b.c2);
        let t2 = Fp2::mul(builder, &t0, &t1);
        let t2 = Fp2::sub(builder, &t2, &a1b1);
        let t2 = Fp2::sub(builder, &t2, &a2b2);
        // Multiply by xi (v^3 = xi)
        // BN254 xi = 1 + u (Fp2 element with c0=1, c1=1)
        let xi = Fp2::new(builder.constant(F::ONE), builder.constant(F::ONE));
        let t2_xi = Fp2::mul(builder, &t2, &xi);

        let c0 = Fp2::add(builder, &a0b0, &t2_xi);

        // Compute c1
        let t3 = Fp2::add(builder, &a.c0, &a.c1);
        let t4 = Fp2::add(builder, &b.c0, &b.c1);
        let t5 = Fp2::mul(builder, &t3, &t4);
        let t5 = Fp2::sub(builder, &t5, &a0b0);
        let t5 = Fp2::sub(builder, &t5, &a1b1);
        let a2b2_xi = Fp2::mul(builder, &a2b2, &xi);
        let c1 = Fp2::add(builder, &t5, &a2b2_xi);

        // Compute c2
        let t6 = Fp2::add(builder, &a.c0, &a.c2);
        let t7 = Fp2::add(builder, &b.c0, &b.c2);
        let t8 = Fp2::mul(builder, &t6, &t7);
        let t8 = Fp2::sub(builder, &t8, &a0b0);
        let t8 = Fp2::sub(builder, &t8, &a2b2);
        let c2 = Fp2::add(builder, &t8, &a1b1);

        Self::new(c0, c1, c2)
    }

    // Fp6 乘以非剩余 ξ (根据 BN254 规范 ξ = v)
    fn mul_by_nonresidue<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        // ξ = v，在 Fp6 = Fp2[v]/(v^3 - ξ), 其中 ξ ∈ Fp2 非剩余元
        let temp_c2 = Fp2::new(builder.constant(F::ZERO), builder.constant(F::ONE));
        let c0 = Fp2::mul(builder, &a.c2, &temp_c2);

        Self {
            c0,
            c1: a.c0,
            c2: a.c1,
        }
    }

    fn neg<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        Self {
            c0: Fp2::neg(builder, &a.c0),
            c1: Fp2::neg(builder, &a.c1),
            c2: Fp2::neg(builder, &a.c2),
        }
    }

    pub fn inverse<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        let c0 = &a.c0;
        let c1 = &a.c1;
        let c2 = &a.c2;

        // 中间变量 t0 = c0^2 - ξ·(c1·c2)
        let c0_sq = Fp2::square(builder, c0);
        let c1c2 = Fp2::mul(builder, c1, c2);
        let xi_c1c2 = Fp2::mul_by_nonresidue(builder, &c1c2);
        let t0 = Fp2::sub(builder, &c0_sq, &xi_c1c2);

        // t1 = c2^2 - ξ·(c0·c1)
        let c2_sq = Fp2::square(builder, c2);
        let c0c1 = Fp2::mul(builder, c0, c1);
        let xi_c0c1 = Fp2::mul_by_nonresidue(builder, &c0c1);
        let t1 = Fp2::sub(builder, &c2_sq, &xi_c0c1);

        // t2 = c1^2 - ξ·(c0·c2)
        let c1_sq = Fp2::square(builder, c1);
        let c0c2 = Fp2::mul(builder, c0, c2);
        let xi_c0c2 = Fp2::mul_by_nonresidue(builder, &c0c2);
        let t2 = Fp2::sub(builder, &c1_sq, &xi_c0c2);

        // 计算分母 denom = c0·t0 + ξ·(c2·t1 + c1·t2)
        let c0t0 = Fp2::mul(builder, c0, &t0);
        let c2t1 = Fp2::mul(builder, c2, &t1);
        let c1t2 = Fp2::mul(builder, c1, &t2);
        let sum = Fp2::add(builder, &c2t1, &c1t2);
        let xi_sum = Fp2::mul_by_nonresidue(builder, &sum);
        let denom = Fp2::add(builder, &c0t0, &xi_sum);

        let denom_inv = Fp2::inverse(builder, &denom);

        // 最终三个系数
        let c0_res = Fp2::mul(builder, &t0, &denom_inv);
        let mul_result = Fp2::mul(builder, &t2, &denom_inv);
        let c1_res = Fp2::neg(builder, &mul_result);
        let c2_res = Fp2::mul(builder, &t1, &denom_inv);

        Fp6::new(c0_res, c1_res, c2_res)
    }
}

#[derive(Clone, Copy)]
struct Fp12 {
    c0: Fp6,
    c1: Fp6,
}

impl Fp12 {
    fn new(c0: Fp6, c1: Fp6) -> Self {
        Self { c0, c1 }
    }

    pub fn zero<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Fp12::new(Fp6::zero(builder), Fp6::zero(builder))
    }

    pub fn one<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let one = builder.constant(F::ONE);
        let zero = builder.constant(F::ZERO);
        let c0 = Fp6::new(
            Fp2::new(one, zero),
            Fp2::new(zero, zero),
            Fp2::new(zero, zero),
        );
        let c1 = Fp6::new(
            Fp2::new(zero, zero),
            Fp2::new(zero, zero),
            Fp2::new(zero, zero),
        );
        Fp12::new(c0, c1)
    }

    // Fp12 加法
    pub fn add<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) -> Self {
        Self {
            c0: Fp6::add(builder, &a.c0, &b.c0),
            c1: Fp6::add(builder, &a.c1, &b.c1),
        }
    }

    // Fp12 减法
    pub fn sub<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) -> Self {
        Self {
            c0: Fp6::sub(builder, &a.c0, &b.c0),
            c1: Fp6::sub(builder, &a.c1, &b.c1),
        }
    }

    // Fp12 乘法
    pub fn mul<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) -> Self {
        // Karatsuba multiplication in Fp12:
        // (a0 + a1 w)(b0 + b1 w) = (a0*b0 + a1*b1*v) + ( (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 ) w
        let a0b0 = Fp6::mul(builder, &a.c0, &b.c0);
        let a1b1 = Fp6::mul(builder, &a.c1, &b.c1);

        // BN254 v = (0,1,0) in Fp6,即v是Fp6中的一个元素（我们这里用c1=Fp2::new(1,0)表示）
        // 这里先定义v为F_p6中的常量
        let v = Fp6::new(
            Fp2::new(builder.constant(F::ZERO), builder.constant(F::ZERO)), // c0 = 0
            Fp2::new(builder.constant(F::ONE), builder.constant(F::ZERO)),  // c1 = 1
            Fp2::new(builder.constant(F::ZERO), builder.constant(F::ZERO)), // c2 = 0
        );

        let a1b1_v = Fp6::mul(builder, &a1b1, &v);

        let c0 = Fp6::add(builder, &a0b0, &a1b1_v);

        let a0_plus_a1 = Fp6::add(builder, &a.c0, &a.c1);
        let b0_plus_b1 = Fp6::add(builder, &b.c0, &b.c1);
        let mid = Fp6::mul(builder, &a0_plus_a1, &b0_plus_b1);
        let mid = Fp6::sub(builder, &mid, &a0b0);
        let mid = Fp6::sub(builder, &mid, &a1b1);

        let c1 = mid;

        Self::new(c0, c1)
    }

    // Fp12 平方 (可用传统公式)
    pub fn square<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        let a0_sq = Fp6::mul(builder, &a.c0, &a.c0);
        let a1_sq = Fp6::mul(builder, &a.c1, &a.c1);
        let a0_a1 = Fp6::add(builder, &a.c0, &a.c1);

        let a1_sq_xi = Fp6::mul_by_nonresidue(builder, &a1_sq);

        let c0 = Fp6::add(builder, &a0_sq, &a1_sq_xi);

        let a0_a1_sq = Fp6::mul(builder, &a0_a1, &a0_a1);
        let a0_sq_plus_a1_sq = Fp6::add(builder, &a0_sq, &a1_sq);
        let c1_temp = Fp6::sub(builder, &a0_a1_sq, &a0_sq_plus_a1_sq);

        Self { c0, c1: c1_temp }
    }

    // Fp12 取逆（复杂，需先实现 Fp6 的逆和 Fp2 的逆）
    pub fn inverse<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        // 用 a^(-1) = a.conj / |a|^2
        let norm = Fp12::norm(builder, a);         // a * a.conj
        let norm_inv = Fp6::inverse(builder, &norm);
        let conj = Fp12::conjugate(builder, a);    // (a0 - a1 * w)
        Fp12 {
            c0: Fp6::mul(builder, &conj.c0, &norm_inv),
            c1: Fp6::mul(builder, &conj.c1, &norm_inv),
        }
    }

    pub fn conjugate<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Self {
        // Fp12 共轭: a0 - a1 * w
        let neg_c1 = Fp6::neg(builder, &a.c1);
        Fp12 { c0: a.c0, c1: neg_c1 }
    }

    pub fn norm<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
    ) -> Fp6 {
        // Fp12 元素范数 norm = a * a.conj = a0^2 - xi * a1^2
        let a0_sq = Fp6::mul(builder, &a.c0, &a.c0);
        let a1_sq = Fp6::mul(builder, &a.c1, &a.c1);
        let xi_a1_sq = Fp6::mul_by_nonresidue(builder, &a1_sq);
        Fp6::sub(builder, &a0_sq, &xi_a1_sq)
    }
}

// G1 点结构（在 Fp 上）
#[derive(Clone, Copy)]
struct G1Point {
    x: Target,
    y: Target,
}

impl G1Point {
    fn new(x: Target, y: Target) -> Self {
        Self { x, y }
    }

    fn add<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        p: &G1Point,
        q: &G1Point,
    ) -> G1Point {
        // 计算斜率 lambda = (y2 - y1) / (x2 - x1)
        let x_diff = builder.sub(q.x, p.x);
        let y_diff = builder.sub(q.y, p.y);
        let x_diff_inv = builder.inverse(x_diff);

        let lambda = builder.mul(y_diff, x_diff_inv);

        // x3 = lambda^2 - x1 - x2
        let lambda_sq = builder.mul(lambda, lambda);
        let x3_intermediate = builder.sub(lambda_sq, p.x);
        let x3 = builder.sub(x3_intermediate, q.x);

        // y3 = lambda * (x1 - x3) - y1
        let x1_minus_x3 = builder.sub(p.x, x3);
        let lambda_times_x1_minus_x3 = builder.mul(lambda, x1_minus_x3); // 将中间结果存储在临时变量中
        let y3 = builder.sub(lambda_times_x1_minus_x3, p.y);

        G1Point::new(x3, y3)
    }

    // 点倍点 P + P
    fn double<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        p: &G1Point,
    ) -> G1Point {
        // lambda = (3*x1^2) / (2*y1)
        let three = builder.constant(F::from_canonical_u64(3));
        let two = builder.constant(F::from_canonical_u64(2));

        let x1_sq = builder.mul(p.x, p.x);
        let numerator = builder.mul(three, x1_sq);
        let denominator = builder.mul(two, p.y);
        let denominator_inv = builder.inverse(denominator);
        let lambda = builder.mul(numerator, denominator_inv);

        // x3 = lambda^2 - 2*x1
        let lambda_sq = builder.mul(lambda, lambda);
        let two_x1 = builder.mul(two, p.x);
        let x3 = builder.sub(lambda_sq, two_x1);

        // y3 = lambda * (x1 - x3) - y1
        let x1_minus_x3 = builder.sub(p.x, x3);
        let lambda_times_x1_minus_x3 = builder.mul(lambda, x1_minus_x3);
        let y3 = builder.sub(lambda_times_x1_minus_x3, p.y);

        G1Point::new(x3, y3)
    }
}

// G2 点结构（在 Fp2 上）
#[derive(Clone, Copy)]
struct G2Point {
    x: Fp2,
    y: Fp2,
}

impl G2Point {
    fn new(x: Fp2, y: Fp2) -> Self {
        Self { x, y }
    }

    /// G2 点加法 (简化，仿射坐标)
    fn add<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        p: &Self,
        q: &Self,
    ) -> Self {
        // lambda = (y2 - y1) / (x2 - x1)
        let x_diff = Fp2::sub(builder, &q.x, &p.x);
        let y_diff = Fp2::sub(builder, &q.y, &p.y);
        let x_diff_inv = Fp2::inverse(builder, &x_diff);
        let lambda = Fp2::mul(builder, &y_diff, &x_diff_inv);

        // x3 = lambda^2 - x1 - x2
        let lambda_sq = Fp2::mul(builder, &lambda, &lambda);
        let x1_plus_x2 = Fp2::add(builder, &p.x, &q.x);
        let x3 = Fp2::sub(builder, &lambda_sq, &x1_plus_x2);

        // y3 = lambda * (x1 - x3) - y1
        let x1_minus_x3 = Fp2::sub(builder, &p.x, &x3);
        let lambda_mul = Fp2::mul(builder, &lambda, &x1_minus_x3);
        let y3 = Fp2::sub(builder, &lambda_mul, &p.y);

        Self::new(x3, y3)
    }

    /// G2 点倍点 (简化，仿射坐标)
    fn double<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        p: &Self,
    ) -> Self {
        let three = builder.constant(F::from_canonical_u64(3));
        let two = builder.constant(F::from_canonical_u64(2));

        // lambda = (3 * x1^2) / (2 * y1)
        let x1_sq = Fp2::mul(builder, &p.x, &p.x);
        let numerator = Fp2::mul_scalar(builder, &x1_sq, three);
        let denominator = Fp2::mul_scalar(builder, &p.y, two);
        let denominator_inv = Fp2::inverse(builder, &denominator);
        let lambda = Fp2::mul(builder, &numerator, &denominator_inv);

        // x3 = lambda^2 - 2 * x1
        let lambda_sq = Fp2::mul(builder, &lambda, &lambda);
        let two_x1 = Fp2::mul_scalar(builder, &p.x, two);
        let x3 = Fp2::sub(builder, &lambda_sq, &two_x1);

        // y3 = lambda * (x1 - x3) - y1
        let x1_minus_x3 = Fp2::sub(builder, &p.x, &x3);
        let lambda_mul = Fp2::mul(builder, &lambda, &x1_minus_x3);
        let y3 = Fp2::sub(builder, &lambda_mul, &p.y);

        Self::new(x3, y3)
    }
}








fn g2_double_step<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    r: &G2Point,
    p: &G1Point,
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









fn miller_loop<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    p: &G1Point,
    q: &G2Point,
) -> Fp12 {
    let mut f = Fp12::one(builder);
    let mut r = *q;

    let ate_loop_bits = [
        0,1,1,0,1,0,0,0,0,0,1,1,0,1,0,0,0,0,0,1,0,0,1,1,0,0,0,0,1,0,0,0,0,0,1
    ];

    for (i, bit) in ate_loop_bits.iter().enumerate() {
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
fn final_exponentiation<F: RichField + Extendable<D>, const D: usize>(
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

fn verify_poseidon_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message: &[Target],
    provided_hash: HashOutTarget,
) {
    let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(message.to_vec());
    builder.connect_hashes(computed_hash, provided_hash);
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
