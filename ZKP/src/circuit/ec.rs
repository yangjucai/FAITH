use plonky2::{
    field::{extension::Extendable},
    hash::{
        hash_types::{RichField},
    },
    iop::{
        target::Target,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
    },
};
use crate::circuit::field::Fp2;

// G1 点结构（在 Fp 上）
#[derive(Clone, Copy)]
pub struct G1Point {
    pub(crate) x: Target,
    pub(crate) y: Target,
}

impl G1Point {
    pub fn new(x: Target, y: Target) -> Self {
        Self { x, y }
    }

    pub fn add<F: RichField + Extendable<D>, const D: usize>(
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
    pub fn double<F: RichField + Extendable<D>, const D: usize>(
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
pub struct G2Point {
    pub(crate) x: Fp2,
    pub(crate) y: Fp2,
}

impl G2Point {
    pub fn new(x: Fp2, y: Fp2) -> Self {
        Self { x, y }
    }

    /// G2 点加法 (简化，仿射坐标)
    pub fn add<F: RichField + Extendable<D>, const D: usize>(
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
    pub fn double<F: RichField + Extendable<D>, const D: usize>(
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
