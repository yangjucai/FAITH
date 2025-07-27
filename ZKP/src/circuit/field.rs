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

// Fp2 结构
#[derive(Clone, Copy)]
pub(crate) struct Fp2 {
    pub(crate) c0: Target,
    pub(crate) c1: Target,
}

impl Fp2 {
    pub fn new(c0: Target, c1: Target) -> Self {
        Self { c0, c1 }
    }

    pub fn zero<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let zero = builder.constant(F::ZERO);
        Self::new(zero, zero)
    }

    // Fp2 乘法 (a + bu)(c + du) = (ac - bd) + (ad + bc)u
    pub fn mul<F: RichField + Extendable<D>, const D: usize>(
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
    pub fn add<F: RichField + Extendable<D>, const D: usize>(
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
    pub fn neg<F: RichField + Extendable<D>, const D: usize>(
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
    pub fn inverse<F: RichField + Extendable<D>, const D: usize>(
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

    pub fn mul_scalar<F: RichField + Extendable<D>, const D: usize>(
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
pub(crate) struct Fp6 {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,
}

impl Fp6 {
    pub fn new(c0: Fp2, c1: Fp2, c2: Fp2) -> Self {
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
    pub fn add<F: RichField + Extendable<D>, const D: usize>(
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
    pub fn sub<F: RichField + Extendable<D>, const D: usize>(
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
    pub fn mul<F: RichField + Extendable<D>, const D: usize>(
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
    pub fn mul_by_nonresidue<F: RichField + Extendable<D>, const D: usize>(
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

    pub fn neg<F: RichField + Extendable<D>, const D: usize>(
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
pub(crate) struct Fp12 {
    c0: Fp6,
    c1: Fp6,
}

impl Fp12 {
    pub fn new(c0: Fp6, c1: Fp6) -> Self {
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
