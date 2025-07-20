use p3_mersenne_31::Mersenne31;
use p3_field::Field;

/// 一个简单的 range proof AIR
#[derive(Debug, Clone)]
pub struct RangeProofAir {
    pub x: Mersenne31, // 公共输入，区间上界
}

impl p3_uni_stark::air::Air<Mersenne31> for RangeProofAir {
    fn width(&self) -> usize { 1 }

    fn eval(
        &self,
        _step: usize,
        vars: &[Mersenne31],
        _next_vars: &[Mersenne31],
        constraints: &mut [Mersenne31],
    ) {
        // vars[0] = w
        // 约束：x-w ∈ [1,30]，即 w < x
        let diff = self.x - vars[0];
        constraints[0] = diff;
    }

    fn num_constraints(&self) -> usize { 1 }
    fn public_inputs(&self) -> Vec<Mersenne31> { vec![self.x] }
}

fn main() {
    type F = Mersenne31;
    // witness
    let w = F::from_canonical_u32(7);
    // public input
    let x = F::from_canonical_u32(13);

    // 构造 trace
    let trace = p3_uni_stark::trace::TraceTable::from_vec(vec![vec![w]]);

    let air = RangeProofAir { x };

    // Stark config
    let config = p3_uni_stark::config::StarkConfig::standard_recursion_config();

    // 生成证明
    let proof = p3_uni_stark::prove(&config, &air, trace, &air.public_inputs()).expect("proof should succeed");

    // 验证证明
    p3_uni_stark::verify(&config, &air, &proof, &air.public_inputs()).expect("verify should succeed");

    println!("Range proof verified: w={} < x={}", w, x);
}