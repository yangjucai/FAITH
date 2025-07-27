use plonky2::{
    field::{extension::Extendable},
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
    },
};

pub fn verify_poseidon_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message: &[Target],
    provided_hash: HashOutTarget,
) {
    let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(message.to_vec());
    builder.connect_hashes(computed_hash, provided_hash);
}
