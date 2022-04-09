use crate::constants::{HEIGHT, OUTPLUSONELOG};
use crate::native::params::PoolParams;
use crate::{
    constants::BATCH_SIZE,
    native::tree_batch::{TreeBatchPub, TreeBatchSec},
};
use fawkes_crypto::circuit::bitify::c_into_bits_le;
use fawkes_crypto::core::signal::Signal;
use fawkes_crypto::ff_uint::Num;
use fawkes_crypto::{
    circuit::{
        bitify::c_from_bits_le,
        bool::CBool,
        cs::{CS, RCS},
        num::CNum,
        poseidon::{c_poseidon, c_poseidon_merkle_proof_root, CMerkleProof},
    },
    core::sizedvec::SizedVec,
    native::poseidon::{poseidon, PoseidonParams},
};

#[derive(Clone, Signal)]
#[Value = "TreeBatchPub<C::Fr>"]
pub struct CTreeBatchPub<C: CS> {
    /// Merkle root of Merkle tree before update
    pub root_before: CNum<C>,
    /// Merkle root of Merkle tree after update
    pub root_after: CNum<C>,
    /// New leafs
    pub leafs: SizedVec<CNum<C>, BATCH_SIZE>,
}

#[derive(Clone, Signal)]
#[Value = "TreeBatchSec<C::Fr>"]
pub struct CTreeBatchSec<C: CS> {
    /// Merkle proof (path and siblings) of previous leaf
    pub proof_filled: CMerkleProof<C, { HEIGHT - OUTPLUSONELOG }>,
    /// Merkle proof (path and siblings) of first new leaf
    pub proof_free: CMerkleProof<C, { HEIGHT - OUTPLUSONELOG }>,
    /// Previous leaf in Merkle tree
    pub prev_leaf: CNum<C>,
}

pub fn tree_batch_update<C: CS, P: PoolParams<Fr = C::Fr>>(
    p: &CTreeBatchPub<C>,
    s: &CTreeBatchSec<C>,
    params: &P,
) {
    // Previous leaf index
    let prev_leaf_index = c_from_bits_le(s.proof_filled.path.as_slice());
    // First new leaf index
    let first_new_leaf_index = c_from_bits_le(s.proof_free.path.as_slice());

    // Zero tree nodes
    let mut default_hashes: Vec<Num<C::Fr>> = vec![Num::ZERO; HEIGHT + 1];
    for i in 0..HEIGHT {
        let t = default_hashes[i];
        default_hashes[i + 1] = poseidon([t, t].as_ref(), params.compress());
    }

    // Zero transaction commitment (merkle root of empty tree with heigth equals OUTPLUSONELOG)
    let zero_leaf = default_hashes[OUTPLUSONELOG];
    let zero_leaf: CNum<C> = p.derive_const(&zero_leaf);

    // Zero full Merkle tree root (merkle root of empty tree with heigth equals HEIGHT)
    let zero_root_value = default_hashes[HEIGHT];

    // Zero tree nodes of transactions Merkle tree
    let default_hashes = default_hashes
        .into_iter()
        .skip(OUTPLUSONELOG)
        .map(|h| p.derive_const(&h))
        .collect();

    // Compute Merkle root with previous leaf on place of previous index
    let root_with_prev_leaf = c_poseidon_merkle_proof_root(&s.prev_leaf, &s.proof_filled, params.compress());
    // Merkle root with previous leaf on place of previous index equals Merkle root before update
    let prev_leaf_corresponds_to_root_before = (root_with_prev_leaf - &p.root_before).is_zero();

    // Index of first new leaf is next to previous leaf index
    let cur_index_is_next_to_previous = (prev_leaf_index + Num::ONE - &first_new_leaf_index).is_zero();

    // Previous leaf is not zero leaf
    let prev_leaf_is_not_empty = !(&s.prev_leaf - &zero_leaf).is_zero();

    // Merkle root before update is root of zero Merkle tree
    let empty_tree = (&p.root_before - zero_root_value).is_zero();

    // For zero Merkle tree first new leaf index must be zero
    let first_new_leaf_index_is_zero = first_new_leaf_index.is_zero();

    // 1. First check
    // Previous leaf is not empty AND previous leaf corresponds to Merkle root before update AND first new leaf index is next to previous leaf index
    // OR
    // Previous Merkle root equals Merkle root of zero Merkle tree AND first new leaf index equals zero
    ((prev_leaf_corresponds_to_root_before
        & prev_leaf_is_not_empty
        & cur_index_is_next_to_previous)
        | empty_tree & first_new_leaf_index_is_zero)
        .assert_const(&true);

    // Compute Merkle root with zero leaf on place of first new leaf
    let computed_root_before =
        c_poseidon_merkle_proof_root(&zero_leaf, &s.proof_free, params.compress());

    // 2. Second check
    // Merkle root with zero leaf on place of first new leaf equals Merkle root before update
    (computed_root_before - &p.root_before).assert_zero();

    // Merkle root with sequential addition of new leafs
    let computed_root_after = c_poseidon_merkle_proof_root_batch(
        &p.leafs,
        &s.proof_free,
        &default_hashes,
        params.compress(),
    );

    // 3. Third check
    // Merkle root with sequential addition of new leafs equals new Merkle root
    (computed_root_after - &p.root_after).assert_zero();
}

pub fn c_poseidon_merkle_proof_root_batch<C: CS, const L: usize>(
    leafs: &SizedVec<CNum<C>, BATCH_SIZE>,
    proof: &CMerkleProof<C, L>,
    default_hashes: &Vec<CNum<C>>,
    params: &PoseidonParams<C::Fr>,
) -> CNum<C> {
    let mut index = c_from_bits_le(proof.path.as_slice());
    let mut left_nodes = proof.sibling.as_slice().to_vec();

    let mut root = default_hashes[0].clone();
    for leaf in leafs.iter() {
        let path = c_into_bits_le(&index, HEIGHT - OUTPLUSONELOG);
        
        root = leaf.clone();
        for (height, is_right) in path.iter().enumerate() {
            let sibling = left_nodes[height].switch(is_right, &default_hashes[height]);
            let first = sibling.switch(is_right, &root);
            let second = &root + sibling - &first;

            left_nodes[height] = left_nodes[height].switch(is_right, &root);
            root = c_poseidon([first, second].as_ref(), params);
        }
        index += Num::ONE;
    }
    root
}
