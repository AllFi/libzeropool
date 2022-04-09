use fawkes_crypto::core::sizedvec::SizedVec;

use crate::{
    fawkes_crypto::{
        native::poseidon::MerkleProof,
        ff_uint::{Num, PrimeField},
        borsh::{self, BorshSerialize, BorshDeserialize},
    },
    constants::{HEIGHT, OUTPLUSONELOG, BATCH_SIZE}
};


use std::fmt::Debug;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TreeBatchPub<Fr:PrimeField> {
    pub root_before: Num<Fr>,
    pub root_after: Num<Fr>,
    pub leafs: SizedVec<Num<Fr>, BATCH_SIZE>
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct TreeBatchSec<Fr:PrimeField> {
    pub proof_filled:MerkleProof<Fr, {HEIGHT - OUTPLUSONELOG}>,
    pub proof_free:MerkleProof<Fr, {HEIGHT - OUTPLUSONELOG}>,
    pub prev_leaf:Num<Fr>
}