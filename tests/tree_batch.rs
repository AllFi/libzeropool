use fawkes_crypto::{
    backend::bellman_groth16::{engines::Bn256, prover, setup::setup, verifier},
    engines::bn256::Fr,
    rand::Rng,
};
use libzeropool::{
    circuit::{
        tree::{tree_update, CTreePub, CTreeSec},
        tree_batch::{tree_batch_update, CTreeBatchPub, CTreeBatchSec},
    },
    constants::BATCH_SIZE,
    fawkes_crypto::{
        circuit::cs::{CS},
        rand::thread_rng,
    },
    native::{
        tree::{TreePub, TreeSec},
        tree_batch::{TreeBatchPub, TreeBatchSec},
    },
    POOL_PARAMS,
};

use std::time::Instant;

use libzeropool::helpers::sample_data::HashTreeState;

#[test]
fn test_tree_update_setup_and_prove() {
    println!("BATCH_SIZE is: {:?}", BATCH_SIZE);

    fn circuit<C: CS<Fr = Fr>>(public: CTreePub<C>, secret: CTreeSec<C>) {
        tree_update(&public, &secret, &*POOL_PARAMS);
    }

    let ts_setup = Instant::now();
    let params = setup::<Bn256, _, _, _>(circuit);
    let duration = ts_setup.elapsed();
    println!("Time elapsed in setup() is: {:?}", duration);

    let mut rng = thread_rng();
    let mut state = HashTreeState::new(&*POOL_PARAMS);
    let mut num_elements: usize = rng.gen_range(1, 1000);

    for _ in 0..num_elements {
        state.push(rng.gen(), &*POOL_PARAMS);
    }

    let mut tree_pubs = Vec::new();
    let mut tree_secs = Vec::new();
    for _ in 0..BATCH_SIZE {
        let root_before = state.root();
        let proof_filled = state.merkle_proof(num_elements - 1);
        let proof_free = state.merkle_proof(num_elements);
        let prev_leaf = state.hashes[0].last().unwrap().clone();
        state.push(rng.gen(), &*POOL_PARAMS);
        let root_after = state.root();
        let leaf = state.hashes[0].last().unwrap().clone();

        let p = TreePub {
            root_before,
            root_after,
            leaf,
        };
        let s = TreeSec {
            proof_filled,
            proof_free,
            prev_leaf,
        };

        tree_pubs.push(p);
        tree_secs.push(s);
        num_elements += 1;
    }

    let ts_prove = Instant::now();
    let mut proofs = Vec::new();
    for (public, secret) in tree_pubs.iter().zip(tree_secs.iter()) {
        let (inputs, snark_proof) = prover::prove(&params, public, secret, circuit);
        proofs.push((inputs, snark_proof));
    }
    let duration = ts_prove.elapsed();
    println!("Time elapsed in prove() is: {:?}", duration);

    let ts_verify = Instant::now();
    for (inputs, snark_proof) in proofs {
        let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
        assert!(res, "Verifier result should be true");
    }
    let duration = ts_verify.elapsed();
    println!("Time elapsed in verify() is: {:?}", duration);
}

#[test]
fn test_tree_update_setup_and_prove_batch() {
    fn circuit<C: CS<Fr = Fr>>(public: CTreeBatchPub<C>, secret: CTreeBatchSec<C>) {
        tree_batch_update(&public, &secret, &*POOL_PARAMS);
    }

    let mut rng = thread_rng();
    let mut state = HashTreeState::new(&*POOL_PARAMS);
    let num_elements: usize = rng.gen_range(1, 1000);

    for _ in 0..num_elements {
        state.push(rng.gen(), &*POOL_PARAMS);
    }

    let root_before = state.root();
    let proof_filled = state.merkle_proof(num_elements - 1);
    let proof_free = state.merkle_proof(num_elements);
    let prev_leaf = state.hashes[0].last().unwrap().clone();

    let mut leafs = Vec::new();
    for _ in 0..BATCH_SIZE {
        state.push(rng.gen(), &*POOL_PARAMS);
        let leaf = state.hashes[0].last().unwrap().clone();
        leafs.push(leaf);
    }
    let root_after = state.root();
    let leafs = leafs.into_iter().collect();

    let p = TreeBatchPub {
        root_before,
        root_after,
        leafs,
    };
    let s = TreeBatchSec {
        proof_filled,
        proof_free,
        prev_leaf,
    };

    let ts_setup = Instant::now();
    let params = setup::<Bn256, _, _, _>(circuit);
    let duration = ts_setup.elapsed();
    println!("Time elapsed in setup() is: {:?}", duration);

    let ts_prove = Instant::now();
    let (inputs, snark_proof) = prover::prove(&params, &p, &s, circuit);
    let duration = ts_prove.elapsed();
    println!("Time elapsed in prove() is: {:?}", duration);

    let ts_verify = Instant::now();
    let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
    assert!(res, "Verifier result should be true");
    let duration = ts_verify.elapsed();
    println!("Time elapsed in verify() is: {:?}", duration);
}