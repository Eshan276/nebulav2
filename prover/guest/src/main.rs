// RISC Zero Guest — runs inside the zkVM
// Proves: "I verified a valid SPHINCS+ (SLH-DSA-SHAKE-128f) signature over tx_bytes"
// Commits to journal: sha256(pubkey) || sha256(tx_bytes)  (64 bytes)

#![no_main]

use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use slh_dsa::{Shake128f, VerifyingKey};
use slh_dsa::signature::Verifier;

risc0_zkvm::guest::entry!(main);


#[derive(serde::Deserialize)]
struct Inputs {
    public_key: Vec<u8>,
    tx_bytes: Vec<u8>,
    signature: Vec<u8>,
}

fn main() {
    // Read inputs from host (not part of the proof — private witness)
    let inputs: Inputs = env::read();

    // Parse the verifying key
    let vk = VerifyingKey::<Shake128f>::try_from(inputs.public_key.as_slice())
        .expect("invalid public key");

    // Parse the signature
    let sig = slh_dsa::Signature::<Shake128f>::try_from(inputs.signature.as_slice())
        .expect("invalid signature");

    // Verify — panics (and thus fails proof generation) if invalid
    vk.verify(&inputs.tx_bytes, &sig)
        .expect("SPHINCS+ signature verification failed");

    // Commit public outputs to journal: sha256(pubkey) || sha256(tx_bytes)
    let pubkey_hash: [u8; 32] = Sha256::digest(&inputs.public_key).into();
    let tx_hash: [u8; 32] = Sha256::digest(&inputs.tx_bytes).into();

    let mut journal = Vec::with_capacity(64);
    journal.extend_from_slice(&pubkey_hash);
    journal.extend_from_slice(&tx_hash);

    env::commit_slice(&journal);
}
