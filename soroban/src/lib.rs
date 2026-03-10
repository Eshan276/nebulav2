//! Soroban contract: SPHINCS+ ZK Verifier Wrapper
//!
//! This contract is a thin wrapper around the Nethermind RISC Zero Groth16
//! verifier (github.com/NethermindEth/stellar-risc0-verifier).
//!
//! Flow:
//!   1. Caller provides: seal, image_id, journal, expected pubkey_hash, expected tx_hash
//!   2. We cross-contract-call the Nethermind verifier with (seal, image_id, sha256(journal))
//!   3. If the proof is valid, we check journal == pubkey_hash || tx_hash
//!   4. Emit a Verified event

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Symbol,
    symbol_short,
};

/// Address of the deployed Nethermind RISC Zero Groth16 verifier contract.
/// Set this after deploying: https://github.com/NethermindEth/stellar-risc0-verifier
const VERIFIER_CONTRACT_KEY: Symbol = symbol_short!("VERIFIER");

#[contracttype]
pub enum DataKey {
    VerifierContract,
}

#[contract]
pub struct SphincsVerifier;

#[contractimpl]
impl SphincsVerifier {
    /// Admin: set the Nethermind verifier contract address (call once after deploy)
    pub fn set_verifier(env: Env, verifier: Address) {
        env.storage().instance().set(&DataKey::VerifierContract, &verifier);
    }

    /// Verify a SPHINCS+ signature ZK proof on-chain.
    ///
    /// Arguments:
    ///   seal        — Groth16 proof bytes (from proof.json)
    ///   image_id    — RISC Zero guest image ID (32 bytes, from proof.json)
    ///   journal     — Journal bytes committed by guest: sha256(pubkey) || sha256(tx) (64 bytes)
    ///   pubkey_hash — Expected sha256(sphincs_pubkey) (32 bytes)
    ///   tx_hash     — Expected sha256(stellar_xdr_tx) (32 bytes)
    ///
    /// Returns true if proof is valid and public inputs match.
    /// Panics (traps) on any failure — safe for use as an authorization check.
    pub fn verify_sphincs_tx(
        env: Env,
        seal: Bytes,
        image_id: BytesN<32>,
        journal: Bytes,
        pubkey_hash: BytesN<32>,
        tx_hash: BytesN<32>,
    ) -> bool {
        // 1. Check journal length
        assert!(journal.len() == 64, "journal must be 64 bytes");

        // 2. Reconstruct expected journal from provided hashes
        let mut expected_journal = Bytes::new(&env);
        expected_journal.append(&Bytes::from_array(&env, &pubkey_hash.to_array()));
        expected_journal.append(&Bytes::from_array(&env, &tx_hash.to_array()));
        assert!(journal == expected_journal, "journal does not match pubkey_hash || tx_hash");

        // 3. Compute sha256(journal) — this is what the Nethermind verifier expects as public input
        let journal_hash: BytesN<32> = env.crypto().sha256(&journal);

        // 4. Cross-contract call to Nethermind RISC Zero Groth16 verifier
        //    Interface: verify(seal: Bytes, image_id: BytesN<32>, journal_digest: BytesN<32>)
        let verifier: Address = env
            .storage()
            .instance()
            .get(&DataKey::VerifierContract)
            .expect("verifier contract not set — call set_verifier first");

        let client = NethermindVerifierClient::new(&env, &verifier);
        client.verify(&seal, &image_id, &journal_hash);
        // The Nethermind verifier panics/traps on invalid proof — if we reach here, it's valid.

        // 5. Emit event
        env.events().publish(
            (symbol_short!("sphincs"), symbol_short!("verified")),
            (pubkey_hash.clone(), tx_hash.clone()),
        );

        true
    }
}

// Minimal client for the Nethermind verifier contract
// Matches the interface from github.com/NethermindEth/stellar-risc0-verifier
mod nethermind_verifier {
    use soroban_sdk::{contractclient, Address, Bytes, BytesN, Env};

    #[contractclient(name = "NethermindVerifierClient")]
    pub trait NethermindVerifier {
        fn verify(env: Env, seal: Bytes, image_id: BytesN<32>, journal_digest: BytesN<32>);
    }
}
use nethermind_verifier::NethermindVerifierClient;

#[cfg(test)]
mod test {
    // Integration tests go here — require a local Stellar network or testnet
    // and deployed Nethermind verifier + proof.json artifacts from bridge.py
}
