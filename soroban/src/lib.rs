// Soroban contract: XMSS Post-Quantum Wallet
//
// A smart wallet where ownership is proven via XMSS-SHA2_10_256 signature,
// verified on-chain via SP1 Groth16 ZK proof (v4.0.0-rc.3 circuit).
//
// ── Wallet model ─────────────────────────────────────────────────────────────
//
//   Identity  = sha256(xmss_pubkey)   [32 bytes, stored as wallet key]
//   Balance   = i128 stroops (XLM)
//   Nonce     = u32  (XMSS leaf index; increments per withdrawal)
//
// ── Public values committed by SP1 guest ─────────────────────────────────────
//
//   [0..32]  pubkey_hash = sha256(xmss_pubkey)
//   [32..64] tx_hash     = sha256(tx_bytes)
//   [64..68] nonce       = leaf_index as LE u32
//   Total: 68 bytes
//
// ── tx_bytes format (what the user signs, 108 bytes) ─────────────────────────
//
//   [0..32]  contract_id   = this contract's address bytes
//   [32..64] pubkey_hash   = sha256(xmss_pubkey)
//   [64..68] nonce         = wallet nonce as LE u32
//   [68..100] destination  = destination Stellar address bytes (32)
//   [100..108] amount      = i64 stroops as BE 8 bytes
//
//   The contract recomputes this and checks tx_hash == sha256(tx_bytes).
//   The user cannot forge a different destination or amount.
//
// ── SP1 Groth16 proof format (proof_bytes, 260 bytes) ────────────────────────
//
//   [0..4]    selector = first 4 bytes of groth16_vkey_hash
//   [4..68]   A: G1 point (X||Y, each 32 bytes BE)
//   [68..196] B: G2 point (X.c1||X.c0||Y.c1||Y.c0, each 32 bytes BE)
//   [196..260] C: G1 point (X||Y, each 32 bytes BE)
//
// ── VK from sp1-contracts/v4.0.0-rc.3/Groth16Verifier.sol ───────────────────

#![no_std]

use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Vec,
    token::TokenClient,
    xdr::ToXdr,
};
use soroban_sdk::crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr};

// ── VK constants (SP1 v4.0.0-rc.3) ──────────────────────────────────────────
// G1 = X(32B) || Y(32B)
// G2 = X.c1(32B) || X.c0(32B) || Y.c1(32B) || Y.c0(32B)  [Soroban: imaginary first]

// ALPHA_G1
// X = 20491192805390485299153009773594534940189261866228447918068658471970481763042
// Y = 9383485363053290200918347156157836566562967994039712273449902621266178545958
const ALPHA_G1_BYTES: [u8; 64] = [
    0x2d, 0x4d, 0x9a, 0xa7, 0xe3, 0x02, 0xd9, 0xdf,
    0x41, 0x74, 0x9d, 0x55, 0x07, 0x94, 0x9d, 0x05,
    0xdb, 0xea, 0x33, 0xfb, 0xb1, 0x6c, 0x64, 0x3b,
    0x22, 0xf5, 0x99, 0xa2, 0xbe, 0x6d, 0xf2, 0xe2,
    0x14, 0xbe, 0xdd, 0x50, 0x3c, 0x37, 0xce, 0xb0,
    0x61, 0xd8, 0xec, 0x60, 0x20, 0x9f, 0xe3, 0x45,
    0xce, 0x89, 0x83, 0x0a, 0x19, 0x23, 0x03, 0x01,
    0xf0, 0x76, 0xca, 0xff, 0x00, 0x4d, 0x19, 0x26,
];

// BETA_NEG_G2
// X_1 = 4252822878758300859123897981450591353533073413197771768651442665752259397132
// X_0 = 6375614351688725206403948262868962793625744043794305715222011528459656738731
// Y_1 = 41207766310529818958173054109690360505148424997958324311878202295167071904
// Y_0 = 11383000245469012944693504663162918391286475477077232690815866754273895001727
const BETA_NEG_G2_BYTES: [u8; 128] = [
    // X.c1 = X_1
    0x09, 0x67, 0x03, 0x2f, 0xcb, 0xf7, 0x76, 0xd1,
    0xaf, 0xc9, 0x85, 0xf8, 0x88, 0x77, 0xf1, 0x82,
    0xd3, 0x84, 0x80, 0xa6, 0x53, 0xf2, 0xde, 0xca,
    0xa9, 0x79, 0x4c, 0xbc, 0x3b, 0xf3, 0x06, 0x0c,
    // X.c0 = X_0
    0x0e, 0x18, 0x78, 0x47, 0xad, 0x4c, 0x79, 0x83,
    0x74, 0xd0, 0xd6, 0x73, 0x2b, 0xf5, 0x01, 0x84,
    0x7d, 0xd6, 0x8b, 0xc0, 0xe0, 0x71, 0x24, 0x1e,
    0x02, 0x13, 0xbc, 0x7f, 0xc1, 0x3d, 0xb7, 0xab,
    // Y.c1 = Y_1
    0x00, 0x17, 0x52, 0xa1, 0x00, 0xa7, 0x2f, 0xdf,
    0x1e, 0x5a, 0x5d, 0x6e, 0xa8, 0x41, 0xcc, 0x20,
    0xec, 0x83, 0x8b, 0xcc, 0xfc, 0xf7, 0xbd, 0x55,
    0x9e, 0x79, 0xf1, 0xc9, 0xc7, 0x59, 0xb6, 0xa0,
    // Y.c0 = Y_0
    0x19, 0x2a, 0x8c, 0xc1, 0x3c, 0xd9, 0xf7, 0x62,
    0x87, 0x1f, 0x21, 0xe4, 0x34, 0x51, 0xc6, 0xca,
    0x9e, 0xea, 0xb2, 0xcb, 0x29, 0x87, 0xc4, 0xe3,
    0x66, 0xa1, 0x85, 0xc2, 0x5d, 0xac, 0x2e, 0x7f,
];

// GAMMA_NEG_G2
// X_1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634
// X_0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781
// Y_1 = 17805874995975841540914202342111839520379459829704422454583296818431106115052
// Y_0 = 13392588948715843804641432497768002650278120570034223513918757245338268106653
const GAMMA_NEG_G2_BYTES: [u8; 128] = [
    // X.c1
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a,
    0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12,
    0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    // X.c0
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76,
    0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd,
    0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    // Y.c1
    0x27, 0x5d, 0xc4, 0xa2, 0x88, 0xd1, 0xaf, 0xb3,
    0xcb, 0xb1, 0xac, 0x09, 0x18, 0x75, 0x24, 0xc7,
    0xdb, 0x36, 0x39, 0x5d, 0xf7, 0xbe, 0x3b, 0x99,
    0xe6, 0x73, 0xb1, 0x3a, 0x07, 0x5a, 0x65, 0xec,
    // Y.c0
    0x1d, 0x9b, 0xef, 0xcd, 0x05, 0xa5, 0x32, 0x3e,
    0x6d, 0xa4, 0xd4, 0x35, 0xf3, 0xb6, 0x17, 0xcd,
    0xb3, 0xaf, 0x83, 0x28, 0x5c, 0x2d, 0xf7, 0x11,
    0xef, 0x39, 0xc0, 0x15, 0x71, 0x82, 0x7f, 0x9d,
];

// DELTA_NEG_G2
// X_1 = 17270349666695681994109533429817368669497520119106681015856196115021033411091
// X_0 = 19629295988673812457237747993086053613709181874324227239033635205670891327060
// Y_1 = 12217031863885588059779845498016696484811402332435719653934590968575679828494
// Y_0 = 14281790459332470419125837541415772351574094165485379719795056490664770278727
const DELTA_NEG_G2_BYTES: [u8; 128] = [
    // X.c1
    0x26, 0x2e, 0xab, 0xe8, 0x15, 0x11, 0xaa, 0x8e,
    0x30, 0x34, 0xcb, 0xd7, 0x5d, 0x42, 0xe7, 0x08,
    0xaa, 0x4e, 0xd8, 0x03, 0x03, 0xfb, 0x0e, 0x4f,
    0xb9, 0x0c, 0xd0, 0xff, 0x6e, 0x90, 0x92, 0x13,
    // X.c0
    0x2b, 0x65, 0xc9, 0xae, 0x26, 0x05, 0xf3, 0xef,
    0x55, 0x40, 0xd3, 0xa6, 0x45, 0x03, 0xc8, 0x4f,
    0xe5, 0xe1, 0xd9, 0xec, 0x6e, 0xb1, 0xbd, 0x3a,
    0x90, 0x6b, 0xbc, 0x80, 0x83, 0x0e, 0x8e, 0x54,
    // Y.c1
    0x1b, 0x02, 0x98, 0x51, 0x53, 0xa1, 0xb7, 0x79,
    0xa4, 0x56, 0xc3, 0xc6, 0x5b, 0xee, 0x53, 0xbd,
    0x53, 0xef, 0xcc, 0xee, 0xc1, 0x0a, 0x7f, 0x53,
    0xbe, 0x8f, 0xaa, 0x0b, 0xd6, 0xc8, 0x92, 0x0e,
    // Y.c0
    0x1f, 0x93, 0x34, 0xfa, 0x25, 0x56, 0x61, 0x9b,
    0x13, 0x0c, 0x61, 0xd8, 0x3e, 0xd5, 0x5c, 0x12,
    0xe4, 0x50, 0xf8, 0xf5, 0xc5, 0x42, 0xa1, 0x39,
    0xc9, 0x72, 0x6c, 0xd3, 0x10, 0xae, 0x15, 0x47,
];

// IC[0]
// X = 6712036353136249806951869451908368653566549662781372756321174254690599374583
// Y = 18149145036868871064182651529802275370638950642742152190925800889169295968585
const IC0_BYTES: [u8; 64] = [
    0x0e, 0xd6, 0xe0, 0xc1, 0x3f, 0x35, 0x32, 0x62,
    0xae, 0x2d, 0xbb, 0xe4, 0x9c, 0xe6, 0xa0, 0xb6,
    0x75, 0x76, 0xd3, 0x8a, 0xaf, 0x59, 0x58, 0x56,
    0x4b, 0xe7, 0x64, 0x83, 0x56, 0x83, 0x0e, 0xf7,
    0x28, 0x20, 0x0d, 0x54, 0x01, 0x35, 0x65, 0xdc,
    0xa1, 0x96, 0x84, 0x1d, 0x0a, 0x3c, 0xd7, 0xa5,
    0xf6, 0x75, 0x31, 0xf9, 0x74, 0x87, 0x72, 0xf5,
    0x53, 0xe1, 0xe9, 0x84, 0x5f, 0x6c, 0x09, 0x49,
];

// IC[1]  (for programVKey / pub_input[0])
// X = 12384021290558951773126140100379496012525836638155233096890881157449062205923
// Y = 16530732960917040406371332977337573092100509754908292717547628595948196259098
const IC1_BYTES: [u8; 64] = [
    0x1b, 0x61, 0x1b, 0x8f, 0x69, 0x6f, 0x28, 0xff,
    0xb6, 0x25, 0x0c, 0x7f, 0xfa, 0xc6, 0x6e, 0xfb,
    0xd6, 0x38, 0xd9, 0x7f, 0x0d, 0x6c, 0x84, 0x3c,
    0x23, 0x69, 0x1c, 0x3a, 0xf5, 0x32, 0xc9, 0xe3,
    0x24, 0x8c, 0x10, 0x33, 0xbd, 0x73, 0xc4, 0xff,
    0x82, 0x0d, 0x48, 0x0a, 0x37, 0xb3, 0x9c, 0xa6,
    0xef, 0x17, 0x85, 0x43, 0xc5, 0xc9, 0x19, 0x04,
    0x59, 0xe8, 0xcf, 0xe3, 0x6c, 0x48, 0xe5, 0x1a,
];

// IC[2]  (for committed_values_digest / pub_input[1])
// X = 18749839173537272836199384751191600551090725238737491530604969678014545165197
// Y = 1828450848853234449784725988911172793808451038026258152543319358376349553777
const IC2_BYTES: [u8; 64] = [
    0x29, 0x74, 0x08, 0x6b, 0xde, 0x6c, 0x91, 0x26,
    0x7b, 0x20, 0x11, 0x37, 0xcf, 0xe6, 0xee, 0x8c,
    0xd5, 0x0f, 0xf0, 0xa3, 0xda, 0x86, 0x1e, 0x80,
    0x85, 0x03, 0xe7, 0xdf, 0x4d, 0xa8, 0x7b, 0x8d,
    0x04, 0x0a, 0xdd, 0xd3, 0x59, 0x13, 0xf1, 0x1e,
    0xa6, 0x84, 0x6f, 0x0d, 0x58, 0x31, 0x26, 0xba,
    0xb9, 0xe8, 0xf8, 0xae, 0x69, 0x79, 0x7d, 0x4c,
    0x2c, 0x7f, 0x19, 0x5b, 0xe0, 0x78, 0x54, 0x71,
];

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    ProgramVKey,
    XlmToken,
    Balance(BytesN<32>),  // pubkey_hash → i128
    Nonce(BytesN<32>),    // pubkey_hash → u32
}

// ── Events ────────────────────────────────────────────────────────────────────

#[contractevent]
pub struct DepositEvent {
    pub pubkey_hash: BytesN<32>,
    pub amount: i128,
    pub new_balance: i128,
}

#[contractevent]
pub struct WithdrawEvent {
    pub pubkey_hash: BytesN<32>,
    pub destination: Address,
    pub amount: i128,
    pub new_balance: i128,
    pub new_nonce: u32,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct XmssWallet;

#[contractimpl]
impl XmssWallet {
    /// Initialize the contract. Call once after deploy.
    ///
    /// program_vkey: 32-byte SP1 program vkey (pub_inputs[0] as BE bytes)
    /// xlm_token:    address of the XLM Stellar Asset Contract
    pub fn init(env: Env, program_vkey: BytesN<32>, xlm_token: Address) {
        env.storage().instance().set(&DataKey::ProgramVKey, &program_vkey);
        env.storage().instance().set(&DataKey::XlmToken, &xlm_token);
    }

    /// Deposit XLM into a PQ wallet identified by pubkey_hash.
    ///
    /// Transfers `amount` stroops from `from` to this contract, then credits
    /// the wallet. Caller must authorize this call (standard Soroban auth).
    ///
    /// Anyone can deposit to any pubkey_hash (like sending to an address).
    pub fn deposit(env: Env, from: Address, pubkey_hash: BytesN<32>, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        from.require_auth();

        let token = Self::xlm_token(&env);
        TokenClient::new(&env, &token).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );

        let bal = Self::balance_of(&env, &pubkey_hash);
        let new_bal = bal + amount;
        env.storage().persistent().set(&DataKey::Balance(pubkey_hash.clone()), &new_bal);

        DepositEvent { pubkey_hash, amount, new_balance: new_bal }.publish(&env);
    }

    /// Return the tx_bytes the user must sign for a withdrawal.
    ///
    /// tx_bytes = contract_id(32) || pubkey_hash(32) || nonce(4 LE) || destination_bytes(32) || amount(8 BE)
    ///          = 108 bytes
    ///
    /// This is a view function — it does not change state.
    /// Feed the returned hex to `xmss sign --tx <hex>`.
    pub fn get_withdraw_msg(
        env: Env,
        pubkey_hash: BytesN<32>,
        destination: Address,
        amount: i128,
    ) -> Bytes {
        let nonce = Self::nonce_of(&env, &pubkey_hash);
        Self::build_tx_bytes(&env, &pubkey_hash, &destination, amount, nonce)
    }

    /// Execute a withdrawal.
    ///
    /// proof_bytes:   260 bytes — SP1 Groth16 proof
    /// public_values: 68 bytes  — pubkey_hash(32) || tx_hash(32) || nonce(4 LE u32)
    /// destination:   Stellar address to receive funds
    /// amount:        stroops to withdraw (must match what was signed)
    pub fn withdraw(
        env: Env,
        proof_bytes: Bytes,
        public_values: Bytes,
        destination: Address,
        amount: i128,
    ) {
        assert!(amount > 0, "amount must be positive");
        assert!(public_values.len() == 68, "public_values must be 68 bytes");

        // ── Parse public_values ───────────────────────────────────────────────
        let pubkey_hash: BytesN<32> = public_values.slice(0..32).try_into()
            .unwrap_or_else(|_| panic!("pubkey_hash"));
        let proof_tx_hash: BytesN<32> = public_values.slice(32..64).try_into()
            .unwrap_or_else(|_| panic!("tx_hash"));

        let mut nb = [0u8; 4];
        for i in 0..4u32 {
            nb[i as usize] = public_values.get(64 + i).unwrap();
        }
        let proof_nonce = u32::from_le_bytes(nb);

        // ── Check nonce matches wallet state ──────────────────────────────────
        let wallet_nonce = Self::nonce_of(&env, &pubkey_hash);
        assert!(proof_nonce == wallet_nonce, "nonce mismatch");

        // ── Recompute tx_bytes and check tx_hash ──────────────────────────────
        let expected_tx_bytes = Self::build_tx_bytes(&env, &pubkey_hash, &destination, amount, wallet_nonce);
        let expected_tx_hash = env.crypto().sha256(&expected_tx_bytes);
        let expected_tx_hash_n: BytesN<32> = expected_tx_hash.into();
        assert!(proof_tx_hash == expected_tx_hash_n, "tx_hash mismatch: wrong destination or amount");

        // ── Verify ZK proof ───────────────────────────────────────────────────
        let program_vkey: BytesN<32> = env.storage().instance()
            .get(&DataKey::ProgramVKey)
            .unwrap_or_else(|| panic!("call init first"));
        Self::groth16_verify(&env, &proof_bytes, &public_values, &program_vkey);

        // ── Check balance ─────────────────────────────────────────────────────
        let bal = Self::balance_of(&env, &pubkey_hash);
        assert!(bal >= amount, "insufficient balance");

        // ── State transition ──────────────────────────────────────────────────
        let new_bal = bal - amount;
        let new_nonce = wallet_nonce + 1;

        env.storage().persistent().set(&DataKey::Balance(pubkey_hash.clone()), &new_bal);
        env.storage().persistent().set(&DataKey::Nonce(pubkey_hash.clone()), &new_nonce);

        // ── Transfer funds ────────────────────────────────────────────────────
        let token = Self::xlm_token(&env);
        TokenClient::new(&env, &token).transfer(
            &env.current_contract_address(),
            &destination,
            &amount,
        );

        WithdrawEvent {
            pubkey_hash,
            destination,
            amount,
            new_balance: new_bal,
            new_nonce,
        }.publish(&env);
    }

    /// Returns the XLM balance (in stroops) for a pubkey_hash.
    pub fn balance(env: Env, pubkey_hash: BytesN<32>) -> i128 {
        Self::balance_of(&env, &pubkey_hash)
    }

    /// Returns the current nonce for a pubkey_hash.
    pub fn nonce(env: Env, pubkey_hash: BytesN<32>) -> u32 {
        Self::nonce_of(&env, &pubkey_hash)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn xlm_token(env: &Env) -> Address {
        env.storage().instance()
            .get(&DataKey::XlmToken)
            .unwrap_or_else(|| panic!("call init first"))
    }

    fn balance_of(env: &Env, pubkey_hash: &BytesN<32>) -> i128 {
        env.storage().persistent()
            .get(&DataKey::Balance(pubkey_hash.clone()))
            .unwrap_or(0i128)
    }

    fn nonce_of(env: &Env, pubkey_hash: &BytesN<32>) -> u32 {
        env.storage().persistent()
            .get(&DataKey::Nonce(pubkey_hash.clone()))
            .unwrap_or(0u32)
    }

    /// Build the 108-byte tx_bytes that the user must sign.
    ///
    /// contract_id(32) || pubkey_hash(32) || nonce(4 LE) || destination(32) || amount(8 BE)
    fn build_tx_bytes(
        env: &Env,
        pubkey_hash: &BytesN<32>,
        destination: &Address,
        amount: i128,
        nonce: u32,
    ) -> Bytes {
        let mut tx = Bytes::new(env);

        // contract_id: 32 bytes (XDR = 4-byte discriminant + 32-byte hash, take [4..36])
        let contract_id: BytesN<32> = env.current_contract_address().to_xdr(env)
            .slice(4..36)
            .try_into()
            .unwrap_or_else(|_| panic!("contract_id"));
        tx.append(&Bytes::from(contract_id.clone()));

        // pubkey_hash: 32 bytes
        tx.append(&Bytes::from(pubkey_hash.clone()));

        // nonce: 4 bytes LE
        let nonce_bytes = nonce.to_le_bytes();
        let nonce_b: BytesN<4> = BytesN::from_array(env, &nonce_bytes);
        tx.append(&Bytes::from(nonce_b));

        // destination: 32 bytes (XDR = 4-byte discriminant + 32-byte key, take [4..36])
        let dest_xdr = destination.to_xdr(env);
        let dest_bytes: BytesN<32> = dest_xdr.slice(4..36).try_into()
            .unwrap_or_else(|_| panic!("dest"));
        tx.append(&Bytes::from(dest_bytes));

        // amount: 8 bytes BE (i64 range is enough for XLM)
        let amount_bytes = (amount as i64).to_be_bytes();
        let amount_b: BytesN<8> = BytesN::from_array(env, &amount_bytes);
        tx.append(&Bytes::from(amount_b));

        tx
    }

    /// Core Groth16 verification using Soroban BN254 host functions.
    fn groth16_verify(
        env: &Env,
        proof_bytes: &Bytes,
        public_values: &Bytes,
        program_vkey: &BytesN<32>,
    ) {
        assert!(proof_bytes.len() == 260, "proof must be 260 bytes");

        let a: Bn254G1Affine = Bn254G1Affine::from_bytes(
            proof_bytes.slice(4..68).try_into().unwrap_or_else(|_| panic!("A"))
        );
        let b: Bn254G2Affine = Bn254G2Affine::from_bytes(
            proof_bytes.slice(68..196).try_into().unwrap_or_else(|_| panic!("B"))
        );
        let c: Bn254G1Affine = Bn254G1Affine::from_bytes(
            proof_bytes.slice(196..260).try_into().unwrap_or_else(|_| panic!("C"))
        );

        let input0 = Fr::from_bytes(program_vkey.clone());

        let pv_hash = env.crypto().sha256(public_values);
        let mut pv_arr = pv_hash.to_array();
        pv_arr[0] &= 0x1f;
        let input1 = Fr::from_bytes(BytesN::<32>::from_array(env, &pv_arr));

        let alpha  = Bn254G1Affine::from_bytes(BytesN::<64>::from_array(env, &ALPHA_G1_BYTES));
        let beta   = Bn254G2Affine::from_bytes(BytesN::<128>::from_array(env, &BETA_NEG_G2_BYTES));
        let gamma  = Bn254G2Affine::from_bytes(BytesN::<128>::from_array(env, &GAMMA_NEG_G2_BYTES));
        let delta  = Bn254G2Affine::from_bytes(BytesN::<128>::from_array(env, &DELTA_NEG_G2_BYTES));
        let ic0    = Bn254G1Affine::from_bytes(BytesN::<64>::from_array(env, &IC0_BYTES));
        let ic1    = Bn254G1Affine::from_bytes(BytesN::<64>::from_array(env, &IC1_BYTES));
        let ic2    = Bn254G1Affine::from_bytes(BytesN::<64>::from_array(env, &IC2_BYTES));

        let bn254 = env.crypto().bn254();
        let vk_x = ic0 + bn254.g1_mul(&ic1, &input0) + bn254.g1_mul(&ic2, &input1);

        // e(A, B) * e(alpha, BETA_NEG) * e(vk_x, GAMMA_NEG) * e(C, DELTA_NEG) == 1
        let mut g1_vec: Vec<Bn254G1Affine> = Vec::new(env);
        g1_vec.push_back(a);
        g1_vec.push_back(alpha);
        g1_vec.push_back(vk_x);
        g1_vec.push_back(c);

        let mut g2_vec: Vec<Bn254G2Affine> = Vec::new(env);
        g2_vec.push_back(b);
        g2_vec.push_back(beta);
        g2_vec.push_back(gamma);
        g2_vec.push_back(delta);

        assert!(bn254.pairing_check(g1_vec, g2_vec), "invalid proof");
    }
}
