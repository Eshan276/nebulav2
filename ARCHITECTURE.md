# nebulav2 — Architecture Reference

XMSS Post-Quantum Wallet on Stellar, using SP1 zkVM + Groth16 proofs via Sindri cloud proving.

---

## 1. High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              USER / OPERATOR                                    │
│                                                                                 │
│   nebula wallet create    nebula fund    nebula withdraw    nebula prove/submit  │
└────────────────────────────────┬────────────────────────────────────────────────┘
                                 │  Rust CLI  (cli/src/main.rs)
                                 │
            ┌────────────────────┼─────────────────────┐
            │                   │                      │
            ▼                   ▼                      ▼
  ┌──────────────────┐ ┌─────────────────────┐ ┌──────────────────────────┐
  │  XMSS Tool       │ │   Sindri Cloud       │ │   Stellar Testnet        │
  │  (xmss binary)   │ │   Proving Service    │ │   (Soroban Contract)     │
  │                  │ │                      │ │                          │
  │  keygen          │ │  SP1 guest ELF       │ │  XmssWallet contract     │
  │  sign tx_bytes   │ │  (sp1/program/)      │ │  (soroban/src/lib.rs)    │
  │  verify locally  │ │                      │ │                          │
  └────────┬─────────┘ │  Groth16 circuit     │ │  init(vkey, xlm_sac)     │
           │           │  (BN254 curve)       │ │  deposit(from, pk_hash)  │
           │ key.json  │                      │ │  withdraw(proof, pv, ..) │
           │ + proof   │  circuit ID:         │ │  balance(pk_hash)        │
           │ _inputs   │  675b1311-...        │ │  nonce(pk_hash)          │
           │ .json     └──────────┬───────────┘ └──────────────────────────┘
           │                     │                           ▲
           │                     │  groth16_proof.json       │
           │                     │  (proof_bytes +           │
           │                     │   public_values)          │
           └─────────────────────┴───────────────────────────┘
                      Data flow for one withdrawal
```

### Detailed Data Flow

```
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │  KEY GENERATION (one time)                                                   │
  │                                                                              │
  │  xmss keygen  ──►  key.json                                                  │
  │                    { public_key: hex(68B), secret_key: hex, next_index: 0 }  │
  │                                                                              │
  │  wallet identity = sha256(public_key)  ──►  pubkey_hash (32 bytes)           │
  └──────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────────┐
  │  FUNDING                                                                     │
  │                                                                              │
  │  User / anyone  ──►  stellar contract invoke deposit                         │
  │                      (standard Soroban auth, XLM transferred to contract)    │
  │                      Soroban: balance[pubkey_hash] += amount                 │
  └──────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────────┐
  │  WITHDRAWAL (4 stages)                                                       │
  │                                                                              │
  │  [1] BUILD tx_bytes                                                          │
  │      CLI queries: nonce = contract.nonce(pubkey_hash)                        │
  │      CLI builds 108-byte tx_bytes (see §3)                                   │
  │                                                                              │
  │  [2] XMSS SIGN                                                               │
  │      xmss sign --tx <tx_bytes_hex>                                           │
  │      → proof_inputs.json  { pk, tx_bytes, sig(2500B), leaf_index, nonce }    │
  │                                                                              │
  │  [3] ZK PROVE (Sindri cloud)                                                 │
  │      POST /api/v1/circuit/{id}/prove  { proof_input: SP1Stdin JSON }         │
  │      SP1 guest runs in zkVM:                                                 │
  │        reads pk, tx_bytes, sig  →  verifies XMSS signature                  │
  │        commits: pubkey_hash, tx_hash, wallet_nonce                           │
  │      Sindri wraps in Groth16 (BN254)                                         │
  │      → groth16_proof.json  { proof_bytes(260B), public_values(68B) }         │
  │                                                                              │
  │  [4] SUBMIT ON-CHAIN                                                         │
  │      stellar contract invoke withdraw \                                      │
  │        --proof_bytes <260B hex> --public_values <68B hex> \                  │
  │        --destination <G...> --amount <stroops>                               │
  │      Soroban contract:                                                       │
  │        1. parses public_values → pubkey_hash, tx_hash, nonce                 │
  │        2. checks nonce == wallet nonce in storage                            │
  │        3. recomputes tx_bytes, checks sha256(tx_bytes) == tx_hash            │
  │        4. verifies Groth16 proof with hardcoded BN254 VK                     │
  │        5. transfers XLM to destination                                       │
  │        6. increments nonce, emits WithdrawEvent                              │
  └──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component-by-Component Explanation

### 2.1 XMSS Tool (`xmss/src/main.rs`)

A standalone Rust binary built from the `xmss` crate (RFC 8391). It manages the post-quantum key material and generates signing inputs for the prover.

**Subcommands:**

| Command | Function |
|---------|----------|
| `xmss keygen` | Generates an XMSS-SHA2_10_256 keypair (h=10, 1024 one-time leaf keys). Writes `key.json`. |
| `xmss sign --tx <hex>` | Loads `key.json`, signs `tx_bytes`, advances `next_index`, writes `proof_inputs.json`. |
| `xmss verify --inputs` | Loads `proof_inputs.json`, verifies the signature locally. |

**Key file format (`key.json`):**
```json
{
  "algorithm": "XMSS-SHA2_10_256",
  "public_key": "<hex, 68 bytes>",
  "secret_key": "<hex, large>",
  "next_index": 0
}
```

**Key properties:**
- Each signing operation irrevocably consumes one XMSS leaf (one-time signature).
- `next_index` is advanced and the mutated secret key is written back after every sign call.
- The public key is 68 bytes: `OID(4) || root(32) || pub_seed(32)`.
- The signature is 2500 bytes: `idx(4) || r(32) || wots(67×32) || auth_path(10×32)`.

**Wallet nonce extraction:**
After signing, `wallet_nonce` is extracted from `tx_bytes[64..68]` (LE u32) — not from the XMSS leaf index. This decouples the on-chain replay counter from the XMSS tree position. A failed transaction burns a leaf but does NOT advance the wallet nonce.

---

### 2.2 SP1 Guest Program (`sp1/program/src/main.rs`)

A `#![no_main]` Rust program that runs inside the SP1 zkVM (RISC-V). It is compiled to an ELF and uploaded to Sindri as the circuit definition. The guest implements the full XMSS-SHA2_10_256 signature verification algorithm from scratch using only the `sha2` crate (no `xmss` crate dependency in the guest — ensures deterministic in-circuit execution).

**Private inputs (read via SP1 stdin, bincode-encoded):**

| Input | Size | Content |
|-------|------|---------|
| `pk_bytes` | 68 bytes | XMSS public key: OID(4) + root(32) + pub_seed(32) |
| `tx_bytes` | 108 bytes | Transaction bytes (what was signed) |
| `sig_bytes` | 2500 bytes | XMSS detached signature |

**Cryptographic operations performed:**
1. Parses the XMSS signature: extracts `idx`, `r`, WOTS+ sig (67×32B), auth path (10×32B).
2. Computes `h_msg(r, root, idx, tx_bytes)` — the message hash used in WOTS+.
3. For each of 67 WOTS+ chains: runs `wots_chain` to recover the WOTS+ public key from the signature.
4. Computes the L-tree over the 67 WOTS+ public key elements to get the leaf.
5. Traverses the 10-level authentication path to compute the root.
6. Asserts `computed_root == root` from the public key.

**Public outputs (committed to the proof's public values):**

| Field | Size | Content |
|-------|------|---------|
| `pubkey_hash` | 32 bytes | `sha256(pk_bytes)` |
| `tx_hash` | 32 bytes | `sha256(tx_bytes)` |
| `wallet_nonce` | 4 bytes | `u32::from_le_bytes(tx_bytes[64..68])` |

Total committed public values: **68 bytes**.

The guest proves: "I know an XMSS signature over `tx_bytes` by the private key corresponding to a public key whose SHA-256 hash is `pubkey_hash`, and the transaction's nonce field is `wallet_nonce`."

---

### 2.3 Sindri Cloud Proving Service

Sindri hosts the compiled SP1 guest ELF as a Groth16 circuit on BN254. The CLI interacts with its REST API.

**Circuit ID (current):** `675b1311-8e2b-4b2c-9f16-44a548a3e2b7`

**SP1Stdin encoding:**
```
proof_input = JSON({
  "buffer": [
    bincode_vec_u8(pk_bytes),   // 8-byte LE length prefix + pk data
    bincode_vec_u8(tx_bytes),
    bincode_vec_u8(sig_bytes),
  ],
  "ptr": 0,
  "proofs": []
})
```

**API flow:**
1. `POST /api/v1/circuit/{id}/prove` — submits job, returns `proof_id`
2. `GET /api/v1/proof/{proof_id}/detail` — polls every 30s until `status == "Ready"`

**Response format:** The `proof.proof` field is base64-encoded msgpack:
```
[[{"Groth16": [
  [pub_input_0_decimal_str, pub_input_1_decimal_str],  // [program_vkey_as_Fr, committed_values_digest_as_Fr]
  enc_proof_hex,    // 256 bytes (A||B||C)
  raw_proof_hex,    // full proof
  vkey_hash_bytes   // 32 bytes
]}]]
```

The CLI's `decode_msgpack_proof` function parses this and extracts:
- `enc_proof` (256 bytes): the raw BN254 proof points
- `vkey_hash` (32 bytes): the SP1 circuit hash
- `pub_input0`: the program verification key as a decimal-encoded field element (converted to 32-byte BE hex)

---

### 2.4 Nebula CLI (`cli/src/main.rs`)

A Rust binary (`nebula`) that orchestrates all components. It reads configuration from `.env` in the project root.

**Required environment variables:**
- `WALLET_CONTRACT_ID` — Soroban contract address (C...)
- `WALLET_CONTRACT_HASH` — the 32-byte inner hash of the contract (hex)
- `SINDRI_API_KEY` — API key for Sindri
- `STELLAR_ACCOUNT` — Stellar account alias (default: `quantum-deployer`)

**Commands:**

| Command | What it does |
|---------|-------------|
| `nebula wallet create` | Generates XMSS keypair via `xmss keygen`; shows pubkey_hash (wallet ID) |
| `nebula wallet info` | Queries contract for balance and nonce |
| `nebula fund --amount` | Calls `contract.deposit`; transfers XLM to the wallet |
| `nebula intent --destination --amount` | Shows the tx_bytes the user needs to sign |
| `nebula prove` | Signs + submits to Sindri + polls; writes `groth16_proof.json` |
| `nebula submit --destination --amount` | Submits cached proof to the contract |
| `nebula withdraw --destination --amount` | Full pipeline: sign + prove + submit |

**Stellar address encoding (`stellar_to_contract_field`):**

The Soroban contract's `build_tx_bytes` uses `address.to_xdr(env).slice(4..36)` to encode addresses into tx_bytes. The CLI replicates this:
- Contract address (C...): `[0,0,0,1] + hash[0..28]` (SC_ADDRESS_TYPE_CONTRACT discriminant + first 28 bytes of hash)
- Account address (G...): `[0,0,0,0,0,0,0,0] + key[0..24]` (two 4-byte discriminants + first 24 bytes of Ed25519 key)

---

### 2.5 Soroban Contract (`soroban/src/lib.rs`)

A `#![no_std]` Rust smart contract deployed on Stellar. It stores wallet balances and nonces keyed by `sha256(xmss_pubkey)`, and enforces withdrawals only when a valid ZK proof is presented.

**Storage layout:**

| Key | Type | Description |
|-----|------|-------------|
| `DataKey::ProgramVKey` | `BytesN<32>` | SP1 program verification key (set at init) |
| `DataKey::XlmToken` | `Address` | XLM Stellar Asset Contract address |
| `DataKey::Balance(pubkey_hash)` | `i128` | XLM balance in stroops |
| `DataKey::Nonce(pubkey_hash)` | `u32` | Replay-protection counter |

**Groth16 verification (`groth16_verify`):**

Uses Soroban's native BN254 host functions. The verification key (VK) is hardcoded from `sp1-contracts/v4.0.0-rc.3/Groth16Verifier.sol` as byte arrays in the contract source. The pairing check performed is:

```
e(A, B) · e(alpha, BETA_NEG) · e(vk_x, GAMMA_NEG) · e(C, DELTA_NEG) == 1
```

Where `vk_x = IC[0] + input0·IC[1] + input1·IC[2]` (linear combination of IC points).

The two public inputs are:
- `input0` = `program_vkey` (32-byte BE, stored at init)
- `input1` = `sha256(public_values)` with the top 3 bits masked to zero (`pv_arr[0] &= 0x1f`) to fit within the BN254 scalar field

---

## 3. Data Format Reference

### 3.1 tx_bytes (108 bytes)

The message the XMSS private key signs. Constructed identically by CLI and Soroban contract.

```
Offset  Size  Field           Content
──────  ────  ──────────────  ──────────────────────────────────────────────────
 0      32    contract_id     address.to_xdr().slice(4..36):
                              [0,0,0,1] + contract_hash[0..28]
32      32    pubkey_hash     sha256(xmss_public_key)
64       4    nonce           wallet nonce as LE u32  ← SP1 guest reads from here
68      32    destination     dest_address.to_xdr().slice(4..36)
                              G...: [0,0,0,0,0,0,0,0] + key[0..24]
                              C...: [0,0,0,1] + hash[0..28]
100      8    amount          i64 stroops as BE 8 bytes
──────────────────────────────────────────────────────────────────────────────
Total: 108 bytes
```

### 3.2 public_values (68 bytes)

Committed by the SP1 guest and passed to the Soroban contract alongside the proof.

```
Offset  Size  Field           Content
──────  ────  ──────────────  ──────────────────────────────────────────────────
 0      32    pubkey_hash     sha256(xmss_public_key)
32      32    tx_hash         sha256(tx_bytes)
64       4    wallet_nonce    u32::from_le_bytes(tx_bytes[64..68])
──────────────────────────────────────────────────────────────────────────────
Total: 68 bytes
```

### 3.3 proof_bytes (260 bytes)

Assembled by the CLI from Sindri's response. Passed as-is to `contract.withdraw`.

```
Offset  Size  Field           Content
──────  ────  ──────────────  ──────────────────────────────────────────────────
 0       4    selector        first 4 bytes of groth16_vkey_hash (circuit ID tag)
 4      64    A (G1)          X(32B BE) || Y(32B BE)
68     128    B (G2)          X.c1(32B) || X.c0(32B) || Y.c1(32B) || Y.c0(32B)
                              (imaginary part first — Soroban BN254 convention)
196     64    C (G1)          X(32B BE) || Y(32B BE)
──────────────────────────────────────────────────────────────────────────────
Total: 260 bytes
```

Note: The enc_proof from Sindri is 256 bytes (A+B+C). The CLI prepends 4 bytes from `vkey_hash[0..4]` to make 260 bytes. The contract reads `A` from `[4..68]`, `B` from `[68..196]`, `C` from `[196..260]`, confirming the 4-byte offset.

### 3.4 Groth16 Public Inputs (SP1 encoding)

SP1 Groth16 wraps the guest's committed values as two BN254 scalar field elements:

```
pub_input[0] = program_vkey        (32-byte BE integer mod BN254 field order)
pub_input[1] = committed_values_digest
             = sha256(public_values) with top 3 bits zeroed
               (masking: pv_arr[0] &= 0x1f  — fits within the 254-bit field)
```

### 3.5 XMSS Parameters

```
Algorithm  : XMSS-SHA2_10_256
n          : 32     (hash output size, bytes)
h          : 10     (tree height, 2^10 = 1024 one-time keys)
w          : 16     (Winternitz parameter)
len        : 67     (WOTS+ chain count: 64 message nibbles + 3 checksum nibbles)
padding_len: 32
d          : 1      (single-layer tree)

Public key : 68 bytes  = OID(4) + root(32) + pub_seed(32)
Signature  : 2500 bytes = idx(4) + r(32) + wots_sig(67×32) + auth_path(10×32)
```

---

## 4. Security Properties

### 4.1 Post-Quantum Security (XMSS Layer)

- **What it guarantees:** The wallet owner is whoever possesses the XMSS private key. An adversary without the private key cannot produce a valid XMSS signature over any `tx_bytes`.
- **Security basis:** XMSS-SHA2_10_256 is standardized in RFC 8391 and NIST SP 800-208. Its security reduces to the second-preimage resistance of SHA-256, which is believed to be secure against quantum computers running Grover's algorithm (128-bit quantum security).
- **Statefulness:** XMSS is a stateful hash-based signature scheme. Each leaf can only be used once. The `key.json` tracks `next_index`; reusing a leaf index would break security. The CLI enforces sequential use.
- **Key lifetime:** With h=10, the keypair supports exactly 1024 withdrawals before it must be rotated.

### 4.2 Soundness (ZK Proof Layer)

- **What it guarantees:** The Soroban contract only accepts a withdrawal if the SP1 Groth16 proof is valid. A valid proof demonstrates that the caller knows an XMSS signature over the exact `tx_bytes` (which embeds the contract address, destination, amount, and nonce). No valid proof can be constructed without the private key.
- **Security basis:** Groth16 on BN254 is computationally sound under the knowledge-of-exponent assumption (KEA) and the q-power Diffie-Hellman assumption. The VK is hardcoded in the contract, preventing circuit substitution.
- **Program integrity:** The SP1 program vkey (`program_vkey`) is committed in `pub_input[0]` and stored in the contract at init time. Any modification to the SP1 guest program produces a different vkey, so proofs from a tampered circuit are rejected.

### 4.3 Replay Protection (Nonce Layer)

- **What it guarantees:** Each valid proof commits to a `wallet_nonce` extracted from `tx_bytes[64..68]`. The contract checks that this nonce equals its stored nonce for the wallet; after a successful withdrawal the nonce is incremented. A proof cannot be replayed.
- **Decoupling design:** The wallet nonce is independent of the XMSS leaf index. A failed Stellar transaction (e.g., network error after signing but before on-chain success) burns an XMSS leaf but does NOT advance the on-chain nonce. The user must re-sign with the next XMSS leaf but using the same wallet nonce.

### 4.4 Transaction Integrity (tx_hash Binding)

- **What it guarantees:** The SP1 guest commits `sha256(tx_bytes)`. The Soroban contract independently recomputes `tx_bytes` from the arguments supplied to `withdraw()` (contract address, pubkey_hash, nonce, destination, amount) and checks that `sha256(recomputed_tx_bytes) == proof_tx_hash`. This prevents an adversary from:
  - Changing the destination address after signing
  - Changing the amount after signing
  - Substituting a different contract as target

### 4.5 Identity Binding

- **What it guarantees:** The SP1 guest commits `sha256(pk_bytes)` as `pubkey_hash`. The wallet's balance and nonce are stored under this hash. An attacker cannot substitute a different public key in the proof input — doing so would change `pubkey_hash`, which would look up a different (empty or unrelated) wallet in the contract.

---

## 5. Withdrawal Flow — Step by Step

### Prerequisites
- `key.json` exists with an unused XMSS leaf
- Wallet has sufficient balance on-chain
- `.env` contains `WALLET_CONTRACT_ID`, `WALLET_CONTRACT_HASH`, `SINDRI_API_KEY`

### Step 1: Query Wallet State

```
nebula wallet info
```

The CLI calls `stellar contract invoke ... -- nonce --pubkey_hash <hex>` and `... -- balance ...` to display current state.

### Step 2: Build tx_bytes and Sign

```
nebula withdraw --destination GD6... --amount 10000000
```

Internally:
1. CLI queries `contract.nonce(pubkey_hash)` from Stellar — returns current `wallet_nonce` (e.g., 0).
2. CLI decodes destination `GD6...` via base32 → 32-byte raw key.
3. CLI constructs `dest_field` = `[0,0,0,0,0,0,0,0] + key[0..24]` (matching contract's XDR slice logic).
4. CLI builds `tx_bytes[108]`:
   ```
   tx[0..32]   = [0,0,0,1] + contract_hash[0..28]   (contract_id field)
   tx[32..64]  = sha256(xmss_public_key)              (pubkey_hash)
   tx[64..68]  = wallet_nonce.to_le_bytes()           (nonce, LE)
   tx[68..100] = dest_field                           (destination)
   tx[100..108]= amount.to_be_bytes()                 (amount, BE i64)
   ```
5. CLI invokes `xmss sign --key key.json --tx <tx_hex>`.
6. XMSS tool loads secret key, calls `sign_detached(tx_bytes)`, advancing the internal OTS index.
7. XMSS tool verifies locally before writing.
8. XMSS tool writes `proof_inputs.json` and updates `key.json` (`next_index += 1`).

### Step 3: Submit to Sindri for Groth16 Proof

1. CLI reads `proof_inputs.json`, extracts `pk`, `tx_bytes`, `sig`.
2. CLI encodes each as `bincode_vec_u8(data)` = `LE-u64-length || data`.
3. CLI constructs SP1Stdin JSON: `{"buffer": [pk_bincoded, tx_bincoded, sig_bincoded], "ptr": 0, "proofs": []}`.
4. CLI calls `POST https://sindri.app/api/v1/circuit/675b1311-.../prove` → gets `proof_id`.
5. CLI polls `GET .../proof/{proof_id}/detail` every 30s.
6. When `status == "Ready"`, the response contains `proof.proof` (base64-encoded msgpack).

### Step 4: Parse Proof Response

1. CLI base64-decodes and msgpack-decodes the proof.
2. Extracts from the `Groth16` tuple:
   - `pub_inputs[0]` (decimal string) → converts to 32-byte BE hex → `program_vkey`
   - `enc_proof_hex` (256 bytes) → raw BN254 proof points A, B, C
   - `vkey_hash` (32 bytes) → circuit identifier
3. Assembles `proof_bytes[260]` = `vkey_hash[0..4] || enc_proof[256]`
4. Computes `public_values[68]`:
   ```
   public_values[0..32]  = sha256(pk_bytes)
   public_values[32..64] = sha256(tx_bytes)
   public_values[64..68] = u32::from_le_bytes(tx_bytes[64..68]).to_le_bytes()
                           (wallet_nonce, extracted from the signed tx)
   ```
5. Writes `groth16_proof.json`.

### Step 5: Submit On-Chain

1. CLI calls:
   ```
   stellar contract invoke --id <CONTRACT> ... -- withdraw \
     --proof_bytes   <260-byte hex>     \
     --public_values <68-byte hex>      \
     --destination   <G... address>     \
     --amount        <stroops>
   ```
2. Soroban contract executes `withdraw()`:

   **a. Parse public_values:**
   - `pubkey_hash` = `public_values[0..32]`
   - `proof_tx_hash` = `public_values[32..64]`
   - `proof_nonce` = `u32::from_le_bytes(public_values[64..68])`

   **b. Nonce check:**
   - `wallet_nonce = storage.get(Nonce(pubkey_hash))` (default 0)
   - Assert `proof_nonce == wallet_nonce`

   **c. tx_hash check:**
   - Contract calls `build_tx_bytes(pubkey_hash, destination, amount, wallet_nonce)`
   - Computes `expected_tx_hash = sha256(recomputed_tx_bytes)`
   - Assert `proof_tx_hash == expected_tx_hash`
   - (This binds destination + amount to what was signed)

   **d. Groth16 verification:**
   - Parse `proof_bytes[4..68]` → G1 point A
   - Parse `proof_bytes[68..196]` → G2 point B
   - Parse `proof_bytes[196..260]` → G1 point C
   - `input0 = Fr(program_vkey)` (from storage)
   - `input1 = Fr(sha256(public_values) with top 3 bits masked)`
   - `vk_x = IC[0] + input0·IC[1] + input1·IC[2]`
   - Assert `e(A,B) · e(α,β_neg) · e(vk_x,γ_neg) · e(C,δ_neg) == 1`

   **e. Balance check:**
   - Assert `balance[pubkey_hash] >= amount`

   **f. State transition:**
   - `balance[pubkey_hash] -= amount`
   - `nonce[pubkey_hash] += 1`

   **g. Token transfer:**
   - `xlm_token.transfer(contract_address, destination, amount)`

   **h. Event emission:**
   - Emits `WithdrawEvent { pubkey_hash, destination, amount, new_balance, new_nonce }`

### Step 6: Confirmation

The CLI prints the Stellar transaction hash. The withdrawal is complete; the wallet nonce has advanced, and the destination account has received the XLM.

---

## 6. Deployed Contracts (Stellar Testnet)

| Item | Value |
|------|-------|
| Contract ID | `CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B` |
| XLM SAC | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` |
| program_vkey | `064d168ca14fc6ec7be2708971d17825973a6cfe5d340db38991ae104bd60140` |
| WALLET_CONTRACT_HASH | `a1c8f4b33bc6133d98258838ab2c3d8f86f201d78719e44ce3102046cd5a55df` |
| Sindri Circuit ID | `675b1311-8e2b-4b2c-9f16-44a548a3e2b7` |
| SP1 version | v4.1.3 (= Groth16 circuit v4.0.0-rc.3) |

---

## 7. File Map

```
nebulav2/
├── xmss/
│   └── src/main.rs          XMSS keygen / sign / verify CLI binary
├── sp1/
│   └── program/
│       ├── src/main.rs      SP1 zkVM guest: XMSS verifier + public value commits
│       └── sindri.json      Groth16 circuit config for Sindri upload
├── soroban/
│   └── src/lib.rs           Soroban smart contract: wallet + Groth16 verifier
├── cli/
│   └── src/main.rs          'nebula' CLI orchestrator
├── bridge.py                Python end-to-end script (predecessor to CLI)
├── proof_inputs.json        Latest signing output (pk, tx_bytes, sig)
├── groth16_proof.json       Latest cached proof (proof_bytes, public_values)
├── key.json                 XMSS keypair (keep secret, back up)
└── .env                     SINDRI_API_KEY, WALLET_CONTRACT_ID, etc.
```
