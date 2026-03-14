# Nebula Devlog — Building a Post-Quantum Wallet on Stellar

> A full account of the architectural decisions, dead ends, and lessons learned building a
> ZK-verified XMSS wallet on Stellar testnet.

---

## The Premise

The goal was simple to state and brutal to execute: build a crypto wallet where the signing
scheme is post-quantum secure, and the on-chain contract enforces it — no classical ECDSA
anywhere in the trust path.

Stellar uses ed25519, which Shor's algorithm kills on a sufficiently powerful quantum computer.
We wanted a wallet where even a quantum adversary with a broken ed25519 cannot steal funds.
The signing key had to be post-quantum. The on-chain verification had to happen inside a ZK proof
so the contract doesn't need to run the full post-quantum verifier natively.

---

## Chapter 1: SPHINCS+ — The First Attempt

The natural starting point for a post-quantum signature scheme is SPHINCS+. It's NIST-standardized
(FIPS 205), stateless (unlike XMSS), and has no quantum attacks. We started there.

**The problem: ZK-unfriendly internals.**

SPHINCS+ uses FORS (Forest of Random Subsets) trees alongside hypertrees. The signature
verification algorithm involves hundreds of independent SHA-256 chains across multiple tree layers,
with a verification complexity that blows up inside a ZK circuit. The SP1 zkVM runs RISC-V, so
in principle any Rust code can be a circuit — but cycle counts matter. SPHINCS+-SHA2-128s produces
~17,000 SHA-256 calls per verification. Inside SP1, each SHA-256 is accelerated via a precompile,
but 17,000 calls still means enormous constraint count, which translates to massive proving time
and cost on Sindri.

We got the circuit to compile. The first proof attempt timed out Sindri's free tier. The second
ran for over 40 minutes. The third produced a proof but the msgpack response was malformed (we
later learned this was a Sindri bug with extremely large proofs).

SPHINCS+ was out.

---

## Chapter 2: Falcon — The Wrong Kind of Fast

Falcon (NIST FIPS 206) is compact and fast to verify. The signature is only ~666 bytes for
Falcon-512, vs SPHINCS+'s ~8,000 bytes. Verification is lightweight: a few NTT (Number Theoretic
Transform) multiplications over a ring. Much more ZK-friendly on paper.

**The problem: key generation is a hardware gate.**

Falcon key generation uses a Gram-Schmidt orthogonalization over NTRU lattices. The reference
implementation requires ~32 GB of RAM for Falcon-1024, and even Falcon-512 keygen is
memory-hungry. We didn't have a machine with that much RAM. Cloud instances with 32+ GB cost
money we didn't want to spend for a testnet experiment.

The deeper issue: Sindri's proving infrastructure wasn't set up to accept Falcon verification
circuits at the time. Falcon uses polynomial arithmetic over `Z[x]/(x^n + 1)` which requires
specific finite field operations that SP1's precompile library didn't accelerate well. We'd be
paying cycle costs for every NTT butterfly.

There was also a Sindri-side issue: when we tried submitting a circuit that relied on
`falcon-rust`, the crate's internal FFI to the reference C implementation didn't cross-compile
cleanly to the RISC-V target SP1 uses. We'd have had to port the entire NTT to pure safe Rust.

Falcon was out.

---

## Chapter 3: XMSS — The Right Choice for the Wrong Reasons

XMSS (eXtended Merkle Signature Scheme, RFC 8391, NIST SP 800-208) is a hash-based stateful
signature scheme. It's older, less flashy than Falcon or SPHINCS+, and has a hard key limit
(1024 signatures with h=10). But it has one killer property: verification is just SHA-256.

Specifically, XMSS-SHA2_10_256 verification is:
1. One `h_msg` computation (a few SHA-256 calls with a specific padding scheme)
2. 67 WOTS+ chain evaluations (67 × up to 15 SHA-256 calls each = ~1,000 SHA-256 calls)
3. 10 tree node hashes for the authentication path

Roughly 1,000–1,200 SHA-256 calls total. SP1 has a SHA-256 precompile. Each precompile call is
cheap in constraint terms. We estimated ~30–60 second proving time on Sindri's infrastructure.
That was acceptable.

**The other reason:** we didn't need to run keygen inside the ZK circuit. Only verification runs
in-circuit. Keygen happens once, locally, with whatever RAM you have. So Falcon's keygen memory
problem was irrelevant — XMSS keygen is trivially cheap.

We chose `XMSS-SHA2_10_256`: tree height h=10 (1024 one-time keys), hash output n=32,
Winternitz parameter w=16. Standard parameters from RFC 8391.

---

## Chapter 4: Writing the SP1 Guest from Scratch

The `xmss` crate in the Rust ecosystem (RustCrypto, v0.1.0-pre.0) has a problem: it depends on
`rand 0.10`, which pulls `getrandom 0.4`. As of early 2026, `getrandom 0.4` has no WASM browser
support. This mattered later for the browser extension, but the immediate problem was different:
the crate wasn't designed for use inside a `#![no_std]` zkVM environment.

So we implemented XMSS-SHA2_10_256 verification from scratch in the SP1 guest
(`sp1/program/src/main.rs`). No external XMSS crate. Just `sha2 = "0.10"` and the RFC.

This took a while. The RFC's pseudocode has several places where the notation is ambiguous about
byte ordering. The bugs we hit:

**h_msg offset bug:** The `H_msg` function prepends a padding block. The RFC says the index
`idx_bytes` goes into a specific offset in a 128-byte input buffer. We had it at bytes [88..96]
initially. Verification kept failing. After tracing through the reference implementation, the
correct offset was [120..128]. Off-by-one in buffer layout from reading the pseudocode too quickly.

**WOTS+ chain direction:** Each WOTS+ chain runs forward during signing and backward during
verification. We had the checksum nibbles inverted, causing verification to use the wrong chain
starting points. Fixed by re-reading section 3.1.2 of the RFC more carefully.

**L-tree padding:** When computing the L-tree over WOTS+ public key elements, the len=67
leaves don't form a perfect binary tree. The RFC specifies a specific way to handle the uneven
layer — we had it right on even layers but wrong when the layer had an odd number of nodes.

Each of these bugs only manifested as "verification fails" with no other indication of where
in the 245-line verifier the failure was. We added intermediate commitment outputs (SP1's
`sp1_zkvm::io::commit` writes to public values) to bisect — basically printf debugging inside
a zkVM.

After about two days of this, local verification passed. Then we submitted to Sindri.

---

## Chapter 5: Sindri Integration

Sindri provides cloud proving for SP1 circuits. You upload your compiled ELF as a Groth16
circuit, then submit proof jobs via REST API.

**Circuit upload:** The SP1 guest compiles to an ELF with `cargo-prove prove build`. Sindri
expects a zip of the project. We initially uploaded with the directory structure intact (i.e.,
the zip contained `program/Cargo.toml`, `program/src/main.rs`, etc.). Sindri's build system
couldn't find the crate root. The fix: flat zip upload with `Cargo.toml` at the root of the
archive, not nested.

**SP1Stdin encoding:** The guest reads inputs from a serialized stdin buffer. The format is
bincode-encoded: each field is prefixed with an 8-byte little-endian length. We had to encode
`pk`, `tx_bytes`, and `sig` this way and wrap in a JSON object:

```json
{
  "buffer": [[...pk bytes...], [...tx bytes...], [...sig bytes...]],
  "ptr": 0,
  "proofs": []
}
```

Each inner array is a list of integers (0–255), not a hex string. Getting this format wrong gave
silent failures on Sindri's side — the circuit would run but commit garbage values.

**Proof response format:** Sindri returns the proof as base64-encoded msgpack. The msgpack
decodes to a nested structure:

```
[{"Groth16": [[pi0, pi1], enc_proof_hex, raw_proof_hex, vkey_hash_bytes]}]
```

Where `pi0` and `pi1` are decimal strings (BN254 field elements as Python-style big integers).
`enc_proof_hex` is the 256-byte raw BN254 proof (A, B, C concatenated). We needed to write a
minimal msgpack decoder to extract these — the full msgpack spec is large but we only needed a
subset of types.

---

## Chapter 6: The Soroban Contract and BN254

The Soroban contract (`soroban/src/lib.rs`) runs on Stellar's smart contract VM. It uses Stellar's
native host functions for BN254 operations (pairing, G1/G2 arithmetic). This is the only practical
way to do Groth16 verification on-chain — you don't want to implement elliptic curve pairings in
WASM.

**The VK bug:** Groth16 verification requires a hardcoded verification key (VK) from the circuit.
The VK constants come from the `Groth16Verifier.sol` file in Succinct's sp1-contracts repo. The
Solidity file lists them as decimal integers. We had to convert these to 32-byte big-endian byte
arrays for the Soroban contract. Our first attempt used Python's `int.to_bytes(32, 'little')` by
mistake. The pairings failed silently — the contract returned an error code, not a panic, so we
had to trace backward from the pairing check to realize the byte order was wrong. Fixed with
`to_bytes(32, 'big')`.

**The G2 encoding bug:** BN254 G2 points have two coordinates (X, Y), each of which is an
element of the quadratic extension field Fp2 — so each coordinate has two components (c0, c1).
The Groth16 proof's `B` point (192 bytes for the B G2 point) needs these components in a specific
order.

The Solidity convention is `[X.c0, X.c1, Y.c0, Y.c1]`. The Soroban BN254 host function expects
`[X.c1, X.c0, Y.c1, Y.c0]` (imaginary part first). We initially swapped the components ourselves,
assuming Sindri's `enc_proof` used the Solidity convention. It doesn't — enc_proof already uses
the Soroban/imaginary-first convention. We were double-swapping. Removed the swap, proofs started
verifying.

---

## Chapter 7: The Nonce Design

The first working design used the XMSS leaf index as the replay protection counter. Every
withdrawal commits the leaf index to the proof public values, and the contract checks that the
incoming leaf index equals one more than the stored value.

This had a subtle problem: **failed transactions**.

If you sign with leaf index 5, submit the proof, but the Stellar transaction fails (network
error, insufficient fee, whatever), the XMSS key has already advanced to leaf index 6. Your
next signing uses leaf 6. But the contract still expects the next withdrawal to have leaf index 6
(since the on-chain counter was never incremented). So the proof committed "leaf 5" but now
you're signing with leaf 6, which would commit "leaf 6" — and the contract would reject it as
a skip.

The fix: decouple the on-chain nonce from the XMSS leaf index entirely.

The new design stores a `wallet_nonce` (u32) independently in contract storage. The nonce is
embedded in `tx_bytes[64..68]` and committed by the SP1 guest as a separate public output. The
XMSS leaf index is purely internal to the XMSS library — the contract never sees it.

Consequence: a failed transaction burns an XMSS leaf (unavoidable — you signed) but does NOT
advance the wallet nonce. The user re-signs the same intent with the next XMSS leaf and the same
wallet nonce. The proof looks different (different leaf, different r value), but commits the same
wallet nonce. The contract accepts it.

This required re-deploying the contract (different storage layout) and re-uploading the Sindri
circuit (the SP1 guest now reads `tx_bytes[64..68]` instead of the XMSS idx field). The new
circuit got ID `675b1311-8e2b-4b2c-9f16-44a548a3e2b7`.

---

## Chapter 8: The Address Encoding Rabbit Hole

The `tx_bytes` structure encodes the destination address as a 32-byte field. The Soroban
contract uses `address.to_xdr(env).slice(4..36)` to produce this encoding, and the CLI had to
replicate it exactly.

This looked simple. It wasn't.

`Address::to_xdr(env)` in Soroban doesn't return an `ScAddress` — it returns an `ScVal` wrapping
an `ScAddress`. The `ScVal` has a 4-byte type discriminant prefix. So the XDR layout for a
contract address `C...` is:

```
[ScVal type = SCV_ADDRESS (4 bytes)]
[ScAddress type = SC_ADDRESS_TYPE_CONTRACT (4 bytes)]
[contract hash (32 bytes)]
```

Total 40 bytes. `.slice(4..36)` gives you bytes 4–36:
`[SC_ADDRESS_TYPE_CONTRACT = 0x00000001 (4 bytes)] + hash[0..28]`

Not the full hash — only the first 28 bytes, with the 4-byte discriminant prepended.

For an account address `G...`:

```
[ScVal type = SCV_ADDRESS (4 bytes)]
[ScAddress type = SC_ADDRESS_TYPE_ACCOUNT (4 bytes)]
[PublicKey type = PUBLIC_KEY_TYPE_ED25519 (4 bytes)]
[Ed25519 key (32 bytes)]
```

Total 44 bytes. `.slice(4..36)` gives:
`[SC_ADDRESS_TYPE_ACCOUNT (4 bytes)] + [PUBLIC_KEY_TYPE_ED25519 (4 bytes)] + key[0..24]`

Which is 8 zero bytes (both discriminants are 0) followed by the first 24 bytes of the key.

We had the contract address encoding wrong first (using the full 32-byte hash instead of 28
bytes), then had the account encoding wrong (missing the second discriminant). Each mistake caused
the tx_hash check in the contract to fail — the contract recomputed `tx_bytes` correctly and
hashed it, but the CLI's `tx_bytes` had a different encoding for the destination field, so the
hashes didn't match.

---

## Chapter 9: The Browser Extension

The CLI worked end-to-end. Next: a Chrome extension so users don't need to install anything.

The extension (React + Vite, Chrome MV3) needed to:
1. Generate XMSS keys (in WASM, from the browser)
2. Sign transactions (in WASM)
3. Get a Groth16 proof (Sindri REST API, from the background service worker)
4. Submit on-chain

Steps 1–3 worked fine. Step 4 hit a wall.

**The BN254 simulation problem:**

The standard way to submit a Soroban transaction from a browser is to call
`simulateTransaction` on the Stellar testnet RPC, get the resource fee estimate, then build and
submit a signed transaction. The problem: `simulateTransaction` runs the contract in a local WASM
VM to estimate costs. But the Stellar testnet RPC has BN254 pairing host functions **disabled**
in simulation mode. The contract's `withdraw` function calls BN254 pairing. Simulation returns
`UnreachableCodeReached`.

The Stellar CLI's `stellar contract invoke` handles this differently — it bypasses the simulation
by running the WASM VM locally with a different set of host function bindings that include BN254.
This is why the CLI worked and the extension didn't.

**The relay server:**

The fix: a relay server running on our VM (`backend.iameshan.tech`). The extension POSTs
`{proof_bytes, public_values, destination, amount_stroops}` to the relay. The relay shells out to
`stellar contract invoke` and returns the transaction hash.

```
Extension → HTTPS POST → Relay (Node.js) → stellar contract invoke → Soroban
```

The relay is a single Node.js ESM file with no dependencies, ~100 lines. It runs in Docker
with the Stellar CLI installed. On startup it registers the relayer key from `$RELAYER_SECRET`
via `echo "$RELAYER_SECRET" | stellar keys add relayer --secret-key`.

The relay is the weakest point in the trust model — it holds a Stellar key with funds delegated
to pay transaction fees. However, it cannot steal user funds: it can only call `withdraw` with
whatever proof and destination the extension sends. The proof cryptographically binds the
destination — the relay can't change it without invalidating the proof.

---

## Chapter 10: The CLI TUI

The final piece was `nebula ui` — a ratatui terminal UI showing balance, nonce, XMSS leaf
usage, and an interactive send wizard.

**The terminal corruption bug:**

When the send flow started, the TUI's alternate screen would get polluted with garbage from
subprocess stdout/stderr. ratatui owns the terminal in alternate screen mode — any writes to
stdout from subprocesses (the `xmss` binary, the `stellar` CLI, our own `println!` calls) go
directly to the terminal and corrupt the rendering.

The fix: a `cmd_withdraw_silent` variant that:
- Redirects subprocess stdout to `/dev/null` or pipes it (discards it)
- Redirects subprocess stderr to `/dev/null`
- Suppresses all `println!` and `print!` calls
- Returns the transaction hash as a `Result<String>` instead of printing it

The UI thread then receives the hash and renders it in the completion screen.

One subtle issue: `stellar contract invoke` prints the Soroban function return value to stdout
(which for our `withdraw` function is `null` — the function returns nothing). The transaction
hash appears in stellar CLI's stderr as `ℹ️  Signing transaction: <64-char-hex>`. In silent mode
we were nulling stderr, so we lost the hash. Fixed by capturing stderr in a pipe, extracting
the hex hash with a regex, and discarding the rest.

---

## Current State

```
XMSS sign (local, Rust binary)
  ↓ proof_inputs.json (pk + tx_bytes + sig)
SP1 guest (XMSS verifier, runs on Sindri)
  ↓ Groth16 proof + public_values
Relay server (stellar contract invoke)
  ↓ Stellar transaction
Soroban contract (BN254 Groth16 verifier)
  ↓ XLM transfer + nonce increment
```

Live on Stellar testnet. Contract `CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B`.
First on-chain withdrawal: 2026-03-12, nonce 0→1.

---

## What We'd Do Differently

**Don't start with SPHINCS+.** It's the obvious choice if you read the NIST announcements, but
verification complexity in a ZK circuit is the wrong metric to optimize — total proving cost is.
Hash count per verification is the number to look at first.

**Prototype the proof format before building the verifier.** We spent days debugging the SP1
guest before we knew what the output of Sindri would look like. Building a small script to
decode a dummy Groth16 proof from Sindri first would have saved us the G2 encoding bug, which
only manifests at the on-chain verification step.

**The relay is the right call for now.** Direct RPC submission from a browser extension doesn't
work with Soroban's BN254 host functions in simulation mode. A relay is the correct architecture
until Stellar testnet enables BN254 in simulation, or until there's a way to precompute resource
fees for BN254-heavy contracts.

**XMSS statefulness is a real constraint.** 1024 signatures per keypair sounds like a lot until
you consider a user who makes daily transactions. A wallet with frequent use exhausts its keys in
under 3 years. The UX around key rotation (generate new wallet, migrate funds) needs to be first-
class, not an afterthought. We haven't built that yet.

---

## Stack Summary

| Layer | Technology | Why |
|-------|-----------|-----|
| Signing | XMSS-SHA2_10_256 (RFC 8391) | ~1,200 SHA-256 calls to verify — ZK-friendly |
| ZK proving | SP1 (Succinct) — RISC-V zkVM | Lets us write the verifier in Rust without circuit DSL |
| Proof system | Groth16 on BN254 | Soroban has native BN254 host functions |
| Cloud proving | Sindri | Managed SP1 → Groth16 compilation and proving |
| Smart contract | Soroban (Stellar) | Native BN254 ops; Rust contracts |
| CLI | Rust (`nebula`) | Orchestrates all components; also ships a TUI |
| Browser extension | Chrome MV3, React, Vite | No install required for end users |
| Relay | Node.js, Docker | Bypasses BN254 simulation limitation in Stellar testnet RPC |
