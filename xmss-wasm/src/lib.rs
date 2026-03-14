//! XMSS-SHA2_10_256 keygen + sign + verify in pure Rust, compiled to WASM.
//! No external xmss crate — only sha2 + wasm-bindgen.
//!
//! Parameters: n=32, h=10, w=16, len=67, d=1
//! pk: 4-byte OID + root(32) + pub_seed(32) = 68 bytes
//! sig: idx(4) + r(32) + wots(67*32) + auth(10*32) = 2500 bytes

use wasm_bindgen::prelude::*;
use sha2::{Digest, Sha256};

// ─── SHA-256 primitives ────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn prf(key: &[u8; 32], adrs: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[31] = 3;
    buf[32..64].copy_from_slice(key);
    buf[64..96].copy_from_slice(adrs);
    sha256(&buf)
}

fn addr_set_km(adrs: &[u8; 32], km: u32) -> [u8; 32] {
    let mut a = *adrs;
    a[28] = (km >> 24) as u8;
    a[29] = (km >> 16) as u8;
    a[30] = (km >> 8) as u8;
    a[31] = km as u8;
    a
}

fn thash_f(pub_seed: &[u8; 32], adrs: &[u8; 32], x: &[u8; 32]) -> [u8; 32] {
    let key = prf(pub_seed, &addr_set_km(adrs, 0));
    let bm  = prf(pub_seed, &addr_set_km(adrs, 1));
    let mut buf = [0u8; 96];
    buf[32..64].copy_from_slice(&key);
    for i in 0..32 { buf[64 + i] = x[i] ^ bm[i]; }
    sha256(&buf)
}

fn thash_h(pub_seed: &[u8; 32], adrs: &[u8; 32], l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let key = prf(pub_seed, &addr_set_km(adrs, 0));
    let bm0 = prf(pub_seed, &addr_set_km(adrs, 1));
    let bm1 = prf(pub_seed, &addr_set_km(adrs, 2));
    let mut buf = [0u8; 128];
    buf[31] = 1;
    buf[32..64].copy_from_slice(&key);
    for i in 0..32 { buf[64 + i] = l[i] ^ bm0[i]; }
    for i in 0..32 { buf[96 + i] = r[i] ^ bm1[i]; }
    sha256(&buf)
}

fn h_msg(r: &[u8; 32], root: &[u8; 32], idx: u32, tx: &[u8]) -> [u8; 32] {
    let mut buf = vec![0u8; 128 + tx.len()];
    buf[31] = 2;
    buf[32..64].copy_from_slice(r);
    buf[64..96].copy_from_slice(root);
    let idx_bytes = (idx as u64).to_be_bytes();
    buf[120..128].copy_from_slice(&idx_bytes);
    buf[128..].copy_from_slice(tx);
    sha256(&buf)
}

// ─── ADRS helpers ──────────────────────────────────────────────────────────

fn make_ots_adrs(ots_idx: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[16..20].copy_from_slice(&ots_idx.to_be_bytes());
    a
}

fn make_ltree_adrs(leaf_idx: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[15] = 1;
    a[16..20].copy_from_slice(&leaf_idx.to_be_bytes());
    a
}

fn make_hashtree_adrs() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[15] = 2;
    a
}

fn adrs_set_chain(a: &[u8; 32], i: u32) -> [u8; 32] {
    let mut b = *a; b[20..24].copy_from_slice(&i.to_be_bytes()); b
}
fn adrs_set_hash(a: &[u8; 32], i: u32) -> [u8; 32] {
    let mut b = *a; b[24..28].copy_from_slice(&i.to_be_bytes()); b
}
fn adrs_set_tree_height(a: &[u8; 32], h: u32) -> [u8; 32] {
    let mut b = *a; b[20..24].copy_from_slice(&h.to_be_bytes()); b
}
fn adrs_set_tree_index(a: &[u8; 32], i: u32) -> [u8; 32] {
    let mut b = *a; b[24..28].copy_from_slice(&i.to_be_bytes()); b
}

// ─── WOTS+ ─────────────────────────────────────────────────────────────────

fn wots_chain(x: &[u8; 32], start: u32, steps: u32, pub_seed: &[u8; 32], adrs: &[u8; 32]) -> [u8; 32] {
    let mut tmp = *x;
    for i in start..start + steps {
        let a = adrs_set_hash(adrs, i);
        tmp = thash_f(pub_seed, &a, &tmp);
    }
    tmp
}

fn wots_pk_from_sk(sk_seed: &[u8; 32], pub_seed: &[u8; 32], ots_adrs: &[u8; 32]) -> [[u8; 32]; 67] {
    let mut pk = [[0u8; 32]; 67];
    for i in 0..67 {
        let chain_adrs = adrs_set_chain(ots_adrs, i as u32);
        let sk_i = prf(sk_seed, &chain_adrs);
        pk[i] = wots_chain(&sk_i, 0, 15, pub_seed, &chain_adrs);
    }
    pk
}

fn wots_sign(msg: &[u8; 32], sk_seed: &[u8; 32], pub_seed: &[u8; 32], ots_adrs: &[u8; 32]) -> [[u8; 32]; 67] {
    let mut lengths = [0u32; 67];
    for i in 0..32 {
        lengths[2 * i]     = (msg[i] >> 4) as u32;
        lengths[2 * i + 1] = (msg[i] & 0xf) as u32;
    }
    let csum: u32 = lengths[..64].iter().map(|&v| 15 - v).sum::<u32>() << 4;
    lengths[64] = (csum >> 12) & 0xf;
    lengths[65] = (csum >> 8)  & 0xf;
    lengths[66] = (csum >> 4)  & 0xf;

    let mut sig = [[0u8; 32]; 67];
    for i in 0..67 {
        let chain_adrs = adrs_set_chain(ots_adrs, i as u32);
        let sk_i = prf(sk_seed, &chain_adrs);
        sig[i] = wots_chain(&sk_i, 0, lengths[i], pub_seed, &chain_adrs);
    }
    sig
}

fn wots_pk_from_sig(sig: &[[u8; 32]; 67], msg: &[u8; 32], pub_seed: &[u8; 32], ots_adrs: &[u8; 32]) -> [[u8; 32]; 67] {
    let mut lengths = [0u32; 67];
    for i in 0..32 {
        lengths[2 * i]     = (msg[i] >> 4) as u32;
        lengths[2 * i + 1] = (msg[i] & 0xf) as u32;
    }
    let csum: u32 = lengths[..64].iter().map(|&v| 15 - v).sum::<u32>() << 4;
    lengths[64] = (csum >> 12) & 0xf;
    lengths[65] = (csum >> 8)  & 0xf;
    lengths[66] = (csum >> 4)  & 0xf;

    let mut pk = [[0u8; 32]; 67];
    for i in 0..67 {
        let chain_adrs = adrs_set_chain(ots_adrs, i as u32);
        pk[i] = wots_chain(&sig[i], lengths[i], 15 - lengths[i], pub_seed, &chain_adrs);
    }
    pk
}

// ─── L-tree ────────────────────────────────────────────────────────────────

fn ltree(wots_pk: &[[u8; 32]; 67], pub_seed: &[u8; 32], ltree_adrs: &[u8; 32]) -> [u8; 32] {
    let mut nodes: Vec<[u8; 32]> = wots_pk.to_vec();
    let mut l = 67usize;
    let mut height = 0u32;
    while l > 1 {
        let pairs = l >> 1;
        let adrs_h = adrs_set_tree_height(ltree_adrs, height);
        for i in 0..pairs {
            let a = adrs_set_tree_index(&adrs_h, i as u32);
            nodes[i] = thash_h(pub_seed, &a, &nodes[2 * i], &nodes[2 * i + 1]);
        }
        if l & 1 != 0 {
            nodes[l >> 1] = nodes[l - 1];
            l = (l >> 1) + 1;
        } else {
            l >>= 1;
        }
        height += 1;
    }
    nodes[0]
}

// ─── Auth path (for a given leaf index, compute auth path from all leaves) ─

fn compute_root(leaf: &[u8; 32], leaf_idx: u32, auth: &[[u8; 32]; 10], pub_seed: &[u8; 32], ht_adrs: &[u8; 32]) -> [u8; 32] {
    let mut node = *leaf;
    let mut idx = leaf_idx;
    for k in 0..10u32 {
        let a = adrs_set_tree_index(&adrs_set_tree_height(ht_adrs, k), idx / 2);
        node = if idx % 2 == 0 {
            thash_h(pub_seed, &a, &node, &auth[k as usize])
        } else {
            thash_h(pub_seed, &a, &auth[k as usize], &node)
        };
        idx >>= 1;
    }
    node
}

// ─── Keygen ────────────────────────────────────────────────────────────────
// Build all 1024 leaves, then compute Merkle root.
// sk = { sk_seed(32), r_seed(32), pub_seed(32), wots_sk_seeds: [[u8;32]; 1024] }
// pk = OID(4) + root(32) + pub_seed(32) = 68 bytes

fn keygen_internal(sk_seed: &[u8; 32], r_seed: &[u8; 32], pub_seed: &[u8; 32]) -> ([u8; 68], Vec<[u8; 32]>) {
    let n = 1024usize;
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(n);
    let ht_adrs = make_hashtree_adrs();

    for i in 0..n {
        let ots_adrs = make_ots_adrs(i as u32);
        let ltree_adrs = make_ltree_adrs(i as u32);
        // Derive per-leaf sk_seed via PRF
        let leaf_sk_seed = prf(sk_seed, &make_ots_adrs(i as u32));
        let wots_pk = wots_pk_from_sk(&leaf_sk_seed, pub_seed, &ots_adrs);
        let leaf = ltree(&wots_pk, pub_seed, &ltree_adrs);
        leaves.push(leaf);
        let _ = ht_adrs;
    }

    // Build Merkle tree (height 10, 1024 leaves)
    let mut tree = leaves.clone();
    let mut level_size = n;
    let mut level_offset = 0usize;
    let mut all_nodes = leaves.clone();

    // Build tree bottom-up
    let mut current = tree.clone();
    let ht = make_hashtree_adrs();
    for h in 0..10u32 {
        let next_size = current.len() / 2;
        let mut next = Vec::with_capacity(next_size);
        for i in 0..next_size {
            let a = adrs_set_tree_index(&adrs_set_tree_height(&ht, h), i as u32);
            next.push(thash_h(pub_seed, &a, &current[2 * i], &current[2 * i + 1]));
        }
        current = next;
        let _ = level_size;
        let _ = level_offset;
        let _ = all_nodes;
    }
    let root = current[0];

    // OID for XMSS-SHA2_10_256 = 0x00000001
    let mut pk = [0u8; 68];
    pk[3] = 1;
    pk[4..36].copy_from_slice(&root);
    pk[36..68].copy_from_slice(pub_seed);

    (pk, leaves)
}

fn compute_auth_path(leaves: &[[u8; 32]], leaf_idx: u32, pub_seed: &[u8; 32]) -> [[u8; 32]; 10] {
    let ht = make_hashtree_adrs();
    let mut current = leaves.to_vec();
    let mut auth = [[0u8; 32]; 10];
    let mut idx = leaf_idx as usize;

    for h in 0..10usize {
        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        auth[h] = current[sibling];
        let next_size = current.len() / 2;
        let mut next = Vec::with_capacity(next_size);
        for i in 0..next_size {
            let a = adrs_set_tree_index(&adrs_set_tree_height(&ht, h as u32), i as u32);
            next.push(thash_h(pub_seed, &a, &current[2 * i], &current[2 * i + 1]));
        }
        current = next;
        idx /= 2;
    }
    auth
}

// ─── Random bytes via getrandom ────────────────────────────────────────────

fn random_bytes_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf
}

// ─── WASM API ──────────────────────────────────────────────────────────────

/// Generate a new XMSS-SHA2_10_256 wallet.
/// Returns JSON: { public_key: hex, secret_key: hex, next_index: 0 }
/// secret_key encodes: sk_seed(32) + r_seed(32) + pub_seed(32) = 96 bytes
/// NOTE: keygen builds 1024 leaves — may take a few seconds in browser.
#[wasm_bindgen]
pub fn xmss_keygen() -> Result<String, JsError> {
    let sk_seed  = random_bytes_32();
    let r_seed   = random_bytes_32();
    let pub_seed = random_bytes_32();

    let (pk, _leaves) = keygen_internal(&sk_seed, &r_seed, &pub_seed);

    let mut sk = [0u8; 96];
    sk[0..32].copy_from_slice(&sk_seed);
    sk[32..64].copy_from_slice(&r_seed);
    sk[64..96].copy_from_slice(&pub_seed);

    let result = serde_json::json!({
        "public_key": hex::encode(pk),
        "secret_key": hex::encode(sk),
        "next_index": 0u32
    });
    Ok(result.to_string())
}

/// Sign tx_bytes with the XMSS key at leaf `leaf_index`.
/// sk_hex: 96-byte hex (sk_seed + r_seed + pub_seed)
/// tx_hex: arbitrary hex
/// Returns 2500-byte signature as hex string.
#[wasm_bindgen]
pub fn xmss_sign(sk_hex: &str, tx_hex: &str, leaf_index: u32) -> Result<String, JsError> {
    let sk_bytes = hex::decode(sk_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let tx_bytes = hex::decode(tx_hex).map_err(|e| JsError::new(&e.to_string()))?;
    if sk_bytes.len() != 96 { return Err(JsError::new("sk must be 96 bytes")); }

    let sk_seed:  [u8; 32] = sk_bytes[0..32].try_into().unwrap();
    let r_seed:   [u8; 32] = sk_bytes[32..64].try_into().unwrap();
    let pub_seed: [u8; 32] = sk_bytes[64..96].try_into().unwrap();

    // Rebuild pk to get root
    let (pk, leaves) = keygen_internal(&sk_seed, &r_seed, &pub_seed);
    let root: [u8; 32] = pk[4..36].try_into().unwrap();

    // r = PRF(r_seed, idx_bytes)
    let mut idx_adrs = [0u8; 32];
    idx_adrs[28..32].copy_from_slice(&leaf_index.to_be_bytes());
    let r = prf(&r_seed, &idx_adrs);

    // Message hash
    let msg_hash = h_msg(&r, &root, leaf_index, &tx_bytes);

    // WOTS+ sign
    let leaf_sk_seed = prf(&sk_seed, &make_ots_adrs(leaf_index));
    let ots_adrs = make_ots_adrs(leaf_index);
    let wots_sig = wots_sign(&msg_hash, &leaf_sk_seed, &pub_seed, &ots_adrs);

    // Auth path
    let auth = compute_auth_path(&leaves, leaf_index, &pub_seed);

    // Encode sig: idx(4) + r(32) + wots(67*32) + auth(10*32) = 2500 bytes
    let mut sig_bytes = Vec::with_capacity(2500);
    sig_bytes.extend_from_slice(&leaf_index.to_be_bytes());
    sig_bytes.extend_from_slice(&r);
    for w in &wots_sig { sig_bytes.extend_from_slice(w); }
    for a in &auth     { sig_bytes.extend_from_slice(a); }

    Ok(hex::encode(sig_bytes))
}

/// SHA-256 hash — returns hex string.
#[wasm_bindgen]
pub fn sha256_hex(data_hex: &str) -> Result<String, JsError> {
    let bytes = hex::decode(data_hex).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex::encode(sha256(&bytes)))
}
