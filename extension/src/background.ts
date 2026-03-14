// Background service worker — Sindri proving + Stellar submission

const SINDRI_CIRCUIT_ID    = '675b1311-8e2b-4b2c-9f16-44a548a3e2b7';
const WALLET_CONTRACT_HASH = 'a1c8f4b33bc6133d98258838ab2c3d8f86f201d78719e44ce3102046cd5a55df';

// ─── Hex helpers ──────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256hex(hex: string): Promise<string> {
  const bytes = hexToBytes(hex);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(hash));
}

// ─── Stellar address decoding ─────────────────────────────────────────────

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input: string): Uint8Array {
  let bits = 0, value = 0;
  const output: number[] = [];
  for (const char of input.toUpperCase()) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) break;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(output);
}

function stellarToRaw(addr: string): Uint8Array {
  const decoded = base32Decode(addr);
  // strip 1-byte version prefix and 2-byte checksum
  return decoded.slice(1, decoded.length - 2);
}

// Match Soroban's Address::to_xdr(env).slice(4..36) encoding
export function stellarToContractField(addr: string): Uint8Array {
  const raw = stellarToRaw(addr);
  const out = new Uint8Array(32);
  if (addr.startsWith('C')) {
    // Contract: [0,0,0,1] + hash[0..28]
    out[3] = 1;
    out.set(raw.slice(0, 28), 4);
  } else {
    // Account G...: 8 zero bytes + key[0..24]
    out.set(raw.slice(0, 24), 8);
  }
  return out;
}

// ─── tx_bytes (108 bytes) ─────────────────────────────────────────────────

export function buildTxBytes(
  pubkeyHashHex: string,
  nonce: number,
  destAddr: string,
  amountStroops: bigint
): Uint8Array {
  const contractHash = hexToBytes(WALLET_CONTRACT_HASH);
  const tx = new Uint8Array(108);
  const dv = new DataView(tx.buffer);

  // [0..32] contract_id_field: [0,0,0,1] + contractHash[0..28]
  tx[3] = 1;
  tx.set(contractHash.slice(0, 28), 4);

  // [32..64] pubkey_hash
  tx.set(hexToBytes(pubkeyHashHex), 32);

  // [64..68] nonce LE u32
  dv.setUint32(64, nonce, true);

  // [68..100] dest field
  tx.set(stellarToContractField(destAddr), 68);

  // [100..108] amount BE i64
  dv.setBigInt64(100, amountStroops, false);

  return tx;
}

// ─── Get wallet balance + nonce via Soroban RPC ───────────────────────────

// ─── Sindri proving ───────────────────────────────────────────────────────

function bincodeVecU8(data: Uint8Array): Uint8Array {
  const len = new Uint8Array(8);
  new DataView(len.buffer).setBigUint64(0, BigInt(data.length), true);
  const out = new Uint8Array(8 + data.length);
  out.set(len); out.set(data, 8);
  return out;
}

export async function sindriProve(
  sindriKey: string,
  pkHex: string,
  txHex: string,
  sigHex: string
): Promise<{ proofBytes: string; publicValues: string }> {
  const pk  = hexToBytes(pkHex);
  const tx  = hexToBytes(txHex);
  const sig = hexToBytes(sigHex);

  const pkBin  = bincodeVecU8(pk);
  const txBin  = bincodeVecU8(tx);
  const sigBin = bincodeVecU8(sig);

  const stdin = {
    buffer: [Array.from(pkBin), Array.from(txBin), Array.from(sigBin)],
    ptr: 0,
    proofs: []
  };

  // Submit to Sindri
  const submitRes = await fetch(
    `https://sindri.app/api/v1/circuit/${SINDRI_CIRCUIT_ID}/prove`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${sindriKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ proof_input: JSON.stringify(stdin) }),
    }
  );
  if (!submitRes.ok) throw new Error(`Sindri submit failed: ${submitRes.status}`);
  const { proof_id } = await submitRes.json();

  // Poll
  for (let i = 0; i < 120; i++) {
    await new Promise(r => setTimeout(r, 5000));
    const pollRes = await fetch(
      `https://sindri.app/api/v1/proof/${proof_id}/detail`,
      { headers: { 'Authorization': `Bearer ${sindriKey}` } }
    );
    const detail = await pollRes.json();
    if (detail.status === 'Ready') {
      return parseProof(detail, pkHex, txHex);
    }
    if (detail.status === 'Failed') throw new Error('Sindri proof failed');
  }
  throw new Error('Sindri timeout');
}

function parseProof(
  detail: any,
  pkHex: string,
  txHex: string
): { proofBytes: string; publicValues: string } {
  // Decode base64 msgpack proof
  const b64 = detail.proof.proof as string;
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const decoded = decodeMsgpack(raw);

  // decoded[0]['Groth16'] = [[pi0,pi1], enc_proof_hex, raw_proof_hex, vkey_hash_bytes]
  const groth16 = decoded[0]['Groth16'];
  const encProofHex: string = groth16[1];
  const vkeyHashBytes: number[] = groth16[3];
  const pi = groth16[0]; // [pi0, pi1] — pi1 = committed_values_digest
  console.log('[nebula] encProofHex length:', encProofHex.length, 'chars =', encProofHex.length/2, 'bytes');
  console.log('[nebula] vkeyHash hex:', bytesToHex(new Uint8Array(vkeyHashBytes)));
  const rawProofHex: string = groth16[2];
  console.log('[nebula] pi1 (committed_values_digest):', JSON.stringify(pi[1]));
  console.log('[nebula] encProofHex[:8]:', encProofHex.slice(0, 8));
  console.log('[nebula] rawProofHex length:', typeof rawProofHex === 'string' ? rawProofHex.length : 'NOT STRING', rawProofHex && typeof rawProofHex === 'string' ? rawProofHex.length/2 + 'bytes' : '');

  // proof_bytes = vkey_hash[0..4] + enc_proof (260 bytes)
  const vkPrefix = bytesToHex(new Uint8Array(vkeyHashBytes.slice(0, 4)));
  const proofBytes = vkPrefix + encProofHex;

  // public_values = sha256(pk) + sha256(tx) + nonce_le_u32
  // Nonce is in tx[64..68]
  const txBytes = hexToBytes(txHex);
  const nonce = new DataView(txBytes.buffer).getUint32(64, true);
  const nonceBuf = new Uint8Array(4);
  new DataView(nonceBuf.buffer).setUint32(0, nonce, true);

  // We'll compute sha256 synchronously via a placeholder — actual hashing is async
  // so we pass raw hex and compute in the caller
  return {
    proofBytes,
    publicValues: `PENDING:${pkHex}:${txHex}:${nonce}`,
  };
}

// ─── Minimal msgpack decoder ──────────────────────────────────────────────

function decodeMsgpack(buf: Uint8Array): any {
  let pos = 0;
  function read(n: number): Uint8Array { const s = buf.slice(pos, pos + n); pos += n; return s; }
  function readU8(): number { return buf[pos++]; }
  function readU16(): number { const v = (buf[pos] << 8) | buf[pos + 1]; pos += 2; return v; }
  function readU32(): number { const v = (buf[pos] << 24 | buf[pos+1] << 16 | buf[pos+2] << 8 | buf[pos+3]) >>> 0; pos += 4; return v; }

  function decode(): any {
    const b = readU8();
    if (b <= 0x7f) return b;
    if (b >= 0x80 && b <= 0x8f) { // fixmap
      const n = b & 0x0f; const obj: any = {};
      for (let i = 0; i < n; i++) { const k = decode(); obj[k] = decode(); } return obj;
    }
    if (b >= 0x90 && b <= 0x9f) { // fixarray
      const n = b & 0x0f; return Array.from({ length: n }, decode);
    }
    if (b >= 0xa0 && b <= 0xbf) { // fixstr
      const n = b & 0x1f; return new TextDecoder().decode(read(n));
    }
    if (b === 0xc4) { const n = readU8(); return Array.from(read(n)); } // bin8
    if (b === 0xc5) { const n = readU16(); return Array.from(read(n)); } // bin16
    if (b === 0xca) { const v = new DataView(read(4).buffer).getFloat32(0); return v; } // float32
    if (b === 0xcb) { const v = new DataView(read(8).buffer).getFloat64(0); return v; } // float64
    if (b === 0xcc) return readU8();   // uint8
    if (b === 0xcd) return readU16();  // uint16
    if (b === 0xce) return readU32();  // uint32
    if (b === 0xd9) { const n = readU8(); return new TextDecoder().decode(read(n)); }  // str8
    if (b === 0xda) { const n = readU16(); return new TextDecoder().decode(read(n)); } // str16
    if (b === 0xdc) { const n = readU16(); return Array.from({ length: n }, decode); } // array16
    if (b === 0xde) { const n = readU16(); const obj: any = {}; for (let i = 0; i < n; i++) { const k = decode(); obj[k] = decode(); } return obj; } // map16
    if (b >= 0xe0) return b - 256; // negative fixint
    throw new Error(`Unknown msgpack byte: 0x${b.toString(16)}`);
  }
  return decode();
}

// ─── Stellar submit (via relay server) ───────────────────────────────────────

const RELAY_URL = 'https://backend.iameshan.tech/relayer';

export async function stellarSubmit(
  proofBytes: string,
  publicValues: string,
  destAddr: string,
  amountStroops: bigint
): Promise<string> {
  const res = await fetch(`${RELAY_URL}/withdraw`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      proof_bytes:    proofBytes,
      public_values:  publicValues,
      destination:    destAddr,
      amount_stroops: Number(amountStroops),
    }),
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Relay error ${res.status}`);
  return data.tx_hash;
}

// ─── Message handler ──────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'PROVE') {
    sindriProve(msg.sindriKey, msg.pkHex, msg.txHex, msg.sigHex)
      .then(result => sendResponse({ ok: true, ...result }))
      .catch(err  => sendResponse({ ok: false, error: err.message }));
    return true;
  }
  if (msg.type === 'SUBMIT') {
    stellarSubmit(msg.proofBytes, msg.publicValues, msg.destAddr, BigInt(msg.amountStroops))
      .then(txHash => sendResponse({ ok: true, txHash }))
      .catch(err   => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});
