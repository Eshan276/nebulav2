"""
bridge.py — orchestrates the XMSS PQ Wallet ZK proof pipeline:

  1. Compute 108-byte tx_bytes = get_withdraw_msg (contract_id||pubkey_hash||nonce||dest||amount)
  2. XMSS sign tx → proof_inputs.json
  3. Submit SP1 Groth16 proof to Sindri
  4. Poll until ready
  5. Parse proof → print stellar contract invoke for `withdraw`

Usage:
    python bridge.py --pubkey-hash <hex32> --destination <Gxxxx> --amount <stroops>
    python bridge.py --pubkey-hash <hex32> --destination <Gxxxx> --amount <stroops> --skip-sign
    python bridge.py --pubkey-hash <hex32> --destination <Gxxxx> --amount <stroops> --skip-prove
    python bridge.py --pubkey-hash <hex32> --destination <Gxxxx> --amount <stroops> --proof-id <id>

Env vars (in .env):
    WALLET_CONTRACT_ID       — deployed XMSS wallet contract (CCQ4...)
    WALLET_CONTRACT_HASH     — 32-byte hex inner hash of contract (for tx_bytes)
    SINDRI_API_KEY           — for Sindri cloud proving
    STELLAR_SECRET_KEY       — for contract invocation (account alias or key)
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# Auto-load .env
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

ROOT = Path(__file__).parent
PROOF_INPUTS = ROOT / "proof_inputs.json"
PROOF_CACHE  = ROOT / "groth16_proof.json"

SINDRI_API = "https://sindri.app/api/v1"
GROTH16_CIRCUIT_ID = "45580910-1595-4c24-a03a-c7f54574e9b0"


# ── helpers ──────────────────────────────────────────────────────────────────

def sindri_request(path, data=None, method=None):
    api_key = os.environ.get("SINDRI_API_KEY", "")
    if not api_key:
        sys.exit("SINDRI_API_KEY not set")
    url = SINDRI_API + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url,
        data=body,
        method=method or ("POST" if body else "GET"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read()
        sys.exit(f"Sindri HTTP {e.code}: {body[:300]}")


def bincode_vec_u8(data: bytes) -> bytes:
    return struct.pack("<Q", len(data)) + data


def build_sp1_stdin(pk: bytes, tx: bytes, sig: bytes) -> dict:
    buffer = [
        list(bincode_vec_u8(pk)),
        list(bincode_vec_u8(tx)),
        list(bincode_vec_u8(sig)),
    ]
    return {"buffer": buffer, "ptr": 0, "proofs": []}


def stellar_address_to_bytes(addr: str) -> bytes:
    """Decode a Stellar strkey address to its raw 32-byte key/hash payload.

    Strips the 1-byte version prefix and 2-byte CRC16 checksum.
    Works for both G... (ed25519 pubkey) and C... (contract ID) addresses.
    """
    pad = (8 - len(addr) % 8) % 8
    decoded = base64.b32decode(addr + "=" * pad)
    return decoded[1:-2]


def stellar_address_to_contract_field(addr: str) -> bytes:
    """Return the 32-byte field the Soroban contract uses for this address in tx_bytes.

    Replicates Address::to_xdr(env).slice(4..36):
      - C... (contract):  [0,0,0,0] discriminant(4) is at [0..4], payload at [4..36]
                          → returns the 32-byte contract hash  ✓
      - G... (account):   XDR = [0,0,0,1][0,0,0,0] + ed25519_key(32) = 40 bytes
                          slice(4..36) = [0,0,0,0] + key[0:28]
                          → returns [0,0,0,0] + first_28_bytes_of_key
    """
    raw = stellar_address_to_bytes(addr)
    if addr.startswith("C"):
        # contract address: XDR = [0,0,0,0] + 32-byte hash → slice(4..36) = hash
        return raw
    else:
        # account address: XDR = [0,0,0,1,0,0,0,0] + 32-byte key → slice(4..36)
        # = [0,0,0,0] + key[0:28]
        return b"\x00\x00\x00\x00" + raw[:28]


def build_tx_bytes(
    contract_hash: bytes,   # 32 bytes — inner hash of wallet contract address
    pubkey_hash: bytes,     # 32 bytes — sha256(xmss_pubkey)
    nonce: int,             # u32 — current wallet nonce
    destination_bytes: bytes,  # 32 bytes — inner payload of destination address
    amount: int,            # i64 stroops
) -> bytes:
    """Build the 108-byte tx that the user signs, matching build_tx_bytes in lib.rs."""
    assert len(contract_hash) == 32
    assert len(pubkey_hash) == 32
    assert len(destination_bytes) == 32
    tx = (
        contract_hash
        + pubkey_hash
        + struct.pack("<I", nonce)
        + destination_bytes
        + struct.pack(">q", amount)
    )
    assert len(tx) == 108
    return tx


def decode_msgpack_proof(raw: bytes) -> dict:
    """Minimal msgpack decoder for SP1 Groth16 proof structure."""
    pos = [0]

    def rb():
        b = raw[pos[0]]; pos[0] += 1; return b

    def rbs(n):
        b = raw[pos[0]:pos[0]+n]; pos[0] += n; return b

    def decode():
        b = rb()
        if 0x90 <= b <= 0x9f: return [decode() for _ in range(b & 0x0f)]
        if 0x80 <= b <= 0x8f:
            d = {}
            for _ in range(b & 0x0f): k = decode(); v = decode(); d[k] = v
            return d
        if 0xa0 <= b <= 0xbf: return rbs(b & 0x1f).decode()
        if b == 0xd9: return rbs(rb()).decode()
        if b == 0xda: return rbs(struct.unpack(">H", rbs(2))[0]).decode()
        if b == 0xdb: return rbs(struct.unpack(">I", rbs(4))[0]).decode()
        if b == 0xc4: return rbs(rb())
        if b == 0xc5: return rbs(struct.unpack(">H", rbs(2))[0])
        if b == 0xc6: return rbs(struct.unpack(">I", rbs(4))[0])
        if b == 0xdc: return [decode() for _ in range(struct.unpack(">H", rbs(2))[0])]
        if b == 0xdd: return [decode() for _ in range(struct.unpack(">I", rbs(4))[0])]
        if b <= 0x7f: return b
        if b >= 0xe0: return b - 256
        if b == 0xcc: return rb()
        if b == 0xcd: return struct.unpack(">H", rbs(2))[0]
        if b == 0xce: return struct.unpack(">I", rbs(4))[0]
        if b == 0xcf: return struct.unpack(">Q", rbs(8))[0]
        raise ValueError(f"Unknown msgpack byte 0x{b:02x} at {pos[0]-1}")

    result = decode()
    inner = result[0]
    g16 = inner["Groth16"]
    pub_inputs, enc_proof_hex, raw_proof_hex, vkey_hash = g16
    if isinstance(vkey_hash, list):
        vkey_hash = bytes(vkey_hash)
    return {
        "pub_inputs": [str(pub_inputs[0]), str(pub_inputs[1])],
        "enc_proof": bytes.fromhex(enc_proof_hex),   # 256 bytes
        "raw_proof": bytes.fromhex(raw_proof_hex),   # 324 bytes
        "vkey_hash": vkey_hash,                       # 32 bytes
    }


def build_proof_bytes(enc_proof: bytes, vkey_hash: bytes) -> bytes:
    """Prepend 4-byte selector to get 260-byte SP1 Groth16 proof."""
    return vkey_hash[:4] + enc_proof


def build_public_values(proof_inputs: dict) -> bytes:
    """Build 68-byte public_values: pubkey_hash(32) + tx_hash(32) + nonce(4 LE u32)."""
    pk = bytes.fromhex(proof_inputs["public_key"])
    tx = bytes.fromhex(proof_inputs["tx_bytes"])
    leaf_index = proof_inputs.get("leaf_index", 0)
    pubkey_hash = hashlib.sha256(pk).digest()
    tx_hash = hashlib.sha256(tx).digest()
    nonce = struct.pack("<I", leaf_index)
    return pubkey_hash + tx_hash + nonce


def get_wallet_nonce(pubkey_hash_hex: str, contract_id: str) -> int:
    """Query the wallet contract for the current nonce of a pubkey_hash."""
    try:
        result = subprocess.run(
            [
                "stellar", "contract", "invoke",
                "--id", contract_id,
                "--network", "testnet",
                "--", "nonce",
                "--pubkey_hash", pubkey_hash_hex,
            ],
            capture_output=True, text=True, check=True,
        )
        return int(result.stdout.strip().strip('"'))
    except subprocess.CalledProcessError as e:
        print(f"Warning: could not query nonce: {e.stderr[:200]}")
        print("Using nonce=0")
        return 0


# ── steps ─────────────────────────────────────────────────────────────────────

def step_sign(pubkey_hash_hex: str, destination: str, amount: int):
    """Build tx_bytes, XMSS sign → proof_inputs.json."""
    xmss_bin = ROOT / "xmss" / "target" / "release" / "xmss"
    key_file  = ROOT / "key.json"

    if not xmss_bin.exists():
        print("Building XMSS binary...")
        r = subprocess.run(["cargo", "build", "--release"], cwd=ROOT / "xmss")
        if r.returncode != 0:
            sys.exit("xmss build failed")

    if not key_file.exists():
        print("Generating XMSS keypair...")
        subprocess.run([str(xmss_bin), "keygen", "--out", str(key_file)], check=True)

    contract_id = os.environ.get("WALLET_CONTRACT_ID", "")
    if not contract_id:
        sys.exit("WALLET_CONTRACT_ID not set in .env")

    contract_hash_hex = os.environ.get("WALLET_CONTRACT_HASH", "")
    if not contract_hash_hex:
        sys.exit("WALLET_CONTRACT_HASH not set in .env")

    contract_hash = bytes.fromhex(contract_hash_hex)
    pubkey_hash = bytes.fromhex(pubkey_hash_hex)
    dest_bytes = stellar_address_to_contract_field(destination)

    # Get current nonce from chain
    nonce = get_wallet_nonce(pubkey_hash_hex, contract_id)
    print(f"Wallet nonce: {nonce}")

    tx_bytes = build_tx_bytes(contract_hash, pubkey_hash, nonce, dest_bytes, amount)
    tx_hex = tx_bytes.hex()
    print(f"tx_bytes ({len(tx_bytes)} bytes): {tx_hex[:32]}...")

    print("Signing tx with XMSS...")
    subprocess.run(
        [str(xmss_bin), "sign", "--key", str(key_file), "--tx", tx_hex, "--out", str(PROOF_INPUTS)],
        check=True,
    )
    print(f"proof_inputs.json written ({PROOF_INPUTS.stat().st_size} bytes)")


def step_prove() -> str:
    """Submit proof job to Sindri, return proof_id."""
    inputs = json.loads(PROOF_INPUTS.read_text())
    pk  = bytes.fromhex(inputs["public_key"])
    tx  = bytes.fromhex(inputs["tx_bytes"])
    sig = bytes.fromhex(inputs["signature"])

    stdin = build_sp1_stdin(pk, tx, sig)
    print(f"Submitting to Sindri circuit {GROTH16_CIRCUIT_ID[:8]}...")
    resp = sindri_request(
        f"/circuit/{GROTH16_CIRCUIT_ID}/prove",
        {"proof_input": json.dumps(stdin)},
    )
    proof_id = resp["proof_id"]
    print(f"Proof job submitted: {proof_id[:8]}...")
    return proof_id


def step_poll(proof_id: str) -> dict:
    """Poll Sindri until proof is ready, return detail response."""
    print(f"Polling proof {proof_id[:8]}...", end="", flush=True)
    for i in range(120):
        detail = sindri_request(f"/proof/{proof_id}/detail")
        status = detail.get("status", "?")
        if status == "Ready":
            print(f" Ready ({detail.get('compute_time', '')})")
            return detail
        if status in ("Failed", "Timed Out"):
            err = detail.get("error", "")
            sys.exit(f"\nProof {status}: {err[:300]}")
        print(".", end="", flush=True)
        time.sleep(30)
    sys.exit("\nTimed out waiting for proof")


def step_parse_and_print(detail: dict, inputs: dict, destination: str, amount: int):
    """Parse the Groth16 proof and print the stellar contract invoke for withdraw."""
    proof_b64 = detail["proof"]["proof"]
    raw = base64.b64decode(proof_b64)
    parsed = decode_msgpack_proof(raw)

    enc_proof  = parsed["enc_proof"]   # 256 bytes
    vkey_hash  = parsed["vkey_hash"]   # 32 bytes
    pub_inputs = parsed["pub_inputs"]  # [str, str]

    proof_bytes   = build_proof_bytes(enc_proof, vkey_hash)
    public_values = build_public_values(inputs)

    program_vkey_int = int(pub_inputs[0])
    program_vkey = program_vkey_int.to_bytes(32, "big")

    nonce = struct.unpack("<I", public_values[64:])[0]

    cache = {
        "proof_id":       detail["proof_id"],
        "proof_bytes":    proof_bytes.hex(),
        "public_values":  public_values.hex(),
        "program_vkey":   program_vkey.hex(),
        "vkey_hash":      vkey_hash.hex(),
        "pubkey_hash":    public_values[:32].hex(),
        "tx_hash":        public_values[32:64].hex(),
        "nonce":          nonce,
        "destination":    destination,
        "amount":         amount,
    }
    PROOF_CACHE.write_text(json.dumps(cache, indent=2))
    print(f"Proof cached to {PROOF_CACHE}")

    contract_id = os.environ.get("WALLET_CONTRACT_ID", "<deploy first>")
    secret_key  = os.environ.get("STELLAR_SECRET_KEY", "quantum-deployer")

    print(f"""
{'='*70}
PROOF READY
{'='*70}
proof_bytes   : {len(proof_bytes)} bytes
public_values : {len(public_values)} bytes
program_vkey  : {program_vkey.hex()}
pubkey_hash   : {public_values[:32].hex()}
tx_hash       : {public_values[32:64].hex()}
nonce         : {nonce}
destination   : {destination}
amount        : {amount} stroops ({amount/10_000_000:.7f} XLM)

── Withdraw on Stellar testnet ───────────────────────────────────────────────
stellar contract invoke \\
  --id {contract_id} \\
  --source-account {secret_key} \\
  --network testnet \\
  -- withdraw \\
  --proof_bytes {proof_bytes.hex()} \\
  --public_values {public_values.hex()} \\
  --destination {destination} \\
  --amount {amount}
""")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="XMSS PQ Wallet bridge")
    parser.add_argument("--pubkey-hash",  required=False, default="",
                        help="sha256(xmss_pubkey) as 64-char hex")
    parser.add_argument("--destination",  required=False, default="",
                        help="Stellar destination address (G...)")
    parser.add_argument("--amount",       type=int, default=0,
                        help="Amount in stroops (1 XLM = 10_000_000)")
    parser.add_argument("--skip-sign",    action="store_true")
    parser.add_argument("--skip-prove",   action="store_true")
    parser.add_argument("--proof-id",     help="Use an existing Sindri proof ID")
    args = parser.parse_args()

    if not args.skip_sign and not args.skip_prove and not args.proof_id:
        if not args.pubkey_hash or not args.destination or not args.amount:
            sys.exit("--pubkey-hash, --destination, and --amount are required for signing")
        step_sign(args.pubkey_hash, args.destination, args.amount)
    else:
        if not PROOF_INPUTS.exists():
            sys.exit("proof_inputs.json not found — run without --skip-sign first")
        existing = json.loads(PROOF_INPUTS.read_text())
        print(f"Using existing proof_inputs.json (leaf_index={existing.get('leaf_index',0)})")

    inputs = json.loads(PROOF_INPUTS.read_text())
    destination = args.destination or ""
    amount      = args.amount or 0

    if args.skip_prove:
        if not PROOF_CACHE.exists():
            sys.exit("groth16_proof.json not found — run without --skip-prove first")
        cache = json.loads(PROOF_CACHE.read_text())
        print(f"Using cached proof {cache['proof_id'][:8]}...")
        contract_id = os.environ.get("WALLET_CONTRACT_ID", "<deploy first>")
        secret_key  = os.environ.get("STELLAR_SECRET_KEY", "quantum-deployer")
        destination = destination or cache.get("destination", "")
        amount      = amount or cache.get("amount", 0)
        print(f"""
stellar contract invoke \\
  --id {contract_id} \\
  --source-account {secret_key} \\
  --network testnet \\
  -- withdraw \\
  --proof_bytes {cache['proof_bytes']} \\
  --public_values {cache['public_values']} \\
  --destination {destination} \\
  --amount {amount}
""")
        return

    proof_id = args.proof_id or step_prove()
    detail   = step_poll(proof_id)
    step_parse_and_print(detail, inputs, destination, amount)
    print("Done.")


if __name__ == "__main__":
    main()
