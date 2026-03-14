// WebCrypto-based key encryption for XMSS wallet storage.
// Uses PBKDF2 → AES-256-GCM for password-protected key storage.

export interface WalletData {
  public_key: string;   // hex, 68 bytes
  secret_key: string;   // hex, 96 bytes
  next_index: number;
}

const STORAGE_KEY = 'nebula_wallet_enc';

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function walletExists(): Promise<boolean> {
  return new Promise(resolve => {
    chrome.storage.local.get(STORAGE_KEY, (res) => {
      resolve(!!res[STORAGE_KEY]);
    });
  });
}

export async function saveWallet(wallet: WalletData, password: string): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt);
  const data = new TextEncoder().encode(JSON.stringify(wallet));
  const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);

  const payload = {
    salt: Array.from(salt),
    iv:   Array.from(iv),
    ct:   Array.from(new Uint8Array(ct)),
  };
  return new Promise(resolve => {
    chrome.storage.local.set({ [STORAGE_KEY]: payload }, resolve);
  });
}

export async function loadWallet(password: string): Promise<WalletData> {
  const payload: any = await new Promise(resolve => {
    chrome.storage.local.get(STORAGE_KEY, (res) => resolve(res[STORAGE_KEY]));
  });
  if (!payload) throw new Error('No wallet found');

  const salt = new Uint8Array(payload.salt);
  const iv   = new Uint8Array(payload.iv);
  const ct   = new Uint8Array(payload.ct);
  const key  = await deriveKey(password, salt);

  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(plain));
}
