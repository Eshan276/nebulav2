import React, { useState, useEffect, useCallback } from 'react'
import ReactDOM from 'react-dom/client'
import { walletExists, saveWallet, loadWallet, WalletData } from './crypto'
import { buildTxBytes, stellarToContractField } from './background'
import * as StellarSdk from '@stellar/stellar-sdk'

const WALLET_CONTRACT_ID  = 'CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B'
const SOROBAN_RPC = 'https://soroban-testnet.stellar.org'
const HORIZON_RPC = 'https://horizon-testnet.stellar.org'
const MAX_LEAVES = 1024

// ─── Styles ────────────────────────────────────────────────────────────────

const S: Record<string, React.CSSProperties> = {
  root:    { width: 380, minHeight: 500, background: '#0a0a0f', color: '#e0e0e0', fontFamily: "'Courier New', monospace", padding: 20 },
  header:  { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, borderBottom: '1px solid #1e1e2e', paddingBottom: 12 },
  title:   { color: '#7c6af7', fontSize: 18, fontWeight: 700, letterSpacing: 2 },
  badge:   { background: '#1e1e2e', color: '#7c6af7', fontSize: 10, padding: '2px 8px', borderRadius: 999, border: '1px solid #7c6af7' },
  card:    { background: '#0e0e1a', border: '1px solid #1e1e2e', borderRadius: 8, padding: 16, marginBottom: 12 },
  label:   { color: '#666', fontSize: 11, marginBottom: 4, textTransform: 'uppercase' as const, letterSpacing: 1 },
  value:   { fontSize: 28, fontWeight: 700, color: '#e0e0e0' },
  sub:     { fontSize: 12, color: '#666', marginTop: 2 },
  row:     { display: 'flex', gap: 12, marginBottom: 12 },
  smallCard: { flex: 1, background: '#0e0e1a', border: '1px solid #1e1e2e', borderRadius: 8, padding: 12 },
  btn:     { width: '100%', padding: '12px 0', background: '#7c6af7', color: '#fff', border: 'none', borderRadius: 8, fontSize: 14, fontFamily: 'inherit', cursor: 'pointer', fontWeight: 700, letterSpacing: 1 },
  btnGhost:{ width: '100%', padding: '10px 0', background: 'transparent', color: '#7c6af7', border: '1px solid #7c6af7', borderRadius: 8, fontSize: 13, fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 },
  input:   { width: '100%', background: '#0e0e1a', border: '1px solid #1e1e2e', borderRadius: 6, padding: '10px 12px', color: '#e0e0e0', fontFamily: 'inherit', fontSize: 13, outline: 'none', boxSizing: 'border-box' as const },
  inputLabel: { color: '#666', fontSize: 11, marginBottom: 6, display: 'block', textTransform: 'uppercase' as const, letterSpacing: 1 },
  step:    { display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', fontSize: 13 },
  stepDot: (status: 'pending' | 'active' | 'done' | 'error') => ({
    width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
    background: status === 'done' ? '#4ade80' : status === 'active' ? '#7c6af7' : status === 'error' ? '#f87171' : '#333',
    boxShadow: status === 'active' ? '0 0 8px #7c6af7' : 'none',
  }),
  progress: { height: 6, background: '#1e1e2e', borderRadius: 999, overflow: 'hidden', marginTop: 6 },
  progressBar: (pct: number) => ({ height: '100%', width: `${pct}%`, background: '#7c6af7', borderRadius: 999, transition: 'width 0.3s' }),
  error:   { color: '#f87171', fontSize: 12, marginTop: 8 },
  mono:    { fontFamily: 'monospace', fontSize: 11, color: '#666', wordBreak: 'break-all' as const },
}

// ─── WASM loader ───────────────────────────────────────────────────────────

let wasmModule: any = null

async function loadWasm() {
  if (wasmModule) return wasmModule
  const wasm = await import('../../xmss-wasm/pkg/xmss_wasm.js')
  await wasm.default()
  wasmModule = wasm
  return wasm
}

// ─── Stellar helpers ───────────────────────────────────────────────────────

async function sha256hex(hex: string): Promise<string> {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  const hash = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function contractCall(method: string, pubkeyHashHex: string): Promise<number> {
  try {
    const server = new StellarSdk.rpc.Server(SOROBAN_RPC)
    const contract = new StellarSdk.Contract(WALLET_CONTRACT_ID)
    const hexBytes = new Uint8Array(pubkeyHashHex.length / 2)
    for (let i = 0; i < pubkeyHashHex.length; i += 2)
      hexBytes[i / 2] = parseInt(pubkeyHashHex.slice(i, i + 2), 16)
    const pubkeyHashBytes = StellarSdk.xdr.ScVal.scvBytes(hexBytes)
    const account = await server.getAccount('GA2UZMETZS7GRYFH4H7LAUZXUP3J6JWMB7IN2E7IHXDQSR7JXU44H4A5')
    const tx = new StellarSdk.TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: StellarSdk.Networks.TESTNET,
    })
      .addOperation(contract.call(method, pubkeyHashBytes))
      .setTimeout(30)
      .build()

    const sim = await server.simulateTransaction(tx)
    if (StellarSdk.rpc.Api.isSimulationError(sim)) return 0
    const retval = (sim as StellarSdk.rpc.Api.SimulateTransactionSuccessResponse).result?.retval
    if (!retval) return 0
    return Number(StellarSdk.scValToNative(retval))
  } catch (e) {
    console.error(`[nebula] contractCall ${method} threw:`, e)
    return 0
  }
}

async function getWalletBalance(pubkeyHashHex: string): Promise<{ balance: number; nonce: number }> {
  const [balance, nonce] = await Promise.all([
    contractCall('balance', pubkeyHashHex),
    contractCall('nonce', pubkeyHashHex),
  ])
  return { balance, nonce }
}

// ─── Views ─────────────────────────────────────────────────────────────────

type View = 'unlock' | 'create' | 'dashboard' | 'send' | 'proving' | 'setup'

interface ProveStep {
  label: string
  status: 'pending' | 'active' | 'done' | 'error'
  detail?: string
}

// ─── App ───────────────────────────────────────────────────────────────────

function App() {
  const [view, setView]     = useState<View>('unlock')
  const [wallet, setWallet] = useState<WalletData | null>(null)
  const [balance, setBalance] = useState<number>(0)
  const [nonce, setNonce]   = useState<number>(0)
  const [pubkeyHash, setPubkeyHash] = useState<string>('')
  const [copied, setCopied] = useState(false)
  const [error, setError]   = useState<string>('')
  const [lastTxHash, setLastTxHash] = useState<string>('')
  const [password, setPassword] = useState('')
  const [sindriKey, setSindriKey] = useState('')
  const [stellarSecret, setStellarSecret] = useState('')

  // Send form
  const [destAddr, setDestAddr]   = useState('')
  const [amount, setAmount]       = useState('')

  // Prove progress
  const [steps, setSteps] = useState<ProveStep[]>([])
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    walletExists().then(exists => {
      if (!exists) setView('create')
    })
    chrome.storage.local.get(['sindri_key', 'stellar_secret'], (res) => {
      if (res.sindri_key) setSindriKey(res.sindri_key)
      if (res.stellar_secret) setStellarSecret(res.stellar_secret)
    })
  }, [])

  const updateStep = (idx: number, status: ProveStep['status'], detail?: string) => {
    setSteps(prev => prev.map((s, i) => i === idx ? { ...s, status, detail } : s))
  }

  const refreshBalance = useCallback(async (hash: string) => {
    try {
      const { balance: b, nonce: n } = await getWalletBalance(hash)
      setBalance(b)
      setNonce(n)
    } catch { /* ignore */ }
  }, [])

  const handleUnlock = async () => {
    try {
      const w = await loadWallet(password)
      setWallet(w)
      const hash = await sha256hex(w.public_key)
      setPubkeyHash(hash)
      setView('dashboard')
      setError('')
      refreshBalance(hash)
    } catch {
      setError('Wrong password')
    }
  }

  const handleCreate = async () => {
    if (!password || password.length < 6) { setError('Password must be at least 6 chars'); return }
    try {
      const wasm = await loadWasm()
      const json = wasm.xmss_keygen()
      const w: WalletData = JSON.parse(json)
      await saveWallet(w, password)
      if (sindriKey) chrome.storage.local.set({ sindri_key: sindriKey })
      setWallet(w)
      const hash = await sha256hex(w.public_key)
      setPubkeyHash(hash)
      setView('dashboard')
      refreshBalance(hash)
    } catch (e: any) {
      setError(e.message)
    }
  }

  const handleSend = async () => {
    if (!wallet || !sindriKey) { setError('Missing wallet or Sindri key'); return }
    if (!destAddr.startsWith('G')) { setError('Destination must be a G... address'); return }
    const amtNum = parseFloat(amount)
    if (isNaN(amtNum) || amtNum <= 0) { setError('Invalid amount'); return }

    const amountStroops = BigInt(Math.round(amtNum * 1e7))
    setView('proving')
    setElapsed(0)

    const stepList: ProveStep[] = [
      { label: 'Building transaction', status: 'active' },
      { label: 'Signing with XMSS key', status: 'pending' },
      { label: 'Generating ZK proof (Sindri)', status: 'pending' },
      { label: 'Submitting to Stellar', status: 'pending' },
    ]
    setSteps(stepList)

    // Elapsed timer
    const startTime = Date.now()
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - startTime) / 1000)), 1000)

    try {
      // Step 1: build tx_bytes — always fetch nonce from chain (not wallet.next_index which tracks XMSS leaves)
      const pubkeyHash = await sha256hex(wallet.public_key)
      const chainNonce = await contractCall('nonce', pubkeyHash)
      const txBytes = buildTxBytes(pubkeyHash, chainNonce, destAddr, amountStroops)
      const txHex = Array.from(txBytes).map(b => b.toString(16).padStart(2, '0')).join('')
      updateStep(0, 'done')

      // Step 2: XMSS sign (use wallet.next_index for leaf, chainNonce for tx nonce)
      updateStep(1, 'active')
      const wasm = await loadWasm()
      const sigHex = wasm.xmss_sign(wallet.secret_key, txHex, wallet.next_index)
      updateStep(1, 'done')

      // Step 3: Sindri prove
      updateStep(2, 'active')
      const proveResult = await new Promise<any>((resolve, reject) => {
        chrome.runtime.sendMessage({
          type: 'PROVE',
          sindriKey,
          pkHex: wallet.public_key,
          txHex,
          sigHex,
        }, (res) => {
          if (res.ok) resolve(res)
          else reject(new Error(res.error))
        })
      })

      // Compute public_values
      const pkHash = await sha256hex(wallet.public_key)
      const txHash = await sha256hex(txHex)
      const nonceBuf = new Uint8Array(4)
      new DataView(nonceBuf.buffer).setUint32(0, chainNonce, true)
      const nonceHex = Array.from(nonceBuf).map(b => b.toString(16).padStart(2, '0')).join('')
      const publicValues = pkHash + txHash + nonceHex
      updateStep(2, 'done')

      // Step 4: submit to Stellar via relayer
      updateStep(3, 'active')
      const submitResult = await new Promise<any>((resolve, reject) => {
        chrome.runtime.sendMessage({
          type: 'SUBMIT',
          proofBytes: proveResult.proofBytes,
          publicValues,
          destAddr,
          amountStroops: amountStroops.toString(),
        }, (res) => {
          if (res.ok) resolve(res)
          else reject(new Error(res.error))
        })
      })
      const submittedTxHash = submitResult.txHash
      setLastTxHash(submittedTxHash)
      updateStep(3, 'done', `tx: ${submittedTxHash.slice(0, 16)}...`)

      // Update wallet nonce
      const newWallet = { ...wallet, next_index: wallet.next_index + 1 }
      await saveWallet(newWallet, password)
      setWallet(newWallet)
      setNonce(newWallet.next_index)

      clearInterval(timer)
    } catch (e: any) {
      const activeIdx = stepList.findIndex(s => s.status === 'active')
      if (activeIdx >= 0) updateStep(activeIdx, 'error', e.message)
      clearInterval(timer)
    }
  }

  // ─── Render ───────────────────────────────────────────────────────────────

  if (view === 'create') return (
    <div style={S.root}>
      <div style={S.header}>
        <span style={S.title}>⬡ NEBULA</span>
        <span style={S.badge}>testnet</span>
      </div>
      <div style={S.card}>
        <div style={S.label}>Create Wallet</div>
        <div style={{ color: '#666', fontSize: 12, marginBottom: 16, lineHeight: 1.6 }}>
          Generates a post-quantum XMSS keypair. Store your password safely — it encrypts your key.
        </div>
        <label style={S.inputLabel}>Password</label>
        <input style={{ ...S.input, marginBottom: 12 }} type="password" placeholder="Min 6 characters"
          value={password} onChange={e => setPassword(e.target.value)} />
        <label style={S.inputLabel}>Sindri API Key</label>
        <input style={{ ...S.input, marginBottom: 16 }} type="password" placeholder="From sindri.app"
          value={sindriKey} onChange={e => setSindriKey(e.target.value)} />
        {error && <div style={S.error}>{error}</div>}
        <button style={S.btn} onClick={handleCreate}>Create Wallet</button>
      </div>
    </div>
  )

  if (view === 'unlock') return (
    <div style={S.root}>
      <div style={S.header}>
        <span style={S.title}>⬡ NEBULA</span>
        <span style={S.badge}>testnet</span>
      </div>
      <div style={S.card}>
        <div style={S.label}>Unlock Wallet</div>
        <input style={{ ...S.input, marginBottom: 12 }} type="password" placeholder="Password"
          value={password} onChange={e => setPassword(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleUnlock()} />
        {error && <div style={S.error}>{error}</div>}
        <button style={S.btn} onClick={handleUnlock}>Unlock</button>
      </div>
    </div>
  )

  if (view === 'dashboard' && wallet) {
    const leavesUsed = wallet.next_index
    const leavesPct = (leavesUsed / MAX_LEAVES) * 100
    return (
      <div style={S.root}>
        <div style={S.header}>
          <span style={S.title}>⬡ NEBULA</span>
          <span style={S.badge}>testnet</span>
        </div>

        <div style={S.card}>
          <div style={S.label}>Balance</div>
          <div style={S.value}>{(balance / 1e7).toFixed(2)} <span style={{ fontSize: 16, color: '#666' }}>XLM</span></div>
          <div style={S.sub}>Contract: {WALLET_CONTRACT_ID.slice(0, 8)}...{WALLET_CONTRACT_ID.slice(-4)}</div>
        </div>

        <div style={S.row}>
          <div style={S.smallCard}>
            <div style={S.label}>Nonce</div>
            <div style={{ fontSize: 22, fontWeight: 700 }}>{nonce}</div>
          </div>
          <div style={S.smallCard}>
            <div style={S.label}>XMSS Leaves</div>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 4 }}>
              {leavesUsed} <span style={{ color: '#666', fontWeight: 400 }}>/ {MAX_LEAVES}</span>
            </div>
            <div style={S.progress}>
              <div style={S.progressBar(leavesPct)} />
            </div>
          </div>
        </div>

        <div style={{ ...S.card, marginBottom: 8 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
            <div style={S.label}>Your Address (Wallet ID)</div>
            <button
              onClick={() => { navigator.clipboard.writeText(pubkeyHash); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
              style={{ background: 'none', border: 'none', color: copied ? '#4ade80' : '#7c6af7', cursor: 'pointer', fontSize: 11, fontFamily: 'inherit' }}
            >{copied ? '✓ copied' : 'copy'}</button>
          </div>
          <div style={S.mono}>{pubkeyHash.slice(0, 20)}...{pubkeyHash.slice(-8)}</div>
          <div style={{ fontSize: 10, color: '#444', marginTop: 4 }}>Share this to receive XLM from others</div>
        </div>

        <button style={S.btn} onClick={() => { setError(''); setView('send') }}>Send XLM</button>
      </div>
    )
  }

  if (view === 'send') return (
    <div style={S.root}>
      <div style={S.header}>
        <span style={S.title}>⬡ SEND XLM</span>
        <span style={S.badge}>testnet</span>
      </div>

      <div style={S.card}>
        <label style={S.inputLabel}>To (G... Stellar address)</label>
        <input style={{ ...S.input, marginBottom: 12 }} placeholder="GDEST..."
          value={destAddr} onChange={e => setDestAddr(e.target.value)} />
        <label style={S.inputLabel}>Amount (XLM)</label>
        <input style={{ ...S.input, marginBottom: 16 }} placeholder="10.0" type="number"
          value={amount} onChange={e => setAmount(e.target.value)} />
        {error && <div style={S.error}>{error}</div>}
        <button style={{ ...S.btn, marginBottom: 8 }} onClick={handleSend}>Confirm & Send</button>
        <button style={S.btnGhost} onClick={() => setView('dashboard')}>← Back</button>
      </div>
    </div>
  )

  if (view === 'proving') return (
    <div style={S.root}>
      <div style={S.header}>
        <span style={S.title}>⬡ PROVING</span>
        <span style={{ color: '#666', fontSize: 12 }}>{elapsed}s elapsed</span>
      </div>

      <div style={S.card}>
        <div style={S.label}>ZK Proof Progress</div>
        {steps.map((step, i) => (
          <div key={i} style={S.step}>
            <div style={S.stepDot(step.status)} />
            <div>
              <div style={{ color: step.status === 'active' ? '#7c6af7' : step.status === 'done' ? '#4ade80' : step.status === 'error' ? '#f87171' : '#666' }}>
                {step.label}
                {step.status === 'active' && ' ...'}
              </div>
              {step.detail && <div style={{ fontSize: 11, color: '#666', marginTop: 2 }}>{step.detail}</div>}
            </div>
          </div>
        ))}
      </div>

      {steps.every(s => s.status === 'done') && (
        <div>
          <div style={{ color: '#4ade80', textAlign: 'center', marginBottom: 12, fontSize: 14 }}>
            ✓ Transaction complete
          </div>
          {lastTxHash && (
            <div style={{ ...S.card, marginBottom: 12 }}>
              <div style={S.label}>Transaction Hash</div>
              <div style={{ ...S.mono, marginBottom: 8 }}>{lastTxHash}</div>
              <a
                href={`https://stellar.expert/explorer/testnet/tx/${lastTxHash}`}
                target="_blank"
                rel="noreferrer"
                style={{ color: '#7c6af7', fontSize: 12 }}
              >
                View on stellar.expert ↗
              </a>
            </div>
          )}
          <button style={S.btn} onClick={() => { setView('dashboard'); refreshBalance(pubkeyHash) }}>Back to Wallet</button>
        </div>
      )}

      {steps.some(s => s.status === 'error') && (
        <button style={S.btnGhost} onClick={() => setView('dashboard')}>← Back</button>
      )}
    </div>
  )

  return null
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />)
