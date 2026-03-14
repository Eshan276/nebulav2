import React, { useState, useEffect, useCallback } from 'react'
import ReactDOM from 'react-dom/client'
import { walletExists, saveWallet, loadWallet, WalletData } from './crypto'
import { buildTxBytes, stellarToContractField } from './background'
import * as StellarSdk from '@stellar/stellar-sdk'

const WALLET_CONTRACT_ID  = 'CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B'
const SOROBAN_RPC = 'https://soroban-testnet.stellar.org'

// ─── Design tokens ──────────────────────────────────────────────────────────

const C = {
  bg:        '#0d0d0d',
  card:      '#161616',
  cardBorder:'#222',
  purple:    '#8b5cf6',
  purpleDim: '#6d28d9',
  green:     '#22c55e',
  red:       '#ef4444',
  text:      '#f5f5f5',
  textMuted: '#888',
  textDim:   '#444',
  surface:   '#1a1a1a',
}

const T: Record<string, React.CSSProperties> = {
  root: {
    width: 380,
    minHeight: 580,
    background: C.bg,
    color: C.text,
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    display: 'flex',
    flexDirection: 'column',
    position: 'relative',
    overflow: 'hidden',
  },
  // Top header bar
  topBar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '16px 20px 12px',
  },
  logo: {
    fontSize: 16,
    fontWeight: 700,
    color: C.text,
    letterSpacing: 0.5,
  },
  netBadge: {
    fontSize: 11,
    color: C.purple,
    background: '#1e1533',
    padding: '3px 10px',
    borderRadius: 20,
    border: `1px solid #3b2d6e`,
    fontWeight: 500,
  },
  // Balance hero card
  heroCard: {
    margin: '0 16px 16px',
    background: 'linear-gradient(135deg, #1a1040 0%, #0d0d1a 100%)',
    borderRadius: 20,
    padding: '28px 24px 24px',
    border: '1px solid #2a1f5e',
    position: 'relative',
    overflow: 'hidden',
  },
  heroGlow: {
    position: 'absolute',
    top: -40,
    right: -40,
    width: 160,
    height: 160,
    background: 'radial-gradient(circle, rgba(139,92,246,0.15) 0%, transparent 70%)',
    pointerEvents: 'none',
  },
  balanceLabel: {
    fontSize: 12,
    color: C.textMuted,
    textTransform: 'uppercase' as const,
    letterSpacing: 1.5,
    marginBottom: 8,
    fontWeight: 500,
  },
  balanceAmount: {
    fontSize: 42,
    fontWeight: 700,
    color: C.text,
    lineHeight: 1,
    marginBottom: 6,
  },
  balanceCurrency: {
    fontSize: 18,
    fontWeight: 400,
    color: C.textMuted,
    marginLeft: 6,
  },
  balanceSub: {
    fontSize: 12,
    color: C.textMuted,
    marginTop: 4,
  },
  // Action buttons row
  actionsRow: {
    display: 'flex',
    justifyContent: 'space-around',
    padding: '4px 24px 20px',
  },
  actionBtn: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    gap: 8,
    cursor: 'pointer',
    background: 'none',
    border: 'none',
    color: C.text,
    padding: 0,
  },
  actionIcon: {
    width: 52,
    height: 52,
    borderRadius: '50%',
    background: C.surface,
    border: `1px solid ${C.cardBorder}`,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: 20,
  },
  actionLabel: {
    fontSize: 12,
    color: C.textMuted,
    fontWeight: 500,
  },
  // Section
  section: {
    padding: '0 16px',
    flex: 1,
  },
  sectionTitle: {
    fontSize: 12,
    color: C.textMuted,
    textTransform: 'uppercase' as const,
    letterSpacing: 1.5,
    fontWeight: 600,
    marginBottom: 10,
  },
  // Token row
  tokenRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 14,
    background: C.card,
    border: `1px solid ${C.cardBorder}`,
    borderRadius: 14,
    padding: '14px 16px',
    marginBottom: 8,
  },
  tokenIcon: {
    width: 40,
    height: 40,
    borderRadius: '50%',
    background: 'linear-gradient(135deg, #8b5cf6, #6d28d9)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: 18,
    flexShrink: 0,
  },
  tokenName: { fontSize: 15, fontWeight: 600, color: C.text },
  tokenSub:  { fontSize: 12, color: C.textMuted, marginTop: 1 },
  tokenAmt:  { marginLeft: 'auto', textAlign: 'right' as const },
  tokenAmtMain: { fontSize: 15, fontWeight: 600, color: C.text },
  tokenAmtSub:  { fontSize: 11, color: C.textMuted, marginTop: 1 },
  // Stats row
  statsRow: {
    display: 'flex',
    gap: 8,
    marginBottom: 16,
  },
  statCard: {
    flex: 1,
    background: C.card,
    border: `1px solid ${C.cardBorder}`,
    borderRadius: 14,
    padding: '12px 14px',
  },
  statLabel: { fontSize: 11, color: C.textMuted, marginBottom: 4, fontWeight: 500 },
  statValue: { fontSize: 18, fontWeight: 700, color: C.text },
  // Progress bar
  progressWrap: { height: 4, background: '#222', borderRadius: 4, marginTop: 6, overflow: 'hidden' },
  // Bottom nav
  bottomNav: {
    display: 'flex',
    justifyContent: 'space-around',
    padding: '12px 0 16px',
    borderTop: `1px solid ${C.cardBorder}`,
    marginTop: 'auto',
  },
  navBtn: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    gap: 4,
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    padding: '4px 16px',
  },
  navIcon: { fontSize: 20 },
  navLabel: { fontSize: 10, fontWeight: 500 },
  // Forms
  formWrap: { padding: '0 16px', flex: 1 },
  inputGroup: { marginBottom: 14 },
  inputLabel: {
    fontSize: 12,
    color: C.textMuted,
    fontWeight: 500,
    marginBottom: 6,
    display: 'block',
    textTransform: 'uppercase' as const,
    letterSpacing: 1,
  },
  input: {
    width: '100%',
    background: C.card,
    border: `1px solid ${C.cardBorder}`,
    borderRadius: 12,
    padding: '12px 14px',
    color: C.text,
    fontFamily: 'inherit',
    fontSize: 14,
    outline: 'none',
    boxSizing: 'border-box' as const,
    transition: 'border-color 0.2s',
  },
  // Buttons
  btnPrimary: {
    width: '100%',
    padding: '14px 0',
    background: C.purple,
    color: '#fff',
    border: 'none',
    borderRadius: 14,
    fontSize: 15,
    fontFamily: 'inherit',
    cursor: 'pointer',
    fontWeight: 600,
    marginBottom: 10,
    transition: 'opacity 0.2s',
  },
  btnSecondary: {
    width: '100%',
    padding: '12px 0',
    background: 'transparent',
    color: C.purple,
    border: `1px solid #2a1f5e`,
    borderRadius: 14,
    fontSize: 14,
    fontFamily: 'inherit',
    cursor: 'pointer',
    fontWeight: 500,
  },
  // Proving steps
  stepRow: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: 12,
    padding: '10px 0',
  },
  stepDotWrap: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    gap: 0,
  },
  // Misc
  error:  { color: C.red, fontSize: 12, marginTop: 6, marginBottom: 4 },
  mono:   { fontFamily: 'monospace', fontSize: 11, color: C.textMuted, wordBreak: 'break-all' as const },
  center: { textAlign: 'center' as const },
}

// ─── WASM loader ─────────────────────────────────────────────────────────────

let wasmModule: any = null
async function loadWasm() {
  if (wasmModule) return wasmModule
  const wasm = await import('../../xmss-wasm/pkg/xmss_wasm.js')
  await wasm.default()
  wasmModule = wasm
  return wasm
}

// ─── Stellar helpers ──────────────────────────────────────────────────────────

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
  } catch { return 0 }
}

async function getWalletBalance(pubkeyHashHex: string) {
  const [balance, nonce] = await Promise.all([
    contractCall('balance', pubkeyHashHex),
    contractCall('nonce', pubkeyHashHex),
  ])
  return { balance, nonce }
}

// ─── Types ────────────────────────────────────────────────────────────────────

type View = 'unlock' | 'create' | 'dashboard' | 'send' | 'proving' | 'activity'
type StepStatus = 'pending' | 'active' | 'done' | 'error'
interface ProveStep { label: string; status: StepStatus; detail?: string }

// ─── Small components ─────────────────────────────────────────────────────────

function StepDot({ status }: { status: StepStatus }) {
  const color = status === 'done' ? C.green : status === 'active' ? C.purple : status === 'error' ? C.red : C.textDim
  return (
    <div style={{
      width: 10, height: 10, borderRadius: '50%', flexShrink: 0, marginTop: 3,
      background: color,
      boxShadow: status === 'active' ? `0 0 10px ${C.purple}` : 'none',
    }} />
  )
}

function TopBar({ title, right }: { title: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div style={T.topBar}>
      <span style={T.logo}>{title}</span>
      {right ?? <span style={T.netBadge}>Testnet</span>}
    </div>
  )
}

// ─── App ──────────────────────────────────────────────────────────────────────

function App() {
  const [view, setView]         = useState<View>('unlock')
  const [wallet, setWallet]     = useState<WalletData | null>(null)
  const [balance, setBalance]   = useState<number>(0)
  const [nonce, setNonce]       = useState<number>(0)
  const [pubkeyHash, setPubkeyHash] = useState<string>('')
  const [copied, setCopied]     = useState(false)
  const [error, setError]       = useState<string>('')
  const [lastTxHash, setLastTxHash] = useState<string>('')
  const [password, setPassword] = useState('')
  const [sindriKey, setSindriKey] = useState('')
  const [destAddr, setDestAddr] = useState('')
  const [amount, setAmount]     = useState('')
  const [steps, setSteps]       = useState<ProveStep[]>([])
  const [elapsed, setElapsed]   = useState(0)
  const [txHistory, setTxHistory] = useState<Array<{ hash: string; amount: string; dest: string; ts: number }>>([])

  useEffect(() => {
    walletExists().then(exists => { if (!exists) setView('create') })
    chrome.storage.local.get(['sindri_key', 'tx_history'], (res) => {
      if (res.sindri_key) setSindriKey(res.sindri_key)
      if (res.tx_history) setTxHistory(res.tx_history)
    })
  }, [])

  const updateStep = (idx: number, status: StepStatus, detail?: string) =>
    setSteps(prev => prev.map((s, i) => i === idx ? { ...s, status, detail } : s))

  const refreshBalance = useCallback(async (hash: string) => {
    try {
      const { balance: b, nonce: n } = await getWalletBalance(hash)
      setBalance(b)
      setNonce(n)
    } catch { }
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
    } catch { setError('Wrong password') }
  }

  const handleCreate = async () => {
    if (!password || password.length < 6) { setError('Password must be at least 6 characters'); return }
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
    } catch (e: any) { setError(e.message) }
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
      { label: 'Generating ZK proof', status: 'pending' },
      { label: 'Submitting to Stellar', status: 'pending' },
    ]
    setSteps(stepList)

    const startTime = Date.now()
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - startTime) / 1000)), 1000)

    try {
      const pkHash = await sha256hex(wallet.public_key)
      const chainNonce = await contractCall('nonce', pkHash)
      const txBytes = buildTxBytes(pkHash, chainNonce, destAddr, amountStroops)
      const txHex = Array.from(txBytes).map(b => b.toString(16).padStart(2, '0')).join('')
      updateStep(0, 'done')

      updateStep(1, 'active')
      const wasm = await loadWasm()
      const sigHex = wasm.xmss_sign(wallet.secret_key, txHex, wallet.next_index)
      updateStep(1, 'done')

      updateStep(2, 'active')
      const proveResult = await new Promise<any>((resolve, reject) => {
        chrome.runtime.sendMessage({ type: 'PROVE', sindriKey, pkHex: wallet.public_key, txHex, sigHex },
          (res) => res.ok ? resolve(res) : reject(new Error(res.error)))
      })

      const txHash = await sha256hex(txHex)
      const nonceBuf = new Uint8Array(4)
      new DataView(nonceBuf.buffer).setUint32(0, chainNonce, true)
      const nonceHex = Array.from(nonceBuf).map(b => b.toString(16).padStart(2, '0')).join('')
      const publicValues = pkHash + txHash + nonceHex
      updateStep(2, 'done')

      updateStep(3, 'active')
      const submitResult = await new Promise<any>((resolve, reject) => {
        chrome.runtime.sendMessage({
          type: 'SUBMIT', proofBytes: proveResult.proofBytes,
          publicValues, destAddr, amountStroops: amountStroops.toString(),
        }, (res) => res.ok ? resolve(res) : reject(new Error(res.error)))
      })

      const submittedTxHash = submitResult.txHash
      setLastTxHash(submittedTxHash)
      updateStep(3, 'done', submittedTxHash?.slice(0, 16) + '...')

      // Save to history
      const newEntry = { hash: submittedTxHash, amount: amtNum.toFixed(2), dest: destAddr, ts: Date.now() }
      const newHistory = [newEntry, ...txHistory].slice(0, 20)
      setTxHistory(newHistory)
      chrome.storage.local.set({ tx_history: newHistory })

      const newWallet = { ...wallet, next_index: wallet.next_index + 1 }
      await saveWallet(newWallet, password)
      setWallet(newWallet)

      clearInterval(timer)
    } catch (e: any) {
      const activeIdx = steps.findIndex(s => s.status === 'active')
      if (activeIdx >= 0) updateStep(activeIdx, 'error', e.message)
      clearInterval(timer)
    }
  }

  // ─── Views ─────────────────────────────────────────────────────────────────

  if (view === 'create') return (
    <div style={T.root}>
      <TopBar title="⬡ Nebula" />
      <div style={{ ...T.formWrap, paddingTop: 8 }}>
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 6 }}>Create your wallet</div>
          <div style={{ fontSize: 13, color: C.textMuted, lineHeight: 1.6 }}>
            Generates a post-quantum XMSS keypair. Your key never leaves this device.
          </div>
        </div>
        <div style={T.inputGroup}>
          <label style={T.inputLabel}>Password</label>
          <input style={T.input} type="password" placeholder="Min 6 characters"
            value={password} onChange={e => setPassword(e.target.value)} />
        </div>
        <div style={T.inputGroup}>
          <label style={T.inputLabel}>Sindri API Key</label>
          <input style={T.input} type="password" placeholder="From sindri.app"
            value={sindriKey} onChange={e => setSindriKey(e.target.value)} />
          <div style={{ fontSize: 11, color: C.textMuted, marginTop: 6 }}>Used for generating ZK proofs on withdrawals</div>
        </div>
        {error && <div style={T.error}>{error}</div>}
        <div style={{ marginTop: 8 }}>
          <button style={T.btnPrimary} onClick={handleCreate}>Create Wallet</button>
        </div>
      </div>
    </div>
  )

  if (view === 'unlock') return (
    <div style={T.root}>
      <TopBar title="⬡ Nebula" />
      <div style={{ ...T.formWrap, paddingTop: 40 }}>
        <div style={{ ...T.center, marginBottom: 32 }}>
          <div style={{ fontSize: 52, marginBottom: 12 }}>⬡</div>
          <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 6 }}>Welcome back</div>
          <div style={{ fontSize: 13, color: C.textMuted }}>Enter your password to unlock</div>
        </div>
        <input style={{ ...T.input, marginBottom: 14 }} type="password" placeholder="Password"
          value={password} onChange={e => setPassword(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleUnlock()} />
        {error && <div style={T.error}>{error}</div>}
        <button style={T.btnPrimary} onClick={handleUnlock}>Unlock</button>
      </div>
    </div>
  )

  if (view === 'dashboard' && wallet) {
    const balanceXlm = (balance / 1e7).toFixed(2)
    return (
      <div style={T.root}>
        <TopBar
          title={<span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 30, height: 30, borderRadius: '50%', background: 'linear-gradient(135deg, #8b5cf6, #6d28d9)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: 14 }}>⬡</span>
            Nebula Wallet
          </span>}
        />

        {/* Balance hero */}
        <div style={T.heroCard}>
          <div style={T.heroGlow} />
          <div style={T.balanceLabel}>Balance</div>
          <div style={T.balanceAmount}>
            {balanceXlm}
            <span style={T.balanceCurrency}>XLM</span>
          </div>
          <div style={T.balanceSub}>on Stellar Testnet</div>
        </div>

        {/* Action buttons */}
        <div style={T.actionsRow}>
          <button style={T.actionBtn} onClick={() => {
            navigator.clipboard.writeText(pubkeyHash)
            setCopied(true)
            setTimeout(() => setCopied(false), 1500)
          }}>
            <div style={T.actionIcon}>{copied ? '✓' : '↓'}</div>
            <span style={T.actionLabel}>{copied ? 'Copied' : 'Receive'}</span>
          </button>
          <button style={T.actionBtn} onClick={() => { setError(''); setView('send') }}>
            <div style={{ ...T.actionIcon, background: C.purple, border: 'none', color: '#fff' }}>↗</div>
            <span style={T.actionLabel}>Send</span>
          </button>
          <button style={T.actionBtn} onClick={() => setView('activity')}>
            <div style={T.actionIcon}>⏱</div>
            <span style={T.actionLabel}>Activity</span>
          </button>
          <button style={T.actionBtn} onClick={() => refreshBalance(pubkeyHash)}>
            <div style={T.actionIcon}>↻</div>
            <span style={T.actionLabel}>Refresh</span>
          </button>
        </div>

        {/* Stats */}
        <div style={T.section}>
          <div style={T.sectionTitle}>Wallet Stats</div>
          <div style={T.statsRow}>
            <div style={T.statCard}>
              <div style={T.statLabel}>Nonce</div>
              <div style={T.statValue}>{nonce}</div>
            </div>
            <div style={T.statCard}>
              <div style={T.statLabel}>Transactions</div>
              <div style={T.statValue}>{txHistory.length}</div>
            </div>
          </div>

          {/* Token row */}
          <div style={T.sectionTitle}>Tokens</div>
          <div style={T.tokenRow}>
            <div style={T.tokenIcon}>✦</div>
            <div>
              <div style={T.tokenName}>Stellar Lumens</div>
              <div style={T.tokenSub}>XLM · Testnet</div>
            </div>
            <div style={T.tokenAmt}>
              <div style={T.tokenAmtMain}>{balanceXlm} XLM</div>
              <div style={T.tokenAmtSub}>Post-quantum wallet</div>
            </div>
          </div>
        </div>

        {/* Bottom nav */}
        <div style={T.bottomNav}>
          {[
            { icon: '⊞', label: 'Wallet', active: true },
            { icon: '↗', label: 'Send', active: false, action: () => setView('send') },
            { icon: '⏱', label: 'Activity', active: false, action: () => setView('activity') },
          ].map(({ icon, label, active, action }) => (
            <button key={label} style={T.navBtn} onClick={action}>
              <span style={{ ...T.navIcon, color: active ? C.purple : C.textMuted }}>{icon}</span>
              <span style={{ ...T.navLabel, color: active ? C.purple : C.textMuted }}>{label}</span>
            </button>
          ))}
        </div>
      </div>
    )
  }

  if (view === 'send') return (
    <div style={T.root}>
      <TopBar
        title={<button style={{ background: 'none', border: 'none', color: C.text, cursor: 'pointer', fontSize: 16, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }} onClick={() => setView('dashboard')}>
          ← Send XLM
        </button>}
      />
      <div style={{ ...T.formWrap, paddingTop: 8 }}>
        {/* Amount input — big and prominent */}
        <div style={{ textAlign: 'center', padding: '24px 0 28px' }}>
          <div style={{ fontSize: 12, color: C.textMuted, marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1.5 }}>Amount</div>
          <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'center', gap: 8 }}>
            <input
              style={{ background: 'none', border: 'none', outline: 'none', fontSize: 48, fontWeight: 700, color: C.text, fontFamily: 'inherit', textAlign: 'center', width: 200 }}
              type="number" placeholder="0"
              value={amount} onChange={e => setAmount(e.target.value)}
            />
            <span style={{ fontSize: 20, color: C.textMuted, fontWeight: 500 }}>XLM</span>
          </div>
          <div style={{ fontSize: 12, color: C.textMuted, marginTop: 8 }}>
            Available: {(balance / 1e7).toFixed(2)} XLM
          </div>
        </div>

        <div style={T.inputGroup}>
          <label style={T.inputLabel}>To</label>
          <input style={T.input} placeholder="G... Stellar address"
            value={destAddr} onChange={e => setDestAddr(e.target.value)} />
        </div>

        {/* Fee note */}
        <div style={{ background: '#1a1040', border: '1px solid #2a1f5e', borderRadius: 12, padding: '10px 14px', marginBottom: 16, fontSize: 12, color: C.textMuted, lineHeight: 1.6 }}>
          ⚡ ZK proof generation takes ~30–60s via Sindri. Your XMSS key signs locally — nothing leaves your device.
        </div>

        {error && <div style={T.error}>{error}</div>}
        <button style={T.btnPrimary} onClick={handleSend}>Confirm & Send</button>
        <button style={T.btnSecondary} onClick={() => setView('dashboard')}>Cancel</button>
      </div>
    </div>
  )

  if (view === 'proving') {
    const allDone = steps.every(s => s.status === 'done')
    const hasError = steps.some(s => s.status === 'error')
    return (
      <div style={T.root}>
        <TopBar title={allDone ? '✓ Complete' : hasError ? '✗ Failed' : `Processing · ${elapsed}s`} />
        <div style={{ ...T.formWrap, paddingTop: 8 }}>

          {/* Steps */}
          <div style={{ background: C.card, border: `1px solid ${C.cardBorder}`, borderRadius: 16, padding: '16px 18px', marginBottom: 16 }}>
            {steps.map((step, i) => (
              <div key={i} style={{ ...T.stepRow, borderBottom: i < steps.length - 1 ? `1px solid ${C.cardBorder}` : 'none', paddingBottom: i < steps.length - 1 ? 10 : 0, marginBottom: i < steps.length - 1 ? 10 : 0 }}>
                <StepDot status={step.status} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 500, color: step.status === 'active' ? C.purple : step.status === 'done' ? C.green : step.status === 'error' ? C.red : C.textMuted }}>
                    {step.label}{step.status === 'active' ? '...' : ''}
                  </div>
                  {step.detail && <div style={{ fontSize: 11, color: C.textMuted, marginTop: 2 }}>{step.detail}</div>}
                </div>
                <div style={{ fontSize: 16 }}>
                  {step.status === 'done' ? '✓' : step.status === 'error' ? '✗' : step.status === 'active' ? '⋯' : ''}
                </div>
              </div>
            ))}
          </div>

          {allDone && (
            <div>
              <div style={{ background: '#0d2010', border: '1px solid #14532d', borderRadius: 16, padding: '16px 18px', marginBottom: 16 }}>
                <div style={{ color: C.green, fontWeight: 600, marginBottom: 8 }}>Transaction Complete</div>
                {lastTxHash && <>
                  <div style={{ fontSize: 11, color: C.textMuted, marginBottom: 4 }}>Transaction Hash</div>
                  <div style={{ ...T.mono, marginBottom: 10 }}>{lastTxHash}</div>
                  <a href={`https://stellar.expert/explorer/testnet/tx/${lastTxHash}`} target="_blank" rel="noreferrer"
                    style={{ color: C.purple, fontSize: 12, fontWeight: 500 }}>
                    View on stellar.expert ↗
                  </a>
                </>}
              </div>
              <button style={T.btnPrimary} onClick={() => { setView('dashboard'); refreshBalance(pubkeyHash) }}>
                Back to Wallet
              </button>
            </div>
          )}

          {hasError && (
            <button style={T.btnSecondary} onClick={() => setView('dashboard')}>← Back to Wallet</button>
          )}
        </div>
      </div>
    )
  }

  if (view === 'activity') return (
    <div style={T.root}>
      <TopBar
        title={<button style={{ background: 'none', border: 'none', color: C.text, cursor: 'pointer', fontSize: 16, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }} onClick={() => setView('dashboard')}>
          ← Activity
        </button>}
      />
      <div style={{ ...T.formWrap, paddingTop: 8 }}>
        {txHistory.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px 0', color: C.textMuted }}>
            <div style={{ fontSize: 36, marginBottom: 12 }}>⏱</div>
            <div style={{ fontSize: 14 }}>No transactions yet</div>
          </div>
        ) : txHistory.map((tx, i) => (
          <div key={i} style={{ ...T.tokenRow, marginBottom: 8 }}>
            <div style={{ ...T.tokenIcon, background: '#1a0f2e', fontSize: 16 }}>↗</div>
            <div>
              <div style={T.tokenName}>Sent {tx.amount} XLM</div>
              <div style={T.tokenSub}>→ {tx.dest.slice(0, 6)}...{tx.dest.slice(-4)}</div>
            </div>
            <div style={T.tokenAmt}>
              <a href={`https://stellar.expert/explorer/testnet/tx/${tx.hash}`} target="_blank" rel="noreferrer"
                style={{ color: C.purple, fontSize: 11 }}>
                View ↗
              </a>
              <div style={{ fontSize: 11, color: C.textMuted, marginTop: 2 }}>
                {new Date(tx.ts).toLocaleDateString()}
              </div>
            </div>
          </div>
        ))}
      </div>
      <div style={T.bottomNav}>
        {[
          { icon: '⊞', label: 'Wallet', action: () => setView('dashboard') },
          { icon: '↗', label: 'Send', action: () => setView('send') },
          { icon: '⏱', label: 'Activity', active: true },
        ].map(({ icon, label, active, action }) => (
          <button key={label} style={T.navBtn} onClick={action}>
            <span style={{ ...T.navIcon, color: active ? C.purple : C.textMuted }}>{icon}</span>
            <span style={{ ...T.navLabel, color: active ? C.purple : C.textMuted }}>{label}</span>
          </button>
        ))}
      </div>
    </div>
  )

  return null
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />)
