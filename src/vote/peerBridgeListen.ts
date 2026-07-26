import { ethers, Wallet } from 'ethers'
import * as fs from 'fs/promises'
import * as path from 'path'
import {
  BASE_CHAIN_ID,
  BASE_CIRCLE_USDC,
  CONET_CHAIN_ID,
  CONET_TREASURY_CREATE2,
  CONET_TREASURY_PEER_CREATE2,
} from './treasuryAddresses'

/**
 * Base Peer BridgeOut → CoNET Peer voteMintFromPeerDeposit / voteMintFromPeerCredit。
 * 仅当钱包为同址 ConetTreasury.isMiner 时启动（Peer onlyMiner 委托 Treasury miner 表）。
 */

function toBaseWssRpcUrl(url: string): string {
  const u = url.trim()
  if (/^wss:\/\//i.test(u)) return u
  if (/^ws:\/\//i.test(u)) return u
  if (/^https:\/\//i.test(u)) {
    try {
      const parsed = new URL(u)
      return `wss://${parsed.host}/ws`
    } catch {
      const host = u.replace(/^https:\/\//i, '').split('/')[0]
      return `wss://${host}/ws`
    }
  }
  if (/^http:\/\//i.test(u)) {
    try {
      const parsed = new URL(u)
      return `ws://${parsed.host}/ws`
    } catch {
      const host = u.replace(/^http:\/\//i, '').split('/')[0]
      return `ws://${host}/ws`
    }
  }
  if (!/:\/\//.test(u)) {
    return `wss://${u.replace(/\/$/, '')}/ws`
  }
  return u
}

function toConetHttpRpcUrl(url: string): string {
  const u = url.trim()
  if (/^https:\/\//i.test(u)) return u
  if (/^http:\/\//i.test(u)) return u
  if (/^wss:\/\//i.test(u)) {
    try {
      const parsed = new URL(u)
      const pathPart = parsed.pathname === '/' || parsed.pathname === '' ? '' : parsed.pathname
      return `https://${parsed.host}${pathPart}`
    } catch {
      return u.replace(/^wss:\/\//i, 'https://')
    }
  }
  if (/^ws:\/\//i.test(u)) {
    try {
      const parsed = new URL(u)
      const pathPart = parsed.pathname === '/' || parsed.pathname === '' ? '' : parsed.pathname
      return `http://${parsed.host}${pathPart}`
    } catch {
      return u.replace(/^ws:\/\//i, 'http://')
    }
  }
  if (!/:\/\//.test(u)) {
    return `https://${u.replace(/\/$/, '')}`
  }
  return u
}

const CONET_RPC_DEFAULT_HTTP = process.env.CONET_RPC || 'https://rpc1.conet.network'
const VOTE_GAS_LIMIT = 1_500_000
const BACKFILL_MAX_BLOCKS = BigInt(process.env.VOTE_PEER_BACKFILL_BLOCKS || process.env.VOTE_BASE_BACKFILL_BLOCKS || '2000')
const LOGS_CHUNK_BLOCKS = BigInt(process.env.VOTE_PEER_LOGS_CHUNK_BLOCKS || process.env.VOTE_BASE_LOGS_CHUNK_BLOCKS || '400')
const LIVE_POLL_INTERVAL_MS = Number(process.env.VOTE_PEER_LIVE_POLL_INTERVAL_MS || process.env.VOTE_BASE_LIVE_POLL_INTERVAL_MS) || 12_000

const TIP_STALL_RESTART_MS = (() => {
  const raw = process.env.VOTE_PEER_TIP_STALL_RESTART_MS ?? process.env.VOTE_BASE_TIP_STALL_RESTART_MS
  if (raw === '0') return 0
  const n = Number(raw)
  if (Number.isFinite(n) && n > 0) return n
  return 60_000
})()

const BASE_GETBLOCK_TIMEOUT_MS = (() => {
  const raw = process.env.VOTE_PEER_GETBLOCK_TIMEOUT_MS ?? process.env.VOTE_BASE_GETBLOCK_TIMEOUT_MS
  if (raw === '0') return 0
  const n = Number(raw)
  if (Number.isFinite(n) && n > 0) return n
  return 45_000
})()

class GetBlockNumberTimeoutError extends Error {
  constructor(readonly timeoutMs: number) {
    super(`getBlockNumber exceeded ${timeoutMs}ms`)
    this.name = 'GetBlockNumberTimeoutError'
  }
}

async function getBaseBlockNumberWithTimeout(provider: ethers.Provider, timeoutMs: number): Promise<bigint> {
  if (timeoutMs <= 0) {
    return BigInt(await provider.getBlockNumber())
  }
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeoutP = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new GetBlockNumberTimeoutError(timeoutMs)), timeoutMs)
  })
  try {
    const n = await Promise.race([provider.getBlockNumber(), timeoutP])
    if (timer !== undefined) clearTimeout(timer)
    return BigInt(n)
  } catch (e) {
    if (timer !== undefined) clearTimeout(timer)
    throw e
  }
}

const TREASURY_ABI = ['function isMiner(address account) view returns (bool)'] as const

const PEER_READ_ABI = [
  'function usdcErc20() view returns (address)',
  'function gbTokenErc20() view returns (address)',
  'function buint() view returns (address)',
  'function wrappedConet() view returns (address)',
  'function hasVotedPeerDeposit(bytes32 depositTxHash, address miner) view returns (bool)',
  'function peerDepositProposals(bytes32 depositTxHash) view returns (uint256 peerChainId, address peerToken, address recipient, uint256 amount, uint8 creditAssetKind, uint256 voteCount, bool executed)',
] as const

const PEER_VOTE_ABI = [
  ...PEER_READ_ABI,
  'function voteMintFromPeerDeposit(bytes32 depositTxHash, uint256 peerChainId, address peerToken, address recipient, uint256 amount) external',
  'function voteMintFromPeerCredit(bytes32 depositTxHash, uint256 sourceChainId, address sourcePeerToken, address recipient, uint256 creditAmount, uint8 creditAssetKind) external',
] as const

const PEER_EVENT_ABI = [
  'event StableSwapBridgeOut(address indexed user, uint8 indexed burnAssetKind, uint256 burnAmount, uint8 indexed creditAssetKind, uint256 creditAmount, uint256 destinationChainId, address recipient)',
  'event NativeAssetBridgeOut(uint8 indexed nativeAsset, address indexed user, uint256 amount, uint256 destinationChainId, address indexed recipient)',
  'event UsdcBridgeOut(address indexed user, uint256 amount, uint256 destinationChainId, address indexed recipient)',
  'event BUintBridgeOut(address indexed user, uint256 amount, uint256 destinationChainId, address indexed recipient)',
  'event GBBridgeOut(address indexed user, uint256 amount, uint256 destinationChainId, address indexed recipient)',
  'event WrappedConetBridgeOut(address indexed user, uint256 amount, uint256 destinationChainId, address indexed recipient)',
] as const

const peerEventIface = new ethers.Interface(PEER_EVENT_ABI)
const PEER_BRIDGE_TOPICS = [
  ethers.id('StableSwapBridgeOut(address,uint8,uint256,uint8,uint256,uint256,address)'),
  ethers.id('NativeAssetBridgeOut(uint8,address,uint256,uint256,address)'),
  ethers.id('UsdcBridgeOut(address,uint256,uint256,address)'),
  ethers.id('BUintBridgeOut(address,uint256,uint256,address)'),
  ethers.id('GBBridgeOut(address,uint256,uint256,address)'),
  ethers.id('WrappedConetBridgeOut(address,uint256,uint256,address)'),
]

const CANONICAL_GB = 1
const CANONICAL_USDC = 2
const CANONICAL_BUINT = 3
const NATIVE_GB = 1
const NATIVE_BUINT = 2
const NATIVE_WCNET = 3

const VOTE_TAG = 'vote-peer'
function debug(msg: string, data?: Record<string, unknown> | object) {
  const ts = new Date().toISOString()
  const suffix = data !== undefined ? ` ${JSON.stringify(data)}` : ''
  console.log(`[${VOTE_TAG}] [${ts}] ${msg}${suffix}`)
}

function baseTxHashFromListenerEvent(event: unknown): string {
  if (event == null || typeof event !== 'object') return ''
  const e = event as Record<string, unknown>
  const top = e.transactionHash
  if (typeof top === 'string' && top.startsWith('0x') && top.length >= 66) return top
  const log = e.log
  if (log != null && typeof log === 'object') {
    const nested = (log as Record<string, unknown>).transactionHash
    if (typeof nested === 'string' && nested.startsWith('0x') && nested.length >= 66) return nested
  }
  return ''
}

function baseTxHashDedupKey(h: string): string {
  const t = h.trim()
  if (!t.startsWith('0x') || t.length < 66) return t
  return t.toLowerCase()
}

function sortLogs(a: ethers.Log, b: ethers.Log): number {
  const ba = BigInt(a.blockNumber)
  const bb = BigInt(b.blockNumber)
  if (ba !== bb) return ba < bb ? -1 : 1
  const ia = BigInt(a.index)
  const ib = BigInt(b.index)
  return ia < ib ? -1 : ia > ib ? 1 : 0
}

function backfillFloorBlock(tip: bigint): bigint {
  if (tip + 1n <= BACKFILL_MAX_BLOCKS) return 0n
  return tip + 1n - BACKFILL_MAX_BLOCKS
}

type ScanStateV1 = {
  version: 1
  lastScannedBlock: string
  basePeerAddrLower: string
  updatedAt: string
}

function defaultScanStatePath(): string {
  return process.env.VOTE_PEER_SCAN_STATE_FILE || path.join(process.cwd(), '.vote-base-peer-bridge-scan-state.json')
}

async function loadScanState(filePath: string): Promise<ScanStateV1 | null> {
  try {
    const raw = await fs.readFile(filePath, 'utf8')
    const j = JSON.parse(raw) as unknown
    if (
      j &&
      typeof j === 'object' &&
      (j as ScanStateV1).version === 1 &&
      typeof (j as ScanStateV1).lastScannedBlock === 'string' &&
      typeof (j as ScanStateV1).basePeerAddrLower === 'string'
    ) {
      return j as ScanStateV1
    }
  } catch {
    /* missing */
  }
  return null
}

async function saveScanState(filePath: string, state: ScanStateV1): Promise<void> {
  const dir = path.dirname(filePath)
  await fs.mkdir(dir, { recursive: true })
  const tmp = `${filePath}.${process.pid}.tmp`
  await fs.writeFile(tmp, JSON.stringify(state, null, 2), 'utf8')
  await fs.rename(tmp, filePath)
}

type PeerTokenCache = {
  usdc: string
  gb: string
  buint: string
  wcnet: string
}

async function loadPeerTokenCache(peer: ethers.Contract): Promise<PeerTokenCache> {
  const [usdc, gb, buint, wcnet] = await Promise.all([
    peer.usdcErc20().catch(() => ethers.ZeroAddress) as Promise<string>,
    peer.gbTokenErc20().catch(() => ethers.ZeroAddress) as Promise<string>,
    peer.buint().catch(() => ethers.ZeroAddress) as Promise<string>,
    peer.wrappedConet().catch(() => ethers.ZeroAddress) as Promise<string>,
  ])
  return {
    usdc: usdc && usdc !== ethers.ZeroAddress ? ethers.getAddress(usdc) : BASE_CIRCLE_USDC,
    gb: gb && gb !== ethers.ZeroAddress ? ethers.getAddress(gb) : ethers.ZeroAddress,
    buint: buint && buint !== ethers.ZeroAddress ? ethers.getAddress(buint) : ethers.ZeroAddress,
    wcnet: wcnet && wcnet !== ethers.ZeroAddress ? ethers.getAddress(wcnet) : ethers.ZeroAddress,
  }
}

function peerTokenForStableBurn(cache: PeerTokenCache, burnKind: number): string {
  if (burnKind === CANONICAL_USDC) return cache.usdc
  if (burnKind === CANONICAL_GB) return cache.gb
  if (burnKind === CANONICAL_BUINT) return cache.buint
  return ethers.ZeroAddress
}

function peerTokenForNativeAsset(cache: PeerTokenCache, nativeAsset: number): string {
  if (nativeAsset === NATIVE_GB) return cache.gb
  if (nativeAsset === NATIVE_BUINT) return cache.buint
  if (nativeAsset === NATIVE_WCNET) return cache.wcnet
  return ethers.ZeroAddress
}

type BridgeVoteJob =
  | {
      kind: 'credit'
      txHash: string
      sourceChainId: bigint
      sourcePeerToken: string
      recipient: string
      creditAmount: bigint
      creditAssetKind: number
    }
  | {
      kind: 'deposit'
      txHash: string
      sourceChainId: bigint
      peerToken: string
      recipient: string
      amount: bigint
    }

function parseBridgeLog(log: ethers.Log, tokenCache: PeerTokenCache): BridgeVoteJob | null {
  const parsed = peerEventIface.parseLog({ data: log.data, topics: log.topics as string[] })
  if (!parsed) return null
  const txHash = log.transactionHash ?? ''
  if (!txHash) return null

  const name = parsed.name
  if (name === 'StableSwapBridgeOut') {
    const destinationChainId = BigInt(parsed.args.destinationChainId)
    if (destinationChainId !== CONET_CHAIN_ID) return null
    const burnAssetKind = Number(parsed.args.burnAssetKind)
    const creditAssetKind = Number(parsed.args.creditAssetKind)
    const sourcePeerToken = peerTokenForStableBurn(tokenCache, burnAssetKind)
    if (!sourcePeerToken || sourcePeerToken === ethers.ZeroAddress) {
      debug('vote-peer skip StableSwap unknown burn token', { burnAssetKind, txHash })
      return null
    }
    const recipient = ethers.getAddress(parsed.args.recipient as string)
    return {
      kind: 'credit',
      txHash,
      sourceChainId: BASE_CHAIN_ID,
      sourcePeerToken,
      recipient,
      creditAmount: BigInt(parsed.args.creditAmount),
      creditAssetKind,
    }
  }

  if (name === 'NativeAssetBridgeOut') {
    const destinationChainId = BigInt(parsed.args.destinationChainId)
    if (destinationChainId !== CONET_CHAIN_ID) return null
    const nativeAsset = Number(parsed.args.nativeAsset)
    const peerToken = peerTokenForNativeAsset(tokenCache, nativeAsset)
    if (!peerToken || peerToken === ethers.ZeroAddress) {
      debug('vote-peer skip NativeAsset unknown token', { nativeAsset, txHash })
      return null
    }
    return {
      kind: 'deposit',
      txHash,
      sourceChainId: BASE_CHAIN_ID,
      peerToken,
      recipient: ethers.getAddress(parsed.args.recipient as string),
      amount: BigInt(parsed.args.amount),
    }
  }

  if (name === 'UsdcBridgeOut' || name === 'BUintBridgeOut' || name === 'GBBridgeOut' || name === 'WrappedConetBridgeOut') {
    const destinationChainId = BigInt(parsed.args.destinationChainId)
    if (destinationChainId !== CONET_CHAIN_ID) return null
    let peerToken = ethers.ZeroAddress
    if (name === 'UsdcBridgeOut') peerToken = tokenCache.usdc
    else if (name === 'BUintBridgeOut') peerToken = tokenCache.buint
    else if (name === 'GBBridgeOut') peerToken = tokenCache.gb
    else peerToken = tokenCache.wcnet
    if (!peerToken || peerToken === ethers.ZeroAddress) {
      debug('vote-peer skip legacy BridgeOut unknown token', { name, txHash })
      return null
    }
    return {
      kind: 'deposit',
      txHash,
      sourceChainId: BASE_CHAIN_ID,
      peerToken,
      recipient: ethers.getAddress(parsed.args.recipient as string),
      amount: BigInt(parsed.args.amount),
    }
  }

  return null
}

async function getPeerBridgeLogsChunked(
  provider: ethers.Provider,
  peerAddr: string,
  fromBlock: bigint,
  toBlock: bigint
): Promise<ethers.Log[]> {
  const out: ethers.Log[] = []
  let start = fromBlock
  while (start <= toBlock) {
    const end = start + LOGS_CHUNK_BLOCKS - 1n <= toBlock ? start + LOGS_CHUNK_BLOCKS - 1n : toBlock
    const chunk = await provider.getLogs({
      address: peerAddr,
      topics: [PEER_BRIDGE_TOPICS],
      fromBlock: start,
      toBlock: end,
    })
    out.push(...chunk)
    start = end + 1n
  }
  return out
}

async function tryVotePeerBridge(
  wallet: Wallet,
  conetPeerAddr: string,
  conetTxProvider: ethers.Provider,
  processedTxHashes: Set<string>,
  job: BridgeVoteJob
): Promise<void> {
  const dedupKey = baseTxHashDedupKey(job.txHash)
  if (processedTxHashes.has(dedupKey)) {
    debug('vote-peer skip duplicate Base tx', { baseTxHash: job.txHash })
    return
  }

  const txHashBytes32 = job.txHash as `0x${string}`
  const conetRead = new ethers.Contract(conetPeerAddr, PEER_READ_ABI, conetTxProvider)

  try {
    const proposal = await conetRead.peerDepositProposals(txHashBytes32)
    if (proposal.executed) {
      debug('vote-peer skip already executed', { baseTxHash: job.txHash })
      processedTxHashes.add(dedupKey)
      return
    }
  } catch (err: unknown) {
    debug('vote-peer peerDepositProposals precheck failed', {
      baseTxHash: job.txHash,
      error: err instanceof Error ? err.message : String(err),
    })
  }

  let alreadyVoted: boolean
  try {
    alreadyVoted = await conetRead.hasVotedPeerDeposit(txHashBytes32, wallet.address)
  } catch (err: unknown) {
    debug('vote-peer hasVotedPeerDeposit precheck failed', {
      baseTxHash: job.txHash,
      error: err instanceof Error ? err.message : String(err),
    })
    return
  }
  if (alreadyVoted) {
    debug('vote-peer skip already voted', { baseTxHash: job.txHash, wallet: wallet.address })
    processedTxHashes.add(dedupKey)
    return
  }

  processedTxHashes.add(dedupKey)

  const conetPeerWithSigner = new ethers.Contract(conetPeerAddr, PEER_VOTE_ABI, wallet.connect(conetTxProvider))

  try {
    if (job.kind === 'credit') {
      debug('vote-peer sending voteMintFromPeerCredit', {
        baseTxHash: job.txHash,
        sourcePeerToken: job.sourcePeerToken,
        recipient: job.recipient,
        creditAmount: job.creditAmount.toString(),
        creditAssetKind: job.creditAssetKind,
      })
      const tx = await conetPeerWithSigner.voteMintFromPeerCredit(
        txHashBytes32,
        job.sourceChainId,
        job.sourcePeerToken,
        job.recipient,
        job.creditAmount,
        job.creditAssetKind,
        { gasLimit: VOTE_GAS_LIMIT }
      )
      const receipt = await tx.wait()
      debug('vote-peer voteMintFromPeerCredit success', {
        conetTxHash: tx.hash,
        blockNumber: receipt?.blockNumber,
        baseTxHash: job.txHash,
      })
      return
    }

    debug('vote-peer sending voteMintFromPeerDeposit', {
      baseTxHash: job.txHash,
      peerToken: job.peerToken,
      recipient: job.recipient,
      amount: job.amount.toString(),
    })
    const tx = await conetPeerWithSigner.voteMintFromPeerDeposit(
      txHashBytes32,
      job.sourceChainId,
      job.peerToken,
      job.recipient,
      job.amount,
      { gasLimit: VOTE_GAS_LIMIT }
    )
    const receipt = await tx.wait()
    debug('vote-peer voteMintFromPeerDeposit success', {
      conetTxHash: tx.hash,
      blockNumber: receipt?.blockNumber,
      baseTxHash: job.txHash,
    })
  } catch (err: unknown) {
    debug('vote-peer vote failed', {
      baseTxHash: job.txHash,
      kind: job.kind,
      error: err instanceof Error ? err.message : String(err),
    })
  }
}

async function processPeerBridgeLogs(
  logs: ethers.Log[],
  wallet: Wallet,
  conetPeerAddr: string,
  conetTxProvider: ethers.Provider,
  processedTxHashes: Set<string>,
  tokenCache: PeerTokenCache
): Promise<void> {
  if (logs.length > 0) {
    debug('vote-peer process BridgeOut log batch', { count: logs.length })
  }
  const sorted = [...logs].sort(sortLogs)
  for (const log of sorted) {
    const job = parseBridgeLog(log, tokenCache)
    if (!job) continue
    await tryVotePeerBridge(wallet, conetPeerAddr, conetTxProvider, processedTxHashes, job)
  }
}

/**
 * 若钱包为 ConetTreasury miner，则监听 Base ConetTreasuryPeer BridgeOut，
 * 在 CoNET 同址 Peer 上 voteMintFromPeerDeposit / voteMintFromPeerCredit（2/3 达票自动 mint）。
 */
export async function startPeerBridgeVoteListen(
  wallet: Wallet,
  basePeerAddr: string = CONET_TREASURY_PEER_CREATE2,
  conetPeerAddr: string = CONET_TREASURY_PEER_CREATE2,
  conetTreasuryAddr: string = CONET_TREASURY_CREATE2,
  baseRpc?: string,
  conetRpc?: string
): Promise<void> {
  const baseRpcRaw = baseRpc || process.env.BASE_RPC || process.env.BASE_RPC_HTTP || 'https://base-rpc.conet.network'
  const baseWssUrl = toBaseWssRpcUrl(baseRpcRaw)
  const conetRpcRaw = conetRpc || process.env.CONET_RPC || process.env.CONET_RPC_WSS || CONET_RPC_DEFAULT_HTTP
  const conetHttpUrl = toConetHttpRpcUrl(conetRpcRaw)

  const baseWsProvider = new ethers.WebSocketProvider(baseWssUrl)
  const conetHttpProvider = new ethers.JsonRpcProvider(conetHttpUrl)
  const basePeerWs = new ethers.Contract(basePeerAddr, PEER_EVENT_ABI, baseWsProvider)
  const conetTreasury = new ethers.Contract(conetTreasuryAddr, TREASURY_ABI, conetHttpProvider)
  const basePeerRead = new ethers.Contract(basePeerAddr, PEER_READ_ABI, baseWsProvider)

  let sessionActive = true
  let pollTimer: ReturnType<typeof setTimeout> | undefined
  let stallWatchTimer: ReturnType<typeof setTimeout> | undefined
  let pollBusy = false
  let rpcTipHighWater = 0n
  let lastRpcTipGrowthAt = Date.now()

  const destroyProviders = async () => {
    await baseWsProvider.destroy().catch(() => undefined)
  }

  const teardownSessionAndRestart = async (reason: string, extra?: Record<string, unknown>) => {
    if (!sessionActive) return
    sessionActive = false
    if (pollTimer !== undefined) {
      clearTimeout(pollTimer)
      pollTimer = undefined
    }
    if (stallWatchTimer !== undefined) {
      clearTimeout(stallWatchTimer)
      stallWatchTimer = undefined
    }
    try {
      basePeerWs.removeAllListeners()
    } catch {
      /* ignore */
    }
    baseWsProvider.removeAllListeners()
    debug('vote-peer restarting Base Peer listener', { reason, ...extra })
    await destroyProviders()
    setImmediate(() => {
      void startPeerBridgeVoteListen(wallet, basePeerAddr, conetPeerAddr, conetTreasuryAddr, baseRpc, conetRpc)
    })
  }

  const checkRpcTipStallAfterFetch = async (cur: bigint, context: string): Promise<boolean> => {
    if (TIP_STALL_RESTART_MS <= 0 || !sessionActive) return false
    if (cur > rpcTipHighWater) {
      rpcTipHighWater = cur
      lastRpcTipGrowthAt = Date.now()
      return false
    }
    const elapsed = Date.now() - lastRpcTipGrowthAt
    if (elapsed < TIP_STALL_RESTART_MS) return false
    await teardownSessionAndRestart('base_tip_stalled', {
      context,
      rpcTipHighWater: rpcTipHighWater.toString(),
      cur: cur.toString(),
      elapsedMs: elapsed,
      thresholdMs: TIP_STALL_RESTART_MS,
    })
    return true
  }

  const basePeerLower = basePeerAddr.toLowerCase()
  const statePath = defaultScanStatePath()

  debug('vote-peer startPeerBridgeVoteListen init', {
    basePeerAddr,
    expectedPeer: CONET_TREASURY_PEER_CREATE2,
    addressMatch: basePeerLower === CONET_TREASURY_PEER_CREATE2.toLowerCase(),
    conetPeerAddr,
    conetTreasuryAddr,
    baseWssUrl,
    conetHttpUrl,
    wallet: wallet.address,
    scanStateFile: statePath,
  })

  if (basePeerLower !== CONET_TREASURY_PEER_CREATE2.toLowerCase()) {
    debug('vote-peer WARN basePeerAddr does not match expected CREATE2', {
      actual: basePeerAddr,
      expected: CONET_TREASURY_PEER_CREATE2,
    })
  }

  let isConetMiner: boolean
  try {
    isConetMiner = await conetTreasury.isMiner(wallet.address)
  } catch (err: unknown) {
    debug('vote-peer ConetTreasury isMiner threw', {
      error: err instanceof Error ? err.message : String(err),
    })
    await destroyProviders()
    return
  }

  debug('vote-peer miner check', { wallet: wallet.address, isConetMiner })
  if (!isConetMiner) {
    debug('vote-peer abort not ConetTreasury miner skipping Peer listener', {})
    await destroyProviders()
    return
  }

  let tipBn: bigint
  try {
    tipBn = await getBaseBlockNumberWithTimeout(baseWsProvider, BASE_GETBLOCK_TIMEOUT_MS)
    rpcTipHighWater = tipBn
    lastRpcTipGrowthAt = Date.now()
    debug('vote-peer Base WebSocket connected', { block: tipBn.toString() })
  } catch (err: unknown) {
    if (err instanceof GetBlockNumberTimeoutError) {
      await teardownSessionAndRestart('base_getBlockNumber_timeout', {
        context: 'initial',
        timeoutMs: err.timeoutMs,
      })
      return
    }
    debug('vote-peer Base getBlockNumber failed', {
      error: err instanceof Error ? err.message : String(err),
    })
    await destroyProviders()
    return
  }

  let tokenCache: PeerTokenCache
  try {
    tokenCache = await loadPeerTokenCache(basePeerRead)
    debug('vote-peer Base Peer token cache', tokenCache)
  } catch (err: unknown) {
    debug('vote-peer loadPeerTokenCache failed', {
      error: err instanceof Error ? err.message : String(err),
    })
    await destroyProviders()
    return
  }

  const processedTxHashes = new Set<string>()

  let prevState = await loadScanState(statePath)
  if (prevState && prevState.basePeerAddrLower !== basePeerLower) {
    debug('vote-peer scan state peer mismatch resetting', {
      prev: prevState.basePeerAddrLower,
      now: basePeerLower,
    })
    prevState = null
  }

  const floor = backfillFloorBlock(tipBn)
  const lastScanned = prevState ? BigInt(prevState.lastScannedBlock) : -1n
  const fromBlock = lastScanned >= 0n ? (lastScanned + 1n > floor ? lastScanned + 1n : floor) : floor

  if (fromBlock <= tipBn) {
    debug('vote-peer backfill BridgeOut eth_getLogs', {
      fromBlock: fromBlock.toString(),
      toBlock: tipBn.toString(),
    })
    try {
      const logs = await getPeerBridgeLogsChunked(baseWsProvider, basePeerAddr, fromBlock, tipBn)
      logs.sort(sortLogs)
      debug('vote-peer backfill logs fetched', { count: logs.length })
      await processPeerBridgeLogs(logs, wallet, conetPeerAddr, conetHttpProvider, processedTxHashes, tokenCache)
    } catch (err: unknown) {
      debug('vote-peer backfill failed', { error: err instanceof Error ? err.message : String(err) })
      await destroyProviders()
      return
    }
  }

  const now = new Date().toISOString()
  await saveScanState(statePath, {
    version: 1,
    lastScannedBlock: tipBn.toString(),
    basePeerAddrLower: basePeerLower,
    updatedAt: now,
  })

  baseWsProvider.on('error', (err: unknown) => {
    debug('vote-peer Base WebSocketProvider error', {
      error: err instanceof Error ? err.message : String(err),
    })
  })

  const handleWsLog = async (logLike: { data?: string; topics?: readonly string[]; transactionHash?: string } | null) => {
    if (!sessionActive || !logLike?.data || !logLike.topics) return
    const txHash = typeof logLike.transactionHash === 'string' ? logLike.transactionHash : ''
    const synthetic = {
      address: basePeerAddr,
      blockHash: '0x',
      blockNumber: 0,
      data: logLike.data,
      index: 0,
      removed: false,
      topics: [...logLike.topics],
      transactionHash: txHash,
      transactionIndex: 0,
    } as unknown as ethers.Log
    const job = parseBridgeLog(synthetic, tokenCache)
    if (!job) return
    debug('vote-peer WS BridgeOut parsed', { name: job.kind, baseTxHash: job.txHash || '(missing)' })
    if (!job.txHash) return
    await tryVotePeerBridge(wallet, conetPeerAddr, conetHttpProvider, processedTxHashes, job)
  }

  const onBridgeEvent = async (...args: unknown[]) => {
    if (!sessionActive) return
    const event = args[args.length - 1]
    const txHash = baseTxHashFromListenerEvent(event)
    let logLike: { data?: string; topics?: readonly string[]; transactionHash?: string } | null = null
    if (event != null && typeof event === 'object') {
      const e = event as Record<string, unknown>
      const nested = e.log
      if (nested != null && typeof nested === 'object') {
        const n = nested as Record<string, unknown>
        logLike = {
          data: typeof n.data === 'string' ? n.data : undefined,
          topics: Array.isArray(n.topics) ? (n.topics as string[]) : undefined,
          transactionHash: txHash || (typeof n.transactionHash === 'string' ? n.transactionHash : undefined),
        }
      }
    }
    if (logLike?.data && logLike.topics) {
      await handleWsLog(logLike)
      return
    }
    debug('vote-peer WS event missing log payload (rely on live poll)', { baseTxHash: txHash || '(missing)' })
  }

  for (const ev of [
    'StableSwapBridgeOut',
    'NativeAssetBridgeOut',
    'UsdcBridgeOut',
    'BUintBridgeOut',
    'GBBridgeOut',
    'WrappedConetBridgeOut',
  ] as const) {
    basePeerWs.on(ev, onBridgeEvent)
  }
  debug('vote-peer WebSocket subscribed Peer BridgeOut events', { basePeerAddr })

  let lastPolledBlock = tipBn
  let livePollTickCount = 0

  const scheduleLivePoll = () => {
    if (!sessionActive || LIVE_POLL_INTERVAL_MS <= 0) return
    pollTimer = setTimeout(() => {
      void livePollTick()
    }, LIVE_POLL_INTERVAL_MS)
  }

  const livePollTick = async () => {
    if (!sessionActive) return
    if (pollBusy) {
      scheduleLivePoll()
      return
    }
    pollBusy = true
    livePollTickCount++
    try {
      const cur = await getBaseBlockNumberWithTimeout(baseWsProvider, BASE_GETBLOCK_TIMEOUT_MS)
      if (await checkRpcTipStallAfterFetch(cur, 'livePoll')) return

      if (cur > lastPolledBlock) {
        const from = lastPolledBlock + 1n
        const logs = await getPeerBridgeLogsChunked(baseWsProvider, basePeerAddr, from, cur)
        debug('vote-peer live poll eth_getLogs', {
          fromBlock: from.toString(),
          toBlock: cur.toString(),
          logsCount: logs.length,
          tick: livePollTickCount,
        })
        await processPeerBridgeLogs(logs, wallet, conetPeerAddr, conetHttpProvider, processedTxHashes, tokenCache)
        lastPolledBlock = cur
        await saveScanState(statePath, {
          version: 1,
          lastScannedBlock: cur.toString(),
          basePeerAddrLower: basePeerLower,
          updatedAt: new Date().toISOString(),
        })
      } else if (livePollTickCount % 10 === 1) {
        debug('vote-peer live poll no new blocks', {
          lastPolledBlock: lastPolledBlock.toString(),
          cur: cur.toString(),
          tick: livePollTickCount,
        })
      }
    } catch (err: unknown) {
      if (err instanceof GetBlockNumberTimeoutError) {
        await teardownSessionAndRestart('base_getBlockNumber_timeout', {
          context: 'livePoll',
          timeoutMs: err.timeoutMs,
        })
        return
      }
      debug('vote-peer live poll error', { error: err instanceof Error ? err.message : String(err) })
    } finally {
      pollBusy = false
      scheduleLivePoll()
    }
  }

  if (LIVE_POLL_INTERVAL_MS > 0) {
    void livePollTick()
    debug('vote-peer live poll scheduled', { intervalMs: LIVE_POLL_INTERVAL_MS })
  }

  if (TIP_STALL_RESTART_MS > 0 && LIVE_POLL_INTERVAL_MS <= 0) {
    const stallCheckMs = Math.min(15_000, Math.max(5_000, Math.floor(TIP_STALL_RESTART_MS / 4)))
    const scheduleStallWatch = () => {
      if (!sessionActive) return
      stallWatchTimer = setTimeout(() => {
        void (async () => {
          if (!sessionActive || pollBusy) {
            scheduleStallWatch()
            return
          }
          pollBusy = true
          try {
            const cur = await getBaseBlockNumberWithTimeout(baseWsProvider, BASE_GETBLOCK_TIMEOUT_MS)
            if (await checkRpcTipStallAfterFetch(cur, 'stallWatch')) return
          } catch (err: unknown) {
            if (err instanceof GetBlockNumberTimeoutError) {
              await teardownSessionAndRestart('base_getBlockNumber_timeout', {
                context: 'stallWatch',
                timeoutMs: err.timeoutMs,
              })
              return
            }
          } finally {
            pollBusy = false
            scheduleStallWatch()
          }
        })()
      }, stallCheckMs)
    }
    scheduleStallWatch()
  }

  debug('vote-peer Base Peer listener ready', {
    basePeerAddr,
    conetPeerAddr,
    baseWssUrl,
    conetHttpUrl,
  })
}
