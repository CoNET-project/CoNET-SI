import { ethers, Wallet } from 'ethers'
import * as fs from 'fs/promises'
import * as path from 'path'

/**
 * 将 BASE_RPC / BASE_RPC_HTTP 等规范为 WebSocket URL，供 eth_subscribe（logs）使用。
 * CoNET Base：`wss://base-rpc.conet.network/ws`
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

/**
 * CoNET L1 JSON-RPC（eth_call / eth_sendRawTransaction）。
 * 生产上 WebSocket 对首次 eth_call 可能长时间无响应，故 isMiner 与投票发交易统一走 HTTP。
 */
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

/** 自当前 tip 起最多向前回填的区块数（含 tip 共 BACKFILL 个区块） */
const BACKFILL_MAX_BLOCKS = BigInt(process.env.VOTE_BASE_BACKFILL_BLOCKS || '2000')
/** 单次 eth_getLogs 分段，避免 RPC 范围过大 */
const LOGS_CHUNK_BLOCKS = BigInt(process.env.VOTE_BASE_LOGS_CHUNK_BLOCKS || '400')
/**
 * 部分 Base WS 节点对 eth_subscribe(logs) 不推送或不可靠，仅靠 contract.on 会漏事件。
 * 用 eth_getLogs 定时补扫与 WS 并行；设为 0 可关闭（不推荐）。
 */
const LIVE_POLL_INTERVAL_MS = Number(process.env.VOTE_BASE_LIVE_POLL_INTERVAL_MS) || 12_000
/**
 * Base `eth_blockNumber` 在连续超过该时间内严格未增长（始终 ≤ 当前高水位）则销毁 WS 并重启一轮 `startBaseVoteListen`。
 * `VOTE_BASE_TIP_STALL_RESTART_MS=0` 关闭。
 */
const TIP_STALL_RESTART_MS = (() => {
  const raw = process.env.VOTE_BASE_TIP_STALL_RESTART_MS
  if (raw === '0') return 0
  const n = Number(raw)
  if (Number.isFinite(n) && n > 0) return n
  return 60_000
})()
/**
 * Base 单次 `eth_blockNumber` 超时（毫秒）：挂起超过该时间则 teardown 并重启监听。
 * `VOTE_BASE_GETBLOCK_TIMEOUT_MS=0` 关闭（与链上行为一致，不推荐生产关闭）。
 */
const BASE_GETBLOCK_TIMEOUT_MS = (() => {
  const raw = process.env.VOTE_BASE_GETBLOCK_TIMEOUT_MS
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

/** `eth_blockNumber` 带超时；超时抛出 {@link GetBlockNumberTimeoutError}。 */
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

const BASE_TREASURY_ABI = [
  'function isMiner(address account) view returns (bool)',
  'event ETHDeposited(address indexed depositor, uint256 amount)',
  'event ERC20Deposited(address indexed depositor, address indexed token, uint256 amount, bytes32 indexed nonce)',
  'event BUnitPurchased(address indexed user, address indexed usdc, uint256 amount)',
] as const

const CONET_TREASURY_ABI = [
  'function isMiner(address account) view returns (bool)',
  'function hasVotedUsdc2BUnit(bytes32 txHash, address miner) view returns (bool)',
  'function voteAirdropBUnitFromBase(bytes32 txHash, address user, uint256 usdcAmount) external',
] as const

const bunitPurchasedIface = new ethers.Interface([
  'event BUnitPurchased(address indexed user, address indexed usdc, uint256 amount)',
])
const BUNIT_PURCHASED_TOPIC = bunitPurchasedIface.getEvent('BUnitPurchased')!.topicHash

/**
 * 统一带 [vote] 且单行输出，便于 `journalctl -f -u conet.service | grep vot`（多行 JSON 续行不含 tag 会被漏掉）。
 */
const VOTE_TAG = 'vote'
function debug(msg: string, data?: Record<string, unknown> | object) {
  const ts = new Date().toISOString()
  const suffix = data !== undefined ? ` ${JSON.stringify(data)}` : ''
  console.log(`[${VOTE_TAG}] [${ts}] ${msg}${suffix}`)
}

/** Base 主网 BaseTreasury（监听 BUnitPurchased）；勿与 ConetTreasury（投票目标）混用 */
const EXPECTED_BASE_TREASURY = '0x5c64a8b0935DA72d60933bBD8cD10579E1C40c58'

/**
 * ethers v6 `contract.on` 回调末参常为 ContractEventPayload：交易哈希在 `log.transactionHash`，
 * 而非顶层 `transactionHash`（否则会出现 WS 触发但 baseTxHash 为空，只能靠 live poll 补投）。
 */
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

function baseBlockLabelFromListenerEvent(event: unknown): string {
  if (event == null || typeof event !== 'object') return ''
  const e = event as Record<string, unknown>
  if (e.blockNumber != null) return String(e.blockNumber)
  const log = e.log
  if (log != null && typeof log === 'object') {
    const bn = (log as Record<string, unknown>).blockNumber
    if (bn != null) return String(bn)
  }
  return ''
}

type ScanStateV1 = {
  version: 1
  /**
   * Base 链「已处理到的块高」检查点（十进制字符串）。
   * 下次启动：`fromBlock = max(lastScannedBlock + 1, tip - BACKFILL + 1)`，避免对同一段历史重复 eth_getLogs / 重复尝试投票。
   * live poll 成功后也会更新此字段。
   */
  lastScannedBlock: string
  baseTreasuryAddrLower: string
  updatedAt: string
}

function defaultScanStatePath(): string {
  return process.env.VOTE_BASE_SCAN_STATE_FILE || path.join(process.cwd(), '.vote-base-bunit-scan-state.json')
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
      typeof (j as ScanStateV1).baseTreasuryAddrLower === 'string'
    ) {
      return j as ScanStateV1
    }
  } catch {
    /* missing or invalid */
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

/**
 * 自 tip 起最多 BACKFILL_MAX_BLOCKS 个区块的最早块号（含）。
 */
function backfillFloorBlock(tip: bigint): bigint {
  if (tip + 1n <= BACKFILL_MAX_BLOCKS) return 0n
  return tip + 1n - BACKFILL_MAX_BLOCKS
}

async function getBUnitPurchasedLogsChunked(
  provider: ethers.Provider,
  baseTreasuryAddr: string,
  fromBlock: bigint,
  toBlock: bigint
): Promise<ethers.Log[]> {
  const out: ethers.Log[] = []
  let start = fromBlock
  while (start <= toBlock) {
    const end = start + LOGS_CHUNK_BLOCKS - 1n <= toBlock ? start + LOGS_CHUNK_BLOCKS - 1n : toBlock
    const chunk = await provider.getLogs({
      address: baseTreasuryAddr,
      topics: [BUNIT_PURCHASED_TOPIC],
      fromBlock: start,
      toBlock: end,
    })
    out.push(...chunk)
    start = end + 1n
  }
  return out
}

/** 内存去重 key：统一小写，避免同一笔 tx 因大小写不同被当成两笔 */
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

async function processBUnitPurchasedLogs(
  logs: ethers.Log[],
  wallet: Wallet,
  conetTreasuryAddr: string,
  conetTxProvider: ethers.Provider,
  processedTxHashes: Set<string>
): Promise<void> {
  if (logs.length > 0) {
    debug('vote process BUnitPurchased log batch', { count: logs.length })
  }
  const sorted = [...logs].sort(sortLogs)
  for (const log of sorted) {
    const txHash = log.transactionHash ?? ''
    const parsed = bunitPurchasedIface.parseLog({ data: log.data, topics: log.topics as string[] })
    if (!parsed) continue
    const { user, usdc, amount } = parsed.args
    await tryVoteBUnitPurchased(
      wallet,
      conetTreasuryAddr,
      conetTxProvider,
      processedTxHashes,
      txHash,
      user,
      usdc,
      amount
    )
  }
}

async function tryVoteBUnitPurchased(
  wallet: Wallet,
  conetTreasuryAddr: string,
  conetTxProvider: ethers.Provider,
  processedTxHashes: Set<string>,
  txHash: string,
  user: string,
  usdc: string,
  amount: bigint
): Promise<void> {
  if (!txHash) {
    debug('vote skip empty base tx hash', {})
    return
  }
  const dedupKey = baseTxHashDedupKey(txHash)
  if (processedTxHashes.has(dedupKey)) {
    debug('vote skip duplicate Base tx already handled', { baseTxHash: txHash })
    return
  }

  const txHashBytes32 = txHash as `0x${string}`
  const conetRead = new ethers.Contract(conetTreasuryAddr, CONET_TREASURY_ABI, conetTxProvider)
  let alreadyVoted: boolean
  try {
    alreadyVoted = await conetRead.hasVotedUsdc2BUnit(txHashBytes32, wallet.address)
  } catch (err: unknown) {
    debug('vote hasVotedUsdc2BUnit precheck failed', {
      baseTxHash: txHash,
      wallet: wallet.address,
      error: err instanceof Error ? err.message : String(err),
    })
    return
  }
  if (alreadyVoted) {
    debug('vote skip Conet hasVotedUsdc2BUnit already true', {
      baseTxHash: txHash,
      wallet: wallet.address,
    })
    processedTxHashes.add(dedupKey)
    return
  }

  processedTxHashes.add(dedupKey)

  debug('vote BUnitPurchased event handling', {
    user,
    usdc,
    amount: amount.toString(),
    baseTxHash: txHash,
  })

  try {
    const conetTreasuryWithSigner = new ethers.Contract(
      conetTreasuryAddr,
      CONET_TREASURY_ABI,
      wallet.connect(conetTxProvider)
    )

    debug('vote sending Conet voteAirdropBUnitFromBase', {
      txHash: txHashBytes32,
      user,
      usdcAmount: amount.toString(),
      gasLimit: VOTE_GAS_LIMIT,
    })

    const tx = await conetTreasuryWithSigner.voteAirdropBUnitFromBase(txHashBytes32, user, amount, {
      gasLimit: VOTE_GAS_LIMIT,
    })
    const receipt = await tx.wait()
    debug('vote Conet voteAirdropBUnitFromBase success', {
      conetTxHash: tx.hash,
      blockNumber: receipt?.blockNumber,
      baseTxHash: txHash,
    })
  } catch (err: unknown) {
    debug('vote Conet voteAirdropBUnitFromBase failed', {
      baseTxHash: txHash,
      error: err instanceof Error ? err.message : String(err),
    })
  }
}

/**
 * 若钱包为 ConetTreasury miner，则：
 * 1) 启动时用 eth_getLogs 回填最近最多 {@link BACKFILL_MAX_BLOCKS} 块内的 BUnitPurchased（WebSocket 不会推送历史日志）；
 * 2) 将已扫描到的 tip 写入本地状态文件（默认 cwd 下 `.vote-base-bunit-scan-state.json`，可用 `VOTE_BASE_SCAN_STATE_FILE` 覆盖）；
 * 3) Base 上再订阅 WebSocket 新事件；Conet 上 isMiner 与 vote 使用 HTTP JsonRpc（避免 CoNET WS 上 eth_call 挂起）。
 *
 * 例：仅订阅时无法看到已上链的 `0x8472766d12337a6a8c42d74daea80aa9a7eaaaae590a6c9b1d019984293757f4`（该笔 receipt 含 BaseTreasury BUnitPurchased），需依赖回填或当时进程已在线。
 *
 * 环境变量：`CONET_RPC`（推荐 HTTPS，用于 isMiner 与投票）；或 `CONET_RPC_WSS`（会转成 https 再用于 HTTP provider）。
 * `VOTE_BASE_BACKFILL_BLOCKS`（默认 2000）；`VOTE_BASE_LOGS_CHUNK_BLOCKS`（默认 400）；`VOTE_BASE_LIVE_POLL_INTERVAL_MS`（默认 12000；0 关闭）。
 * `VOTE_BASE_TIP_STALL_RESTART_MS`（默认 60000）：Base `getBlockNumber` 高水位在该毫秒内未增长则重建 WS 监听；0 关闭。
 * `VOTE_BASE_GETBLOCK_TIMEOUT_MS`（默认 45000）：单次 `getBlockNumber` 挂起超过该毫秒则重建 WS 监听；0 关闭超时。
 *
 * 去重：单次进程内用内存 Set（按 Base tx hash 小写）避免回溯/WS/poll 重复处理同一笔；
 * 持久化 `lastScannedBlock` 避免重启后重复扫描同一段块。
 * 发交易前只读调用 `hasVotedUsdc2BUnit(baseTxHash, wallet)`，已为 true 则跳过，避免删状态后重复扫窗时白烧 gas。
 */
export async function startBaseVoteListen(
  wallet: Wallet,
  baseTreasuryAddr: string,
  conetTreasuryAddr: string,
  baseRpc?: string,
  conetRpc?: string
): Promise<void> {
  const baseRpcRaw = baseRpc || process.env.BASE_RPC || process.env.BASE_RPC_HTTP || 'https://base-rpc.conet.network'
  const baseWssUrl = toBaseWssRpcUrl(baseRpcRaw)
  const conetRpcRaw =
    conetRpc || process.env.CONET_RPC || process.env.CONET_RPC_WSS || CONET_RPC_DEFAULT_HTTP
  const conetHttpUrl = toConetHttpRpcUrl(conetRpcRaw)

  const baseWsProvider = new ethers.WebSocketProvider(baseWssUrl)
  const conetHttpProvider = new ethers.JsonRpcProvider(conetHttpUrl)
  const baseTreasuryWs = new ethers.Contract(baseTreasuryAddr, BASE_TREASURY_ABI, baseWsProvider)
  const conetTreasury = new ethers.Contract(conetTreasuryAddr, CONET_TREASURY_ABI, conetHttpProvider)

  let sessionActive = true
  let pollTimer: ReturnType<typeof setInterval> | undefined
  let stallWatchTimer: ReturnType<typeof setInterval> | undefined
  let pollBusy = false
  /** 本轮会话内 Base `getBlockNumber` 见过的最大块高；严格大于该值才视为「增长」 */
  let rpcTipHighWater = 0n
  let lastRpcTipGrowthAt = Date.now()

  const destroyProviders = async () => {
    await baseWsProvider.destroy().catch(() => undefined)
  }

  const teardownSessionAndRestart = async (reason: string, extra?: Record<string, unknown>) => {
    if (!sessionActive) return
    sessionActive = false
    if (pollTimer !== undefined) {
      clearInterval(pollTimer)
      pollTimer = undefined
    }
    if (stallWatchTimer !== undefined) {
      clearInterval(stallWatchTimer)
      stallWatchTimer = undefined
    }
    try {
      baseTreasuryWs.removeAllListeners()
    } catch {
      /* ignore */
    }
    baseWsProvider.removeAllListeners()
    debug('vote restarting Base listener (tip stall / watchdog)', { reason, ...extra })
    await destroyProviders()
    setImmediate(() => {
      void startBaseVoteListen(wallet, baseTreasuryAddr, conetTreasuryAddr, baseRpc, conetRpc)
    })
  }

  /**
   * 在已成功取得 `cur = getBlockNumber()` 后调用；若需重启则返回 true（会话已 teardown）。
   */
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

  const baseTreasuryLower = baseTreasuryAddr.toLowerCase()
  const statePath = defaultScanStatePath()

  debug('vote startBaseVoteListen init', {
    baseTreasuryAddr,
    expectedBaseTreasury: EXPECTED_BASE_TREASURY,
    addressMatch: baseTreasuryLower === EXPECTED_BASE_TREASURY.toLowerCase(),
    baseWssUrl,
    baseRpcRaw,
    conetHttpUrl,
    conetRpcRaw,
    conetTreasuryAddr,
    wallet: wallet.address,
    backfillMaxBlocks: BACKFILL_MAX_BLOCKS.toString(),
    scanStateFile: statePath,
    baseGetBlockTimeoutMs: BASE_GETBLOCK_TIMEOUT_MS,
  })

  if (baseTreasuryLower !== EXPECTED_BASE_TREASURY.toLowerCase()) {
    debug('vote WARN baseTreasuryAddr does not match expected', {
      actual: baseTreasuryAddr,
      expected: EXPECTED_BASE_TREASURY,
    })
  }

  debug('vote calling ConetTreasury isMiner', { conetHttpUrl, wallet: wallet.address })
  let isConetMiner: boolean
  try {
    isConetMiner = await conetTreasury.isMiner(wallet.address)
  } catch (err: unknown) {
    debug('vote ConetTreasury isMiner threw', {
      conetHttpUrl,
      error: err instanceof Error ? err.message : String(err),
    })
    await destroyProviders()
    return
  }

  debug('vote miner check ConetTreasury isMiner result', {
    wallet: wallet.address,
    baseTreasury: baseTreasuryAddr,
    conetTreasury: conetTreasuryAddr,
    isConetMiner,
  })

  if (!isConetMiner) {
    debug('vote abort not ConetTreasury miner skipping listener', { isConetMiner })
    await destroyProviders()
    return
  }

  debug('vote listener setup verifying Base WebSocket RPC', {})
  let tipBn: bigint
  try {
    tipBn = await getBaseBlockNumberWithTimeout(baseWsProvider, BASE_GETBLOCK_TIMEOUT_MS)
    rpcTipHighWater = tipBn
    lastRpcTipGrowthAt = Date.now()
    debug('vote Base WebSocket connected', { block: tipBn.toString() })
  } catch (err: unknown) {
    if (err instanceof GetBlockNumberTimeoutError) {
      debug('vote Base WebSocket getBlockNumber timeout', {
        baseWssUrl,
        timeoutMs: err.timeoutMs,
        context: 'initial',
      })
      await teardownSessionAndRestart('base_getBlockNumber_timeout', {
        context: 'initial',
        timeoutMs: err.timeoutMs,
      })
      return
    }
    const errMsg = err instanceof Error ? err.message : String(err)
    debug('vote Base WebSocket getBlockNumber failed', { baseWssUrl, error: errMsg })
    await destroyProviders()
    return
  }

  const processedTxHashes = new Set<string>()

  let prevState = await loadScanState(statePath)
  if (prevState && prevState.baseTreasuryAddrLower !== baseTreasuryLower) {
    debug('vote scan state treasury mismatch resetting checkpoint', {
      prev: prevState.baseTreasuryAddrLower,
      now: baseTreasuryLower,
    })
    prevState = null
  }

  const floor = backfillFloorBlock(tipBn)
  const lastScanned = prevState ? BigInt(prevState.lastScannedBlock) : -1n
  const fromBlock = lastScanned >= 0n ? (lastScanned + 1n > floor ? lastScanned + 1n : floor) : floor

  if (fromBlock <= tipBn) {
    debug('vote backfill BUnitPurchased eth_getLogs range', {
      fromBlock: fromBlock.toString(),
      toBlock: tipBn.toString(),
      floor: floor.toString(),
      lastScanned: lastScanned >= 0n ? lastScanned.toString() : null,
    })
    try {
      const logs = await getBUnitPurchasedLogsChunked(baseWsProvider, baseTreasuryAddr, fromBlock, tipBn)
      logs.sort(sortLogs)
      debug('vote backfill logs fetched', { count: logs.length })
      await processBUnitPurchasedLogs(logs, wallet, conetTreasuryAddr, conetHttpProvider, processedTxHashes)
    } catch (err: unknown) {
      debug('vote backfill eth_getLogs failed', { error: err instanceof Error ? err.message : String(err) })
      await destroyProviders()
      return
    }
  } else {
    debug('vote backfill skipped already scanned through tip', {
      fromBlock: fromBlock.toString(),
      tip: tipBn.toString(),
    })
  }

  const now = new Date().toISOString()
  await saveScanState(statePath, {
    version: 1,
    lastScannedBlock: tipBn.toString(),
    baseTreasuryAddrLower: baseTreasuryLower,
    updatedAt: now,
  })
  debug('vote scan state written', {
    path: statePath,
    lastScannedBlock: tipBn.toString(),
    updatedAt: now,
  })

  baseWsProvider.on('error', (err: unknown) => {
    debug('vote Base WebSocketProvider error', { error: err instanceof Error ? err.message : String(err) })
  })

  baseTreasuryWs.on(
    'BUnitPurchased',
    async (user: string, usdc: string, amount: bigint, event: unknown) => {
      if (!sessionActive) return
      const txHash = baseTxHashFromListenerEvent(event)
      const blockNumber = baseBlockLabelFromListenerEvent(event)
      debug('vote WS eth_subscribe BUnitPurchased fired', {
        baseTxHash: txHash || '(missing, rely on live poll if empty)',
        blockNumber: blockNumber || '(missing)',
        user,
        usdc,
        amount: amount.toString(),
      })
      await tryVoteBUnitPurchased(
        wallet,
        conetTreasuryAddr,
        conetHttpProvider,
        processedTxHashes,
        txHash,
        user,
        usdc,
        amount
      )
    }
  )
  debug('vote WebSocket subscribed BUnitPurchased eth_subscribe', { baseTreasuryAddr })

  let lastPolledBlock = tipBn
  let livePollTickCount = 0
  const livePollTick = async () => {
    if (!sessionActive) return
    if (pollBusy) return
    pollBusy = true
    livePollTickCount++
    try {
      const cur = await getBaseBlockNumberWithTimeout(baseWsProvider, BASE_GETBLOCK_TIMEOUT_MS)
      if (await checkRpcTipStallAfterFetch(cur, 'livePoll')) return

      if (cur <= lastPolledBlock) {
        if (livePollTickCount % 10 === 1) {
          debug('vote live poll no new blocks', {
            lastPolledBlock: lastPolledBlock.toString(),
            cur: cur.toString(),
            tick: livePollTickCount,
          })
        }
        return
      }
      const from = lastPolledBlock + 1n
      const logs = await getBUnitPurchasedLogsChunked(baseWsProvider, baseTreasuryAddr, from, cur)
      debug('vote live poll eth_getLogs', {
        fromBlock: from.toString(),
        toBlock: cur.toString(),
        logsCount: logs.length,
        tick: livePollTickCount,
      })
      await processBUnitPurchasedLogs(logs, wallet, conetTreasuryAddr, conetHttpProvider, processedTxHashes)
      lastPolledBlock = cur
      const pollNow = new Date().toISOString()
      await saveScanState(statePath, {
        version: 1,
        lastScannedBlock: cur.toString(),
        baseTreasuryAddrLower: baseTreasuryLower,
        updatedAt: pollNow,
      })
    } catch (err: unknown) {
      if (err instanceof GetBlockNumberTimeoutError) {
        await teardownSessionAndRestart('base_getBlockNumber_timeout', {
          context: 'livePoll',
          timeoutMs: err.timeoutMs,
        })
        return
      }
      debug('vote live poll error', { error: err instanceof Error ? err.message : String(err) })
    } finally {
      pollBusy = false
    }
  }

  if (LIVE_POLL_INTERVAL_MS > 0) {
    pollTimer = setInterval(() => {
      void livePollTick()
    }, LIVE_POLL_INTERVAL_MS)
    void livePollTick()
    debug('vote live poll scheduled eth_getLogs backup', {
      intervalMs: LIVE_POLL_INTERVAL_MS,
      startAfterBlock: lastPolledBlock.toString(),
      tipStallRestartMs: TIP_STALL_RESTART_MS,
      baseGetBlockTimeoutMs: BASE_GETBLOCK_TIMEOUT_MS,
    })
  } else {
    debug('vote live poll disabled VOTE_BASE_LIVE_POLL_INTERVAL_MS=0', {})
  }

  if (TIP_STALL_RESTART_MS > 0 && LIVE_POLL_INTERVAL_MS <= 0) {
    const stallCheckMs = Math.min(15_000, Math.max(5_000, Math.floor(TIP_STALL_RESTART_MS / 4)))
    stallWatchTimer = setInterval(() => {
      void (async () => {
        if (!sessionActive) return
        if (pollBusy) return
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
          debug('vote stall watch getBlockNumber error', {
            error: err instanceof Error ? err.message : String(err),
          })
        } finally {
          pollBusy = false
        }
      })()
    }, stallCheckMs)
    debug('vote stall watch scheduled (live poll off)', {
      stallCheckMs,
      tipStallRestartMs: TIP_STALL_RESTART_MS,
      baseGetBlockTimeoutMs: BASE_GETBLOCK_TIMEOUT_MS,
    })
  }

  debug('vote BaseTreasury listener ready WS plus live poll', {
    baseTreasuryAddr,
    baseWssUrl,
    conetHttpUrl,
  })
}
