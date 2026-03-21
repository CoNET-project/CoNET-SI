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
 * CoNET L1：与 bizSite `CONET_MAINNET_WSS` 一致，默认 `wss://mainnet-rpc.conet.network`（无 /ws 后缀，与 Base 不同）。
 */
function toConetWssRpcUrl(url: string): string {
  const u = url.trim()
  if (/^wss:\/\//i.test(u)) return u
  if (/^ws:\/\//i.test(u)) return u
  try {
    if (/^https:\/\//i.test(u)) {
      const parsed = new URL(u)
      const pathPart = parsed.pathname === '/' || parsed.pathname === '' ? '' : parsed.pathname
      return `wss://${parsed.host}${pathPart}`
    }
    if (/^http:\/\//i.test(u)) {
      const parsed = new URL(u)
      const pathPart = parsed.pathname === '/' || parsed.pathname === '' ? '' : parsed.pathname
      return `ws://${parsed.host}${pathPart}`
    }
  } catch {
    /* fall through */
  }
  if (!/:\/\//.test(u)) {
    return `wss://${u.replace(/\/$/, '')}`
  }
  return u
}

const CONET_RPC_DEFAULT_HTTP = process.env.CONET_RPC || 'https://mainnet-rpc.conet.network'
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

const BASE_TREASURY_ABI = [
  'function isMiner(address account) view returns (bool)',
  'event ETHDeposited(address indexed depositor, uint256 amount)',
  'event ERC20Deposited(address indexed depositor, address indexed token, uint256 amount, bytes32 indexed nonce)',
  'event BUnitPurchased(address indexed user, address indexed usdc, uint256 amount)',
] as const

const CONET_TREASURY_ABI = [
  'function isMiner(address account) view returns (bool)',
  'function voteAirdropBUnitFromBase(bytes32 txHash, address user, uint256 usdcAmount) external',
] as const

const bunitPurchasedIface = new ethers.Interface([
  'event BUnitPurchased(address indexed user, address indexed usdc, uint256 amount)',
])
const BUNIT_PURCHASED_TOPIC = bunitPurchasedIface.getEvent('BUnitPurchased')!.topicHash

const VOTE_TAG = 'vote'
function debug(msg: string, data?: object) {
  const ts = new Date().toISOString()
  console.log(`[${ts}] [${VOTE_TAG}] ${msg}`, data ? JSON.stringify(data, null, 2) : '')
}

const EXPECTED_BASE_TREASURY = '0x5c64a8b0935DA72d60933bBD8cD10579E1C40c58'

type ScanStateV1 = {
  version: 1
  /** 已完成回填/扫描到的 Base 区块高度（十进制字符串） */
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
  conetWsProvider: ethers.WebSocketProvider,
  processedTxHashes: Set<string>
): Promise<void> {
  const sorted = [...logs].sort(sortLogs)
  for (const log of sorted) {
    const txHash = log.transactionHash ?? ''
    const parsed = bunitPurchasedIface.parseLog({ data: log.data, topics: log.topics as string[] })
    if (!parsed) continue
    const { user, usdc, amount } = parsed.args
    await tryVoteBUnitPurchased(
      wallet,
      conetTreasuryAddr,
      conetWsProvider,
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
  conetWsProvider: ethers.WebSocketProvider,
  processedTxHashes: Set<string>,
  txHash: string,
  user: string,
  usdc: string,
  amount: bigint
): Promise<void> {
  if (!txHash || processedTxHashes.has(txHash)) return
  processedTxHashes.add(txHash)

  debug('BUnitPurchased', { user, usdc, amount: amount.toString(), baseTxHash: txHash })

  try {
    const conetTreasuryWithSigner = new ethers.Contract(
      conetTreasuryAddr,
      CONET_TREASURY_ABI,
      wallet.connect(conetWsProvider)
    )
    const txHashBytes32 = txHash as `0x${string}`

    debug('Voting voteAirdropBUnitFromBase', {
      txHash: txHashBytes32,
      user,
      usdcAmount: amount.toString(),
      gasLimit: VOTE_GAS_LIMIT,
    })

    const tx = await conetTreasuryWithSigner.voteAirdropBUnitFromBase(txHashBytes32, user, amount, {
      gasLimit: VOTE_GAS_LIMIT,
    })
    const receipt = await tx.wait()
    debug('voteAirdropBUnitFromBase success', { txHash: tx.hash, blockNumber: receipt?.blockNumber })
  } catch (err: unknown) {
    debug('voteAirdropBUnitFromBase failed', { error: err instanceof Error ? err.message : String(err) })
  }
}

/**
 * 若钱包为 ConetTreasury miner，则：
 * 1) 启动时用 eth_getLogs 回填最近最多 {@link BACKFILL_MAX_BLOCKS} 块内的 BUnitPurchased（WebSocket 不会推送历史日志）；
 * 2) 将已扫描到的 tip 写入本地状态文件（默认 cwd 下 `.vote-base-bunit-scan-state.json`，可用 `VOTE_BASE_SCAN_STATE_FILE` 覆盖）；
 * 3) 再订阅 WebSocket 新事件。
 *
 * 例：仅订阅时无法看到已上链的 `0x8472766d12337a6a8c42d74daea80aa9a7eaaaae590a6c9b1d019984293757f4`（该笔 receipt 含 BaseTreasury BUnitPurchased），需依赖回填或当时进程已在线。
 *
 * 环境变量：可选 `CONET_RPC_WSS`；`VOTE_BASE_BACKFILL_BLOCKS`（默认 2000）；`VOTE_BASE_LOGS_CHUNK_BLOCKS`（默认 400）；
 * `VOTE_BASE_LIVE_POLL_INTERVAL_MS`（默认 12000，eth_getLogs 补扫；0 关闭）。
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
    conetRpc || process.env.CONET_RPC_WSS || process.env.CONET_RPC || CONET_RPC_DEFAULT_HTTP
  const conetWssUrl = toConetWssRpcUrl(conetRpcRaw)

  const baseWsProvider = new ethers.WebSocketProvider(baseWssUrl)
  const conetWsProvider = new ethers.WebSocketProvider(conetWssUrl)
  const baseTreasuryWs = new ethers.Contract(baseTreasuryAddr, BASE_TREASURY_ABI, baseWsProvider)
  const conetTreasury = new ethers.Contract(conetTreasuryAddr, CONET_TREASURY_ABI, conetWsProvider)

  const destroyProviders = async () => {
    await Promise.all([
      baseWsProvider.destroy().catch(() => undefined),
      conetWsProvider.destroy().catch(() => undefined),
    ])
  }

  const baseTreasuryLower = baseTreasuryAddr.toLowerCase()
  const statePath = defaultScanStatePath()

  debug('startBaseVoteListen init', {
    baseTreasuryAddr,
    expectedBaseTreasury: EXPECTED_BASE_TREASURY,
    addressMatch: baseTreasuryLower === EXPECTED_BASE_TREASURY.toLowerCase(),
    baseWssUrl,
    baseRpcRaw,
    conetWssUrl,
    conetRpcRaw,
    conetTreasuryAddr,
    wallet: wallet.address,
    backfillMaxBlocks: BACKFILL_MAX_BLOCKS.toString(),
    scanStateFile: statePath,
  })

  if (baseTreasuryLower !== EXPECTED_BASE_TREASURY.toLowerCase()) {
    debug('WARN: baseTreasuryAddr does not match expected', {
      actual: baseTreasuryAddr,
      expected: EXPECTED_BASE_TREASURY,
    })
  }

  const isConetMiner = await conetTreasury.isMiner(wallet.address)

  debug('Miner check', {
    wallet: wallet.address,
    baseTreasury: baseTreasuryAddr,
    conetTreasury: conetTreasuryAddr,
    isConetMiner,
  })

  if (!isConetMiner) {
    debug('Not ConetTreasury miner, skipping BaseTreasury listener', { isConetMiner })
    await destroyProviders()
    return
  }

  debug('Listener setup: verifying Base WebSocket RPC')
  let tipBn: bigint
  try {
    tipBn = BigInt(await baseWsProvider.getBlockNumber())
    debug('Listener setup: Base WebSocket connected', { block: tipBn.toString() })
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err)
    debug(`Listener setup: Base WebSocket getBlockNumber failed baseWssUrl=${baseWssUrl} error=${errMsg}`)
    await destroyProviders()
    return
  }

  const processedTxHashes = new Set<string>()

  let prevState = await loadScanState(statePath)
  if (prevState && prevState.baseTreasuryAddrLower !== baseTreasuryLower) {
    debug('Scan state treasury mismatch, resetting checkpoint', {
      prev: prevState.baseTreasuryAddrLower,
      now: baseTreasuryLower,
    })
    prevState = null
  }

  const floor = backfillFloorBlock(tipBn)
  const lastScanned = prevState ? BigInt(prevState.lastScannedBlock) : -1n
  const fromBlock = lastScanned >= 0n ? (lastScanned + 1n > floor ? lastScanned + 1n : floor) : floor

  if (fromBlock <= tipBn) {
    debug('Backfill BUnitPurchased via eth_getLogs', {
      fromBlock: fromBlock.toString(),
      toBlock: tipBn.toString(),
      floor: floor.toString(),
      lastScanned: lastScanned >= 0n ? lastScanned.toString() : null,
    })
    try {
      const logs = await getBUnitPurchasedLogsChunked(baseWsProvider, baseTreasuryAddr, fromBlock, tipBn)
      logs.sort(sortLogs)
      debug('Backfill logs fetched', { count: logs.length })
      await processBUnitPurchasedLogs(logs, wallet, conetTreasuryAddr, conetWsProvider, processedTxHashes)
    } catch (err: unknown) {
      debug('Backfill eth_getLogs failed', { error: err instanceof Error ? err.message : String(err) })
      await destroyProviders()
      return
    }
  } else {
    debug('Backfill skipped (already scanned through tip)', {
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
  debug('Scan state written', {
    path: statePath,
    lastScannedBlock: tipBn.toString(),
    updatedAt: now,
  })

  baseWsProvider.on('error', (err: unknown) => {
    debug('Base WebSocketProvider error', { error: err instanceof Error ? err.message : String(err) })
  })
  conetWsProvider.on('error', (err: unknown) => {
    debug('Conet WebSocketProvider error', { error: err instanceof Error ? err.message : String(err) })
  })

  baseTreasuryWs.on(
    'BUnitPurchased',
    async (user: string, usdc: string, amount: bigint, event: ethers.EventLog) => {
      const txHash = event.transactionHash ?? ''
      await tryVoteBUnitPurchased(
        wallet,
        conetTreasuryAddr,
        conetWsProvider,
        processedTxHashes,
        txHash,
        user,
        usdc,
        amount
      )
    }
  )

  let lastPolledBlock = tipBn
  let livePollTickCount = 0
  if (LIVE_POLL_INTERVAL_MS > 0) {
    const livePollTick = async () => {
      livePollTickCount++
      try {
        const cur = BigInt(await baseWsProvider.getBlockNumber())
        if (cur <= lastPolledBlock) {
          if (livePollTickCount % 10 === 1) {
            debug('Live poll (no new blocks)', {
              lastPolledBlock: lastPolledBlock.toString(),
              cur: cur.toString(),
              tick: livePollTickCount,
            })
          }
          return
        }
        const from = lastPolledBlock + 1n
        const logs = await getBUnitPurchasedLogsChunked(baseWsProvider, baseTreasuryAddr, from, cur)
        debug('Live poll eth_getLogs', {
          fromBlock: from.toString(),
          toBlock: cur.toString(),
          logsCount: logs.length,
          tick: livePollTickCount,
        })
        await processBUnitPurchasedLogs(logs, wallet, conetTreasuryAddr, conetWsProvider, processedTxHashes)
        lastPolledBlock = cur
        const pollNow = new Date().toISOString()
        await saveScanState(statePath, {
          version: 1,
          lastScannedBlock: cur.toString(),
          baseTreasuryAddrLower: baseTreasuryLower,
          updatedAt: pollNow,
        })
      } catch (err: unknown) {
        debug('Live poll error', { error: err instanceof Error ? err.message : String(err) })
      }
    }
    setInterval(livePollTick, LIVE_POLL_INTERVAL_MS)
    void livePollTick()
    debug('Live poll scheduled (eth_getLogs backup for unreliable log subscriptions)', {
      intervalMs: LIVE_POLL_INTERVAL_MS,
      startAfterBlock: lastPolledBlock.toString(),
    })
  } else {
    debug('Live poll disabled (VOTE_BASE_LIVE_POLL_INTERVAL_MS=0)')
  }

  debug('BaseTreasury BUnitPurchased listener started (WebSocket eth_subscribe + optional live poll)', {
    baseTreasuryAddr,
    baseWssUrl,
    conetWssUrl,
  })
}
