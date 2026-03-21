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

/**
 * 统一带 [vote] 且单行输出，便于 `journalctl -f -u conet.service | grep vot`（多行 JSON 续行不含 tag 会被漏掉）。
 */
const VOTE_TAG = 'vote'
function debug(msg: string, data?: Record<string, unknown> | object) {
  const ts = new Date().toISOString()
  const suffix = data !== undefined ? ` ${JSON.stringify(data)}` : ''
  console.log(`[${VOTE_TAG}] [${ts}] ${msg}${suffix}`)
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
  if (processedTxHashes.has(txHash)) {
    debug('vote skip duplicate Base tx already handled', { baseTxHash: txHash })
    return
  }
  processedTxHashes.add(txHash)

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
    const txHashBytes32 = txHash as `0x${string}`

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

  const destroyProviders = async () => {
    await baseWsProvider.destroy().catch(() => undefined)
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
    tipBn = BigInt(await baseWsProvider.getBlockNumber())
    debug('vote Base WebSocket connected', { block: tipBn.toString() })
  } catch (err: unknown) {
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
    async (user: string, usdc: string, amount: bigint, event: ethers.EventLog) => {
      const txHash = event.transactionHash ?? ''
      const blockNumber = event.blockNumber?.toString?.() ?? String(event.blockNumber)
      debug('vote WS eth_subscribe BUnitPurchased fired', {
        baseTxHash: txHash,
        blockNumber,
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
  if (LIVE_POLL_INTERVAL_MS > 0) {
    const livePollTick = async () => {
      livePollTickCount++
      try {
        const cur = BigInt(await baseWsProvider.getBlockNumber())
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
        debug('vote live poll error', { error: err instanceof Error ? err.message : String(err) })
      }
    }
    setInterval(livePollTick, LIVE_POLL_INTERVAL_MS)
    void livePollTick()
    debug('vote live poll scheduled eth_getLogs backup', {
      intervalMs: LIVE_POLL_INTERVAL_MS,
      startAfterBlock: lastPolledBlock.toString(),
    })
  } else {
    debug('vote live poll disabled VOTE_BASE_LIVE_POLL_INTERVAL_MS=0', {})
  }

  debug('vote BaseTreasury listener ready WS plus live poll', {
    baseTreasuryAddr,
    baseWssUrl,
    conetHttpUrl,
  })
}
