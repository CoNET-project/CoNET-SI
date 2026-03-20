import { ethers, Wallet } from 'ethers'

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
      const path = parsed.pathname === '/' || parsed.pathname === '' ? '' : parsed.pathname
      return `wss://${parsed.host}${path}`
    }
    if (/^http:\/\//i.test(u)) {
      const parsed = new URL(u)
      const path = parsed.pathname === '/' || parsed.pathname === '' ? '' : parsed.pathname
      return `ws://${parsed.host}${path}`
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

const VOTE_TAG = 'vote'
function debug(msg: string, data?: object) {
  const ts = new Date().toISOString()
  console.log(`[${ts}] [${VOTE_TAG}] ${msg}`, data ? JSON.stringify(data, null, 2) : '')
}

const EXPECTED_BASE_TREASURY = '0x5c64a8b0935DA72d60933bBD8cD10579E1C40c58'

/**
 * 若钱包为 ConetTreasury miner，则通过 Base 链 WebSocket（eth_subscribe logs）监听 BaseTreasury 的 BUnitPurchased。
 * 不在 Base 端要求 miner；isMiner / voteAirdropBUnitFromBase 经 CoNET WebSocket JSON-RPC 完成。
 *
 * 环境变量：可选 `CONET_RPC_WSS`（已是 wss 时优先）；否则用 `CONET_RPC` 或默认 HTTPS 推导 wss。
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

  debug('startBaseVoteListen init', {
    baseTreasuryAddr,
    expectedBaseTreasury: EXPECTED_BASE_TREASURY,
    addressMatch: baseTreasuryAddr.toLowerCase() === EXPECTED_BASE_TREASURY.toLowerCase(),
    baseWssUrl,
    baseRpcRaw,
    conetWssUrl,
    conetRpcRaw,
    conetTreasuryAddr,
    wallet: wallet.address,
  })

  if (baseTreasuryAddr.toLowerCase() !== EXPECTED_BASE_TREASURY.toLowerCase()) {
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
  try {
    const bn = await baseWsProvider.getBlockNumber()
    debug('Listener setup: Base WebSocket connected', { block: bn.toString() })
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err)
    debug(`Listener setup: Base WebSocket getBlockNumber failed baseWssUrl=${baseWssUrl} error=${errMsg}`)
    await destroyProviders()
    return
  }

  const processedTxHashes = new Set<string>()

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
  )

  debug('BaseTreasury BUnitPurchased listener started (WebSocket eth_subscribe)', {
    baseTreasuryAddr,
    baseWssUrl,
    conetWssUrl,
  })
}
