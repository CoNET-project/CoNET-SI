import { ethers, Wallet } from 'ethers'

/** 将 wss:// 转为 https://，供 eth_getLogs 轮询使用（不依赖 WebSocket） */
function toHttpRpcUrl(url: string): string {
  return url.replace(/^wss:\/\//, 'https://').replace(/\/ws\/?$/, '') || url
}

/** Base RPC：优先 BASE_RPC_HTTP（HTTP-only RPC 如 1rpc.io），否则将 BASE_RPC 的 wss 转为 https */
const BASE_RPC_DEFAULT = toHttpRpcUrl(
  process.env.BASE_RPC_HTTP || process.env.BASE_RPC || 'https://1rpc.io/base'
)
const CONET_RPC_DEFAULT = process.env.CONET_RPC || 'https://mainnet-rpc.conet.network'
const VOTE_GAS_LIMIT = 1_500_000
const POLL_INTERVAL_MS = Number(process.env.VOTE_POLL_INTERVAL_MS) || 12_000

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

/**
 * Poll BaseTreasury logs via eth_getLogs (no eth_newFilter). Compatible with base-rpc.conet.network.
 */
async function getBUnitPurchasedLogs(
  baseProvider: ethers.JsonRpcProvider,
  baseTreasuryAddr: string,
  bunitPurchasedTopic: string,
  fromBlock: bigint,
  toBlock: bigint
): Promise<ethers.Log[]> {
  const logs = await baseProvider.getLogs({
    address: baseTreasuryAddr,
    topics: [bunitPurchasedTopic],
    fromBlock,
    toBlock,
  })
  return logs
}

const EXPECTED_BASE_TREASURY = '0x5c64a8b0935DA72d60933bBD8cD10579E1C40c58'

/**
 * Check if wallet is miner of ConetTreasury.
 * If so, poll BaseTreasury for BUnitPurchased via eth_getLogs (base-rpc.conet.network compatible).
 * BaseTreasury miner status is not required.
 */
export async function startBaseVoteListen(
  wallet: Wallet,
  baseTreasuryAddr: string,
  conetTreasuryAddr: string,
  baseRpc?: string,
  conetRpc?: string
): Promise<void> {
  const baseRpcUrl = toHttpRpcUrl(baseRpc || BASE_RPC_DEFAULT)
  const isHttp = /^https:\/\//.test(baseRpcUrl)
  const baseProvider = new ethers.JsonRpcProvider(baseRpcUrl)
  const conetProvider = new ethers.JsonRpcProvider(conetRpc || CONET_RPC_DEFAULT)
  const baseTreasury = new ethers.Contract(baseTreasuryAddr, BASE_TREASURY_ABI, baseProvider)
  const conetTreasury = new ethers.Contract(conetTreasuryAddr, CONET_TREASURY_ABI, conetProvider)

  debug('startBaseVoteListen init', {
    baseTreasuryAddr,
    expectedBaseTreasury: EXPECTED_BASE_TREASURY,
    addressMatch: baseTreasuryAddr.toLowerCase() === EXPECTED_BASE_TREASURY.toLowerCase(),
    baseRpcUrl,
    isHttp,
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
    debug('Not ConetTreasury miner, skipping BaseTreasury poller', { isConetMiner })
    return
  }

  debug('Poller setup: getting BUnitPurchased topic')
  const bunitPurchasedIface = new ethers.Interface([
    'event BUnitPurchased(address indexed user, address indexed usdc, uint256 amount)',
  ])
  const bunitPurchasedTopic = bunitPurchasedIface.getEvent('BUnitPurchased')?.topicHash
  if (!bunitPurchasedTopic) {
    debug('Could not get BUnitPurchased topic, skipping poller')
    return
  }

  const baseRpcProtocol = baseRpcUrl.startsWith('https://') ? 'https' : baseRpcUrl.startsWith('wss://') ? 'wss' : baseRpcUrl.startsWith('http://') ? 'http' : 'unknown'
  debug('Poller setup: fetching initial block from Base RPC', { baseRpcUrl, protocol: baseRpcProtocol })
  let lastBlock: bigint
  try {
    lastBlock = BigInt(await baseProvider.getBlockNumber())
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err)
    debug(`Poller setup: Base getBlockNumber failed baseRpcUrl=${baseRpcUrl} protocol=${baseRpcProtocol} error=${errMsg}`)
    return
  }
  debug('Poller setup: got initial block', { block: lastBlock.toString() })
  debug('Starting BaseTreasury poller (eth_getLogs)', {
    pollIntervalMs: POLL_INTERVAL_MS,
    baseTreasuryAddr,
    bunitPurchasedTopic,
    isHttp,
    initialBlock: lastBlock.toString(),
  })
  const processedTxHashes = new Set<string>()
  let tickCount = 0

  const tick = async () => {
    tickCount++
    try {
      const currentBlock = BigInt(await baseProvider.getBlockNumber())
      if (currentBlock <= lastBlock) {
        if (tickCount % 5 === 1) {
          debug('Poll tick (no new blocks)', { lastBlock: lastBlock.toString(), currentBlock: currentBlock.toString(), tickCount })
        }
        return
      }

      const fromBlock = lastBlock + 1n
      const logs = await getBUnitPurchasedLogs(
        baseProvider,
        baseTreasuryAddr,
        bunitPurchasedTopic,
        fromBlock,
        currentBlock
      )

      debug('Poll tick', {
        fromBlock: fromBlock.toString(),
        toBlock: currentBlock.toString(),
        logsCount: logs.length,
        tickCount,
      })

      for (const log of logs) {
        const txHash = log.transactionHash ?? ''
        if (processedTxHashes.has(txHash)) continue
        processedTxHashes.add(txHash)

        const parsed = bunitPurchasedIface.parseLog({ data: log.data, topics: log.topics as string[] })
        if (!parsed) continue
        const { user, usdc, amount } = parsed.args

        debug('BUnitPurchased', { user, usdc, amount: amount.toString(), baseTxHash: txHash })

        try {
          const conetTreasuryWithSigner = new ethers.Contract(
            conetTreasuryAddr,
            CONET_TREASURY_ABI,
            wallet.connect(conetProvider)
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

      lastBlock = currentBlock
    } catch (err: unknown) {
      debug('Poll tick error', { error: err instanceof Error ? err.message : String(err) })
    }
  }

  setInterval(tick, POLL_INTERVAL_MS)
  tick()

  debug('BaseTreasury poller started', {
    baseTreasuryAddr,
    initialLastBlock: lastBlock.toString(),
    pollIntervalMs: POLL_INTERVAL_MS,
    isHttp,
  })
}

