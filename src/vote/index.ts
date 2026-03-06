import { ethers, Wallet } from 'ethers'

const BASE_RPC_DEFAULT = process.env.BASE_RPC || 'https://1rpc.io/base'
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

function debug(msg: string, data?: object) {
  const ts = new Date().toISOString()
  console.log(`[${ts}] [vote] ${msg}`, data ? JSON.stringify(data, null, 2) : '')
}

/**
 * Poll BaseTreasury logs via eth_getLogs (no eth_newFilter). Compatible with 1rpc.io/base.
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

/**
 * Check if wallet is miner of ConetTreasury.
 * If so, poll BaseTreasury for BUnitPurchased via eth_getLogs (1rpc.io compatible).
 * BaseTreasury miner status is not required.
 */
export async function startBaseVoteListen(
  wallet: Wallet,
  baseTreasuryAddr: string,
  conetTreasuryAddr: string,
  baseRpc?: string,
  conetRpc?: string
): Promise<void> {
  const baseRpcUrl = baseRpc || BASE_RPC_DEFAULT
  const baseProvider = new ethers.JsonRpcProvider(baseRpcUrl)
  const conetProvider = new ethers.JsonRpcProvider(conetRpc || CONET_RPC_DEFAULT)
  const baseTreasury = new ethers.Contract(baseTreasuryAddr, BASE_TREASURY_ABI, baseProvider)
  const conetTreasury = new ethers.Contract(conetTreasuryAddr, CONET_TREASURY_ABI, conetProvider)

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

  const bunitPurchasedIface = new ethers.Interface([
    'event BUnitPurchased(address indexed user, address indexed usdc, uint256 amount)',
  ])
  const bunitPurchasedTopic = bunitPurchasedIface.getEvent('BUnitPurchased')?.topicHash
  if (!bunitPurchasedTopic) {
    debug('Could not get BUnitPurchased topic, skipping poller')
    return
  }

  debug('Starting BaseTreasury poller (eth_getLogs, no eth_newFilter)', {
    pollIntervalMs: POLL_INTERVAL_MS,
  })

  let lastBlock = BigInt(await baseProvider.getBlockNumber())
  const processedTxHashes = new Set<string>()

  const tick = async () => {
    try {
      const currentBlock = BigInt(await baseProvider.getBlockNumber())
      if (currentBlock <= lastBlock) return

      const logs = await getBUnitPurchasedLogs(
        baseProvider,
        baseTreasuryAddr,
        bunitPurchasedTopic,
        lastBlock + 1n,
        currentBlock
      )

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

  debug('BaseTreasury poller started')
}

