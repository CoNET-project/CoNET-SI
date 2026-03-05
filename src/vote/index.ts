import { ethers, Wallet } from 'ethers'

const BASE_RPC_DEFAULT = process.env.BASE_RPC || 'wss://base-rpc.conet.network/ws'
const CONET_RPC_DEFAULT = process.env.CONET_RPC || 'https://mainnet-rpc1.conet.network'
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

function debug(msg: string, data?: object) {
  const ts = new Date().toISOString()
  console.log(`[${ts}] [vote] ${msg}`, data ? JSON.stringify(data, null, 2) : '')
}

/**
 * Check if wallet is miner of ConetTreasury.
 * If so, start listening to BaseTreasury events. On BUnitPurchased, vote via ConetTreasury.
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
  const baseProvider =
    baseRpcUrl.startsWith('wss://') || baseRpcUrl.startsWith('ws://')
      ? new ethers.WebSocketProvider(baseRpcUrl)
      : new ethers.JsonRpcProvider(baseRpcUrl)
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
    debug('Not ConetTreasury miner, skipping BaseTreasury event listener', { isConetMiner })
    return
  }

  debug('Starting BaseTreasury event listener (ETHDeposited, ERC20Deposited, BUnitPurchased)')

  const baseTreasuryWithProvider = new ethers.Contract(baseTreasuryAddr, BASE_TREASURY_ABI, baseProvider)

  baseTreasuryWithProvider.on('ETHDeposited', (depositor: string, amount: bigint) => {
    debug('ETHDeposited', { depositor, amount: amount.toString() })
  })

  baseTreasuryWithProvider.on('ERC20Deposited', (depositor: string, token: string, amount: bigint, nonce: string) => {
    debug('ERC20Deposited', { depositor, token, amount: amount.toString(), nonce })
  })

  const bunitPurchasedIface = new ethers.Interface([
    'event BUnitPurchased(address indexed user, address indexed usdc, uint256 amount)',
  ])
  const bunitPurchasedTopic = bunitPurchasedIface.getEvent('BUnitPurchased')?.topicHash
  if (!bunitPurchasedTopic) {
    debug('Could not get BUnitPurchased topic, skipping listener')
    return
  }

  baseProvider.on(
    {
      address: baseTreasuryAddr,
      topics: [bunitPurchasedTopic],
    },
    async (log: ethers.Log) => {
      const parsed = bunitPurchasedIface.parseLog({ data: log.data, topics: log.topics as string[] })
      if (!parsed) return
      const { user, usdc, amount } = parsed.args

      debug('BUnitPurchased', { user, usdc, amount: amount.toString(), baseTxHash: log.transactionHash })

      try {
        const conetTreasuryWithSigner = new ethers.Contract(conetTreasuryAddr, CONET_TREASURY_ABI, wallet.connect(conetProvider))
        const txHashBytes32 = log.transactionHash as `0x${string}`

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

  debug('BaseTreasury event listener started')
}

