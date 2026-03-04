/**
 * 聆听 BaseTreasury 的 ERC20Deposited 和 BUnitPurchased 事件，
 * 校验交易 hash，提取 to 钱包和金额，供 miner 投票使用。
 */
import { ethers, Contract, JsonRpcProvider, EventLog } from 'ethers'

const BASE_RPC = process.env.BASE_RPC ?? 'https://mainnet.base.org'
const BASE_CHAIN_ID = 8453

const BaseTreasuryABI = [
  'event ERC20Deposited(address indexed depositor, address indexed token, uint256 amount, bytes32 indexed nonce)',
  'event BUnitPurchased(address indexed user, address indexed usdc, uint256 amount)',
]

export interface ERC20DepositedPayload {
  txHash: string
  to: string
  token: string
  amount: bigint
  nonce: string
}

export interface BUnitPurchasedPayload {
  txHash: string
  to: string
  usdc: string
  amount: bigint
}

export type BaseVoteEventPayload = {
  type: 'ERC20Deposited'
  payload: ERC20DepositedPayload
} | {
  type: 'BUnitPurchased'
  payload: BUnitPurchasedPayload
}

export type BaseVoteEventCallback = (payload: BaseVoteEventPayload) => void | Promise<void>

let provider: JsonRpcProvider | null = null
let contract: Contract | null = null
let listeners: BaseVoteEventCallback[] = []

/**
 * 从交易 receipt 校验 hash 并返回事件数据
 */
async function verifyAndParseERC20Deposited(
  provider: JsonRpcProvider,
  txHash: string,
  depositor: string,
  token: string,
  amount: bigint,
  nonce: string
): Promise<ERC20DepositedPayload | null> {
  try {
    const receipt = await provider.getTransactionReceipt(txHash)
    if (!receipt || receipt.hash !== txHash) return null
    return { txHash, to: depositor, token, amount, nonce }
  } catch {
    return null
  }
}

export async function verifyAndParseBUnitPurchased(
  provider: JsonRpcProvider,
  txHash: string,
  user: string,
  usdc: string,
  amount: bigint
): Promise<BUnitPurchasedPayload | null> {
  try {
    const receipt = await provider.getTransactionReceipt(txHash)
    if (!receipt || receipt.hash !== txHash) return null
    return { txHash, to: user, usdc, amount }
  } catch {
    return null
  }
}

function notifyListeners(payload: BaseVoteEventPayload) {
  for (const cb of listeners) {
    try {
      const r = cb(payload)
      if (r instanceof Promise) r.catch(() => {})
    } catch (_) {}
  }
}

/**
 * 注册事件回调
 */
export function onBaseVoteEvent(callback: BaseVoteEventCallback) {
  listeners.push(callback)
  return () => {
    listeners = listeners.filter((c) => c !== callback)
  }
}

/**
 * 启动聆听 BaseTreasury 的 ERC20Deposited 和 BUnitPurchased 事件
 */
export async function startBaseVoteListen(
  baseTreasuryAddress: string,
  rpcUrl?: string
): Promise<() => void> {
  const url = rpcUrl ?? BASE_RPC
  provider = new JsonRpcProvider(url)
  contract = new Contract(baseTreasuryAddress, BaseTreasuryABI, provider)

  const handleERC20Deposited = async (
    depositor: string,
    token: string,
    amount: bigint,
    nonce: string,
    event: EventLog
  ) => {
    const txHash = event.transactionHash
    const payload = await verifyAndParseERC20Deposited(
      provider!,
      txHash,
      depositor,
      token,
      amount,
      nonce
    )
    if (payload) {
      notifyListeners({ type: 'ERC20Deposited', payload })
    }
  }

  const handleBUnitPurchased = async (
    user: string,
    usdc: string,
    amount: bigint,
    event: EventLog
  ) => {
    const txHash = event.transactionHash
    const payload = await verifyAndParseBUnitPurchased(
      provider!,
      txHash,
      user,
      usdc,
      amount
    )
    if (payload) {
      notifyListeners({ type: 'BUnitPurchased', payload })
    }
  }

  contract.on('ERC20Deposited', handleERC20Deposited)
  contract.on('BUnitPurchased', handleBUnitPurchased)

  return () => {
    contract?.removeAllListeners('ERC20Deposited')
    contract?.removeAllListeners('BUnitPurchased')
    provider = null
    contract = null
  }
}

/**
 * 查询历史事件（按区块范围）
 */
export async function queryBaseVoteEvents(
  baseTreasuryAddress: string,
  fromBlock: number,
  toBlock: number | 'latest',
  rpcUrl?: string
): Promise<BaseVoteEventPayload[]> {
  const url = rpcUrl ?? BASE_RPC
  const prov = new JsonRpcProvider(url)
  const c = new Contract(baseTreasuryAddress, BaseTreasuryABI, prov)
  const results: BaseVoteEventPayload[] = []

  const erc20Logs = await c.queryFilter(
    c.filters.ERC20Deposited(),
    fromBlock,
    toBlock === 'latest' ? 'latest' : toBlock
  )
  for (const log of erc20Logs) {
    if (!(log instanceof EventLog)) continue
    const [depositor, token, amount, nonce] = log.args
    const txHash = log.transactionHash
    const payload = await verifyAndParseERC20Deposited(
      prov,
      txHash,
      depositor,
      token,
      amount,
      nonce
    )
    if (payload) results.push({ type: 'ERC20Deposited', payload })
  }

  const purchaseLogs = await c.queryFilter(
    c.filters.BUnitPurchased(),
    fromBlock,
    toBlock === 'latest' ? 'latest' : toBlock
  )
  for (const log of purchaseLogs) {
    if (!(log instanceof EventLog)) continue
    const [user, usdc, amount] = log.args
    const txHash = log.transactionHash
    const payload = await verifyAndParseBUnitPurchased(
      prov,
      txHash,
      user,
      usdc,
      amount
    )
    if (payload) results.push({ type: 'BUnitPurchased', payload })
  }

  return results
}
